/**
 * child.c
 *
 * Child process initialization and container setup.
 *
 * OVERVIEW:
 * This file implements the container child process's main function and all the
 * namespace/security setup that happens before executing the target program.
 * The child process runs in new namespaces created by clone() and must
 * configure its isolated environment.
 *
 * SECURITY LAYERS:
 * - Namespace isolation (UTS, PID, mount, network, IPC)
 * - Filesystem isolation (pivot_root to separate root)
 * - Capability dropping (remove all Linux capabilities)
 * - Syscall filtering (seccomp-bpf whitelist)
 * - Resource limits (cgroups for CPU, memory, PIDs)
 *
 * EXECUTION FLOW:
 * - Wait for parent to configure cgroups
 * - Join cgroup
 * - Set hostname
 * - Set up mount namespace
 * - Drop all capabilities
 * - Lock capabilities
 * - Apply seccomp filter
 * - Execute target program
 */

#include <errno.h>
#include <linux/audit.h>
#include <linux/capability.h>
#include <linux/filter.h>
#include <linux/limits.h>
#include <linux/seccomp.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "cgroups.h"
#include "child.h"
#include "context.h"
#include "filter.h"

/**
 * setup_uts_namespace - Configure the UTS namespace hostname
 * @ctx: Container configuration containing the desired hostname
 *
 * Sets the hostname visible inside the container.
 *
 * UTS NAMESPACE:
 * Unix Time-Sharing namespace isolates:
 * - Hostname
 * - NIS domain name
 *
 * Return: 0 on success, -1 on failure
 */
static int setup_uts_namespace(struct container_ctx *ctx) {
  if (sethostname(ctx->hostname, strlen(ctx->hostname)) == -1) {
    fprintf(stderr, "Failed to set hostname: %s\n", strerror(errno));
    return -1;
  }

  return 0;
}

/**
 * setup_mount_propagation - Make root mount private
 *
 * Marks the root mount (/) as private to prevent mount/unmount events from
 * propagating between the container and host. This is essential for isolating
 * mount namespace.
 *
 * MOUNT PROPAGATION:
 * Mounts can be:
 * - MS_SHARED: Events propagate to peer mounts
 * - MS_PRIVATE: Events don't propagate (isolated)
 * - MS_SLAVE: Recieve events but don't send them
 * - MS_UNBINDABLE: Can't be bind mounted
 *
 * Without this, mounting /proc in the container would also mount it on the
 * host. Making / private ensures the mounts stay isolated.
 *
 * MS_REC applies the change recursively to all mounts under /.
 *
 * Return: 0 on success, -1 on failure
 */
static int setup_mount_propagation(void) {
  if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) == -1) {
    fprintf(stderr, "Failed to setup mount propagation: %s\n", strerror(errno));
    return -1;
  }

  return 0;
}

/**
 * setup_overlay - Configure overlayfs for writable rootfs
 * @ctx: Container configuration containing paths for overlayFS
 *
 * Creates an overlay filesystem:
 * - Lower layer: Read-only rootfs
 * - Upper layer: Writable layer
 * - Work layer: Temporary workspace used by overlayfs for atomic operations
 * - Merged: Combined view of lower and upper that becomes the new root
 *
 * OVERLAYFS:
 * When files are read, overlayfs checks upper first then falls back to lower
 * When files are written, changes always got to upper (copied upwards from
 * lower if needed) The merged directory presents a unified view where the
 * modified files in upper mask the originals in lower.
 *
 * TMPFS:
 * A tmpfs is mounted at overlay_base to store the upper and work directories in
 * RAM. This has a few effects:
 * - File operations are faster (since RAM is faster than disk)
 * - No persistent filesystem state
 * - The lower layer (original rootfs) remains unchanged
 *
 * Return: 0 on success, -1 on failure
 */
static int setup_overlay(struct container_ctx *ctx) {

  if (mkdir(ctx->overlay_base, 0755) == -1 && errno != EEXIST) {
    fprintf(stderr, "Failed to create overlayfs base directory: %s\n",
            strerror(errno));
    return -1;
  }

  char tmpfs_opts[32];
  snprintf(tmpfs_opts, sizeof(tmpfs_opts), "size=%dM", ctx->tmpfs_size);

  /**
   * Everything created inside of the tmpfs lives in RAM and only exists as long
   * as the sandbox is running.
   */
  if (mount("tmpfs", ctx->overlay_base, "tmpfs", 0, tmpfs_opts) == -1) {
    fprintf(stderr, "Failed to mount tmpfs: %s\n", strerror(errno));
    return -1;
  }

  /*
   * Construct paths for the working, upper, and merged directories of our
   * overlay.
   */
  int work_len = strlen(ctx->overlay_base) + strlen("/work") + 1;
  char *overlay_work = malloc(work_len);
  if (!overlay_work) {
    fprintf(stderr,
            "Failed to allocate memory for overlayfs work directory: %s\n",
            strerror(errno));
    return -1;
  }
  snprintf(overlay_work, work_len, "%s/work", ctx->overlay_base);

  int upper_len = strlen(ctx->overlay_base) + strlen("/upper") + 1;
  char *overlay_upper = malloc(upper_len);
  if (!overlay_upper) {
    fprintf(stderr,
            "Failed to allocate memory for overlayfs upper directory: %s\n",
            strerror(errno));
    free(overlay_work);
    return -1;
  }
  snprintf(overlay_upper, upper_len, "%s/upper", ctx->overlay_base);

  int merged_len = strlen(ctx->overlay_base) + strlen("/merged") + 1;
  char *overlay_merged = malloc(merged_len);
  if (!overlay_merged) {
    fprintf(stderr,
            "Failed to allocate memory for overlayfs merged directory: %s\n",
            strerror(errno));
    free(overlay_work);
    free(overlay_upper);
    return -1;
  }
  snprintf(overlay_merged, upper_len, "%s/merged", ctx->overlay_base);

  if (mkdir(overlay_work, 0755) == -1) {
    fprintf(stderr, "Failed to create overlayfs working directory: %s\n",
            strerror(errno));
    free(overlay_work);
    free(overlay_upper);
    free(overlay_merged);
    return -1;
  }

  if (mkdir(overlay_upper, 0755) == -1) {
    fprintf(stderr, "Failed to create overlay upper directory: %s\n",
            strerror(errno));
    free(overlay_work);
    free(overlay_upper);
    free(overlay_merged);
    return -1;
  }

  if (mkdir(overlay_merged, 0755) == -1) {
    fprintf(stderr, "Failed to create overlay work directory: %s\n",
            strerror(errno));
    free(overlay_work);
    free(overlay_upper);
    free(overlay_merged);
    return -1;
  }

  const int mount_opts_length = strlen("lowerdir=,upperdir=,workdir=") +
                                strlen(ctx->rootfs) + strlen(overlay_upper) +
                                strlen(overlay_work) + 1;

  char *mount_opts = malloc(mount_opts_length);
  if (!mount_opts) {
    fprintf(stderr, "Failed to allocate memory for overlay mount options: %s\n",
            strerror(errno));
    free(overlay_work);
    free(overlay_upper);
    free(overlay_merged);
    return -1;
  }

  snprintf(mount_opts, mount_opts_length, "lowerdir=%s,upperdir=%s,workdir=%s",
           ctx->rootfs, overlay_upper, overlay_work);

  free(overlay_work);
  free(overlay_upper);

  if (mount("overlay", overlay_merged, "overlay", 0, mount_opts) == -1) {
    fprintf(stderr, "Failed to mount overlay: %s\n", strerror(errno));
    free(overlay_merged);
    return -1;
  }

  /*
   * For the sake of simplicity, we update the rootfs path to be the overlay
   * merged directory
   */
  free(ctx->rootfs);
  ctx->rootfs = strdup(overlay_merged);
  if (!ctx->rootfs) {
    fprintf(stderr, "Failed to update rootfs pointer: %s\n", strerror(errno));
    free(overlay_merged);
    return -1;
  }

  free(overlay_merged);
  return 0;
}

/**
 * setup_rootfs - Change root filesystem using pivot_root
 * @ctx: Container configuration containing rootfs path
 *
 * Replaces the current root filesystem with a new one, completely isolating the
 * container's filesystem view from the host. Uses pivot_root instead of chroot
 * for better security.
 *
 * We opt for pivot_root instead of chroot because the latter only changes how
 * "/" is resolved without actually change the root mount.
 *
 * WORKFLOW:
 * - Bind mount rootfs onto itself (required by pivot_root)
 * - Create temporary directory for old root
 * - Call pivot_root
 * - chdir("/") to move to new root
 * - Unmount old root (removes access to host filesystem)
 * - Remove temporary directory
 *
 * pivot_root requires new_root to be a mount point. Bind mounting it onto
 * itself makes it a mount point if it wasn't already.
 *
 * Return: 0 on success, -1 on failure
 */
static int setup_rootfs(struct container_ctx *ctx) {
  if (mount(ctx->rootfs, ctx->rootfs, "bind", MS_BIND | MS_REC, NULL) == -1) {
    fprintf(stderr, "Failed to setup bind-mount rootfs onto itself: %s\n",
            strerror(errno));
    return -1;
  }

  /*
   * put_old is the location we'll store the old rootfs at before we unmount it
   */
  char put_old[PATH_MAX];
  snprintf(put_old, PATH_MAX, "%s/.pivot_old", ctx->rootfs);

  /*
   * Create the directory to store the old root.
   * EEXIST is okay here, directory might exist from a previous run.
   */
  if (mkdir(put_old, 0700) == -1 && errno != EEXIST) {
    fprintf(stderr, "Failed to make directory %s: %s\n", put_old,
            strerror(errno));
    return -1;
  }

  /*
   * pivot_root does not have a glibc wrapper.
   * This differs from chroot, which only changes how pathnames starting with
   * "/" are resolved.
   *
   * pivot_root moves the root mount to put_old and makes new_root the new root
   * mount. This is more secure than chroot because it actually changes the root
   * mount and allows us to unmount the old root, removing access to it
   * entirely.
   */
  if (syscall(SYS_pivot_root, ctx->rootfs, put_old) == -1) {
    fprintf(stderr, "Failed to change root mount: %s\n", strerror(errno));
    return -1;
  }

  /* Navigate to our new root directory */
  if (chdir("/") == -1) {
    fprintf(stderr, "Failed to navigate to new root directory: %s\n",
            strerror(errno));
    return -1;
  }

  /*
   * Unmounting the old root means that the container can't see the host
   * filesystem. umount2 differs from umount in that it supports flags. The
   * MNT_DETACH flag means "detach the mount immediately, even if busy, and
   * clean up once no references remain".
   *
   * This is important for security, because it fully isolates the container
   * from the host filesystem.
   */
  if (umount2("/.pivot_old", MNT_DETACH) == -1) {
    fprintf(stderr, "Failed to unmount old root: %s\n", strerror(errno));
    return -1;
  }

  /* We don't need the temp directory anymore so we remove it */
  if (rmdir("/.pivot_old") == -1) {
    fprintf(stderr, "Failed to remove temporary directory: %s\n",
            strerror(errno));
    return -1;
  }

  return 0;
}

/**
 * mount_dev - Mount /dev filesystem
 *
 * Mounts a devtmpfs filesystem at /dev to provide access to device files. The
 * container's /dev is isolated from the host's /dev because we're in a mount
 * namespace.
 *
 * DEVTMPFS:
 * A virtual filesystem maintained by the kernel that automatically creates
 * device nodes. Many programs need to access files within /dev, so it is
 * important to mount it.
 *
 * Return: 0 on success, -1 on failure
 */
static int mount_dev(void) {
  if (mount("devtmpfs", "/dev", "devtmpfs", 0, "") == -1) {
    fprintf(stderr, "Failed to mount devtmpfs: %s\n", strerror(errno));
    return -1;
  }

  return 0;
}

/**
 * mount_proc - Mount /proc filesystem
 *
 * Mounts a proc filesystem at /proc. Because we're in a PID namespace, this
 * /proc shows only processes in our namespace rather than host processes.
 *
 * PROC FILESYSTEM:
 * /proc is a virtual filesystem that provides information about:
 * - Running processes (/proc/[pid]/)
 * - System information (/proc/cpuinfo, /proc/meminfo)
 * - Kernel parameters (/proc/sys/)
 *
 * RATIONALE:
 * Many programs read /proc to get process information. The PID namespace
 * ensures that they only see container processes.
 *
 * Return: 0 on success, -1 on failure
 */
static int mount_proc(void) {
  if (mount("proc", "/proc", "proc", 0, NULL) == -1) {
    fprintf(stderr, "Failed to mount proc: %s\n", strerror(errno));
    return -1;
  }

  return 0;
}

/**
 * drop_capabilities - Remove all Linux capabilities from the process
 *
 * Removes all capabilities from the capability bounding set and clears the
 * effective/permitted/inheritable capability sets. This greatly limits what the
 * container can do, even if it is running as root inside.
 *
 * LINUX CAPABILITIES:
 * These break root's power into smaller privileges. Some examples are:
 * - CAP_NET_ADMIN: Configure network
 * - CAP_SYS_ADMIN: Various admin operations
 * - CAP_SYS_CHROOT: Use chroot()
 * - CAP_SYS_MODULE: Load kernel modules
 *
 * CAPABILITY SETS:
 * - Bounding: Maximum capabilities that a process can gain
 * - Permitted: Capabilities the process is allowed to use
 * - Effective: Capabilities currently active
 * - Inheritable: Capabilities that can be inherited by child processes
 *
 * WORKFLOW:
 * - Drop each capability from the bounding set using prctl
 * - Clear all three capability sets using capset
 *
 * Return: 0 on success, -1 on failure
 */
static int drop_capabilities(void) {
  /*
   * Remove all capabilities from the bounding set.
   * CAP_LAST_CAP is the highest capability number currently defined.
   */
  for (int cap = 0; cap <= CAP_LAST_CAP; cap++) {
    /*
     * PR_CAPBSET removes a capability from the bounding set.
     * Afterwards, the process can never acquire that capability again.
     */
    if (syscall(SYS_prctl, PR_CAPBSET_DROP, cap, 0, 0, 0) == -1) {
      // EINVAL means the capability number doesn't exist
      if (errno != EINVAL) {
        fprintf(stderr, "Failed to drop capability %d from bounding set: %s\n",
                cap, strerror(errno));
        return -1;
      }
    }
  }

  /*
   * Clear all capability sets, ensuring the process has no capabilities at all.
   */
  struct __user_cap_header_struct header;
  struct __user_cap_data_struct data[2];

  memset(&header, 0, sizeof(header));
  memset(&data, 0, sizeof(data));

  /*
   * _LINUX_CAPABILITY_VERSION_3 is the current capability API version as of
   * Feb. 2026.
   */
  header.version = _LINUX_CAPABILITY_VERSION_3;

  /*
   * pid = 0 means "current process"
   */
  header.pid = 0;

  /*
   * capset sets the capability sets to the values in data, Since we zeroed it,
   * this clears all capabilities.
   */
  if (syscall(SYS_capset, &header, data) == -1) {
    fprintf(stderr, "Failed to clear capability sets: %s\n", strerror(errno));
    return -1;
  }

  return 0;
}

/**
 * lock_capabilities - Prevent privilege escalation
 *
 * Sets the PR_SET_NO_NEW_PRIVS flag, which prevents the process and its
 * descendants from gaining new privileges through execve().
 *
 * prctl itself always takes five arguments, though the compiler will default
 * missing args to zero if you omit them. It is the first flag that indicates
 * how many of the args will be meaningful. Trailing zeroes are included here
 * for clarity's sake.
 *
 * Return: 0 on success, -1 on failure
 */
static int lock_capabilities(void) {
  if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == -1) {
    fprintf(stderr, "Failed to set PR_SET_NO_NEW_PRIVS: %s\n", strerror(errno));
    return -1;
  }

  return 0;
}

/**
 * apply_seccomp - Install seccomp-bpf syscall filter
 *
 * Installs a whitelist-based syscall filter using seccomp-bpf. After this, only
 * explicitly allowed syscalls can be executed. Any attempt to use a
 * non-whitelisted syscall will cause the process to be killed.
 *
 * SECCOMP-BPF:
 * Seccomp (Secure Computing) with BPF (Berkeley Packet Filter) allows filtering
 * system calls using a small bytecode program. The kernel runs this program on
 * every syscall attempt.
 *
 * FILTER ACTIONS:
 * - SECCOMP_RET_ALLOW: Execute the syscall normally
 * - SECCOMP_RET_KILL_PROCESS: Kill the process
 * - SECCOMP_RET_KILL_THREAD: Kill the calling thread
 * - SECCOMP_RET_ERRNO: Return an error code
 * - SECCOMP_RET_TRAP: Send SIGSYS to the process
 *
 * We use SECCOMP_RET_ALLOW for whitelisted syscalls and
 * SECCOMP_RET_KILL_PROCESS for everything else.
 *
 * A seccomp filter cannot be removed once installed.
 *
 * Return: 0 on success, -1 on failure
 */
static int apply_seccomp(void) {
  if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, get_fprog(), 0, 0) == -1) {
    fprintf(stderr, "Failed to install seccomp filter: %s\n", strerror(errno));
    return -1;
  }

  return 0;
}

/**
 * child_main - Entry point for the container child process
 * @arg: Pointer to container_ctx structure (cast from void * due to clone
 * syscall prototype)
 *
 * Called by clone() and runs in the new namespaces. It sets up all container
 * isolation and security mechanisms before executing the target program.
 *
 * The child process becomes PID 1 in its PID namespace.
 *
 * SYNCHRONIZATION:
 * Uses a pipe to wait for the parent to finish cgroup setup so that the child
 * doesn't try to join a cgroup that doesn't exist yet.
 *
 * SECURITY LAYERS:
 * 1. Namespace isolation: Separate hostname, PID tree, mounts, network, IPC
 * 2. Resource limits via cgroups: CPU, memory, swap, PID count
 * 3. Filesystem isolation: Separate root via pivot_root syscall
 * 4. Capability dropping: Removes all Linux capabilities
 * 5. Syscall filtering: Whitelist-based seccomp-bpf filter
 *
 * Return: Only returns on error (-1), because execvp replaces the process image
 * witht the target program on success.
 */
int child_main(void *arg) {
  struct container_ctx *ctx = arg;
  char *pong;

  /*
   * Wait for parent to configure cgroups. This blocks until the parent writes
   * to the pipe.
   */
  if (read(ctx->pipe_fds[0], &pong, 1) == -1) {
    fprintf(stderr, "Failed to read from pipe: %s\n", strerror(errno));
    return -1;
  }

  /*
   * Join the cgroup configured by the parent
   */
  if (add_self_to_cgroup() == -1) {
    return -1;
  }

  /*
   * Set the hostname visible inside the container
   */
  if (setup_uts_namespace(ctx) == -1) {
    return -1;
  }

  /*
   * Make mounts private to prevent propagation to/from host
   */
  if (setup_mount_propagation() == -1) {
    return -1;
  }

  /*
   * OverlayFS gives the user a temporary filesystem on top of the read-only
   * rootfs, this is used extensively in Docker.
   */
  if (setup_overlay(ctx) == -1) {
    return -1;
  }

  /*
   * Change root filesystem to isolate from host
   */
  if (setup_rootfs(ctx) == -1) {
    return -1;
  }

  /*
   * Mount /dev for device access
   */
  if (mount_dev() == -1) {
    return -1;
  }

  /*
   * Mount /proc for process information
   */
  if (mount_proc() == -1) {
    return -1;
  }

  /*
   * Remove all capabilities to limit what the process can do
   */
  if (drop_capabilities() == -1) {
    return -1;
  }

  /*
   * Prevent gaining new privileges (required before installing seccomp filter)
   */
  if (lock_capabilities() == -1) {
    return -1;
  }

  /*
   * Install syscall filter to allow only whitelisted operations
   */
  if (apply_seccomp() == -1) {
    return -1;
  }

  /*
   * Execute the target program.
   * This replaces the current process image, so this function doesn't return on
   * success.
   */
  execvp(ctx->cmd[0], ctx->cmd);

  /* This is only reachable on error */
  fprintf(stderr, "Failed to execute %s: %s\n", ctx->cmd[0], strerror(errno));
  return -1;
}
