/**
 * child_filesystem.c
 *
 * OVERVIEW:
 * Handles the filesystem isolation layer of the container, including:
 * - OverlayFS: Provides writable layer on top of read-only rootfs
 * - /proc: Process information isolated to the container's PID namespace
 * - /dev: Device access via devtmpfs
 * - tmpfs: The overlay is created within a temporary filesystem located in RAM
 *
 * OVERLAYFS LAYERS:
 * - Lower: Read-only original rootfs
 * - Upper: Writable layer for modifications
 * - Work: Temporary workspace used for atomic file operations
 * - Merged: The combined view that is used as the container's new rootfs
 */

#include <errno.h>
#include <linux/limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "child_filesystem.h"
#include "context.h"

/**
 * mount_tmpfs - Mount the temporary filesystem at overlay_base
 * @ctx: Container configuration containing paths for overlayFS
 *
 * A tmpfs is mounted at overlay_base to store the upper and work directories in
 * RAM. This has a few effects:
 * - File operations are faster (since RAM is faster than disk)
 * - No persistent filesystem state
 * - The lower layer (original rootfs) remains unchanged
 *
 * Return: 0 on success, -1 on failure
 */
static int mount_tmpfs(struct container_ctx *ctx) {
  const int TMPFS_OPTS_LEN = 32;

  if (mkdir(ctx->overlay_base, 0755) == -1 && errno != EEXIST) {
    fprintf(stderr, "Failed to create overlayfs base directory: %s\n",
            strerror(errno));
    return -1;
  }

  char tmpfs_opts[TMPFS_OPTS_LEN];
  snprintf(tmpfs_opts, TMPFS_OPTS_LEN, "size=%dM", ctx->tmpfs_size);

  /**
   * Everything created inside of the tmpfs lives in RAM and only exists as long
   * as the sandbox is running.
   */
  if (mount("tmpfs", ctx->overlay_base, "tmpfs", 0, tmpfs_opts) == -1) {
    fprintf(stderr, "Failed to mount tmpfs: %s\n", strerror(errno));
    return -1;
  }

  return 0;
}

/**
 * cleanup_overlay_dirs - Free all dynamically allocated memory in overlay_dirs
 * struct
 * @dirs: Struct containing overlay directories
 *
 * Frees all heap-allocated memory in the overlay_dirs structure. This is safe
 * to call even if initialization fails partway through since we check for NULL.
 */
static void cleanup_overlay_dirs(struct overlay_dirs *dirs) {
  if (dirs->overlay_work) {
    free(dirs->overlay_work);
  }

  if (dirs->overlay_upper) {
    free(dirs->overlay_upper);
  }

  if (dirs->overlay_merged) {
    free(dirs->overlay_merged);
  }

  if (dirs) {
    free(dirs);
  }
}

/**
 * construct_overlay_paths - Builds paths to work, upper, and merged dirs in
 * overlayfs
 * @ctx: Container context containing overlay base directory
 *
 * Return: Struct containing overlay paths, NULL on failure
 */
static struct overlay_dirs *construct_overlay_paths(struct container_ctx *ctx) {
  struct overlay_dirs *dirs = {0};
  dirs = malloc(sizeof(struct overlay_dirs));

  int work_len = strlen(ctx->overlay_base) + strlen("/work") + 1;
  dirs->overlay_work = malloc(work_len);
  if (!dirs->overlay_work) {
    fprintf(stderr,
            "Failed to allocate memory for overlayfs work directory: %s\n",
            strerror(errno));
    cleanup_overlay_dirs(dirs);
    return NULL;
  }
  snprintf(dirs->overlay_work, work_len, "%s/work", ctx->overlay_base);

  int upper_len = strlen(ctx->overlay_base) + strlen("/upper") + 1;
  dirs->overlay_upper = malloc(upper_len);
  if (!dirs->overlay_upper) {
    fprintf(stderr,
            "Failed to allocate memory for overlayfs upper directory: %s\n",
            strerror(errno));
    cleanup_overlay_dirs(dirs);

    return NULL;
  }
  snprintf(dirs->overlay_upper, upper_len, "%s/upper", ctx->overlay_base);

  int merged_len = strlen(ctx->overlay_base) + strlen("/merged") + 1;
  dirs->overlay_merged = malloc(merged_len);
  if (!dirs->overlay_merged) {
    fprintf(stderr,
            "Failed to allocate memory for overlayfs merged directory: %s\n",
            strerror(errno));
    cleanup_overlay_dirs(dirs);
    return NULL;
  }
  snprintf(dirs->overlay_merged, merged_len, "%s/merged", ctx->overlay_base);

  return dirs;
}

/**
 * make_overlay_dirs - Create directories required by overlayfs
 * @dirs: Struct containing overlay directories
 *
 * Makes all of the directories required by overlayfs using the paths built by
 * construct_overlay_paths.
 *
 * Return: 0 on success, -1 on failure
 */
static int make_overlay_dirs(struct overlay_dirs *dirs) {
  if (mkdir(dirs->overlay_work, 0755) == -1) {
    fprintf(stderr, "Failed to create overlayfs working directory: %s\n",
            strerror(errno));
    return -1;
  }

  if (mkdir(dirs->overlay_upper, 0755) == -1) {
    fprintf(stderr, "Failed to create overlay upper directory: %s\n",
            strerror(errno));
    return -1;
  }

  if (mkdir(dirs->overlay_merged, 0755) == -1) {
    fprintf(stderr, "Failed to create overlay work directory: %s\n",
            strerror(errno));
    return -1;
  }

  return 0;
}

/**
 * mount_overlay - Mount overlayfs with the paths previously created for it
 * @ctx: Container configuration containing rootfs path
 * @dirs: Struct containing overlay paths
 *
 * Mounts the overlay directories themselves. After mounting, the rootfs path is
 * updated to be the overlay merged directory for the sake of simplicity.
 *
 * Return: 0 on success, -1 on failure
 */
static int mount_overlay(struct container_ctx *ctx, struct overlay_dirs *dirs) {
  const int mount_opts_length =
      strlen("lowerdir=,upperdir=,workdir=") + strlen(ctx->rootfs) +
      strlen(dirs->overlay_upper) + strlen(dirs->overlay_work) + 1;

  char *mount_opts = malloc(mount_opts_length);
  if (!mount_opts) {
    fprintf(stderr, "Failed to allocate memory for overlay mount options: %s\n",
            strerror(errno));
    return -1;
  }

  snprintf(mount_opts, mount_opts_length, "lowerdir=%s,upperdir=%s,workdir=%s",
           ctx->rootfs, dirs->overlay_upper, dirs->overlay_work);

  if (mount("overlay", dirs->overlay_merged, "overlay", 0, mount_opts) == -1) {
    fprintf(stderr, "Failed to mount overlay: %s\n", strerror(errno));
    return -1;
  }

  free(ctx->rootfs);
  ctx->rootfs = strdup(dirs->overlay_merged);
  if (!ctx->rootfs) {
    fprintf(stderr, "Failed to update rootfs pointer: %s\n", strerror(errno));
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
int setup_overlay(struct container_ctx *ctx) {
  if (mount_tmpfs(ctx) == -1) {
    return -1;
  }

  struct overlay_dirs *dirs = {0};
  dirs = construct_overlay_paths(ctx);
  if (!dirs) {
    return -1;
  }

  if (make_overlay_dirs(dirs) == -1) {
    cleanup_overlay_dirs(dirs);
    return -1;
  }

  if (mount_overlay(ctx, dirs) == -1) {
    cleanup_overlay_dirs(dirs);
    return -1;
  }

  cleanup_overlay_dirs(dirs);

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
int setup_rootfs(struct container_ctx *ctx) {
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
int mount_dev(void) {
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
int mount_proc(void) {
  if (mount("proc", "/proc", "proc", 0, NULL) == -1) {
    fprintf(stderr, "Failed to mount proc: %s\n", strerror(errno));
    return -1;
  }

  return 0;
}
