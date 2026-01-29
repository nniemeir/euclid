// We'll want to make it so that rootfs is RDONLY and mount a tmpfs over it,
// still need to learn how to do that

#include <errno.h>
#include <linux/audit.h>
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

#include "child.h"
#include "filter.h"

static void setup_uts_namespace(struct container_ctx *ctx) {
  /* CLONE_NEWUTS means this hostname is visible only inside the container */
  if (sethostname(ctx->hostname, strlen(ctx->hostname)) == -1) {
    fprintf(stderr, "Failed to set hostname: %s\n", strerror(errno));
    exit(EXIT_FAILURE);
  }
}

static void setup_mount_propagation(void) {
  /* Make / a private mount point so changes don't leak to host.
     MS_REC is used with MS_BIND to create a recursive bind mount.
     MS_PRIVATE stops mount and unmount events from propagating into or out of
     the mount
   */
  if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) == -1) {
    fprintf(stderr, "Failed to setup mount propagation: %s\n", strerror(errno));
    exit(EXIT_FAILURE);
  }
}

static void setup_rootfs(struct container_ctx *ctx) {
  /* Bind-mount rootfs onto itself (required before pivot_root)
   * A bind mount makes a file or a directory subtree visible at another point
   * within the single directory hierarchy.
   */
  if (mount(ctx->rootfs, ctx->rootfs, "bind", MS_BIND | MS_REC, NULL) == -1) {
    fprintf(stderr, "Failed to setup bind-mount rootfs onto itself: %s\n", strerror(errno));
    exit(EXIT_FAILURE);
  }

  /* put_old is the location we'll store the old rootfs at before we unmount it
   */
  char put_old[PATH_MAX];
  snprintf(put_old, PATH_MAX, "%s/.pivot_old", ctx->rootfs);
  if (mkdir(put_old, 0777) == -1 && errno != EEXIST) {
    fprintf(stderr, "Failed to make directory %s: %s\n", put_old, strerror(errno));
    exit(EXIT_FAILURE);
  }

  /* pivot_root does not have a glibc wrapper.
   * This differs from chroot, which only changes how pathnames starting with
   * "/" are resolved.
   */
  if (syscall(SYS_pivot_root, ctx->rootfs, put_old) == -1) {
    fprintf(stderr, "Failed to change root mount: %s\n", strerror(errno));
    exit(EXIT_FAILURE);
  }

  /* Navigate to our new root directory */
  if (chdir("/") == -1) {
    fprintf(stderr, "Failed to navigate to new root directory: %s\n", strerror(errno));
    exit(EXIT_FAILURE);
  }

  /* Unmounting the old root means that the container can't see the host
   * filesystem. umount2 differs from umount in that it supports flags. The
   * MNT_DETACH flag means "detach the mount immediately, even if busy, and
   * clean up once no references remain"
   */
  if (umount2("/.pivot_old", MNT_DETACH) == -1) {
    fprintf(stderr, "Failed to unmount old root: %s\n", strerror(errno));
    exit(EXIT_FAILURE);
  }

  /* We don't need the temp directory anymore so we remove it */
  if (rmdir("/.pivot_old") == -1) {
    fprintf(stderr, "Failed to remove temporary directory: %s\n", strerror(errno));
    exit(EXIT_FAILURE);
  }
}

static void mount_dev(void) {
  if (mount("devtmpfs", "/dev", "devtmpfs", 0, "") == -1) {
    fprintf(stderr, "Failed to mount devtmpfs: %s\n", strerror(errno));
    exit(EXIT_FAILURE);
  }
}

static void mount_proc(void) {
  /* Mount the new rootfs' proc so that we see processes within our new PID
   * namespace */
  if (mount("proc", "/proc", "proc", 0, NULL) == -1) {
    fprintf(stderr, "Failed to mount proc: %s\n", strerror(errno));
    exit(EXIT_FAILURE);
  }
}

/**
 * prctl itself always takes five arguments, though the compiler will default
 * missing args to zero if you omit them. It is the first flag that indicates
 * how many of the args will be meaningful. Trailing zeroes are included here
 * for clarity's sake.
 */
void apply_seccomp(void) {
  /* This tells the kernel not to increase privileges from this point forward */
  if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == -1) {
    fprintf(stderr, "Failed to set PR_SET_NO_NEW_PRIVS: %s\n", strerror(errno));
    exit(1);
  }
  /* Installs the seccomp filter defined in prog array */
  if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, get_fprog(), 0, 0) == -1) {
    fprintf(stderr, "Failed to install seccomp filter: %s\n", strerror(errno));
    exit(1);
  }
}

int child_main(void *arg) {
  struct container_ctx *ctx = arg;
  char *blarg;
  read(ctx->pipe_rd, &blarg, 1);

  setup_uts_namespace(ctx);

  setup_mount_propagation();

  setup_rootfs(ctx);

  mount_dev();

  mount_proc();

  // Apply the seccomp filter we defined above
  apply_seccomp();

  // This process becomes PID 1 in the new PID namespace
  execvp(ctx->cmd[0], ctx->cmd);

  /* This is only reachable on error */
  fprintf(stderr, "Failed to execute %s: %s\n", ctx->cmd[0], strerror(errno));
  return 1;
}
