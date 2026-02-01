/**
 * ASSUMES CGROUPS V2
 * We make a new cgroup by adding a new directory to /sys/fs/cgroup (use
 * permissions 755). The system will make the necessary files for us, we only
 * write to the files corresponding to limits we want to set. We'll want to use
 * the open syscall with O_WRONLY.
 * We add a process to the cgroup by writing its pid to the cgroup.procs file in
 * the group's directory.
 *
 * memory.max - Maximum memory for the process
 *
 */

#include <errno.h>
#include <fcntl.h>
#include <linux/limits.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "context.h"

static const int VALUE_MAX = 128;

static int enable_controllers(void) {
  const char *subtree_path = "/sys/fs/cgroup/cgroup.subtree_control";

  int subtree_control_fd = open(subtree_path, O_WRONLY | O_CLOEXEC);
  if (subtree_control_fd == -1) {
    fprintf(stderr, "Failed to open %s: %s\n", subtree_path, strerror(errno));
    return -1;
  }

  if (write(subtree_control_fd, "+cpu +memory +pids\n", 20) == -1) {
    fprintf(stderr, "Failed to write to %s: %s\n", subtree_path,
            strerror(errno));
    if (close(subtree_control_fd) == -1) {
      fprintf(stderr, "Failed to close %s: %s\n", subtree_path,
              strerror(errno));
    }
    return -1;
  }

  if (close(subtree_control_fd) == -1) {
    fprintf(stderr, "Failed to close %s: %s\n", subtree_path, strerror(errno));
    return -1;
  }

  return 0;
}

static int make_cgroup_dir(void) {
  const char *group_dir = "/sys/fs/cgroup/euclid";

  int dir_status = mkdir(group_dir, 0755);
  if (dir_status == -1 && errno != EEXIST) {
    fprintf(stderr, "Failed to make directory %s: %s\n", group_dir,
            strerror(errno));
    return -1;
  }

  return 0;
}

int add_process_to_cgroup(void) {
  const char *procs_path = "/sys/fs/cgroup/euclid/cgroup.procs";
  int procs_fd = open(procs_path, O_WRONLY | O_CLOEXEC);

  if (procs_fd == -1) {
    fprintf(stderr, "Failed to open %s: %s\n", procs_path, strerror(errno));
    return -1;
  }

  if (write(procs_fd, "0\n", 2) == -1) {
    fprintf(stderr, "Failed to write to %s: %s\n", procs_path, strerror(errno));
    if (close(procs_fd) == -1) {
      fprintf(stderr, "Failed to close %s: %s\n", procs_path, strerror(errno));
    }
    return -1;
  }

  if (close(procs_fd) == -1) {
    fprintf(stderr, "Failed to close %s: %s\n", procs_path, strerror(errno));
    return -1;
  }

  return 0;
}

static int set_limit_int(char *filename, int value) {
  char limit_path[PATH_MAX];
  snprintf(limit_path, PATH_MAX, "/sys/fs/cgroup/euclid/%s", filename);

  int limit_fd = open(limit_path, O_WRONLY | O_CLOEXEC);

  if (limit_fd == -1) {
    fprintf(stderr, "Failed to open %s: %s\n", filename, strerror(errno));
    return -1;
  }

  char value_str[VALUE_MAX];

  if (value == -1) {
    snprintf(value_str, VALUE_MAX, "max\n");
  } else {
    snprintf(value_str, VALUE_MAX, "%d\n", value);
  }

  if (write(limit_fd, value_str, strlen(value_str)) == -1) {
    fprintf(stderr, "Failed to write to %s: %s\n", filename, strerror(errno));
    if (close(limit_fd) == -1) {
      fprintf(stderr, "Failed to close %s: %s\n", filename, strerror(errno));
    }
    return -1;
  }

  if (close(limit_fd) == -1) {
    fprintf(stderr, "Failed to close %s: %s\n", filename, strerror(errno));
    return -1;
  }

  return 0;
}

static int set_limit_str(char *filename, char *value) {
  char limit_path[PATH_MAX];

  snprintf(limit_path, PATH_MAX, "/sys/fs/cgroup/euclid/%s", filename);

  int limit_fd = open(limit_path, O_WRONLY | O_CLOEXEC);

  if (limit_fd == -1) {
    fprintf(stderr, "Failed to open %s: %s\n", filename, strerror(errno));
    return -1;
  }

  char value_str[VALUE_MAX - 1];
  snprintf(value_str, VALUE_MAX, "%s\n", value);

  if (write(limit_fd, value_str, strlen(value_str)) == -1) {
    fprintf(stderr, "Failed to write to %s: %s\n", filename, strerror(errno));
    if (close(limit_fd) == -1) {
      fprintf(stderr, "Failed to close %s: %s\n", filename, strerror(errno));
    }
    return -1;
  }

  if (close(limit_fd) == -1) {
    fprintf(stderr, "Failed to close %s: %s\n", filename, strerror(errno));
    return -1;
  }

  return 0;
}

int configure_cgroups(struct container_ctx *ctx) {
  if (enable_controllers()) {
    return -1;
  }

  if (make_cgroup_dir() == -1) {
    return -1;
  }

  if (set_limit_str("cpu.max", ctx->cpu_max) == -1) {
    return -1;
  }

  if (set_limit_int("memory.max", ctx->mem_max) == -1) {
    return -1;
  }

  if (set_limit_int("memory.high", ctx->mem_high) == -1) {
    return -1;
  }

  if (set_limit_int("memory.swap.max", ctx->mem_swap_max) == -1) {
    return -1;
  }

  if (set_limit_int("pids.max", ctx->pids_max) == -1) {
    return -1;
  }

  return 0;
}