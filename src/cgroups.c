/**
 * cgroups.c
 *
 * Control group (cgroup) configuration for container resource limits.
 *
 * OVERVIEW:
 * Implements cgroups v2 management for limiting container resource usage.
 * Creates a dedicated cgroup directory and configures CPU, memory, and process
 * limits by writing to special kernel files.
 *
 * CGROUPS V2:
 * Cgroups v2 uses a unified hierarchy:
 * - Single mount point: /sys/fs/cgroup
 * - Controllers enabled via cgroup.subtree_control
 * - Limits set by writing to controller-specific files
 * - Processes added by writing PIDs to cgroup.procs
 */

#include <errno.h>
#include <fcntl.h>
#include <linux/limits.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "context.h"

/**
 * VALUE_MAX - Maximum length for values written to cgroup files
 *
 * Limits are written as strings, so we need a buffer large enough for the
 * largest possible value while leaving room for newline and null terminator.
 */
static const int VALUE_MAX = 128;

/**
 * enable_controllers - Enable required cgroup controllers
 *
 * Writes "+cpu +memory +pids" to /sys/fs/cgroup/cgroup.subtree_control to
 * enable these controllers for child cgroups. This has to be done before
 * creating the euclid cgroup.
 *
 * CONTROLLER PURPOSES:
 * - cpu: Limits CPU time available to the cgroup
 * - memory: Limits RAM and swap usage
 * - pids: Limits number of processes/threads (prevents fork bombs)
 *
 * The '+' prefix enables the controller, '-' would disable it.
 *
 * Return: 0 on success, -1 on failure
 */
static int enable_controllers(void) {
  const char *subtree_path = "/sys/fs/cgroup/cgroup.subtree_control";

  /*
   * O_WRONLY: Open for writing only
   * O_CLOEXEC: Close file descriptor on exec() (prevents leaking to child)
   */
  int subtree_control_fd = open(subtree_path, O_WRONLY | O_CLOEXEC);
  if (subtree_control_fd == -1) {
    fprintf(stderr, "Failed to open %s: %s\n", subtree_path, strerror(errno));
    return -1;
  }

  /*
   * Write the controller list to enable them.
   */
  if (write(subtree_control_fd, "+cpu +memory +pids\n", 20) == -1) {
    fprintf(stderr, "Failed to write to %s: %s\n", subtree_path,
            strerror(errno));
    /*
     * We still need to close the file descriptor to avoid a resoruce leak. We
     * check for close() errors too.
     */
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

/**
 * make_cgroup_dir - Create the euclid cgroup directory
 *
 * Creates /sys/fs/cgroup/euclid with permissions 0755. The kernel creates the
 * necessary control files inside this directory once it is created.
 *
 * EEXIST:
 * If the directory already exists, we treat it as success. The existing limits
 * will be overwritten.
 *
 * Return: 0 on success, -1 on failure
 */
static int make_cgroup_dir(void) {
  const char *group_dir = "/sys/fs/cgroup/euclid";

  int dir_status = mkdir(group_dir, 0755);

  /*
   * mkdir returns -1 on error and sets errno.
   * EEXIST means the directory already exists, which is okay in this context.
   */
  if (dir_status == -1 && errno != EEXIST) {
    fprintf(stderr, "Failed to make directory %s: %s\n", group_dir,
            strerror(errno));
    return -1;
  }

  return 0;
}

/**
 * add_self_to_cgroup - Move calling process into the euclid group
 *
 * Writes "0" to /sys/fs/cgroup/euclid/cgroup.procs to add the current process
 * to the cgroup.
 *
 * PROCESS MIGRATION:
 * When a process joins a cgroup:
 * - It immediately becomes subject to the cgroup's resource limits
 * - All future children inherit the cgroup membership
 * - The process cannot leave the cgroup (except to a child cgroup)
 *
 * TIMING:
 * This must be called by the child process after the parent has:
 * - Called enable_controllers()
 * - Called make_cgroup_dir()
 * - Called set_limit_* functions to configure limits
 *
 * The pipe synchronization in main.c ensures this ordering
 *
 * Return: 0 on success, -1 on failure
 */
int add_self_to_cgroup(void) {
  const char *procs_path = "/sys/fs/cgroup/euclid/cgroup.procs";
  int procs_fd = open(procs_path, O_WRONLY | O_CLOEXEC);

  if (procs_fd == -1) {
    fprintf(stderr, "Failed to open %s: %s\n", procs_path, strerror(errno));
    return -1;
  }

  /*
   * Write "0\n" to add the current process. We could use the actual PID, but
   * "0" is simpler.
   */
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

/**
 * set_limit_int - Write an integer limit to a cgroup control file
 * @filename: Name of the control file
 * @value: Limit value to write (-1 for "max")
 *
 * Generic function for setting integer-based cgroup limits. Constructs the full
 * path, converts the integer to a string, and writes it to the control file.
 *
 * SPECIAL VALUE:
 * Passing -1 writes the string "max" instead of a number, which removes the
 * limit for that resource
 *
 * Return: 0 on success, -1 on failure
 */
static int set_limit_int(char *filename, int value) {
  char limit_path[PATH_MAX];
  snprintf(limit_path, PATH_MAX, "/sys/fs/cgroup/euclid/%s", filename);

  int limit_fd = open(limit_path, O_WRONLY | O_CLOEXEC);

  if (limit_fd == -1) {
    fprintf(stderr, "Failed to open %s: %s\n", filename, strerror(errno));
    return -1;
  }

  char value_str[VALUE_MAX];

  /*
   * Convert the value to a string. If value is -1, we use "max instead of -1"
   */
  if (value == -1) {
    snprintf(value_str, VALUE_MAX, "max\n");
  } else {
    snprintf(value_str, VALUE_MAX, "%d\n", value);
  }

  /*
   * Write the value string to the control file.
   */
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

/**
 * set_limit_str - Write a string limit to a cgroup control file
 * @filename: Name of the control file
 * @value: Limit value to write
 *
 * Generic function for setting string-based cgroup limits.
 *
 * Return: 0 on success, -1 on failure
 */
static int set_limit_str(char *filename, char *value) {
  char limit_path[PATH_MAX];

  snprintf(limit_path, PATH_MAX, "/sys/fs/cgroup/euclid/%s", filename);

  int limit_fd = open(limit_path, O_WRONLY | O_CLOEXEC);

  if (limit_fd == -1) {
    fprintf(stderr, "Failed to open %s: %s\n", filename, strerror(errno));
    return -1;
  }

  /*
   * Append a newline to the value string.
   * Most cgroup files expect this.
   */
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

/**
 * configure_cgroups - Set up and configure the container's cgroup
 * @ctx: Container configuration containing resource limit values
 *
 * Entry point for cgroup setup. This function orchestrates the creation of the
 * cgroup and configuration of all resource limits.
 *
 * EXECUTION ORDER:
 * - Enable controllers in parent cgroup
 * - Create euclid cgroup directory
 * - Configure CPU limit (cpu.max)
 * - Configure hard memory limit (memory.max)
 * - Configure soft memory limit (memory.high)
 * - Configure swap limit (memory.swap.max)
 * - Configure PID limit (pids.max)
 *
 * This must be called by the parent process before the child calls
 * add_process_to_cgroup(), this is ensured by the pipe mechanism in main.c.
 *
 * Return: 0 on success, -1 on failure
 */
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