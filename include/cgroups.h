/**
 * cgroups.h
 *
 * Control group management interface for container resource limits.
 *
 * OVERVIEW:
 * Handles the creation and configuration of cgroups v2 for the container.
 * Cgroups provides a mechanism to limit and monitor resource usage (CPU,
 * memory, PIDs) for processes.
 *
 * TALK ABOUT CGROUPS v1 vs v2
 *
 * WORKFLOW:
 * - Parent process calls configure_cgroups() to set limits
 * - Child process calls add_self_to_cgroup() to join the cgroup
 * - Kernel enforces the configured limits on the child
 */

#ifndef CGROUPS_H
#define CGROUPS_H

#include "context.h"

/**
 * configure_cgroups - Set up cgroup with resource limits
 * @ctx: Container configuration contianing resource limit values
 *
 * Creates a new cgroup directory at /sys/fs/cgroup/euclid and configures
 * resource limits by writing to the cgroup's control files.
 *
 * This must be called by the parent process before the child joins the cgroup,
 * as it requires privileges to enable controllers and create the cgroup
 * directory.
 *
 * Configured limits:
 * - cpu.max: CPU quota
 * - memory.max: Hard memory limit in bytes
 * - memory.high: Soft memory limit (triggers reclaim)
 * - memory.swap.max: Maximum swap usage
 * - pids.max: Maximum number of processes/threads
 *
 * Return: 0 on success, -1 on failure
 */
int configure_cgroups(struct container_ctx *ctx);

/**
 * add_self_to_cgroup - Move calling process into the configured cgroup
 *
 * Adds the calling process to the euclid cgroup by writing "0" to the
 * cgroups.procs file, which tells the kernel to add the current process.
 *
 * This must be called by the child process after configure_cgroups() has been
 * called by the parent. Once in the cgroup, the kernel will enforce all
 * configured resource limits on this process and its children.
 *
 * Return: 0 on success, -1 on failure
 */
int add_self_to_cgroup(void);

#endif
