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
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "cgroups.h"
#include "child.h"
#include "child_filesystem.h"
#include "child_namespaces.h"
#include "child_security.h"
#include "context.h"

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
