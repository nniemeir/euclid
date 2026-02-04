/**
 * context.h
 *
 * Container configuration structure and initialization.
 *
 * OVERVIEW:
 * Defines the container_ctx structure that holds all configuration parameters
 * for the container. This includes the target program, resource limits, and
 * synchronization primatives.
 *
 * DESIGN RATIONALE:
 * Configuration is compile-time rather than runtime to reduce the attack
 * surface. External configuration files could be exploited or tampered with,
 * while compile-time constants are baked into the binary.
 *
 * MEMORY MANAGEMENT:
 * The context is allocated on the heap and must be properly freed. This is
 * necessary because the child process needs its own stack and context that
 * persists across the clone() call.
 */

#ifndef CONTEXT_H
#define CONTEXT_H

/**
 * struct container_ctx - Container configuration and state
 * @hostname: Hostname visible inside the container
 * @rootfs: Path to the root filesystem directory to use
 * @cmd: NULL-terminated array of command and arguments to execute
 * @cpu_max: CPU quota string in cgroups format "quota period"
 * @mem_high: Soft memory limit in bytes (triggers reclaim)
 * @mem_max: Hard memory limit in bytes (OOM kill if exceeded)
 * @mem_swap_max: Maximum swap usage in bytes (0 to disable swap)
 * @pids_max: Maximum number of PIDS (prevents fork bombs)
 * @pipe_fds: File descriptors for parent-child synchronization
 * @overlay_base: Directory to store tmpfs overlay
 * @tmpfs_size: Size of the tempfs fileystem in Megabytes
 *
 * SYNCHRONIZATION:
 * The pipe_fds are used to coordinate between parent and child:
 * - Parent creates cgroup and configures limits
 * - Parent writes to pipe_fds[1]
 * - Child blocks on read from pipe_fds[0]
 * - Child receives signal and joins cgroup
 */
struct container_ctx {
  char **cmd;
  char *hostname;
  char *rootfs;
  char *cpu_max;
  int mem_high;
  int mem_max;
  int mem_swap_max;
  int pids_max;
  int pipe_fds[2];
  char *overlay_base;
  int tmpfs_size;
};

/**
 * cleanup_ctx - Free all memory allocated for container context
 * @ctx: Container context to free
 *
 * Frees all dynamically allocated memory in the context structure. This
 * includes all string fields and the context itself.
 *
 * Safe to call even if some allocations failed during init_ctx(), as it checks
 * for NULL before freeing.
 */
void cleanup_ctx(struct container_ctx *ctx);

/**
 * init_ctx - Initialize container context with configuration
 * @pipe_fds: Pipe file descriptors for parent-child synchronization
 *
 * Allocates and initializes a container_ctx structure with values from the
 * compile-time constants defined in context.c.
 *
 * Memory allocation:
 * - All string fields duplicated using strdup()
 * - Command array is allocated and each argument is duplicated
 * - If any allocation fails, previously allocated memory is freed
 *
 * The pipe file descriptors are stored but not created by this function. The caller (main) must create the pipe before calling init_ctx().
 *
 * Return: Pointer to initialized context on success, NULL on failure
 */
struct container_ctx *init_ctx(int pipe_fds[2]);

#endif