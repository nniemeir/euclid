/**
 * context.c
 *
 * OVERVIEW:
 * Provides initialization and cleanup for the container_ctx structure, which
 * holds all configuration parameters for the container. Configuration values
 * are defined as compile-time constants to reduce the attack surface.
 *
 * DESIGN RATIONALE:
 * Using hardcoded constants instead of configuration files offers several
 * security benefits:
 * - No file parsing attack surface
 * - No TOCTOU (time-of-check-time-of-use) races on config files
 * - No need to validate untrusted input
 * - Configuration is immutable
 * - Simpler code makes the project easier to audit
 *
 * MEMORY ALLOCATION:
 * The context and all of its string fields are dynamically allocated because:
 * - The child process has a separate stack from the parent
 * - Stack-allocated data would be invalid after clone() returns
 */

#include "errno.h"
#include <linux/limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "context.h"

/*
 * ============================================================================
 * CONTAINER CONFIGURATION
 * ============================================================================
 *
 * These constants define the container's behavior and resource limits.
 * Modify these values and recompile to change the container's configuration.
 */

/**
 * HOSTNAME - Container hostname visible in UTS namespace
 *
 * Sets the hostname that processes inside the container will see.
 */
static const char *HOSTNAME = "euclid";

/**
 * ROOTFS - Path to root filesystem directory
 *
 * This directory will become "/" inside the container after pivot_root.
 * Must contain a valid Linux root filesystem.
 */
static const char *ROOTFS = "/home/noodle/alpine";

/**
 * CMD - Command to execute inside the container
 *
 * The first element is the program to execute, remaining elements are
 * arguments.
 *
 * EXECUTION:
 * - Executed via execvp(), so PATH is searched
 * - This process becomes PID 1 in the container's PID namespace
 * - When this process exits, the container terminates
 */
static const char *CMD[] = {"/bin/sh"};

/*
 * ============================================================================
 * RESOURCE LIMITS
 * ============================================================================
 *
 * These limits are enforced by cgroups v2 and prevent the container from
 * consuming excessive resources or performing fork bomb attacks.
 */

/**
 * CPU_MAX - CPU quota in cgroups v2 format
 *
 * Format: "quota period" where both values are in microseconds
 *
 * EXAMPLES:
 *   "100000 100000" = 100ms per 100ms = 1 full CPU core (100%)
 *   "50000 100000"  = 50ms per 100ms = 0.5 CPU cores (50%)
 *   "200000 100000" = 200ms per 100ms = 2 CPU cores (200%)
 *   "max 100000"    = unlimited quota = all available CPUs
 *
 * The container can use up to quota microseconds of CPU time per period
 * microseconds. If it exceeds this, its throttled until the next period.
 */
static const char *CPU_MAX = "100000, 100000";

/**
 * MEM_MAX - Hard memory limit in bytes
 *
 * Maximum amount of RAM the container can use. If exceeded, the kernel's OOM
 * (Out of Memory) killer will terminate processes in the container.
 *
 * This should definitely be adjusted based on the application being tested
 */
static const int MEM_MAX = 512000000;

/**
 * MEM_HIGH - Soft memory limit in bytes
 *
 * Threshold at which the kernel starts aggressively reclaiming memory from the
 * container. This is a soft limit, the container can exceed it temporarily but
 * will experience slowdowns as the kernel reclaims memory.
 *
 * CURRENT SETTING: 90% of MEM_MAX
 *
 * This provides a soft warning before hitting the hard limit.
 */
static const int MEM_HIGH = (int)(MEM_MAX - (MEM_MAX * 0.10));

/**
 * MEM_SWAP_MAX - Maximum swap usage in bytes
 *
 * Limits how much swap space the container can use. Swap allows the kernel to
 * move inactive memory to disk, freeing RAM.
 *
 * CURRENT SETTING: 0 (disabled)
 */
static const int MEM_SWAP_MAX = 0;

/**
 * PIDS_MAX - Maximum number of processes/threads
 *
 * Limits the total number of PIDs (processes + threads) that can exist in the
 * container. This prevents fork bomb attacks.
 *
 * FORK BOMB PREVENTATION:
 * A fork bomb creates processes in an infinite loop. Without a PID limit, this
 * would consume all available PIDs on the system, potentially resulting in
 * Denial of Service. With PIDS_MAX, the fork bomb is limited to 256 processes
 * and can't affect the host.
 */
static const int PIDS_MAX = 256;

/**
 * NUM_COMMAND_ARGS - Number of elements in CMD array
 *
 * Calculated at compile time using sizeof. Used for allocating space and
 * iterating over command arguments.
 */
static const unsigned int NUM_COMMAND_ARGS = sizeof(CMD) / sizeof(CMD[0]);

/**
 * cleanup_ctx - Free all dynamically allocated memory in container context
 * @ctx: Container context to clean up
 *
 * Frees all heap-allocated memory in the context structure. This is safe to
 * call even if initialization fails partway through since we check for NULL.
 */
void cleanup_ctx(struct container_ctx *ctx) {
  for (unsigned int i = 0; i < NUM_COMMAND_ARGS; i++) {
    if (ctx->cmd[i]) {
      free(ctx->cmd[i]);
    }
  }

  if (ctx->cmd) {
    free(ctx->cmd);
  }

  if (ctx->hostname) {
    free(ctx->hostname);
  }

  if (ctx->rootfs) {
    free(ctx->rootfs);
  }

  if (ctx->cpu_max) {
    free(ctx->cpu_max);
  }

  free(ctx);
}

/**
 * init_ctx - Allocate and initialize container context
 * @pipe_fds: Pipe file descriptors for parent-child synchronization
 *
 * Creates a new container_ctx structure and initializes it with values from the
 * compile-time constants. All string fields are duplicated using strdup() to
 * ensure they persist.
 *
 * INITIALIZATION PROCESS:
 * - Allocate context structure
 * - Duplicate hostname string
 * - Duplicate rootfs path string
 * - Allocate command argument array
 * - Duplicate each command argument
 * - Duplicate CPU limit string
 * - Copy numeric limits
 * - Store pipe file descriptors
 *
 * STRDUP:
 * strdup() allocates memory and copies a string. We use it instead of direct assignment because:
 * - String constants are in read-only memory
 * - We need mutable copies that can be freed
 * - Memory management is cleaner since everything is heap-allocated
 *
 * COMMAND ARRAY:
 * The command array is NULL-terminated (execvp requirement), so we allocate NUM_COMMAND_ARGS + 1 elements and set the last to NULL.
 *
 * Return: Pointer to initialized context on success, NULL on failure
 */
struct container_ctx *init_ctx(int pipe_fds[2]) {
  struct container_ctx *ctx = {0};
  ctx = malloc(sizeof(struct container_ctx));
  if (!ctx) {
    fprintf(stderr, "Memory allocation failed for container_ctx: %s\n",
            strerror(errno));
    return NULL;
  }

  ctx->hostname = strdup(HOSTNAME);
  if (!ctx->hostname) {
    fprintf(stderr, "Failed to duplicate string for hostname: %s\n",
            strerror(errno));
    cleanup_ctx(ctx);
    return NULL;
  }

  ctx->rootfs = strdup(ROOTFS);
  if (!ctx->rootfs) {
    fprintf(stderr, "Failed to duplicate string for rootfs: %s\n",
            strerror(errno));
    cleanup_ctx(ctx);
    return NULL;
  }

  ctx->cmd = malloc((NUM_COMMAND_ARGS + 1) * sizeof(char *));
  if (!ctx->cmd) {
    fprintf(stderr, "Memory allocation failed for container_ctx->cmd: %s\n",
            strerror(errno));
    free(ctx);
    return NULL;
  }

  for (unsigned int i = 0; i < NUM_COMMAND_ARGS; i++) {
    ctx->cmd[i] = strdup(CMD[i]);
    if (!ctx->cmd[i]) {
      fprintf(stderr,
              "Failed to duplicate string for command argument %d: %s\n", i,
              strerror(errno));
      cleanup_ctx(ctx);
      return NULL;
    }
  }
  
  ctx->cmd[NUM_COMMAND_ARGS] = NULL;

  ctx->cpu_max = strdup(CPU_MAX);
  if (!ctx->cpu_max) {
    fprintf(stderr, "Failed to duplicate string for cpu.max: %s\n",
            strerror(errno));
    cleanup_ctx(ctx);
    return NULL;
  }

  ctx->mem_high = MEM_HIGH;
  ctx->mem_max = MEM_MAX;
  ctx->mem_swap_max = MEM_SWAP_MAX;

  ctx->pids_max = PIDS_MAX;

  ctx->pipe_fds[0] = pipe_fds[0];
  ctx->pipe_fds[1] = pipe_fds[1];

  return ctx;
}