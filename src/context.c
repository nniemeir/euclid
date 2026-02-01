// This looks weird but it is necessary because the child process has its own
// stack

#include "errno.h"
#include <linux/limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "context.h"

// Child Configuration
static const char *HOSTNAME = "euclid";
static const char *ROOTFS = "/home/noodle/alpine";
static const char *CMD[] = {"/bin/sh"};

// Resource Limits
// 1 Core
static const char *CPU_MAX = "100000, 100000";
// Hard memory limit
static const int MEM_MAX = 512000000;
// Soft memory limit (10%)
static const int MEM_HIGH = (MEM_MAX - (MEM_MAX * 0.10));
// Disable Swap
static const int MEM_SWAP_MAX = 0;
// Prevent Fork Bombs
static const int PIDS_MAX = 256;

static const unsigned int NUM_COMMAND_ARGS = sizeof(CMD) / sizeof(CMD[0]);

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
}

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

  ctx->cmd = malloc(NUM_COMMAND_ARGS * sizeof(char *));
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