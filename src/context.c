#include "errno.h"
#include <linux/limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "context.h"

static const char *CMD[] = {"/bin/ls", "-l"};
static const unsigned int NUM_COMMAND_ARGS = sizeof(CMD) / sizeof(CMD[0]);
static const char *ROOTFS = "/home/noodle/alpine";
static const char *HOSTNAME = "euclid";

// This looks weird but it is necessary because the child process has its own
// stack

void cleanup_ctx(struct container_ctx *ctx) {
  for (unsigned int i = 0; i < NUM_COMMAND_ARGS; i++) {
    if (ctx->cmd[i]) {
      free(ctx->cmd[i]);
    }
  }

  if (ctx->cmd) {
    free(ctx->cmd);
  }
  
  if (ctx->rootfs) {
    free(ctx->rootfs);
  }
  
  if (ctx->hostname) {
    free(ctx->hostname);
  }
}

struct container_ctx *init_ctx(int pipe_fds[2]) {
  struct container_ctx *ctx = malloc(sizeof(struct container_ctx));
  if (!ctx) {
    fprintf(stderr, "Memory allocation failed for container_ctx: %s\n",
            strerror(errno));
    return NULL;
  }
  
  ctx->rootfs = strdup(ROOTFS);
  
  ctx->hostname = strdup(HOSTNAME);
  
  ctx->cmd = malloc(NUM_COMMAND_ARGS * sizeof(char *));
  if (!ctx->cmd) {
    fprintf(stderr, "Memory allocation failed for container_ctx->cmd: %s\n",
            strerror(errno));
    free(ctx);
    return NULL;
  }

  for (unsigned int i = 0; i < NUM_COMMAND_ARGS; i++) {
    ctx->cmd[i] = strdup(CMD[i]);
  }
  ctx->cmd[NUM_COMMAND_ARGS + 1] = NULL;
  
  ctx->pipe_fds[0] = pipe_fds[0];
  ctx->pipe_fds[1] = pipe_fds[1];
  
  return ctx;
}