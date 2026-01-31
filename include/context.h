#ifndef CONTEXT_H
#define CONTEXT_H

struct container_ctx {
  char *hostname;
  char *rootfs;
  char **cmd;
  int pipe_fds[2];
};

struct container_ctx *init_ctx(int pipe_fds[2]);

#endif