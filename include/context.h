#ifndef CONTEXT_H
#define CONTEXT_H

struct container_ctx {
  char *hostname;
  char *rootfs;
  char **cmd;
  char *cpu_max;
  int mem_high;
  int mem_max;
  int mem_swap_max;
  int pids_max;
  int pipe_fds[2];
};

struct container_ctx *init_ctx(int pipe_fds[2]);

#endif