#ifndef CHILD_H
#define CHILD_H

struct container_ctx {
  char *hostname;
  char *rootfs;
  char **cmd;
  int pipe_rd;
};

int child_main(void *arg);

#endif
