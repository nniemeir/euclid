#ifndef CHILD_H
#define CHILD_H

struct child_args {
  char *hostname;
  char *rootfs;
  char **cmd;
};

int child_main(void *arg);

#endif
