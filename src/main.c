#define _GNU_SOURCE
#include <fcntl.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#include "child.h"

#define STACK_SIZE (1024 * 1024)

int main(int argc, char *argv[]) {
  if (argc < 4) {
    fprintf(stderr, "usage: %s <rootfs> <hostname> <cmd>\n", argv[0]);
    return 1;
  }

  struct child_args ca;
  ca.rootfs = argv[1];
  ca.hostname = argv[2];
  ca.cmd = &argv[3];

  // Allocate stack for clone
  char *stack = malloc(STACK_SIZE);
  if (!stack) {
    perror("malloc");
    exit(EXIT_FAILURE);
  }

  char *stack_top = stack + STACK_SIZE;

  int flags =
      CLONE_NEWUTS | CLONE_NEWPID | CLONE_NEWNS | SIGCHLD;

  int pid = clone(child_main, stack_top, flags, &ca);
  if (pid == -1) {
    perror("clone");
    exit(EXIT_FAILURE);
  }

  // Parent: wait for container process (PID 1 in its namespace)
  int status;
  waitpid(pid, &status, 0);
  if (WIFEXITED(status)) {
    printf("Child exited normally\n");
  }
  
  if (WIFSIGNALED(status)) {
    int sig = WTERMSIG(status);
    printf("Child killed by signal %d\n", sig);
    if (sig == SIGSYS) {
      printf("Likely seccomp violation\n");
    }
  }

  free(stack);
  return 0;
}
