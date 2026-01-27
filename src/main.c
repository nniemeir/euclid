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

static int spawn_container(struct child_args *ca) {
  // Allocate stack for clone
  char *stack = malloc(STACK_SIZE);
  if (!stack) {
    perror("malloc");
    exit(EXIT_FAILURE);
  }

  char *stack_top = stack + STACK_SIZE;

  int flags = CLONE_NEWUTS | CLONE_NEWPID | CLONE_NEWNS | SIGCHLD;

  int pid = clone(child_main, stack_top, flags, ca);
  if (pid == -1) {
    perror("clone");
    free(stack);
    exit(EXIT_FAILURE);
  }

  free(stack);

  return pid;
}

static void wait_for_container(const int pid) {
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
}

int main(int argc, char *argv[]) {
    if (argc < 4) {
    fprintf(stderr, "usage: %s <rootfs> <hostname> <cmd>\n", argv[0]);
    return 1;
  }

  struct child_args *ca = malloc(sizeof(struct child_args));

  ca->rootfs = argv[1];
  ca->hostname = argv[2];
  ca->cmd = &argv[3];
  
  // Parent: wait for container process (PID 1 in its namespace)
  int pid = spawn_container(ca);

  wait_for_container(pid);

  free(ca);

  return 0;
}
