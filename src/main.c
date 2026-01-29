#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#include "cgroups.h"
#include "child.h"

#define STACK_SIZE (1024 * 1024)

static int spawn_container(struct container_ctx *ca) {
  // Allocate stack for clone
  char *stack = malloc(STACK_SIZE);
  if (!stack) {
    fprintf(stderr, "Memory allocation failed for child's stack: %s\n", strerror(errno));
    exit(EXIT_FAILURE);
  }

  char *stack_top = stack + STACK_SIZE;

  int flags = CLONE_NEWUTS | CLONE_NEWPID | CLONE_NEWNS | SIGCHLD;

  int pid = clone(child_main, stack_top, flags, ca);
  if (pid == -1) {
    fprintf(stderr, "Failed to create child process: %s\n", strerror(errno));
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
    printf("Child killed by signal %d: %s\n", sig, strsignal(sig));
    if (sig == SIGSYS) {
      printf("Likely seccomp violation.\n");
    }
  }
}

int main(int argc, char *argv[]) {
  if (argc < 4) {
    fprintf(stderr, "usage: %s <rootfs> <hostname> <cmd>\n", argv[0]);
    return 1;
  }

  struct container_ctx *ctx = malloc(sizeof(struct container_ctx));

  ctx->rootfs = argv[1];
  ctx->hostname = argv[2];
  ctx->cmd = &argv[3];

  int pipe_fds[2]; 
  if (pipe(pipe_fds) == -1) {
    fprintf(stderr, "Failed to create pipe: %s\n", strerror(errno));
    exit(EXIT_FAILURE);
  }

  ctx->pipe_rd = pipe_fds[0];

  // Parent: wait for container process (PID 1 in its namespace)
  int pid = spawn_container(ctx);

  configure_cgroups(pid);

  char blorg = 'c';
  write(pipe_fds[1], &blorg, 1);

  wait_for_container(pid);

  free(ctx);

  return 0;
}