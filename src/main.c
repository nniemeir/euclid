/**
 * main.c
 *
 * Container orchestration and lifecycle management.
 *
 * OVERVIEW:
 * This orchestrates the creation of a containerized environment using Linux
 * namespaces, cgroups, and seccomp-bpf filtering.
 *
 * EXECUTION FLOW:
 * - Create pipe for parent-child synchronization
 * - Initialize container configuration
 * - Spawn container child process (clone with namespaces flags)
 * - Configure cgroups (parent)
 * - Signal child to proceed (via pipe)
 * - Wait for child to exit
 * - Clean up resources
 *
 * NAMESPACES USED:
 * - CLONE_NEWUTS: Isolated hostname
 * - CLONE_NEWPID: Isolated process tree (child is PID 1)
 * - CLONE_NEWNS: Isolated mount table
 * - CLONE_NEWNET: Isolated network stack
 * - CLONE_NEWIPC: Isolated IPC resources
 *
 * CLONE_NEWUSER is planned for later versions.
 */

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
#include "context.h"

/**
 * STACK_SIZE - Size of stack for the child process
 *
 * The clone() syscall requires a separate stack for the child process.
 *
 * On x86_64, stacks grown downward (from high addresses to low).
 * We allocate the stack at the low address and pass a pointer to the top to
 * clone().
 */
#define STACK_SIZE (1024 * 1024)

/**
 * spawn_container - Create child process in new namespaces
 * @ctx: Container configuration
 *
 * Creates a new process using clone() with namespace isolation flags.
 * The child process will execute child_main() in the new namespaces.
 *
 * CLONE VS FORK:
 * - fork(): Creates a complete copy of the process
 * - clone(): Can selectively share/isolate resources via flags
 *
 * NAMESPACE FLAGS:
 * - CLONE_NEWUTS: New UTS namespace (hostname)
 * - CLONE_NEWPID: New PID namespace (child becomes PID 1)
 * - CLONE_NEWNS: New mount namespace (isolated mounts)
 * - CLONE_NEWNET: New network namespace (no network access)
 * - CLONE_NEWIPC: New IPC namespace (isolated IPC)
 * - SIGCHLD: Send SIGCHLD to parent when child exits
 *
 * STACK ALLOCATION:
 * clone() requires a separate stack for the child. We allocate this on the heap
 * and free it after clone() returns.
 *
 * Return: Child PID on success, -1 on failure
 */
static int spawn_container(struct container_ctx *ctx) {
  /*
   * Allocate stack for the child process.
   * Must be heap-allocated to ensure its valid across clone().
   */
  char *stack = malloc(STACK_SIZE);
  if (!stack) {
    fprintf(stderr, "Memory allocation failed for child's stack: %s\n",
            strerror(errno));
    return -1;
  }

  /*
   * Calculate the top of the stack since stacks grow downward on x86_64
   */
  char *stack_top = stack + STACK_SIZE;

  /*
   * Set up namespace flags for clone().
   *
   * SIGCHLD ensures we get notified when the child exits so we can call wait()
   * to reap it.
   */
  int flags = CLONE_NEWUTS | CLONE_NEWPID | CLONE_NEWNS | CLONE_NEWNET |
              CLONE_NEWIPC | SIGCHLD;

  /*
   * Create the child process.
   * The child begins execution in child_main() with the new namespaces already
   * active
   */
  int pid = clone(child_main, stack_top, flags, ctx);
  if (pid == -1) {
    fprintf(stderr, "Failed to create child process: %s\n", strerror(errno));
    free(stack);
    return -1;
  }

  /*
   * The child has its own copy of the stack, so we can free it here
   */
  free(stack);

  return pid;
}

/**
 * wait_for_container - Wait for container to exit and report status
 * @pid: PID of container process
 *
 * Blocks until the container process exits, then reports how it terminated.
 * This is essential for proper process cleanup.
 */
static void wait_for_container(const int pid) {
  int status;

  /*
   * Wait for the specific child process to change state. This blocks until the
   * child exits.
   */
  waitpid(pid, &status, 0);

  /*
   * Check if process exited normally by calling exit() or returning from main
   */
  if (WIFEXITED(status)) {
    printf("Child exited normally\n");
  }

  /*
   * Check if process was killed by a signal
   */
  if (WIFSIGNALED(status)) {
    int sig = WTERMSIG(status);
    printf("Child killed by signal %d: %s\n", sig, strsignal(sig));

    /*
     * SIGSYS (31) is sent by seccomp when a non-whitelisted syscall is
     * attempted.
     */
    if (sig == SIGSYS) {
      printf("Likely seccomp violation.\n");
    }
  }
}

/**
 * main - Entry pointer for the program
 *
 * Orchestrates the creation and management of a containerized environment.
 *
 * PROCESS:
 * - Create pipe for parent-child synchronization
 * - Initialize container configuration
 * - Spawn child process in new namespaces
 * - Configure cgroups (parent)
 * - Signal child to proceed (via pipe write)
 * - Wait for child to complete
 * - Clean up resources
 *
 * Return: EXIT_SUCCESS on success, EXIT_FAILURE on failure
 */
int main(void) {
  /*
   * Create a pipe for synchronization between parent and child.
   * pipe_fds[0] is the read end, pipe_fds[1] is the write end.
   *
   * The child will block until the parent writes to pipe_fds[1], ensuring
   * cgroups are configured before the child tries to join them.
   */
  int pipe_fds[2];
  if (pipe(pipe_fds) == -1) {
    fprintf(stderr, "Failed to create pipe: %s\n", strerror(errno));
    exit(EXIT_FAILURE);
  }

  /*
   * Initialize container configuration.
   * This allocates memory and copies configuration from the compile-time
   * constants in context.c.
   */
  struct container_ctx *ctx = init_ctx(pipe_fds);
  if (!ctx) {
    fprintf(stderr, "Failed to configure container, exiting...\n");
    exit(EXIT_FAILURE);
  }

  /*
   * Create the child process in new namespaces.
   * The child will execute child_main() but will block on the pipe read before
   * proceeding with setup.
   */
  int pid = spawn_container(ctx);
  if (pid == -1) {
    fprintf(stderr, "Failed to create container, exiting...\n");
    exit(EXIT_FAILURE);
  }

  /*
   * Configure cgroups for resource limits
   * This must be done by the parent because it involves writing to privileged
   * directories.
   */
  if (configure_cgroups(ctx)) {
    fprintf(stderr, "Failed to configure cgroups, exiting...\n");
    exit(EXIT_FAILURE);
  }

  /*
   * Signal the child to proceed
   */
  char ping = 'c';
  if (write(ctx->pipe_fds[1], &ping, 1) == -1) {
    fprintf(stderr, "Failed to write to pipe: %s\n", strerror(errno));
    exit(EXIT_FAILURE);
  }

  /*
   * Wait for the container to exit.
   * This blocks until the child process terminates, then prints information
   * about how it exited.
   *
   * This is essential for proper process cleanup and determining why the
   * container exited.
   */
  wait_for_container(pid);

  /*
   * Clean up container context.
   * Frees all allocated memory to prevent leaks.
   */
  cleanup_ctx(ctx);

  exit(EXIT_SUCCESS);
}