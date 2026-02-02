/**
 * child.h
 *
 * Child process entry point for container initialization.
 *
 * OVERVIEW:
 * Contains the main function executed by the child process after clone(). It
 * orchestrates the setup of all container isolation mechanisms before executing
 * the target program.
 *
 * WORKFLOW:
 * - Wait for parent to configure cgroups
 * - Join the cgroup
 * - Set up UTS namespace
 * - Configure mount namespace (pivot_root, proc, dev)
 * - Drop all capabilities
 * - Apply seccomp filter
 * - Execute target program
 *
 * NAMESPACES:
 * - UTS: Isolated hostname
 * - PID: Isolated process tree (child becomes PID 1)
 * - Mount: Isolated filesystem view
 * - Network: No network access (isolated network stack)
 * - IPC: Isolated Inter-process communication resources
 */

#ifndef CHILD_H
#define CHILD_H

/**
 * child_main - Entry point for the container child process
 * @arg: Pointer to container_ctx structure (cast from void * due to clone
 * syscall prototype)
 *
 * Called by clone() and runs in the new namespaces. It sets up all container
 * isolation and security mechanisms before executing the target program.
 *
 * The child process becomes PID 1 in its PID namespace.
 *
 * SYNCHRONIZATION:
 * Uses a pipe to wait for the parent to finish cgroup setup so that the child
 * doesn't try to join a cgroup that doesn't exist yet.
 *
 * SECURITY LAYERS:
 * 1. Namespace isolation: Separate hostname, PID tree, mounts, network, IPC
 * 2. Resource limits via cgroups: CPU, memory, swap, PID count
 * 3. Filesystem isolation: Separate root via pivot_root syscall
 * 4. Capability dropping: Removes all Linux capabilities
 * 5. Syscall filtering: Whitelist-based seccomp-bpf filter
 *
 * Return: Only returns on error (-1), because execvp replaces the process image
 * witht the target program on success.
 */
int child_main(void *arg);

#endif
