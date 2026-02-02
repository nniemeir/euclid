/**
 * filter.h
 *
 * Seccomp-BPF syscall filter interface
 *
 * OVERVIEW:
 * Provides access to a pre-configured seccomp filter that implements a
 * whitelist-based syscall policy.
 *
 * SECCOMP-BPF:
 * Seccomp (Secure Computing) with BPF (Berkeley Packet Filter) allows filtering
 * of system calls using a simple bytecode program. The kernel executes this
 * program on every syscall to determine if it should be allowed.
 *
 * DESIGN:
 * - BPF program loads current syscall number from seccomp_data structure
 * - Compares against each allowed syscall number
 * - Returns SECCOMP_RET_ALLOW if matched
 * - Returns SECCOMP_RET_KILL_PROCESS if no match found
 *
 * LIMITATIONS:
 * - Cannot be removed once installed
 * - Must be installed after dropping capabilities to prevent bypass
 * - Does not support loops (BPF limitation)
 */

#ifndef FILTER_H
#define FILTER_H

#include <linux/filter.h>

/**
 * get_fprog - Get pointer to seccomp filter program
 *
 * Returns a pointer to the sock_fprog structure containing the syscall filter.
 * The structure contains:
 * - len: Number of BPF instructions
 * - filter: Pointer to array of sock_filter instructions
 *
 * USAGE:
 * Pass the returned pointer to prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, ...)
 * to install the filter.
 *
 * Before installing a seccomp filter, you should:
 * - Call prctl(PR_SET_NO_NEW_PRIVS, 1) to prevent privilege escalation
 * - Drop all capabilities to prevent filter bypass
 *
 * Once installed, the filter cannot be removed or modified. Any attempt to
 * execute a non-whitelisted syscall will kill the process with SIGSYS.
 *
 * Return: Pointer to sock_fprog structure
 */
const struct sock_fprog *get_fprog(void);

#endif