/**
 * child_security.h
 *
 * OVERVIEW:
 * Handles the last security hardening layers after namespace and filesystem
 * isolation are complete. This includes:
 * - Dropping capabilities
 * - Preventing further capabilities from being granted via PR_SET_NO_NEW_PRIVS
 * - Applying a seccomp-bpf syscall whitelist
 */

#ifndef CHILD_SECURITY_H
#define CHILD_SECURITY_H

/**
 * drop_capabilities - Remove all Linux capabilities from the process
 *
 * Removes all capabilities from the capability bounding set and clears the
 * effective/permitted/inheritable capability sets. This greatly limits what the
 * container can do, even if it is running as root inside.
 *
 * Return: 0 on success, -1 on failure
 */
int drop_capabilities(void);

/**
 * lock_capabilities - Prevent privilege escalation
 *
 * Sets the PR_SET_NO_NEW_PRIVS flag, which prevents the process and its
 * descendants from gaining new privileges through execve().
 *
 * Return: 0 on success, -1 on failure
 */
int lock_capabilities(void);

/**
 * apply_seccomp - Install seccomp-bpf syscall filter
 *
 * Installs a whitelist-based syscall filter using seccomp-bpf. After this, only
 * explicitly allowed syscalls can be executed. Any attempt to use a
 * non-whitelisted syscall will cause the process to be killed.
 *
 * Return: 0 on success, -1 on failure
 */
int apply_seccomp(void);

#endif
