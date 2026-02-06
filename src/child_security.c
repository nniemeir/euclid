/**
 * child_security.c
 *
 * OVERVIEW:
 * Handles the last security hardening layers after namespace and filesystem
 * isolation are complete. This includes:
 * - Dropping capabilities
 * - Preventing further capabilities from being granted via PR_SET_NO_NEW_PRIVS
 * - Applying a seccomp-bpf syscall whitelist
 *
 * CAPABILITIES:
 * Linux capabilities divide root's abilities into smaller permissions. We don't
 * want the container to perform privileged operations, so we drop all
 * capabilites.
 *
 * SECCOMP-BPF:
 * Secure Computing Mode with Berkeley Packet Filter allows for syscall
 * filtering. The filter is defined as a bytecode program that runs on ever
 * syscall attempt.
 */

#include <errno.h>
#include <linux/capability.h>
#include <linux/prctl.h>
#include <linux/seccomp.h>
#include <stdio.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "filter.h"

/**
 * drop_capabilities - Remove all Linux capabilities from the process
 *
 * Removes all capabilities from the capability bounding set and clears the
 * effective/permitted/inheritable capability sets. This greatly limits what the
 * container can do, even if it is running as root inside.
 *
 * LINUX CAPABILITIES:
 * These break root's power into smaller privileges. Some examples are:
 * - CAP_NET_ADMIN: Configure network
 * - CAP_SYS_ADMIN: Various admin operations
 * - CAP_SYS_CHROOT: Use chroot()
 * - CAP_SYS_MODULE: Load kernel modules
 *
 * CAPABILITY SETS:
 * - Bounding: Maximum capabilities that a process can gain
 * - Permitted: Capabilities the process is allowed to use
 * - Effective: Capabilities currently active
 * - Inheritable: Capabilities that can be inherited by child processes
 *
 * WORKFLOW:
 * - Drop each capability from the bounding set using prctl
 * - Clear all three capability sets using capset
 *
 * Return: 0 on success, -1 on failure
 */
int drop_capabilities(void) {
  /*
   * Remove all capabilities from the bounding set.
   * CAP_LAST_CAP is the highest capability number currently defined.
   */
  for (int cap = 0; cap <= CAP_LAST_CAP; cap++) {
    /*
     * PR_CAPBSET removes a capability from the bounding set.
     * Afterwards, the process can never acquire that capability again.
     */
    if (syscall(SYS_prctl, PR_CAPBSET_DROP, cap, 0, 0, 0) == -1) {
      // EINVAL means the capability number doesn't exist
      if (errno != EINVAL) {
        fprintf(stderr, "Failed to drop capability %d from bounding set: %s\n",
                cap, strerror(errno));
        return -1;
      }
    }
  }

  /*
   * Clear all capability sets, ensuring the process has no capabilities at all.
   */
  struct __user_cap_header_struct header;
  struct __user_cap_data_struct data[2];

  memset(&header, 0, sizeof(header));
  memset(&data, 0, sizeof(data));

  /*
   * _LINUX_CAPABILITY_VERSION_3 is the current capability API version as of
   * Feb. 2026.
   */
  header.version = _LINUX_CAPABILITY_VERSION_3;

  /*
   * pid = 0 means "current process"
   */
  header.pid = 0;

  /*
   * capset sets the capability sets to the values in data, Since we zeroed it,
   * this clears all capabilities.
   */
  if (syscall(SYS_capset, &header, data) == -1) {
    fprintf(stderr, "Failed to clear capability sets: %s\n", strerror(errno));
    return -1;
  }

  return 0;
}

/**
 * lock_capabilities - Prevent privilege escalation
 *
 * Sets the PR_SET_NO_NEW_PRIVS flag, which prevents the process and its
 * descendants from gaining new privileges through execve().
 *
 * prctl itself always takes five arguments, though the compiler will default
 * missing args to zero if you omit them. It is the first flag that indicates
 * how many of the args will be meaningful. Trailing zeroes are included here
 * for clarity's sake.
 *
 * Return: 0 on success, -1 on failure
 */
int lock_capabilities(void) {
  if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == -1) {
    fprintf(stderr, "Failed to set PR_SET_NO_NEW_PRIVS: %s\n", strerror(errno));
    return -1;
  }

  return 0;
}

/**
 * apply_seccomp - Install seccomp-bpf syscall filter
 *
 * Installs a whitelist-based syscall filter using seccomp-bpf. After this, only
 * explicitly allowed syscalls can be executed. Any attempt to use a
 * non-whitelisted syscall will cause the process to be killed.
 *
 * SECCOMP-BPF:
 * Seccomp (Secure Computing) with BPF (Berkeley Packet Filter) allows filtering
 * system calls using a small bytecode program. The kernel runs this program on
 * every syscall attempt.
 *
 * FILTER ACTIONS:
 * - SECCOMP_RET_ALLOW: Execute the syscall normally
 * - SECCOMP_RET_KILL_PROCESS: Kill the process
 * - SECCOMP_RET_KILL_THREAD: Kill the calling thread
 * - SECCOMP_RET_ERRNO: Return an error code
 * - SECCOMP_RET_TRAP: Send SIGSYS to the process
 *
 * We use SECCOMP_RET_ALLOW for whitelisted syscalls and
 * SECCOMP_RET_KILL_PROCESS for everything else.
 *
 * A seccomp filter cannot be removed once installed.
 *
 * Return: 0 on success, -1 on failure
 */
int apply_seccomp(void) {
  if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, get_fprog(), 0, 0) == -1) {
    fprintf(stderr, "Failed to install seccomp filter: %s\n", strerror(errno));
    return -1;
  }

  return 0;
}