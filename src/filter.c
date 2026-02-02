/**
 * filter.c
 *
 * Seccomp-BPF syscall filter implementation
 *
 * OVERVIEW:
 * Implements a whitelist-based syscall filter using seecomp-bpf. Only
 * explicitly allowed syscalls can execute, all others cause the process to be
 * killed by the kernel.
 *
 * SECCOMP-BPF:
 * Seccomp-bpf allows filtering syscalls using a small bytecode program. The
 * kernel executes this program on every syscall to decide whether to allow it.
 * The BPF virtual machine is simple:
 * - Two registers: Accumulator (A) and Index (X)
 * - Limited instruction set (load, store, jump, arithmetic, return)
 * - No loops
 * - Can only access the seccomp_data structure
 *
 * WORFKLOW:
 * - Process attempts syscall
 * - Kernel populates seccomp_data with syscall number and arguments
 * - Kernel runs BPF program on this data
 * - BPF program returns an action
 * - Kernel acts on this action
 *
 * BLOCKED SYSCALLS:
 * Some syscalls that were intentionally omitted include getxattr, lgetxattr,
 * and fgetxattr. These syscalls can be useful for reconnaissance as the probe
 * extended attributes. For this reason, running the sandbox through debugging
 * tools like valgrind will result in the child being killed under signal 31
 * (bad syscall).
 */
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <stddef.h>
#include <sys/syscall.h>

/**
 * ALLOW - Macro to generate BPF instructions for whitelisting a syscall
 * @syscall: Syscall number to allow (e.g., __NR_READ)
 *
 * BREAKDOWN:
 * First instruction (conditional jump):
 * - BPF_JMPG: This is a jump instruction
 * - BPF_JEQ: Jump if equal
 * - BPF_K: Compare to a constant (K = constant)
 * - syscall: The constant to compare against
 * - 0: If true (equal), skip 0 instructions (fall through to allow)
 * - 1: If false (not equal), skip 1 instructions (jump over allow)
 *
 * Second instruction (return):
 * - BPF_RET: Return from the BPF program
 * - BPF_K: Return a constant value
 * - SECCOMP_RET_ALLOW: The constant to return (allow syscall)
 */
#define ALLOW(syscall)                                                         \
  BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, syscall, 0, 1),                          \
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)

/**
 * filter - BPF program instructions for syscall filtering
 *
 * This array contains all the BPF instructions that make up our filter. The
 * kernel executes these instructions in order on every syscall.
 *
 * PROGRAM:
 * - Load syscall number from seccomp_data into accumulator
 * - Check if it matches any allowed syscall using ALLOW macros
 * - If no match found, kill the process
 */
static const struct sock_filter filter[] = {
    /*
     * The seccomp_data struct contains information about the syscall
     * being requested, with the nr field giving the number of the call. The
     * BPF_STMT macro tells BPF what operation to perform and gives it an
     * argument for the operation. BPF has two registers, the accumulator (A)
     * and the index register (X). BPF_LD means "Load into A". BPF_W means "Load
     * a 32-bit word". BPF can load from an absolute offset or an indirect
     * offset, seccomp uses absolute offsets so we use the BPF_ABS option.
     */
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),

    /*
     * TODO - For each allowed syscall (this will take a while)
     * - What It Does
     * - Risk Level
     * - Potential Misuse
     * - Mitigations
     * - Decision Rationale
     */

    /*
     * ========================================================================
     * FILE AND DIRECTORY OPERATIONS
     * ========================================================================
     */
    ALLOW(__NR_access),
    ALLOW(__NR_faccessat),
    ALLOW(__NR_chdir),
    ALLOW(__NR_close),
    ALLOW(__NR_dup),
    ALLOW(__NR_dup2),
    ALLOW(__NR_dup3),
    ALLOW(__NR_fchmod),
    ALLOW(__NR_fchmodat),
    ALLOW(__NR_fchown),
    ALLOW(__NR_fchownat),
    ALLOW(__NR_fcntl),
    ALLOW(__NR_fdatasync),
    ALLOW(__NR_fstat),
    ALLOW(__NR_fsync),
    ALLOW(__NR_getcwd),
    ALLOW(__NR_getdents64),
    ALLOW(__NR_lseek),
    ALLOW(__NR_lstat),
    ALLOW(__NR_mkdir),
    ALLOW(__NR_mkdirat),
    ALLOW(__NR_newfstatat),
    ALLOW(__NR_open),
    ALLOW(__NR_openat),
    ALLOW(__NR_openat2),
    ALLOW(__NR_pipe),
    ALLOW(__NR_poll),
    ALLOW(__NR_pread64),
    ALLOW(__NR_pwrite64),
    ALLOW(__NR_read),
    ALLOW(__NR_readlink),
    ALLOW(__NR_readlinkat),
    ALLOW(__NR_readv),
    ALLOW(__NR_rename),
    ALLOW(__NR_renameat),
    ALLOW(__NR_renameat2),
    ALLOW(__NR_rmdir),
    ALLOW(__NR_stat),
    ALLOW(__NR_statx),
    ALLOW(__NR_symlink),
    ALLOW(__NR_symlinkat),
    ALLOW(__NR_unlink),
    ALLOW(__NR_unlinkat),
    ALLOW(__NR_utimensat),
    ALLOW(__NR_write),
    ALLOW(__NR_writev),

    /*
     * ========================================================================
     * PROCESS MANAGEMENT
     * ========================================================================
     */
    ALLOW(__NR_arch_prctl),
    ALLOW(__NR_clone),
    ALLOW(__NR_execve),
    ALLOW(__NR_execveat),
    ALLOW(__NR_exit),
    ALLOW(__NR_exit_group),
    ALLOW(__NR_fork),
    ALLOW(__NR_getpid),
    ALLOW(__NR_getpgid),
    ALLOW(__NR_getppid),
    ALLOW(__NR_gettid),
    ALLOW(__NR_getuid),
    ALLOW(__NR_geteuid),
    ALLOW(__NR_prctl),
    ALLOW(__NR_setpgid),
    ALLOW(__NR_wait4),
    ALLOW(__NR_waitid),

    /*
     * ========================================================================
     * MEMORY MANAGEMENT
     * ========================================================================
     */
    ALLOW(__NR_brk),
    ALLOW(__NR_madvise),
    ALLOW(__NR_mmap),
    ALLOW(__NR_mprotect),
    ALLOW(__NR_mremap),
    ALLOW(__NR_munmap),

    /*
     * ========================================================================
     * TIME AND SCHEDULING
     * ========================================================================
     */
    ALLOW(__NR_clock_gettime),
    ALLOW(__NR_clock_nanosleep),
    ALLOW(__NR_gettimeofday),
    ALLOW(__NR_nanosleep),
    ALLOW(__NR_time),
    ALLOW(__NR_sched_yield),

    /*
     * ========================================================================
     * SIGNALS
     * ========================================================================
     */
    ALLOW(__NR_rt_sigaction),
    ALLOW(__NR_rt_sigprocmask),
    ALLOW(__NR_rt_sigreturn),
    ALLOW(__NR_sigaltstack),
    ALLOW(__NR_tgkill),
    ALLOW(__NR_tkill),

    /*
     * ========================================================================
     * RESOURCE LIMITS
     * ========================================================================
     */
    ALLOW(__NR_getrlimit),
    ALLOW(__NR_prlimit64),
    ALLOW(__NR_setrlimit),

    /*
     * ========================================================================
     * MISCELLANEOUS
     * ========================================================================
     */
    ALLOW(__NR_futex),
    ALLOW(__NR_getrandom),
    ALLOW(__NR_ioctl),
    ALLOW(__NR_set_robust_list),
    ALLOW(__NR_set_tid_address),
    ALLOW(__NR_uname),
    ALLOW(__NR_umask),

    /*
     * If execution reaches this point, none of the ALLOW macros matched.
     * This indicates that the syscall is not whitelisted, so we kill the
     * process.
     */
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
};

/**
 * prog - Seccomp filter program structure
 *
 * Wraps the filter instructions in a sock_fprog structure that the kernel
 * expects. This structure contains:
 * - len: Number of instructions in the program
 * - filter: Pointer to the instruction array
 *
 * The filter is baked into the binary at compile time for security.
 */
static const struct sock_fprog prog = {
    /* The number of BPF instructions */
    .len = sizeof(filter) / sizeof(filter[0]),
    /* Pointer to the filter array defined above */
    .filter = (struct sock_filter *)filter,
};

/**
 * get_fprog - Get pointer to seccomp filter program
 *
 * This gets passed to prctl(PR_SET_SECCOMP, ...) to install the filter.
 *
 * Return: Pointer to sock_fprog structure
 */
const struct sock_fprog *get_fprog(void) { return &prog; }
