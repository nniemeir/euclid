#include <linux/filter.h>
#include <linux/seccomp.h>
#include <stddef.h>
#include <sys/syscall.h>

/**
 * FIRST LINE:
 * SECOND LINE: This is a
 * conditional jump, no looping since BPF doesn't support them. JEQ means Jump
 * if equal, and BPF_K means we want to compare A to an immediate constant. the
 * constant we're comparing to is the syscall number for read(). We then say,
 * "Continue without jumping if A = NR_READ". Last, we say "Jump one space if A
 * != NR_READ": this skips allowing the call.
 * This gets used for each syscall. It means "Return the constant
 * SECCOMP_RET_ALLOW", which tells the syscall to execute normally
 */
#define ALLOW(syscall)                                                         \
  BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, syscall, 0, 1),                          \
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)

static const struct sock_filter filter[] = {
    /**
     * The seccomp_data struct contains information about the syscall
     * being requested, with the nr field giving the number of the call. The
     * BPF_STMT macro tells BPF what operation to perform and gives it an
     * argument for the operation. BPF has two registers, the accumulator (A)
     * and the index register (X). BPF_LD means "Load into A". BPF_W means "Load
     * a 32-bit word". BPF can load from an absolute offset or an indirect
     * offset, seccomp uses absolute offsets so we use the BPF_ABS option.
     */
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
    ALLOW(__NR_access),
    ALLOW(__NR_arch_prctl),
    ALLOW(__NR_brk),
    ALLOW(__NR_chdir),
    ALLOW(__NR_chmod),
    ALLOW(__NR_chown),
    ALLOW(__NR_clock_gettime),
    ALLOW(__NR_clock_nanosleep),
    ALLOW(__NR_clone),
    ALLOW(__NR_close),
    ALLOW(__NR_dup),
    ALLOW(__NR_dup2),
    ALLOW(__NR_dup3),
    ALLOW(__NR_execve),
    ALLOW(__NR_execveat),
    ALLOW(__NR_exit),
    ALLOW(__NR_exit_group),
    ALLOW(__NR_faccessat),
    ALLOW(__NR_fchmod),
    ALLOW(__NR_fchmodat),
    ALLOW(__NR_fchown),
    ALLOW(__NR_fchownat),
    ALLOW(__NR_fcntl),
    ALLOW(__NR_fdatasync),
    ALLOW(__NR_fork),
    ALLOW(__NR_fstat),
    ALLOW(__NR_fsync),
    ALLOW(__NR_futex),
    ALLOW(__NR_getcwd),
    ALLOW(__NR_getdents64),
    ALLOW(__NR_geteuid),
    ALLOW(__NR_getpid),
    ALLOW(__NR_getpgid),
    ALLOW(__NR_getppid),
    ALLOW(__NR_getrandom),
    ALLOW(__NR_getrlimit),
    ALLOW(__NR_gettid),
    ALLOW(__NR_gettimeofday),
    ALLOW(__NR_getuid),
    ALLOW(__NR_ioctl),
    ALLOW(__NR_lseek),
    ALLOW(__NR_lstat),
    ALLOW(__NR_madvise),
    ALLOW(__NR_mkdir),
    ALLOW(__NR_mkdirat),
    ALLOW(__NR_mmap),
    ALLOW(__NR_mprotect),
    ALLOW(__NR_mremap),
    ALLOW(__NR_munmap),
    ALLOW(__NR_newfstatat),
    ALLOW(__NR_nanosleep),
    ALLOW(__NR_open),
    ALLOW(__NR_openat),
    ALLOW(__NR_openat2),
    ALLOW(__NR_poll),
    ALLOW(__NR_pread64),
    ALLOW(__NR_prctl),
    ALLOW(__NR_prlimit64),
    ALLOW(__NR_pwrite64),
    ALLOW(__NR_read),
    ALLOW(__NR_readlink),
    ALLOW(__NR_readlinkat),
    ALLOW(__NR_readv),
    ALLOW(__NR_rename),
    ALLOW(__NR_renameat),
    ALLOW(__NR_renameat2),
    ALLOW(__NR_rmdir),
    ALLOW(__NR_rt_sigaction),
    ALLOW(__NR_rt_sigprocmask),
    ALLOW(__NR_rt_sigreturn),
    ALLOW(__NR_sched_yield),
    ALLOW(__NR_set_robust_list),
    ALLOW(__NR_set_tid_address),
    ALLOW(__NR_setpgid),
    ALLOW(__NR_setrlimit),
    ALLOW(__NR_sigaltstack),
    ALLOW(__NR_stat),
    ALLOW(__NR_statx),
    ALLOW(__NR_symlink),
    ALLOW(__NR_symlinkat),
    ALLOW(__NR_time),
    ALLOW(__NR_tgkill),
    ALLOW(__NR_uname),
    ALLOW(__NR_umask),
    ALLOW(__NR_unlink),
    ALLOW(__NR_unlinkat),
    ALLOW(__NR_wait4),
    ALLOW(__NR_waitid),
    ALLOW(__NR_write),
    ALLOW(__NR_writev),
    ALLOW(__NR_utimensat),

    // TODO: These should only be allowed for UNIX sockets
    ALLOW(__NR_socket),
    ALLOW(__NR_connect),
    ALLOW(__NR_sendfile),
    ALLOW(__NR_recvfrom),

    /* If none of the allowed syscalls are a match, we kill the process */
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
};

static const struct sock_fprog prog = {
    /* The number of BPF instructions */
    .len = sizeof(filter) / sizeof(filter[0]),
    /* Pointer to the filter array defined above */
    .filter = (struct sock_filter *)filter,
};


const struct sock_filter *get_filter(void) {
    return filter;
}

const struct sock_fprog *get_fprog(void) {
    return &prog;
}
