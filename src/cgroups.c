/**
 * ASSUMES CGROUPS V2
 * We make a new cgroup by adding a new directory to /sys/fs/cgroup (use
 * permissions 755). The system will make the necessary files for us, we only
 * write to the files corresponding to limits we want to set. We'll want to use
 * the open syscall with O_WRONLY.
 * We add a process to the cgroup by writing its pid to the cgroup.procs file in
 * the group's directory.
 *
 * memory.max - Maximum memory for the process
 *
 */

#include <errno.h>
#include <fcntl.h>
#include <linux/limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* This is the cgroup that the current process belongs to */
static char *get_proc_cgroup(void) {
  // We currently assume this is only one line, sometimes it is multiple
  int proc_cgroup_fd = open("/proc/self/cgroup", O_RDONLY);
  if (proc_cgroup_fd == -1) {
    fprintf(stderr, "Failed to open /proc/self/cgroup: %s\n", strerror(errno));
    return NULL;
  }

  char *proc_cgroup = malloc(PATH_MAX);
  if (!proc_cgroup) {
    fprintf(stderr, "Memory allocation failed for proc_cgroup: %s\n",
            strerror(errno));
    return NULL;
  }

  int bytes_read = read(proc_cgroup_fd, proc_cgroup, PATH_MAX);
  if (bytes_read == -1) {
    fprintf(stderr, "Failed to read to proc_group_fd: %s\n", strerror(errno));
    free(proc_cgroup);
    return NULL;
  }

  if (close(proc_cgroup_fd) == -1) {
    fprintf(stderr, "Failed to close /proc/self/cgroup: %s\n", strerror(errno));
    free(proc_cgroup);
    return NULL;
  }

  // Isolate the actual path
  // This is brittle, should be improved later
  proc_cgroup[bytes_read - 1] = '\0';
  char *orig_proc_cgroup = proc_cgroup;
  proc_cgroup = strchr(proc_cgroup, ':');
  if (!proc_cgroup) {
    fprintf(stderr, "Malformed /proc/self/cgroup\n");
    free(orig_proc_cgroup);
    return NULL;
  }

  proc_cgroup = proc_cgroup + 2;

  char *parsed_proc_cgroup = malloc(PATH_MAX);
  if (!parsed_proc_cgroup) {
    fprintf(stderr, "Memory allocation failed for parsed_proc_cgroup: %s\n",
            strerror(errno));
    return NULL;
  }

  snprintf(parsed_proc_cgroup, PATH_MAX, "/sys/fs/cgroup%s", proc_cgroup);

  free(orig_proc_cgroup);

  return parsed_proc_cgroup;
}

static int enable_memory_controller(char *proc_cgroup) {
  // use strrchr to find last /
  // null terminate at it
  // if parsed_cgroup_dir == /sys/fs/cgroup
  // break
  // if cgroup.subtree_control exists in parsed_cgroup_dir
  // write +memory to it
  char *subtree_path = malloc(PATH_MAX);
  if (!subtree_path) {
    fprintf(stderr, "Memory allocation failed for subtree_path: %s\n",
            strerror(errno));
    return -1;
  }

  snprintf(subtree_path, PATH_MAX, "%s/cgroup.subtree_control", proc_cgroup);

  int subtree_control_fd = open(subtree_path, O_WRONLY);
  if (subtree_control_fd == -1) {
    fprintf(stderr, "Failed to open %s: %s\n", subtree_path, strerror(errno));
    free(subtree_path);
    return -1;
  }

  if (write(subtree_control_fd, "+memory\n", 9) == -1) {
    fprintf(stderr, "Failed to write to %s: %s\n", subtree_path,
            strerror(errno));
    if (close(subtree_control_fd) == -1) {
      fprintf(stderr, "Failed to close %s: %s\n", subtree_path,
              strerror(errno));
    }
    free(subtree_path);
    return -1;
  }

  if (close(subtree_control_fd) == -1) {
    fprintf(stderr, "Failed to close %s: %s\n", subtree_path, strerror(errno));
    free(subtree_path);
    return -1;
  }

  free(subtree_path);

  return 0;
}

static int make_cgroup_dir(char *proc_cgroup) {
  char *group_dir = malloc(PATH_MAX);
  if (!group_dir) {
    fprintf(stderr, "Memory allocation failed for group_dir: %s\n",
            strerror(errno));
    return -1;
  }

  snprintf(group_dir, PATH_MAX, "%s/euclid", proc_cgroup);

  int dir_status = mkdir(group_dir, 0755);
  if (dir_status == -1 && errno != EEXIST) {
    fprintf(stderr, "Failed to make directory %s: %s\n", group_dir,
            strerror(errno));
    free(group_dir);
    return -1;
  }

  free(group_dir);

  return 0;
}

static int set_memory_limit(char *proc_cgroup) {
  char *memory_max_path = malloc(PATH_MAX);
  if (!memory_max_path) {
    fprintf(stderr, "Memory allocation failed for memory_max_path: %s\n",
            strerror(errno));
    return -1;
  }

  snprintf(memory_max_path, PATH_MAX, "%s/euclid/memory.max", proc_cgroup);

  int memory_max_fd = open(memory_max_path, O_WRONLY);

  if (memory_max_fd == -1) {
    fprintf(stderr, "Failed to open %s: %s\n", memory_max_path,
            strerror(errno));
    free(memory_max_path);
    return -1;
  }

  if (write(memory_max_fd, "1000000\n", 9) == -1) {
    fprintf(stderr, "Failed to write to %s: %s\n", memory_max_path,
            strerror(errno));
    if (close(memory_max_fd) == -1) {
      fprintf(stderr, "Failed to close %s: %s\n", memory_max_path,
              strerror(errno));
    }
    free(memory_max_path);
    return -1;
  }

  if (close(memory_max_fd) == -1) {
    fprintf(stderr, "Failed to close %s: %s\n", memory_max_path,
            strerror(errno));
    free(memory_max_path);
    return -1;
  }

  free(memory_max_path);

  return 0;
}

static int add_process_to_cgroup(char *proc_cgroup, int pid) {
  char *procs_path = malloc(PATH_MAX);
  if (!procs_path) {
    fprintf(stderr, "Memory allocation failed for procs_path: %s\n",
            strerror(errno));
    return -1;
  }

  snprintf(procs_path, PATH_MAX, "%s/euclid/cgroup.procs", proc_cgroup);

  int procs_fd = open(procs_path, O_WRONLY);

  if (procs_fd == -1) {
    fprintf(stderr, "Failed to open %s: %s\n", procs_path, strerror(errno));
    free(procs_path);
    return -1;
  }

  char pid_str[10];
  int len = snprintf(pid_str, sizeof(pid_str), "%d\n", pid);
  if (write(procs_fd, pid_str, len) == -1) {
    fprintf(stderr, "Failed to write to %s: %s\n", procs_path, strerror(errno));
    if (close(procs_fd) == -1) {
      fprintf(stderr, "Failed to close %s: %s\n", procs_path, strerror(errno));
    }
    free(procs_path);
    return -1;
  }

  if (close(procs_fd) == -1) {
    fprintf(stderr, "Failed to close %s: %s\n", procs_path, strerror(errno));
    free(procs_path);
    return -1;
  }

  free(procs_path);

  return 0;
}

int configure_cgroups(int pid) {
  char *proc_cgroup = get_proc_cgroup();

  if (!proc_cgroup) {
    return -1;
  }

  if (make_cgroup_dir(proc_cgroup) == -1) {
    free(proc_cgroup);
    return -1;
  }

  if (enable_memory_controller(proc_cgroup) == -1) {
    free(proc_cgroup);
    return -1;
  }

  if (set_memory_limit(proc_cgroup) == -1) {
    free(proc_cgroup);
    return -1;
  }

  if (add_process_to_cgroup(proc_cgroup, pid) == -1) {
    free(proc_cgroup);
    return -1;
  }

  free(proc_cgroup);

  return 0;
}