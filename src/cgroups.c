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

int configure_cgroups(int pid) {

  // We currently assume this is only one line, sometimes it is multiple
  int proc_cgroup_fd = open("/proc/self/cgroup", O_RDONLY);
  if (proc_cgroup_fd == -1) {
    fprintf(stderr, "Failed to open /proc/self/group: %s\n", strerror(errno));
    return -1;
  }

  char *cgroup_dir = malloc(4096);
  if (!cgroup_dir) {
    fprintf(stderr, "Memory allocation failed for cgroup_dir: %s\n",
            strerror(errno));
    return -1;
  }

  int bytes_read = read(proc_cgroup_fd, cgroup_dir, 4096);
  if (bytes_read == -1) {
    fprintf(stderr, "Failed to read to proc_group_fd: %s\n", strerror(errno));
    free(cgroup_dir);
    return -1;
  }

  if (close(proc_cgroup_fd) == -1) {
    fprintf(stderr, "Failed to close /proc/self/cgroup: %s\n", strerror(errno));
    free(cgroup_dir);
    return -1;
  }

  // This is brittle, should be improved later
  cgroup_dir[bytes_read - 1] = '\0';
  char *orig_cgroup_dir = cgroup_dir;
  cgroup_dir = strchr(cgroup_dir, ':');
  cgroup_dir = cgroup_dir + 2;
  char *parsed_cgroup_dir = malloc(PATH_MAX);
  if (!parsed_cgroup_dir) {
    fprintf(stderr, "Memory allocation failed for parsed_cgroup_dir: %s\n",
            strerror(errno));
    return -1;
  }
  snprintf(parsed_cgroup_dir, PATH_MAX, "/sys/fs/cgroup%s", cgroup_dir);
  free(orig_cgroup_dir);

  // use strrchr to find last /
  // null terminate at it
  // if parsed_cgroup_dir == /sys/fs/cgroup
  // break
  // if cgroup.subtree_control exists in parsed_cgroup_dir
  // write +memory to it

  char *group_dir = malloc(PATH_MAX);
  if (!group_dir) {
    fprintf(stderr, "Memory allocation failed for group_dir: %s\n",
            strerror(errno));
    return -1;
  }

  char *subtree_path = malloc(PATH_MAX);
  if (!subtree_path) {
    fprintf(stderr, "Memory allocation failed for subtree_path: %s\n",
            strerror(errno));
    return -1;
  }

  char *memory_max_path = malloc(PATH_MAX);
  if (!memory_max_path) {
    fprintf(stderr, "Memory allocation failed for memory_max_path: %s\n",
            strerror(errno));
    return -1;
  }

  char *procs_path = malloc(PATH_MAX);
  if (!procs_path) {
    fprintf(stderr, "Memory allocation failed for procs_path: %s\n",
            strerror(errno));
    return -1;
  }

  snprintf(subtree_path, PATH_MAX, "%s/cgroup.subtree_control",
           parsed_cgroup_dir);
  snprintf(group_dir, PATH_MAX, "%s/euclid", parsed_cgroup_dir);

  snprintf(memory_max_path, PATH_MAX, "%s/euclid/memory.max",
           parsed_cgroup_dir);
  snprintf(procs_path, PATH_MAX, "%s/euclid/cgroup.procs", parsed_cgroup_dir);

  int subtree_control_fd = open(subtree_path, O_WRONLY);
  if (subtree_control_fd == -1) {
    fprintf(stderr, "Failed to open %s: %s\n", subtree_path, strerror(errno));
    free(subtree_path);
    free(group_dir);
    free(memory_max_path);
    free(procs_path);
    return -1;
  }

  if (write(subtree_control_fd, "+memory", 8) == -1) {
    fprintf(stderr, "Failed to write to %s: %s\n", subtree_path, strerror(errno));
    free(subtree_path);
    free(group_dir);
    free(memory_max_path);
    free(procs_path);
    return -1;
  }

  char *walkup_str = strdup(parsed_cgroup_dir);
  char *slash_ptr = strrchr(walkup_str, '/');
  *slash_ptr = '\0';
  printf("After first slash termination: %s\n", walkup_str);
  free(walkup_str);

  // WE STILL NEED TO WALK UP THE TREE AND ADD +memory THERE

  if (close(subtree_control_fd) == -1) {
    fprintf(stderr, "Failed to close %s: %s\n", subtree_path, strerror(errno));
    free(subtree_path);
    free(group_dir);
    free(memory_max_path);
    free(procs_path);
    return -1;
  }

  free(subtree_path);

  int dir_status = mkdir(group_dir, 0755);
  if (dir_status == -1 && errno != EEXIST) {
    fprintf(stderr, "Failed to make directory %s: %s\n", group_dir,
            strerror(errno));
    free(group_dir);
    free(memory_max_path);
    free(procs_path);
    return -1;
  }

  free(group_dir);

  int memory_max_fd = open(memory_max_path, O_WRONLY);

  if (memory_max_fd == -1) {
    fprintf(stderr, "Failed to open %s: %s\n", memory_max_path, strerror(errno));
    free(memory_max_path);
    free(procs_path);
    return -1;
  }

  if (write(memory_max_fd, "1000000", 7) == -1) {
    fprintf(stderr, "Failed to write to %s: %s\n", memory_max_path,
            strerror(errno));
    free(memory_max_path);
    free(procs_path);
    return -1;
  }

  if (close(memory_max_fd) == -1) {
    fprintf(stderr, "Failed to close %s: %s\n", memory_max_path, strerror(errno));
    free(memory_max_path);
    free(procs_path);
    return -1;
  }

  free(memory_max_path);

  int procs_fd = open(procs_path, O_WRONLY);

  if (procs_fd == -1) {
    fprintf(stderr, "Failed to open %s: %s\n", procs_path, strerror(errno));
    free(procs_path);
    return -1;
  }

  char pid_str[10];
  int len = snprintf(pid_str, sizeof(pid_str), "%d", pid);
  if (write(procs_fd, pid_str, len) == -1) {
    fprintf(stderr, "Failed to write to %s: %s\n", procs_path, strerror(errno));
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