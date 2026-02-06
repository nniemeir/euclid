
/**
 * child_filesystem.h
 *
 * OVERVIEW:
 * Handles the filesystem isolation layer of the container, including:
 * - OverlayFS: Provides writable layer on top of read-only rootfs
 * - /proc: Process information isolated to the container's PID namespace
 * - /dev: Device access via devtmpfs
 * - tmpfs: The overlay is created within a temporary filesystem located in RAM
 */

#ifndef CHILD_FILESYSTEM_H
#define CHILD_FILESYSTEM_H

#include "context.h"

/**
 * struct overlay_dirs - paths to directories required by overlayFS
 * @overlay_work: Used for atomic file operations ({overlay_base}/work)
 * @overlay_upper: Used for writable layer ({overlay_base}/upper)
 * @overlay_merged: Used for combined view of layers ({overlay_base}/merged)
 */
struct overlay_dirs {
  char *overlay_work;
  char *overlay_upper;
  char *overlay_merged;
};

/**
 * setup_overlay - Configure overlayfs for writable rootfs
 * @ctx: Container configuration containing paths for overlayFS
 *
 * Creates an overlay filesystem:
 * - Lower layer: Read-only rootfs
 * - Upper layer: Writable layer
 * - Work layer: Temporary workspace used by overlayfs for atomic operations
 * - Merged: Combined view of lower and upper that becomes the new root
 * 
 * Return: 0 on success, -1 on failure
 */
int setup_overlay(struct container_ctx *ctx);

/**
 * setup_rootfs - Change root filesystem using pivot_root
 * @ctx: Container configuration containing rootfs path
 *
 * Replaces the current root filesystem with a new one, completely isolating the
 * container's filesystem view from the host. Uses pivot_root instead of chroot
 * for better security.
 *
 * Return: 0 on success, -1 on failure
 */
int setup_rootfs(struct container_ctx *ctx);

/**
 * mount_dev - Mount /dev filesystem
 *
 * Mounts a devtmpfs filesystem at /dev to provide access to device files. The
 * container's /dev is isolated from the host's /dev because we're in a mount
 * namespace.
 * 
 * Return: 0 on success, -1 on failure
 */
int mount_dev(void);

/**
 * mount_proc - Mount /proc filesystem
 *
 * Mounts a proc filesystem at /proc. Because we're in a PID namespace, this
 * /proc shows only processes in our namespace rather than host processes.
 * 
 * Return: 0 on success, -1 on failure
 */
int mount_proc(void);

#endif
