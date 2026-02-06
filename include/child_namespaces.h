/**
 * child_namespaces.h
 *
 * OVERVIEW:
 * Handles namespace-level isolation setup. It configures the Unix Timesharing
 * namespace (hostname) and mount namespace propagation to ensure that the
 * container is easier to distinguish by hostname and that its filesystem mounts
 * are isolated from the host.
 */

#ifndef CHILD_NAMESPACES_H
#define CHILD_NAMESPACES_H

#include "context.h"

/**
 * setup_uts_namespace - Configure the UTS namespace hostname
 * @ctx: Container configuration containing the desired hostname
 *
 * Sets the hostname visible inside the container.
 * 
 * Return: 0 on success, -1 on failure
 */
int setup_uts_namespace(struct container_ctx *ctx);

/**
 * setup_mount_propagation - Make root mount private
 *
 * Marks the root mount (/) as private to prevent mount/unmount events from
 * propagating between the container and host. This is essential for isolating
 * mount namespace.
 *
 * Return: 0 on success, -1 on failure
 */
int setup_mount_propagation(void);

#endif
