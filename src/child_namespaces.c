/**
 * child_namespaces.c
 *
 * OVERVIEW:
 * Handles namespace-level isolation setup. It configures the Unix Timesharing
 * namespace (hostname) and mount namespace propagation to ensure that the
 * container is easier to distinguish by hostname and that its filesystem mounts
 * are isolated from the host.
 *
 * MOUNT PROPAGATION:
 * Mount namespaces share mount events with their parent by default. For proper
 * isolation, we make the root mount private via the MS_PRIVATE option.
 */

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/mount.h>
#include <unistd.h>

#include "context.h"

/**
 * setup_uts_namespace - Configure the UTS namespace hostname
 * @ctx: Container configuration containing the desired hostname
 *
 * Sets the hostname visible inside the container.
 *
 * UTS NAMESPACE:
 * Unix Time-Sharing namespace isolates:
 * - Hostname
 * - NIS domain name
 *
 * Return: 0 on success, -1 on failure
 */
int setup_uts_namespace(struct container_ctx *ctx) {
  if (sethostname(ctx->hostname, strlen(ctx->hostname)) == -1) {
    fprintf(stderr, "Failed to set hostname: %s\n", strerror(errno));
    return -1;
  }

  return 0;
}

/**
 * setup_mount_propagation - Make root mount private
 *
 * Marks the root mount (/) as private to prevent mount/unmount events from
 * propagating between the container and host. This is essential for isolating
 * mount namespace.
 *
 * MOUNT PROPAGATION:
 * Mounts can be:
 * - MS_SHARED: Events propagate to peer mounts
 * - MS_PRIVATE: Events don't propagate (isolated)
 * - MS_SLAVE: Recieve events but don't send them
 * - MS_UNBINDABLE: Can't be bind mounted
 *
 * Without this, mounting /proc in the container would also mount it on the
 * host. Making / private ensures the mounts stay isolated.
 *
 * MS_REC applies the change recursively to all mounts under /.
 *
 * Return: 0 on success, -1 on failure
 */
int setup_mount_propagation(void) {
  if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) == -1) {
    fprintf(stderr, "Failed to setup mount propagation: %s\n", strerror(errno));
    return -1;
  }

  return 0;
}
