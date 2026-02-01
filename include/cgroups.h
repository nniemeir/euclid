#ifndef CGROUPS_H
#define CGROUPS_H

#include "context.h"

int configure_cgroups(struct container_ctx *ctx);
int add_process_to_cgroup(void);

#endif
