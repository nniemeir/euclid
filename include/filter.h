#ifndef FILTER_H
#define FILTER_H

#include <linux/filter.h>

const struct sock_fprog *get_fprog(void);

#endif