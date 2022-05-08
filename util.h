#ifndef SOCKSLIB_UTIL_H
#define SOCKSLIB_UTIL_H

#include <stddef.h>

int sockslib_send(int, const void *, size_t);
int sockslib_read(int, void *, size_t);
int sockslib_connect(int);

#endif /* SOCKSLIB_UTIL_H */
