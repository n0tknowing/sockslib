#ifndef SOCKSLIB_UTIL_H
#define SOCKSLIB_UTIL_H

#include <stddef.h>
#include <sys/types.h>

int sockslib_send(int, const void *, size_t);
int sockslib_read(int, void *, size_t);
int sockslib_connect(int, const struct sockaddr *, socklen_t, int, int);
int sockslib_set_nonblock(int, int);
int sockslib_set_nodelay(int, int);

#endif /* SOCKSLIB_UTIL_H */
