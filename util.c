#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <stddef.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>

#include "sockslib.h"
#include "util.h"

int sockslib_send(int fd, const void *buf, size_t len)
{
	ssize_t ret = 0;
	const unsigned char *s = buf;

	while (len) {
		ret = send(fd, s, len, 0);
		if (ret > 0) {
			len -= ret;
			s += ret;
			continue;
		} else if (ret < 0) {
			return -SOCKS_ERR_SYS_ERRNO;
		} else {
			return -SOCKS_ERR_EMPTY_RESP;
		}
	}

	return SOCKS_ERR_OK;
}

int sockslib_read(int fd, void *buf, size_t len)
{
	ssize_t ret;

	ret = recv(fd, buf, len, 0);
	if (ret < 0)
		return -SOCKS_ERR_SYS_ERRNO;

	return ret ? SOCKS_ERR_OK : -SOCKS_ERR_EMPTY_RESP;
}

int sockslib_connect(int fd)
{
	(void)fd;
	return SOCKS_ERR_OK;
}
