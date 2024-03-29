/*
 * Widianto Nur Firmansah <xnaltasee@gmail.com>
 *
 * BSD-3-Clause
 */

#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <fcntl.h>
#include <netinet/tcp.h>
#include <stddef.h>
#include <sys/types.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>

#include "sockslib.h"
#include "util.h"

int sockslib_wait(int fd, int method, int timeout_sec)
{
	if (method < SOCKSLIB_WREAD && method > SOCKSLIB_WCONN)
		return -SOCKS_EARG;

	if (timeout_sec < 0 || timeout_sec > 900)
		return -SOCKS_ELONG;

	errno = 0;

	fd_set set;
	int ret, try;
	struct timeval tm;

	ret = timeout_sec * 2;

	for (try = ret < 25 ? ret : 25; try > 0; try--) {
		tm.tv_sec = (time_t)timeout_sec;
		tm.tv_usec = 0;

		FD_ZERO(&set);
		FD_SET(fd, &set);

		switch (method) {
		case SOCKSLIB_WSEND:
		case SOCKSLIB_WCONN:
			ret = select(fd + 1, NULL, &set, NULL, &tm);
			break;
		case SOCKSLIB_WREAD:
			ret = select(fd + 1, &set, NULL, NULL, &tm);
			break;
		}

		if (ret < 0 && errno != EINTR)
			return -SOCKS_ESYS;
		else if (FD_ISSET(fd, &set))
			return SOCKS_OK;
	}

	return -SOCKS_ETIMEOUT;
}

int sockslib_send(int fd, const void *buf, size_t len)
{
	int rc;
	ssize_t ret;
	const unsigned char *send_buf = buf;

	rc = sockslib_wait(fd, SOCKSLIB_WSEND, 5);
	if (rc < 0)
		return rc;

	ret = send(fd, send_buf, len, 0);
	if (ret < 0)
		return -SOCKS_ESYS;

	return ret ? SOCKS_OK : -SOCKS_EEMPTY;
}

int sockslib_read(int fd, void *buf, size_t len)
{
	int rc;
	ssize_t ret;

	rc = sockslib_wait(fd, SOCKSLIB_WREAD, 5);
	if (rc < 0)
		return rc;

	ret = recv(fd, buf, len, 0);
	if (ret < 0)
		return -SOCKS_ESYS;

	return ret ? SOCKS_OK : -SOCKS_EEMPTY;
}

int sockslib_connect(int fd, const struct sockaddr *addr, socklen_t len)
{
	int ret;

	ret = connect(fd, addr, len);
	if (ret < 0) {
		ret = sockslib_wait(fd, SOCKSLIB_WCONN, 5);
		if (ret < 0)
			return ret;
	}

	return SOCKS_OK;
}

int sockslib_set_nonblock(int fd, int opt)
{
	int flags, ret;

	flags = fcntl(fd, F_GETFL, NULL);
	if (flags < 0)
		ret = -1;

	if (opt)
		flags |= O_NONBLOCK;
	else
		flags &= (~O_NONBLOCK);

	ret = fcntl(fd, F_SETFL, flags);
	if (ret < 0)
		ret = -1;

	return !!opt + ret;
}

int sockslib_set_nodelay(int fd, int opt)
{
	int ret;

	ret = setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(int));
	if (ret < 0)
		ret = -1;

	return !!opt + ret;
}
