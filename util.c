/*
 * Nathanael Eka Oktavian <nathekavian@gmail.com>
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
		return -SOCKS_ERR_BAD_ARG;

	if (timeout_sec < 0 || timeout_sec > 900)
		return -SOCKS_ERR_TOO_LONG;

	fd_set set;
	int ret, try;
	struct timeval tm;

	ret = timeout_sec * 2;

	for (try = ret < 25 ? ret : 25; try > 0; try--) {
		if (errno		 &&
		    errno != EINPROGRESS &&
		    errno != EAGAIN	 &&
		    errno != EWOULDBLOCK &&
		    errno != EALREADY)
			return -SOCKS_ERR_SYS_ERRNO;

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
			return -SOCKS_ERR_SYS_ERRNO;
		else if (FD_ISSET(fd, &set))
			return SOCKS_ERR_OK;
	}

	return -SOCKS_ERR_CONN_TIMEOUT;
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
		return -SOCKS_ERR_SYS_ERRNO;

	return ret ? SOCKS_ERR_OK : -SOCKS_ERR_EMPTY_RESP;
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
		return -SOCKS_ERR_SYS_ERRNO;

	return ret ? SOCKS_ERR_OK : -SOCKS_ERR_EMPTY_RESP;
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

	return SOCKS_ERR_OK;
}

int sockslib_set_nonblock(int fd, int opt)
{
	int ret;

	ret = fcntl(fd, F_GETFL, NULL);
	if (ret < 0)
		return -SOCKS_ERR_SYS_ERRNO;

	if (opt)
		ret |= O_NONBLOCK;
	else
		ret &= (~O_NONBLOCK);

	if (fcntl(fd, F_SETFL, ret) < 0)
		return -SOCKS_ERR_SYS_ERRNO;

	return SOCKS_ERR_OK;
}

int sockslib_set_nodelay(int fd, int opt)
{
	int ret;

	ret = setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(int));
	if (ret < 0)
		return -SOCKS_ERR_SYS_ERRNO;

	return SOCKS_ERR_OK;
}
