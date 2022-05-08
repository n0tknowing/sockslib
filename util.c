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

int sockslib_send(int fd, const void *buf, size_t len)
{
	ssize_t ret;
	const unsigned char *send_buf = buf;

	for (;;) {
		ret = send(fd, send_buf, len, 0);
		if (ret >= 0)
			break;

		if (errno != EAGAIN && errno != EWOULDBLOCK)
			return -SOCKS_ERR_SYS_ERRNO;
	}

	return ret ? SOCKS_ERR_OK : -SOCKS_ERR_EMPTY_RESP;
}

int sockslib_read(int fd, void *buf, size_t len)
{
	ssize_t ret;

	for (;;) {
		ret = recv(fd, buf, len, 0);
		if (ret >= 0)
			break;

		if (errno != EAGAIN && errno != EWOULDBLOCK)
			return -SOCKS_ERR_SYS_ERRNO;
	}

	return ret ? SOCKS_ERR_OK : -SOCKS_ERR_EMPTY_RESP;
}

int sockslib_connect(int fd, const struct sockaddr *addr, socklen_t len)
{
	int ret;
	fd_set set;
	struct timeval tm;

	tm.tv_sec = 15;
	tm.tv_usec = 0;

	ret = connect(fd, addr, len);
	if (ret < 0) {
		if (errno != EINPROGRESS) {
			ret = -SOCKS_ERR_SYS_ERRNO;
			goto done;
		}

		for (;;) {
			FD_ZERO(&set);
			FD_SET(fd, &set);

			ret = select(fd + 1, NULL, &set, NULL, &tm);
			if (ret < 0 && errno != EINTR) {
				ret = -SOCKS_ERR_SYS_ERRNO;
				goto done;
			} else if (FD_ISSET(fd, &set)) {
				ret = SOCKS_ERR_OK;
				goto done;
			} else {
				ret = -SOCKS_ERR_CONN_TIMEOUT;
				goto done;
			}
		}
	}

done:
	return ret;
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
