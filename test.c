#define _POSIX_C_SOURCE 200809L
#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "csocks5.h"

/* only ipv4 is tested */
int main(int argc, char **argv)
{
	if (argc < 3)
		return -1;

	const char *host = argv[1];
	const char *port = argv[2];

	int ret = 1, fd;
	struct socks_ctx *ctx = socks_init();
	if (!ctx)
		err(1, "socks_init");

	ret = socks_set_auth(ctx, "foo", "bar");
	if (ret < 0)
		goto fail;

	ret = socks_set_server(ctx, "socks5.foo-bar.org", "1773");
	if (ret < 0)
		goto fail;

	ret = socks_connect_server(ctx);
	if (ret < 0)
		goto fail;

	ret = socks_set_addr4(ctx, host, port);
	if (ret < 0)
		goto fail;

	fd = socks_connect(ctx);
	if (fd < 0)
		goto fail;

	char buf[10];
	ssize_t r, k = 1;

	dprintf(fd, "GET / HTTP/1.1\r\n"
		    "Host: %s:%s\r\n"
		    "\r\n", host, port);

	while (k) {
		r = recv(fd, buf, 9, 0);
		if (r != 9)
			k = 0;
		buf[r] = 0;
		printf("%s", buf);
	}

	printf("\n");

fail:
	if (errno)
		perror(NULL);

	socks_end(ctx);
	return ret;
}
