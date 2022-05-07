#define _POSIX_C_SOURCE 200809L
#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "sockslib.h"

static void usage(void)
{
	fprintf(stderr, "usage: prog host port method\n\n");
	fprintf(stderr, "method:\n");
	fprintf(stderr, "  - ipv4\n");
	fprintf(stderr, "  - ipv6\n");
	fprintf(stderr, "  - name\n");
	exit(1);
}

int main(int argc, char **argv)
{
	if (argc < 4)
		usage();

	errno = 0;

	const char *host = argv[1];
	const char *port = argv[2];
	const char *method = argv[3];

	int ret = 1;
	struct socks_ctx *ctx = socks_init();
	if (!ctx)
		err(1, "socks_init");

	/* If the SOCKS server is authenticated using RFC1929,
	 * then change it to #if 1 */
#if 0
	ret = socks_set_auth(ctx, "foo", "bar");
	if (ret < 0)
		goto fail;
#endif

	/* set the SOCKS server here */
	ret = socks_set_server(ctx, "socks5.foo-bar.org", "1773");
	if (ret < 0)
		goto fail;

	/* then, connect it */
	ret = socks_connect_server(ctx);
	if (ret < 0)
		goto fail;

	if (!strcmp(method, "ipv4"))
		ret = socks_set_addr4(ctx, host, port);
	else if (!strcmp(method, "ipv6"))
		ret = socks_set_addr6(ctx, host, port);
	else if (!strcmp(method, "name"))
		ret = socks_set_addrname(ctx, host, port);
	else
		usage();

	if (ret < 0)
		goto fail;

	/* now, perform the request */
	ret = socks_connect(ctx);
	if (ret < 0)
		goto fail;

	/* if success, let's GET a HTTP web */
	char buf[10];
	ssize_t r, k = 1;

	dprintf(ret, "GET / HTTP/1.1\r\n"
		    "Host: %s:%s\r\n"
		    "\r\n", host, port);

	while (k) {
		r = recv(ret, buf, 9, 0);
		if (r != 9)
			k = 0;
		buf[r] = 0;
		printf("%s", buf);
	}

	printf("\n");

fail:
	/* Example use of socks_strerror() and errno handling */
	if (ret < 0) {
		fprintf(stderr, "(%d): ", ret);
		fprintf(stderr, "%s\n", ret == -SOCKS_ERR_SYS_ERRNO ?
					strerror(errno) : socks_strerror(ret));
	}

	socks_end(ctx);
	return ret;
}
