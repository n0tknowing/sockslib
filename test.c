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

	/* set the SOCKS server here.
	 * port sets to NULL, it means we use the default port 1080
	 */
	ret = socks_set_server(ctx, "socks5.foo.bar", NULL);
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
	ret = socks_request_connect(ctx);
	if (ret < 0)
		goto fail;

	/* success */
	printf("Connected, file descriptor = %d\n", ret);
	ret = 0;
fail:
	/* Example use of socks_strerror() and errno handling */
	if (ret < 0) {
		fprintf(stderr, "(%d): ", ret);
		fprintf(stderr, "%s\n", ret == -SOCKS_ERR_SYS_ERRNO ?
					strerror(errno) : socks_strerror(ret));
	}

	socks_end(ctx);
	return !!ret;
}
