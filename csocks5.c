#define _POSIX_C_SOURCE 200809L
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <netdb.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "csocks5.h"

static int socks_negotiate(int fd)
{
	unsigned char req_buf[5], resp_buf[2];

	req_buf[0] = 0x05;
	req_buf[1] = 0x03;
	req_buf[2] = 0x00;
	req_buf[3] = 0x01;
	req_buf[4] = 0x02;

	if (send(fd, req_buf, 5, 0) < 0)
		return -1;

	if (recv(fd, resp_buf, 2, 0) < 0)
		return -1;

	return resp_buf[1];
}

static int socks_setaddr(int type, void *dest, const char *ip)
{
	if (inet_pton(type, ip, dest) <= 0) {
		errno = EFAULT;
		return -1;
	}

	return 0;
}

struct socks_ctx {
	int reply;
	int fd;
	struct addrinfo *server;
	char user[255], pass[255];
	unsigned char user_len, pass_len;
	int is_auth;
	int atyp;
	unsigned char ip[sizeof(struct in6_addr)];
	char name[255];
	unsigned char  name_len;
	in_port_t port;
};

struct socks_ctx *socks_init(void)
{
	struct socks_ctx *ctx = malloc(sizeof(*ctx));
	if (!ctx)
		return NULL;

	ctx->reply = -1;
	ctx->fd = -1;
	ctx->atyp = -1;
	ctx->user_len = 0;
	ctx->pass_len = 0;
	ctx->name_len = 0;
	ctx->is_auth = 0;
	ctx->port = 0;
	memset(ctx->user, 0, 255);
	memset(ctx->pass, 0, 255);
	memset(ctx->name, 0, 255);
	memset(ctx->ip, 0, sizeof(ctx->ip));
	ctx->server = NULL;

	return ctx;
}

int socks_set_auth(struct socks_ctx *ctx, const char *user, const char *pass)
{
	if (!user || !*user || !pass || !*pass) {
		errno = EINVAL;
		return -1;
	}

	size_t ul = strlen(user);
	size_t pl = strlen(pass);

	memcpy(ctx->user, user, ul);
	memcpy(ctx->pass, pass, pl);
	ctx->user_len = ul;
	ctx->pass_len = pl;

	return 0;
}

int socks_set_server(struct socks_ctx *ctx, const char *host, const char *port)
{
	if (!ctx)
		return -1;

	int fd;
	struct addrinfo hint, *res, *addr;
	memset(&hint, 0, sizeof(hint));

	hint.ai_family = AF_INET;
	hint.ai_socktype = SOCK_STREAM;

	if (getaddrinfo(host, port, &hint, &res) < 0) {
		errno = EADDRNOTAVAIL;
		return -1;
	}

	for (addr = res; addr; addr = addr->ai_next) {
		fd = socket(AF_INET, SOCK_STREAM, 0);
		if (fd < 0)
			continue;
		break;
	}

	if (!addr) {
		freeaddrinfo(res);
		errno = EADDRNOTAVAIL;
		return -1;
	}

	ctx->fd = fd;
	ctx->server = addr;
	return 0;
}

int socks_connect_server(struct socks_ctx *ctx)
{
	if (!ctx)
		return -1;

	int method, ok = 0;
	ssize_t len = 0;
	unsigned char *auth_buf = NULL, res_buf[2];

	if (connect(ctx->fd, ctx->server->ai_addr, ctx->server->ai_addrlen) < 0)
		return -1;

	method = socks_negotiate(ctx->fd);
	switch (method) {
	case 0:
		ok = 1;
		break;
	case 2:
		auth_buf = malloc(3 + ctx->user_len + ctx->pass_len);
		if (!auth_buf)
			return -1;

		auth_buf[len++] = 0x01;

		auth_buf[len++] = ctx->user_len;
		memcpy(auth_buf + len, ctx->user, ctx->user_len);
		len += ctx->user_len;

		auth_buf[len++] = ctx->pass_len;
		memcpy(auth_buf + len, ctx->pass, ctx->pass_len);
		len += ctx->pass_len;

		if (send(ctx->fd, auth_buf, len, 0) < 0)
			goto auth_fail;

		if (recv(ctx->fd, res_buf, 2, 0) < 0)
			goto auth_fail;

		if (res_buf[1] == 0) {
			ok = 1;
			ctx->is_auth = 1;
		} else {
			errno = EPERM;
			ctx->is_auth = -1; /* auth fail */
		}
auth_fail:
		free(auth_buf);
		auth_buf = NULL;
		break;
	default:
		errno = ENOTSUP;
		break;
	}

	return ok ? 0 : -1;
}

int socks_set_addr4(struct socks_ctx *ctx, const char *ip, const char *port)
{
	if (!ctx) {
		errno = EINVAL;
		return -1;
	}

	ctx->atyp = 1;
	ctx->port = htons(atoi(port));
	return socks_setaddr(AF_INET, ctx->ip, ip);
}

int socks_set_addr6(struct socks_ctx *ctx, const char *ip, const char *port)
{
	if (!ctx) {
		errno = EINVAL;
		return -1;
	}

	ctx->atyp = 4;
	ctx->port = htons(atoi(port));
	return socks_setaddr(AF_INET6, ctx->ip, ip);
}

int socks_set_addrname(struct socks_ctx *ctx, const char *name, const char *port)
{
	if (!ctx) {
		errno = EINVAL;
		return -1;
	}

	ctx->name_len = strlen(name);
	ctx->atyp = 3;
	ctx->port = htons(atoi(port));
	memcpy(ctx->name, name, ctx->name_len);

	return 0;
}

int socks_connect(struct socks_ctx *ctx)
{
	if (!ctx) {
		errno = EINVAL;
		return -1;
	}

	int ok = 0;
	unsigned char req_buf[512], resp_buf[512];  /* big enough? */
	size_t len = 0;

	req_buf[len++] = 0x05;
	req_buf[len++] = 0x01; /* CONNECT */
	req_buf[len++] = 0x00; /* reserved */
	req_buf[len++] = ctx->atyp;

	switch (ctx->atyp) {
	case 1: /* ipv4 */
		memcpy(req_buf + len, ctx->ip, 4);
		len += 4;
		break;
	case 3: /* domain name */
		req_buf[len++] = ctx->name_len;
		memcpy(req_buf + len, ctx->name, ctx->name_len);
		len += ctx->name_len;
		break;
	case 4: /* ipv6 */
		memcpy(req_buf + len, ctx->ip, 16);
		len += 16;
		break;
	default:
		errno = EAFNOSUPPORT;
		return -1;
	}

	memcpy(req_buf + len, &(ctx->port), 2);
	len += 2;

#if 0
	for (size_t i = 0; i <len; i++)
		printf("%02x (%c), ", req_buf[i], req_buf[i]);
	printf("\n");
#endif

	if (send(ctx->fd, req_buf, len, 0) < 0)
		return -1;

	if (recv(ctx->fd, resp_buf, len, 0) < 0)
		return -1;

	switch (resp_buf[1]) {
	case 0x00:
		ok = 1;
		break;
	case 0x01:
	case 0x02:
	case 0x05:
		errno = ECONNREFUSED;
		break;
	case 0x03:
		errno = ENETUNREACH;
		break;
	case 0x04:
		errno = EHOSTUNREACH;
		break;
	case 0x06:
		errno = ETIMEDOUT;
		break;
	case 0x07:
		errno = ENOTSUP;
		break;
	case 0x08:
		errno = EADDRNOTAVAIL;
		break;
	default:
		errno = EINVAL;
		break;
	}

	return ok ? ctx->fd : -1;
}

void socks_end(struct socks_ctx *ctx)
{
	if (!ctx)
		return;

	if (ctx->fd != -1)
		close(ctx->fd);
	if (ctx->server)
		freeaddrinfo(ctx->server);

	free(ctx);
}

