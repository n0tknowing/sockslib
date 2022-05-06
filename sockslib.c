/*
 * Nathanael Eka Oktavian <nathanael@nand.eu.org>
 *
 * BSD-3-Clause
 */

#define _POSIX_C_SOURCE 200809L
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <netdb.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "sockslib.h"

static int socks_negotiate(int fd)
{
	unsigned char req_buf[4], resp_buf[2];

	req_buf[0] = SOCKS_VERSION;
	req_buf[1] = 2; /* Total of requested methods */
	req_buf[2] = SOCKS_NO_AUTH;
	req_buf[3] = SOCKS_AUTH_USERPASS;

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

	return SOCKS_ERR_OK;
}

static void server_clear(struct socks_ctx *ctx)
{
	struct socks_server *s;

	s = &ctx->server;
	s->s_addr = NULL;
	s->s_port = 0;
	s->fd = -1;
}

static void auth_clear(struct socks_ctx *ctx)
{
	struct socks_auth *a;

	a = &ctx->auth;
	a->method = 0;
	a->authed = 0;
	memset(a->username, 0, sizeof(a->username));
	memset(a->password, 0, sizeof(a->password));
	a->user_len = 0;
	a->pass_len = 0;
}

struct socks_ctx *socks_init(void)
{
	struct socks_ctx *ctx;

	ctx = malloc(sizeof(*ctx));
	if (!ctx)
		return NULL;

	ctx->atyp = 0;
	ctx->d_addr.name[0] = 0;
	ctx->d_port = 0;
	ctx->d_name_len = 0;
	ctx->reply = -1;
	ctx->ver = SOCKS_VERSION;

	auth_clear(ctx);
	server_clear(ctx);

	return ctx;
}

const char *socks_strerror(int code)
{
	/* see enum socks_err in sockslib.h */
	static const char *str[] = {
		"", "SOCKS server failure", "Connection not allowed",
		"Network unreachable", "Host unreachable",
		"Connection refused", "TTL expired", "Command not supported",
		"Address type not supported", "Authentication failed",
		"Invalid argument"
	};

	code = (code < 0) ? -code : code;
	if (code >= SOCKS_ERR_OK && code <= SOCKS_ERR_INVALID_ARG)
		return str[code];

	return "Unknown error";
}

int socks_set_auth(struct socks_ctx *ctx, const char *u, const char *p)
{
	if (!ctx)
		return -SOCKS_ERR_INVALID_ARG;

	if (!u || !*u || !p || !*p)
		return -SOCKS_ERR_INVALID_ARG;

	size_t ul, pl;

	ul = strlen(u);
	pl = strlen(p);

	if (ul > 255 || pl > 255)
		return -SOCKS_ERR_INVALID_AUTH;

	memcpy(ctx->auth.username, u, ul);
	memcpy(ctx->auth.password, p, pl);
	ctx->auth.user_len = ul;
	ctx->auth.pass_len = pl;

	return SOCKS_ERR_OK;
}

int socks_set_server(struct socks_ctx *ctx, const char *host, const char *port)
{
	if (!ctx)
		return -SOCKS_ERR_INVALID_ARG;

	int fd;
	struct addrinfo hint, *res, *addr;
	memset(&hint, 0, sizeof(hint));

	hint.ai_family = AF_INET;
	hint.ai_socktype = SOCK_STREAM;

	if (getaddrinfo(host, port, &hint, &res) < 0)
		return -SOCKS_ERR_CONN_REFUSED;

	for (addr = res; addr; addr = addr->ai_next) {
		fd = socket(AF_INET, SOCK_STREAM, 0);
		if (fd < 0)
			continue;
		break;
	}

	if (!addr) {
		freeaddrinfo(res);
		return -SOCKS_ERR_CONN_REFUSED;
	}

	ctx->server.fd = fd;
	ctx->server.s_addr = addr;
	return SOCKS_ERR_OK;
}

int socks_connect_server(struct socks_ctx *ctx)
{
	if (!ctx)
		return -SOCKS_ERR_INVALID_ARG;

	int ret = SOCKS_ERR_INVALID_AUTH;
	ssize_t len = 0;
	unsigned char *auth_buf = NULL, res_buf[2];

	if (connect(ctx->server.fd,
		    ctx->server.s_addr->ai_addr,
		    ctx->server.s_addr->ai_addrlen) < 0)
		return -1;

	ctx->auth.method = socks_negotiate(ctx->server.fd);
	switch (ctx->auth.method) {
	case SOCKS_NO_AUTH:
		ret = SOCKS_ERR_OK;
		break;
	case SOCKS_AUTH_USERPASS:
		auth_buf = malloc(3 + ctx->auth.user_len + ctx->auth.pass_len);
		if (!auth_buf)
			return -1;

		auth_buf[len++] = SOCKS_AUTH_VERSION;

		auth_buf[len++] = ctx->auth.user_len;
		memcpy(auth_buf + len, ctx->auth.username, ctx->auth.user_len);
		len += ctx->auth.user_len;

		auth_buf[len++] = ctx->auth.pass_len;
		memcpy(auth_buf + len, ctx->auth.password, ctx->auth.pass_len);
		len += ctx->auth.pass_len;

		if (send(ctx->server.fd, auth_buf, len, 0) < 0)
			goto auth_fail;

		if (recv(ctx->server.fd, res_buf, 2, 0) < 0)
			goto auth_fail;

		if (res_buf[1] == 0) {
			ret = SOCKS_ERR_OK;
			ctx->auth.authed = 1;
		}
auth_fail:
		free(auth_buf);
		auth_buf = NULL;
		break;
	default:
		ret = SOCKS_ERR_INVALID_ARG;
		break;
	}

	return ret ? -ret : SOCKS_ERR_OK;
}

int socks_set_addr4(struct socks_ctx *ctx, const char *ip, const char *port)
{
	if (!ctx)
		return -SOCKS_ERR_INVALID_ARG;

	ctx->atyp = SOCKS_ATYP_IPV4;
	ctx->d_port = htons(atoi(port));

	return socks_setaddr(AF_INET, ctx->d_addr.ip4, ip);
}

int socks_set_addr6(struct socks_ctx *ctx, const char *ip, const char *port)
{
	if (!ctx)
		return -SOCKS_ERR_INVALID_ARG;

	ctx->atyp = SOCKS_ATYP_IPV6;
	ctx->d_port = htons(atoi(port));

	return socks_setaddr(AF_INET6, ctx->d_addr.ip6, ip);
}

int socks_set_addrname(struct socks_ctx *ctx, const char *name, const char *port)
{
	if (!ctx)
		return -SOCKS_ERR_INVALID_ARG;

	ctx->d_name_len = strlen(name);
	ctx->atyp = SOCKS_ATYP_NAME;
	ctx->d_port = htons(atoi(port));
	memcpy(ctx->d_addr.name, name, ctx->d_name_len);

	return SOCKS_ERR_OK;
}

int socks_connect(struct socks_ctx *ctx)
{
	if (!ctx)
		return -SOCKS_ERR_INVALID_ARG;

	unsigned char req_buf[512], resp_buf[512];  /* big enough? */
	size_t len = 0;

	req_buf[len++] = SOCKS_VERSION;
	req_buf[len++] = SOCKS_CMD_CONNECT;
	req_buf[len++] = 0x00; /* reserved */
	req_buf[len++] = ctx->atyp;

	switch (ctx->atyp) {
	case SOCKS_ATYP_IPV4: /* ipv4 */
		memcpy(req_buf + len, ctx->d_addr.ip4, 4);
		len += 4;
		break;
	case SOCKS_ATYP_NAME: /* domain name */
		req_buf[len++] = ctx->d_name_len;
		memcpy(req_buf + len, ctx->d_addr.name, ctx->d_name_len);
		len += ctx->d_name_len;
		break;
	case SOCKS_ATYP_IPV6: /* ipv6 */
		memcpy(req_buf + len, ctx->d_addr.ip6, 16);
		len += 16;
		break;
	default:
		return -SOCKS_ERR_CMD_NOT_SUPP;
	}

	memcpy(req_buf + len, &ctx->d_port, 2);
	len += 2;

	if (send(ctx->server.fd, req_buf, len, 0) < 0)
		return -1;

	if (recv(ctx->server.fd, resp_buf, len, 0) < 0)
		return -1;

	ctx->reply = resp_buf[1];
	return ctx->reply ? -ctx->reply : ctx->server.fd;
}

void socks_end(struct socks_ctx *ctx)
{
	if (!ctx)
		return;

	if (ctx->server.fd != -1)
		close(ctx->server.fd);
	if (ctx->server.s_addr)
		freeaddrinfo(ctx->server.s_addr);

	free(ctx);
}
