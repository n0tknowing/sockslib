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
#include "util.h"

static int socks_get_auth_method(int fd)
{
	int ret;
	unsigned char req_buf[4], resp_buf[2];

	req_buf[0] = SOCKS_VERSION;
	req_buf[1] = 2; /* Total of requested methods */
	req_buf[2] = SOCKS_NO_AUTH;
	req_buf[3] = SOCKS_AUTH_USERPASS;

	ret = sockslib_send(fd, req_buf, 4);
	if (ret < 0)
		return ret;

	ret = sockslib_read(fd, resp_buf, 2);
	if (ret < 0)
		return ret;

	ret = resp_buf[1];
	return ret;
}

static int socks_do_authentication(struct socks_ctx *ctx)
{
	int ret;
	size_t ul, pl;
	ssize_t len = 0;
	const char *u, *p;
	unsigned char *auth_buf = NULL, resp_buf[2];

	ul = ctx->auth.user_len;
	pl = ctx->auth.pass_len;
	u = ctx->auth.username;
	p = ctx->auth.password;

	auth_buf = malloc(3 + ul + pl);
	if (!auth_buf)
		return -SOCKS_ERR_NO_MEM;

	/* RFC1929 authentication version */
	auth_buf[len++] = SOCKS_AUTH_VERSION;

	/* username */
	auth_buf[len++] = ul;
	memcpy(auth_buf + len, u, ul);
	len += ul;

	/* password */
	auth_buf[len++] = pl;
	memcpy(auth_buf + len, p, pl);
	len += pl;

	ret = sockslib_send(ctx->server.fd, auth_buf, len);
	if (ret < 0)
		goto malloc_cleanup;

	ret = sockslib_read(ctx->server.fd, resp_buf, 2);
	if (ret < 0)
		goto malloc_cleanup;

	if (resp_buf[1] != 0) {
		ret = -SOCKS_ERR_BAD_AUTH;
		goto malloc_cleanup;
	}

	ctx->auth.authed = 1;
	ret = SOCKS_ERR_OK;

malloc_cleanup:
	free(auth_buf);
	return ret;
}

static int socks_setaddr(int type, void *dest, const char *ip)
{
	int ret;

	if (inet_pton(type, ip, dest) <= 0)
		ret = -SOCKS_ERR_ADDR_NOTSUPP;
	else
		ret = SOCKS_ERR_OK;

	return ret;
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
		"Address type not supported", "Authentication method not supported",
		"Invalid authentication", "Value too long",
		"Out of memory", "Invalid argument", "Empty Request/Response",
		"Connection timeout", "System error (check errno)"
	};

	code = (code < 0) ? -code : code;
	if (code >= SOCKS_ERR_OK && code <= SOCKS_ERR_SYS_ERRNO)
		return str[code];

	return "Unknown error";
}

int socks_set_auth(struct socks_ctx *ctx, const char *u, const char *p)
{
	if (!ctx)
		return -SOCKS_ERR_BAD_ARG;

	if (!u || !*u || !p || !*p)
		return -SOCKS_ERR_BAD_ARG;

	size_t ul, pl;

	ul = strlen(u);
	pl = strlen(p);

	if (ul > 255 || pl > 255)
		return -SOCKS_ERR_BAD_AUTH;

	memcpy(ctx->auth.username, u, ul);
	memcpy(ctx->auth.password, p, pl);
	ctx->auth.user_len = ul;
	ctx->auth.pass_len = pl;

	return SOCKS_ERR_OK;
}

int socks_set_server(struct socks_ctx *ctx, const char *host, const char *port)
{
	if (!ctx || !host || !*host)
		return -SOCKS_ERR_BAD_ARG;

	if (!port || !*port)
		port = "1080";

	int fd, ret;
	struct addrinfo hint, *res, *addr;
	memset(&hint, 0, sizeof(hint));

	hint.ai_family = AF_UNSPEC;
	hint.ai_socktype = SOCK_STREAM;

	ret = getaddrinfo(host, port, &hint, &res);
	switch (ret) {
	case 0:
		break;
	case EAI_BADFLAGS:  /* useful for debugging */
		return -SOCKS_ERR_BAD_ARG;
	case EAI_AGAIN:
		return -SOCKS_ERR_CONN_REFUSED;
	case EAI_FAIL:
		return -SOCKS_ERR_SERV_FAIL;
	case EAI_MEMORY:
		return -SOCKS_ERR_NO_MEM;
	case EAI_SYSTEM:
		return -SOCKS_ERR_SYS_ERRNO;
	default:
		return -SOCKS_ERR_ADDR_NOTSUPP;
	}

	for (addr = res; addr; addr = addr->ai_next) {
		fd = socket(addr->ai_family, SOCK_STREAM, 0);
		if (fd < 0)
			continue;
		break;
	}

	if (!addr) {
		freeaddrinfo(res);
		return -SOCKS_ERR_SERV_FAIL;
	}

	ret = sockslib_set_nodelay(fd, 1);
	if (ret < 0)
		return ret;

	ret = sockslib_set_nonblock(fd, 1);
	if (ret < 0)
		return ret;

	ctx->server.fd = fd;
	ctx->server.s_addr = addr;
	ctx->server.s_port = htons(atoi(port));

	return ret;
}

int socks_connect_server(struct socks_ctx *ctx)
{
	if (!ctx)
		return -SOCKS_ERR_BAD_ARG;

	int ret;

	/* TODO: expose these variables to user */
	int timeout_sec = 5;
	int try_connect = timeout_sec * 2;

	ret = sockslib_connect(ctx->server.fd,
			       ctx->server.s_addr->ai_addr,
			       ctx->server.s_addr->ai_addrlen,
			       timeout_sec,
			       try_connect);
	if (ret < 0)
		return ret;

	ret = socks_get_auth_method(ctx->server.fd);
	if (ret < 0)
		return ret;

	ctx->auth.method = ret;
	switch (ctx->auth.method) {
	case SOCKS_NO_AUTH:
		ctx->auth.authed = 1;
		ret = SOCKS_ERR_OK;
		break;
	case SOCKS_AUTH_USERPASS:
		ret = socks_do_authentication(ctx);
		break;
	default:
		ret = -SOCKS_ERR_AUTH_NOTSUPP;
		break;
	}

	return ret;
}

int socks_set_addr4(struct socks_ctx *ctx, const char *ip, const char *port)
{
	if (!ctx)
		return -SOCKS_ERR_BAD_ARG;

	if (!ip || !*ip || !port || !*port)
		return -SOCKS_ERR_BAD_ARG;

	ctx->atyp = SOCKS_ATYP_IPV4;
	ctx->d_port = htons(atoi(port));

	return socks_setaddr(AF_INET, ctx->d_addr.ip4, ip);
}

int socks_set_addr6(struct socks_ctx *ctx, const char *ip, const char *port)
{
	if (!ctx)
		return -SOCKS_ERR_BAD_ARG;

	if (!ip || !*ip || !port || !*port)
		return -SOCKS_ERR_BAD_ARG;

	ctx->atyp = SOCKS_ATYP_IPV6;
	ctx->d_port = htons(atoi(port));

	return socks_setaddr(AF_INET6, ctx->d_addr.ip6, ip);
}

int socks_set_addrname(struct socks_ctx *ctx, const char *name, const char *port)
{
	if (!ctx)
		return -SOCKS_ERR_BAD_ARG;

	if (!name || !*name || !port || !*port)
		return -SOCKS_ERR_BAD_ARG;

	ctx->d_name_len = strlen(name);
	if (ctx->d_name_len > 255)
		return -SOCKS_ERR_TOO_LONG;

	ctx->atyp = SOCKS_ATYP_NAME;
	ctx->d_port = htons(atoi(port));
	memcpy(ctx->d_addr.name, name, ctx->d_name_len);

	return SOCKS_ERR_OK;
}

int socks_request_connect(struct socks_ctx *ctx)
{
	if (!ctx)
		return -SOCKS_ERR_BAD_ARG;

	int ret;
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
		return -SOCKS_ERR_ADDR_NOTSUPP;
	}

	memcpy(req_buf + len, &ctx->d_port, 2);
	len += 2;

	ret = sockslib_send(ctx->server.fd, req_buf, len);
	if (ret < 0)
		return ret;

	ret = sockslib_read(ctx->server.fd, resp_buf, len);
	if (ret < 0)
		return ret;

	ctx->reply = resp_buf[1];
	if (ctx->reply == SOCKS_ERR_OK) {
		ret = sockslib_set_nodelay(ctx->server.fd, 0);
		if (ret < 0)
			return ret;
		ret = sockslib_set_nonblock(ctx->server.fd, 0);
		if (ret < 0)
			return ret;
		return ctx->server.fd;
	}

	return -ctx->reply;
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
