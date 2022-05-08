/*
 * Nathanael Eka Oktavian <nathanael@nand.eu.org>
 *
 * BSD-3-Clause
 */

#ifndef SOCKSLIB_H
#define SOCKSLIB_H

#define _POSIX_C_SOURCE 200809L
#include <netdb.h>
#include <stddef.h>
#include <stdint.h>

#define SOCKS_VERSION		5
#define SOCKS_AUTH_VERSION	1

enum socks_auth_method {
	SOCKS_NO_AUTH = 0,
	SOCKS_AUTH_GSSAPI,
	SOCKS_AUTH_USERPASS
};

enum socks_cmd_method {
	SOCKS_CMD_CONNECT = 1
	/* SOCKS_CMD_BIND, */
	/* SOCKS_CMD_UDP */
};

enum socks_address_type {
	SOCKS_ATYP_IPV4 = 1,
	SOCKS_ATYP_NAME = 3,
	SOCKS_ATYP_IPV6 = 4
};

/* One MUST set any of this with negative value
 * instead of the original value (except for SOCKS_ERR_OK),
 * and place the error code within the function return.
 *
 * example:
 *   return -SOCKS_ERR_SERV_FAIL;
 */
enum socks_err {
	/* From SOCKS 5 specification */
	SOCKS_ERR_OK = 0,
	SOCKS_ERR_SERV_FAIL,
	SOCKS_ERR_CONN_NOTALLOW,
	SOCKS_ERR_NET_UNREACH,
	SOCKS_ERR_HOST_UNREACH,
	SOCKS_ERR_CONN_REFUSED,
	SOCKS_ERR_TTL_EXPIRED,
	SOCKS_ERR_CMD_NOTSUPP,
	SOCKS_ERR_ADDR_NOTSUPP,
	/* sockslib */
	SOCKS_ERR_AUTH_NOTSUPP,
	SOCKS_ERR_BAD_AUTH,
	SOCKS_ERR_TOO_LONG,
	SOCKS_ERR_NO_MEM,
	SOCKS_ERR_BAD_ARG,
	SOCKS_ERR_EMPTY_RESP,
	SOCKS_ERR_CONN_TIMEOUT,
	SOCKS_ERR_SYS_ERRNO
};

/* SOCKS server information */
struct socks_server {
	struct addrinfo *s_addr;  /* Address information */
	uint16_t s_port;  /* Connected port */
	int fd; /* The file descriptor that will used after a SOCKS request */
};

/* SOCKS authentication (V5 only) */
struct socks_auth {
	int method;  /* authentication method */
	int authed;  /* is authenticated? */
	/* RFC1929 */
	char username[255], password[255];
	size_t user_len, pass_len;
	/* RFC1961?? */
};

struct socks_ctx {
	int ver;  /* SOCKS version */
	struct socks_server server;
	struct socks_auth auth;
	int reply;
	int atyp;  /* Destination address type */
	union {
		uint8_t ip4[4];
		uint8_t ip6[16];
		char name[255];
	} d_addr;
	size_t d_name_len;
	uint16_t d_port;
};

struct socks_ctx *socks_init(void);

int socks_set_auth(struct socks_ctx *, const char *, const char *);
int socks_set_server(struct socks_ctx *, const char *, const char *);
int socks_connect_server(struct socks_ctx *);

int socks_set_addr4(struct socks_ctx *, const char *, const char *);
int socks_set_addr6(struct socks_ctx *, const char *, const char *);
int socks_set_addrname(struct socks_ctx *, const char *, const char *);

int socks_request_connect(struct socks_ctx *);

const char *socks_strerror(int);

void socks_end(struct socks_ctx *);
#endif /* SOCKSLIB_H */
