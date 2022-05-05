#ifndef libsocks5_h
#define libsocks5_h

struct socks_ctx;

struct socks_ctx *socks_init(void);
int socks_set_auth(struct socks_ctx *, const char *, const char *);
int socks_set_server(struct socks_ctx *, const char *, const char *);
int socks_connect_server(struct socks_ctx *);
int socks_set_addr4(struct socks_ctx *, const char *, const char *);
int socks_set_addr6(struct socks_ctx *, const char *, const char *);
int socks_set_addrname(struct socks_ctx *, const char *, const char *);
int socks_connect(struct socks_ctx *);
void socks_end(struct socks_ctx *);

#endif /* libsocks5_h */
