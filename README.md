# sockslib - simple SOCKS client library

## Status

- It works on Domain name (ex. www.google.com), IPv4, and IPV6.
- Only RFC1929 authentication method that currently supported.
- Only `CONNECT` command that currently supported when performing a SOCKS request.
- TCP only (No UDP supported yet).
- APIs are still unstable.

## API

#### Create context
```c
struct socks_ctx *socks_init(void);
```

#### Set authentication
```c
int socks_set_auth(struct socks_ctx *ctx, const char *user, const char *pass);
```

#### Set SOCKS server
```c
int socks_set_server(struct socks_ctx *ctx, const char *host, const char *port);
```

#### Connect to the SOCKS server
```c
int socks_connect_server(struct socks_ctx *ctx);
```

#### Set IPv4 address and port of destination host
```c
int socks_set_addr4(struct socks_ctx *ctx, const char *ipv4, const char *port);
```

#### Set IPv6 address and port of destination host
```c
int socks_set_addr6(struct socks_ctx *ctx, const char *ipv6, const char *port);
```

#### Set Fully qualified domain name and port of destination host
```c
int socks_set_addrname(struct socks_ctx *ctx, const char *name, const char *port);
```

#### Perform a SOCKS request (CONNECT command)
```c
int socks_connect(struct socks_ctx *ctx);
```

If `socks_connect()` success, it returns a file descriptor that you can use
just like a simple `socket()` + `connect()` socket, you can use socket operations
like `send()`, `write()`, `recv()`, `read()`, etc...

#### Cleanup
```c
void socks_end(struct socks_ctx *ctx);
```


## References
- [RFC1928](https://datatracker.ietf.org/doc/html/rfc1928),  SOCKS Protocol Version 5
- [RFC1929](https://datatracker.ietf.org/doc/html/rfc1929),  Username/Password Authentication for SOCKS V5
