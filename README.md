# sockslib - simple SOCKS client library

## Status

- It works on Domain name (ex. www.google.com), IPv4, and IPV6.
- Only RFC1929 authentication method that currently supported.
- Only `CONNECT` command that currently supported when performing a SOCKS request.
- TCP only (No UDP supported yet).
- APIs are still unstable.
- Only tested on Linux (glibc).

## API

#### Create context
- Return value: pointer to `struct socks_ctx` if success, NULL on error.
```c
struct socks_ctx *socks_init(void);
```

#### Set authentication
- `user`:  NUL-terminated RFC 1929 Username (Max 255 characters).
- `pass`:  NUL-terminated RFC 1929 Password (Max 255 characters).
- Return value: `SOCKS_ERR_OK (0)` on success, negative number on error.
```c
int socks_set_auth(struct socks_ctx *ctx, const char *user, const char *pass);
```

#### Set SOCKS server
- `host`:  SOCKS server, it can be IPv4 or IPv6 or Domain name.
- `port`:  If sets to NULL, default to 1080.
- Return value: `SOCKS_ERR_OK (0)` on success, negative number on error.
```c
int socks_set_server(struct socks_ctx *ctx, const char *host, const char *port);
```

#### Connect to the SOCKS server
- Return value: `SOCKS_ERR_OK (0)` on success, negative number on error.
```c
int socks_connect_server(struct socks_ctx *ctx);
```

#### Set IPv4 address and port of destination host
- `ipv4`:  IPv4 address of destination host you want to proxy.
- `port`:  Port number of destination host you want to proxy.
- Return value: `SOCKS_ERR_OK (0)` on success, negative number on error.
```c
int socks_set_addr4(struct socks_ctx *ctx, const char *ipv4, const char *port);
```

#### Set IPv6 address and port of destination host
- `ipv6`:  IPv6 address of destination host you want to proxy.
- `port`:  Port number of destination host you want to proxy.
- Return value: `SOCKS_ERR_OK (0)` on success, negative number on error.
```c
int socks_set_addr6(struct socks_ctx *ctx, const char *ipv6, const char *port);
```

#### Set Fully qualified domain name and port of destination host
- `name`:  Domain name of destination host you want to proxy (Max 255 characters).
- `port`:  Port number of destination host you want to proxy.
- Return value: `SOCKS_ERR_OK (0)` on success, negative number on error.
```c
int socks_set_addrname(struct socks_ctx *ctx, const char *name, const char *port);
```

#### Perform a SOCKS request (CONNECT command)
- Return value: On success, it returns a file descriptor that you can use
  just like a simple `socket()` + `connect()` socket, you can use socket operations
  like `send()`, `write()`, `recv()`, `read()`, etc..<br/>
  On error, it returns negative number.
```c
int socks_request_connect(struct socks_ctx *ctx);
```

#### Cleanup
- Return value: Always success.
```c
void socks_end(struct socks_ctx *ctx);
```


## References
- [RFC1928](https://datatracker.ietf.org/doc/html/rfc1928),  SOCKS Protocol Version 5
- [RFC1929](https://datatracker.ietf.org/doc/html/rfc1929),  Username/Password Authentication for SOCKS V5
