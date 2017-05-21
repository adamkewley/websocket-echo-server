# Websocket Echo Server

An extremely basic implementation of a websocket echo server. Used as
a learning exercise.


## Building

Built with `gcc (Ubuntu 5.4.0-6ubuntu1~16.04.4) 5.4.0 20160609` using
`GNU Make 4.1`. Requires the nodejs
[http-parser](https://github.com/nodejs/http-parser) and OpenSSL to be
installed.

```bash
make all
```

## Running

When executed, will open a random available port and start listening
for HTTP messages on that port. The server will only accept websocket
handshakes, which it will upgrade to initiate a full websocket
sesssion.

```bash
./main
```
