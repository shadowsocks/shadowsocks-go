# shadowsocks-go

Current version: 0.6.2 [![Build Status](https://travis-ci.org/shadowsocks/shadowsocks-go.png?branch=develop)](https://travis-ci.org/shadowsocks/shadowsocks-go)

shadowsocks-go is a lightweight tunnel proxy which can help you get through firewalls. It is a port of [shadowsocks](https://github.com/clowwindy/shadowsocks).

The protocol is compatible with the origin shadowsocks (if both have been upgraded to the latest version).

**Note `server_password` option syntax changed in 0.6.2, the client now connects to servers in the order specified in the config.**

# Install

Compiled client binaries are provided on [google code](http://code.google.com/p/shadowsocks-go/downloads/list). (Compiled with cgo disabled.)

You can also install from source (assume you have go installed):

```
# on server
go get github.com/shadowsocks/shadowsocks-go/cmd/shadowsocks-server
# on client
go get github.com/shadowsocks/shadowsocks-go/cmd/shadowsocks-local
```

It's recommend to disable cgo when compiling shadowsocks-go. This will prevent the go runtime from creating too many threads for dns lookup.

# Usage

Both the server and client program will look for `config.json` in the current directory. You can use `-c` option to specify another configuration file.

Configuration file is in json format and has the same syntax with [shadowsocks-nodejs](https://github.com/clowwindy/shadowsocks-nodejs/). You can download the sample [`config.json`](https://github.com/shadowsocks/shadowsocks-go/blob/master/config.json), change the following values:

```
server          your server ip or hostname
server_port     server port
local_port      local socks5 proxy port
method          encryption method, null by default, or use "rc4"
password        a password used to encrypt transfer
timeout         server option, in seconds
```

Run `shadowsocks-server` on your server. To run it in the background, run `shadowsocks-server > log &`.

On client, run `shadowsocks-local`. Change proxy settings of your browser to

```
SOCKS5 127.0.0.1:local_port
```

## Command line options

Command line options can override settings from configuration files. Use `-h` option to see all available options.

```
shadowsocks-local -s server_name -p server_port -l local_port -k password -m rc4 -c config.json
shadowsocks-server -p server_port -k password -t timeout -m rc4 -c config.json
```

Use `-d` option to enable debug message.


## Use multiple servers on client

```
server_password    specify multiple server and password, server should be in the form of host:port
```

Here's a sample configuration [`client-multi-server.json`](https://github.com/shadowsocks/shadowsocks-go/blob/master/sample-config/client-multi-server.json). Given `server_password`, client program will ignore `server_port`, `server` and `password` options.

Servers are chosen in the order specified in the config. If a server can't be connected (connection failure), the client will try the next one. (Client will retry failed server with some probability to discover server recovery.)

## Multiple users with different passwords on server

The server can support users with different passwords. Each user will be served by a unique port. Use the following options on the server for such setup:

```
port_password   specify multiple ports and passwords to support multiple users
```

Here's a sample configuration [`server-multi-port.json`](https://github.com/shadowsocks/shadowsocks-go/blob/master/sample-config/server-multi-port.json). Given `port_password`, server program will ignore `server_port` and `password` options.

### Update port password for a running server

Edit the config file used to start the server, then send `SIGHUP` to the server process.

# Note to OpenVZ users

**Use OpenVZ VM that supports vswap**. Otherwise, the OS will incorrectly account much more memory than actually used. shadowsocks-go on OpenVZ VM with vswap takes about 3MB memory after startup. (Refer to [this issue](https://github.com/shadowsocks/shadowsocks-go/issues/3) for more details.)

If vswap is not an option and memory usage is a problem for you, try [shadowsocks-libuv](https://github.com/dndx/shadowsocks-libuv).
