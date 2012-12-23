# shadowsocks-go #

shadowsocks-go is a lightweight tunnel proxy which can help you get through firewalls. It is a port of [shadowsocks](https://github.com/clowwindy/shadowsocks).

The protocol is compatible with the origin shadowsocks (if both have been upgraded to the latest version).

# Install #

Compiled client binaries are provided on [google code](http://code.google.com/p/shadowsocks-go/downloads/list).

You can also install from source (assume you have go installed):

On server, run

```
go get github.com/shadowsocks/shadowsocks-go/cmd/shadowsocks-server
```

On client, run

```
go get github.com/shadowsocks/shadowsocks-go/cmd/shadowsocks-local
```

# Usage #

Both the server and client program will look for `config.json` in the current directory. You can use `-c` option to specify another configuration file.

The configuration syntax is the same with [shadowsocks-nodejs](https://github.com/clowwindy/shadowsocks-nodejs/). You can download the sample [`config.json`](https://github.com/shadowsocks/shadowsocks-go/blob/master/config.json), change the following values:

```
server          your server ip or hostname
server_port     server port
local_port      local socks5 proxy port
password        a password used to encrypt transfer

timeout         server option, in seconds
port_password   server option, specify multiple ports and passwords to support multiple users
cache_enctable  server option, store computed encryption table on disk to speedup server startup
```

Given `port_password` option, server program will ignore `server_port` and `password` options.

Run `shadowsocks-server` on your server. To run it in the background, run `shadowsocks-server > log &`.

On client, run `shadowsocks-local`. Change proxy settings of your browser to

```
SOCKS5 127.0.0.1:local_port
```

## Command line options ##

Command line options can override settings from configuration files.

```
shadowsocks-local -s server_name -p server_port -l local_port -k password -c config.json
shadowsocks-server -p server_port -k password -t timeout -c config.json
```

Use `-d` option to enable debug message.

## Encryption table cache ##

If the server has many different passwords, startup would be slow because it takes much time to calculate encryption tables. It's recommended to enable the `cache_enctable` option if you have more than 20 different passwords. This will save the computed encryption table in the file `table.cache`.

Note: unused password will not be deleted, so you may need to delete the table cache file if it grows too big.

## Updating port password for a running server  ##

Edit the config file used to start the server, then send `SIGHUP` to the server process.
