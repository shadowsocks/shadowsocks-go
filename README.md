# shadowsocks-go [![GoDoc](https://godoc.org/github.com/shadowsocks/shadowsocks-go?status.svg)](https://godoc.org/github.com/shadowsocks/shadowsocks-go) [![Go Report Card](https://goreportcard.com/badge/github.com/arthurkiller/shadowsocks-go)](https://goreportcard.com/report/github.com/arthurkiller/shadowsocks-go) [![Build Status](https://travis-ci.org/arthurkiller/shadowsocks-go.png?branch=master)](https://travis-ci.org/arthurkiller/shadowsocks-go) [![Docker Repository on Quay.io](https://quay.io/repository/arthurkiller/shadowsocks-go/status "Docker Repository on Quay.io")](https://quay.io/repository/arthurkiller/shadowsocks-go/status) [![slack](https://img.shields.io/badge/chat%20on%20slack-ready-orange.svg)](https://shadowsocks-go.slack.com)

___Current version: 2.0.0 alpha & Testing passed via go1.8___

shadowsocks-go is a lightweight tunnel proxy which can help you get through firewalls. It is a port of [shadowsocks](https://github.com/clowwindy/shadowsocks).

shadowsocks-go v2.0 is based on old version and has been totally reconstruct. Aimed to be easy use as a packet for gopher and server developer to by pass GFW.

The protocol is compatible with the origin shadowsocks (if both have been upgraded to the latest version).

**Note `server_password` option syntax changed in 0.6.2, the client now connects to servers in the order specified in the config.**

**Please develop on the latest develop branch if you want to send pull request.**

# What's new
* Reconstruct this project
* Bug fix and stability improvement
* Redesign the interface for easy extension
* New features for shadowsocks-go user

# Install

Download precompiled binarys from the [release page](https://github.com/shadowsocks/shadowsocks-go/releases). (All compiled with cgo disabled, except the mac version.)

You can also install from source (assume you have go installed):

```
# on server
go get github.com/shadowsocks/shadowsocks-go/cmd/shadowsocks-server
# on client
go get github.com/shadowsocks/shadowsocks-go/cmd/shadowsocks-local
```

It's recommended to disable cgo when compiling shadowsocks-go. This will prevent the go runtime from creating too many threads for dns lookup.

# Usage

Both the server and client program will look for `config.json` in the current directory. You can use `-c` option to specify another configuration file.

Configuration file is in json format and has the same syntax with [shadowsocks-nodejs](https://github.com/clowwindy/shadowsocks-nodejs/). You can download the sample [`config.json`](https://github.com/shadowsocks/shadowsocks-go/blob/master/config.json), change the following values:



Run `shadowsocks-server` on your server. To run it in the background, run `hohup shadowsocks-server > log &`.

On client, run `shadowsocks-local`. Change proxy settings of your browser to

```
SOCKS5 127.0.0.1:local_port
```

## About encryption methods

AES is recommended for shadowsocks-go. [Intel AES Instruction Set](http://en.wikipedia.org/wiki/AES_instruction_set) will be used if available and can make encryption/decryption very fast. To be more specific, **`aes-128-cfb` is recommended as it is faster and [secure enough](https://www.schneier.com/blog/archives/2009/07/another_new_aes.html)**.

**rc4 and table encryption methods are deprecated because they are not secure.**

## Command line options

Command line options can override settings from configuration files. Use `-h` option to see all available options.
ss-local
```
Usage of ./shadowsocks-local:
  -addr string
        local socks5 proxy serve address (default "127.0.0.1")
  -config string
        specify config file
  -level string
        given the logger level for ss to logout info, can be set in debug info warn error panic (default "info")
  -method string
        encryption method, default: aes-256-cfb. end with -auth mean enable OTA (default "aes-256-cfb")
  -multiserver string
        3 modes for shadowsocks local detect ss server:
                fastest: get fastest server to request
                round-robin: get round-robin server to request
                dissable: only request for first server (default "fastest")
  -passwd string
        server password
  -port int
        local socks5 proxy port (default 1085)
  -saddr string
        server address
  -sport int
        server port
  -timeout int
        timeout in seconds (default 300)
  -u    use the udp to serve
  -v    print version
```

ss-remote
```
Usage of ./shadowsocks-server:
  -config string
        specify config file
  -core int
        maximum number of CPU cores to use, default is determinied by Go runtime
  -disable_udp
        diasbale UDP service, enable bydefault (default true)
  -level string
        given the logger level for ss to logout info, can be set in debug info warn error (default "info")
  -method string
        encryption method, default: aes-256-cfb (default "aes-256-cfb")
  -passwd string
        password
  -port string
        server port
  -pprof int
        set the metrix port to Enable the pprof and matrix(TODO), keep it 0 will disable this feature
  -timeout int
        timeout in seconds (default 300)
  -v    print version
```


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

# WIP
* Make up the Encrypt packet with a better interface for easy extension
* Add the AEAD (testing in local)
* add PAC list for use

# Note to OpenVZ users

**Use OpenVZ VM that supports vswap**. Otherwise, the OS will incorrectly account much more memory than actually used. shadowsocks-go on OpenVZ VM with vswap takes about 3MB memory after startup. (Refer to [this issue](https://github.com/shadowsocks/shadowsocks-go/issues/3) for more details.)

If vswap is not an option and memory usage is a problem for you, try [shadowsocks-libev](https://github.com/madeye/shadowsocks-libev).
