#!/bin/bash

OPTION="-p 8389 -k foobar"
LOCAL_PORT="1090"
SOCKS="127.0.0.1:$LOCAL_PORT"

test_get() {
    local url
    local method
    local server_pid
    local local_pid
    url=$1
    method=$2

    shadowsocks-server $OPTION -m "$method" >/dev/null 2>&1 &
    server_pid=$!
    shadowsocks-local $OPTION -s 127.0.0.1 -l $LOCAL_PORT -m "$method" >/dev/null 2>&1 &
    local_pid=$!

    # wait server and client finish startup
    sleep 1

    if curl -s --socks5 $SOCKS $url >/dev/null 2>&1; then
        echo "get $url $method passed"
    else
        echo "get $url $method FAILED!!!"
        exit 1
    fi
    kill -SIGINT $server_pid
    kill -SIGINT $local_pid
}

test_get baidu.com
test_get baidu.com rc4

