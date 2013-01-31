#!/bin/bash

OPTION="-p 8389 -k foobar -d"
LOCAL_PORT="1090"
SOCKS="127.0.0.1:$LOCAL_PORT"

test_get() {
    local url
    local method
    local server_pid
    local local_pid
    url=$1
    method=$2

    shadowsocks-server $OPTION -m "$method" &
    server_pid=$!
    shadowsocks-local $OPTION -s 127.0.0.1 -l $LOCAL_PORT -m "$method" &
    local_pid=$!

    # wait server and client finish startup
    sleep 0.5

    # get 5 times
    for i in {1..5}; do
        if ! curl -s --socks5 $SOCKS $url >/dev/null 2>&1; then
            echo "=============================="
            echo "GET $url $method FAILED!!!"
            echo "=============================="
            kill -SIGINT $server_pid
            kill -SIGINT $local_pid
            exit 1
        fi
    done
    echo "=============================="
    echo "GET $url $method passed"
    echo "=============================="
    kill -SIGINT $server_pid
    kill -SIGINT $local_pid
    sleep 0.5
}

#test_get localhost:4000
test_get baidu.com
test_get baidu.com rc4

