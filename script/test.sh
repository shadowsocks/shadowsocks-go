#!/bin/bash

OPTION="-p 8389 -k foobar -d"
LOCAL_PORT="1090"
SOCKS="127.0.0.1:$LOCAL_PORT"

test_get() {
    local url
    url=$1
    target=$2
    code=$3

    if [[ -z $code ]]; then
        code="200"
    fi

    # get 5 times
    for i in {1..2}; do
        # -s silent to disable progress meter, but enable --show-error
        # -i to include http header
        # -L to follow redirect so we should always get HTTP 200
        cont=`curl --socks5 $SOCKS -s --show-error -i -L $url 2>&1`
        ok=`echo $cont | grep -E -o "HTTP/1\.1 +$code"`
        html=`echo $cont | grep -E -o -i "$target"`
        if [[ -z $ok || -z $html ]] ; then
            echo "=============================="
            echo "GET $url FAILED!!!"
            echo "$ok"
            echo "$html"
            echo $cont
            echo "=============================="
            return 1
        fi
        sleep 0.3
    done
    return 0
}

test_shadowsocks() {
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
    sleep 1

    # get 5 times
    for i in {1..5}; do
        if ! test_get $url "<html"; then
            kill -SIGTERM $server_pid
            kill -SIGTERM $local_pid
            return 1
        fi
    done
    echo "=============================="
    echo "GET $url $method passed"
    echo "=============================="
    kill -SIGTERM $server_pid
    kill -SIGTERM $local_pid
    sleep 1
}

test_shadowsocks baidu.com
test_shadowsocks baidu.com rc4

