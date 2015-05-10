#!/bin/bash

# Use [ -n "$TRAVIS" ] to test for running on Travis-CI.

# Run in the scripts directory.
cd "$( dirname "${BASH_SOURCE[0]}" )"

LOCAL_PORT="1090"
SERVER_PORT="8389"
OPTION="-p $SERVER_PORT -k foobar"
SOCKS="127.0.0.1:$LOCAL_PORT"
HTTP_PORT="8123"

wait_server() {
    local port
    port=$1
    for i in {1..20}; do
        # sleep first because this maybe called immediately after server start
        sleep 0.1
        nc -z -w 4 127.0.0.1 $port && break
    done
}

start_http_server() {
    go build http.go
    ./http $HTTP_PORT &
    wait_server $HTTP_PORT
    http_pid=$!
}

stop_http_server() {
    kill -SIGTERM $http_pid
}

test_get() {
    local url
    local target
    local code
    url=$1
    target=$2
    code=$3

    if [[ -z $code ]]; then
        code="200"
    fi

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
    return 0
}

test_shadowsocks() {
    local url
    local method
    local server_pid
    local local_pid
    url=$1
    method=$2

    $SERVER $OPTION -m "$method" &
    server_pid=$!
    wait_server $SERVER_PORT

    $LOCAL $OPTION -s 127.0.0.1 -l $LOCAL_PORT -m "$method" &
    local_pid=$!
    wait_server $LOCAL_PORT

    for i in {1..3}; do
        if ! test_get $url "shadowsocks-go"; then
            kill -SIGTERM $server_pid
            kill -SIGTERM $local_pid
            stop_http_server
            exit 1
        fi
    done
    echo "=============================="
    echo "GET $url $method passed"
    echo "=============================="
    kill -SIGTERM $server_pid
    kill -SIGTERM $local_pid
    sleep 0.1
}

test_server_local_pair() {
    echo "============================================================"
    echo "server: $SERVER, local: $LOCAL"
    echo "============================================================"

    local url
    url=http://127.0.0.1:$HTTP_PORT/README.md
    test_shadowsocks $url table
    test_shadowsocks $url rc4
    test_shadowsocks $url rc4-md5
    test_shadowsocks $url aes-128-cfb
    test_shadowsocks $url aes-192-cfb
    test_shadowsocks $url aes-256-cfb
    test_shadowsocks $url bf-cfb
    test_shadowsocks $url des-cfb
    test_shadowsocks $url cast5-cfb
    test_shadowsocks $url chacha20
    test_shadowsocks $url salsa20
}

start_http_server

SERVER="shadowsocks-server"
LOCAL="shadowsocks-local"
test_server_local_pair

if [[ -n $SS_PYTHON ]]; then
    SERVER="$SS_PYTHON/server.py --forbidden-ip="
    LOCAL="shadowsocks-local"
    test_server_local_pair

    SERVER="shadowsocks-server"
    LOCAL="$SS_PYTHON/local.py"
    test_server_local_pair
fi

stop_http_server
