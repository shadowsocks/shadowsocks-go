#!/bin/bash

if [ $# != 3 ]; then
    echo "$0 <socks addr> <N request> <url>"
    exit 1
fi

socks=$1
n=$2
url=$3

for i in `seq 1 $n`; do
    curl -s --socks5 $socks $url >/dev/null
    if [ $(($i % 1000)) -eq 0 ]; then
        echo "finished $i request"
    fi
done

