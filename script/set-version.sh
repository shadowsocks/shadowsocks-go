#!/bin/bash

cd "$( dirname "${BASH_SOURCE[0]}" )/.."

if [ $# != 1 ]; then
    echo "Usage: $0 <version>"
    exit 1
fi

version=$1
#echo $version

sed -i -e "s,\(\tversion \+= \)\".*\"$,\1\"$version\"," shadowsocks/util.go
sed -i -e "s/Version:.*$/Version: $version-1/" deb/DEBIAN/control

