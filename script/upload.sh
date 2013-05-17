#!/bin/bash

cd "$( dirname "${BASH_SOURCE[0]}" )/.."

if [[ $# != 2 ]]; then
    echo "upload.sh <username> <passwd>"
    exit 1
fi

version=$(awk '/\tconst version =/ { print $4 }' shadowsocks/util.go | sed -e 's/"//g')
username=$1
passwd=$2

upload() {
    summary=$1
    file=$2
    googlecode_upload.py -l Featured -u "$username" -w "$passwd" -s "$summary" -p "shadowsocks-go" "$file"
}

upload "$version OS X Client 64bit" bin/shadowsocks-local-mac64-$version.gz
upload "$version Linux Client 32bit" bin/shadowsocks-local-linux32-$version.gz
upload "$version Linux Client 64bit" bin/shadowsocks-local-linux64-$version.gz
upload "$version Windows Client 64bit" bin/shadowsocks-local-win64-$version.zip
upload "$version Windows Client 32bit" bin/shadowsocks-local-win32-$version.zip

upload "$version Linux Server 32bit" bin/shadowsocks-server-linux32-$version.gz
upload "$version Linux Server 64bit" bin/shadowsocks-server-linux64-$version.gz

upload "$version Linux Server deb 32bit" bin/shadowsocks-go_$version-1-386.deb
upload "$version Linux Server deb 64bit" bin/shadowsocks-go_$version-1-amd64.deb

