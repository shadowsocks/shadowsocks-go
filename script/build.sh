#!/bin/bash

cd "$( dirname "${BASH_SOURCE[0]}" )/.."

version=`grep 'const version = ' ./shadowsocks/util.go | sed -e 's/.*= //' | sed -e 's/"//g'`
echo "creating shadowsocks binary version $version"

ROOT=`pwd`
bindir=$ROOT/bin
mkdir -p $bindir

build() {
    local name
    local GOOS
    local GOARCH

    if [[ $1 == "darwin" ]]; then
        # Enable CGO for OS X so change network location will not cause problem.
        export CGO_ENABLED=1
    else
        export CGO_ENABLED=0
    fi

    prog=shadowsocks-$4
    pushd cmd/$prog
    name=$prog-$3-$version
    echo "building $name"
    GOOS=$1 GOARCH=$2 go build -a || exit 1
    if [[ $1 == "windows" ]]; then
        mv $prog.exe $ROOT/script/
        pushd $ROOT/script/
        cp $ROOT/config.json sample-config.json
        cp $ROOT/sample-config/client-multi-server.json multi-server.json
        zip $name.zip $prog.exe shadowsocks.exe sample-config.json multi-server.json
        rm -f $prog.exe sample-config.json multi-server.json
        mv $name.zip $bindir
        popd
    else
        mv $prog $name
        gzip -f $name
        mv $name.gz $bindir
    fi
    popd
}

build darwin amd64 mac64 local
build linux amd64 linux64 local
build linux 386 linux32 local
build windows amd64 win64 local
build windows 386 win32 local

#build darwin amd64 mac64 server
build linux amd64 linux64 server
build linux 386 linux32 server
build windows amd64 win64 server
build windows 386 win32 server

#script/createdeb.sh amd64
#script/createdeb.sh i386
#mv shadowsocks-go_$version-1-*.deb bin/
#rm -rf shadowsocks-go_$version-1*
