#!/bin/bash

cd "$( dirname "${BASH_SOURCE[0]}" )/.."
ver=$(awk '/\tconst version =/ { print $4 }' shadowsocks/util.go | sed -e 's/"//g')

if [[ $# != 1 ]]; then
    echo "$0 <arch, i386 or amd64>"
    exit 1
fi

export CGO_ENABLED=0
export GOOS=linux

arch=$1
case $arch in
    i386)
        export GOARCH=386
        ;;
    amd64)
        export GOARCH=amd64
        ;;
    *)
        echo "arch $i not supported"
        exit 1
        ;;
esac

# build shadowsocks server
pushd cmd/shadowsocks-server
go build -a -v || exit 1
popd

# create debian package
DEBDIR=shadowsocks-go_$ver-1-$arch
rm -rf $DEBDIR
cp -r deb $DEBDIR

sed -i -e "s/VER/$ver/" $DEBDIR/DEBIAN/control || exit 1
sed -i -e "s/^Architecture.*$/Architecture: $arch/" $DEBDIR/DEBIAN/control || exit 1

mkdir -p $DEBDIR/usr/bin
cp cmd/shadowsocks-server/shadowsocks-server $DEBDIR/usr/bin/
rm -f cmd/shadowsocks-server/shadowsocks-server

fakeroot dpkg-deb --build $DEBDIR

