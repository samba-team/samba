#!/bin/bash

d=$(dirname $0)

cd $d/..
PREFIX=$HOME/testprefix

for d in lib/replace lib/talloc lib/tevent lib/tdb source4/lib/ldb; do
    echo "`date`: testing $d"
    pushd $d || exit 1
    rm -rf bin
    type waf
    waf configure --enable-developer --prefix=$PREFIX || exit 1
    time waf build || exit 1
    time waf build || exit 1
    waf install || exit 1
    popd
done
ldd source4/lib/ldb/bin/ldbadd
