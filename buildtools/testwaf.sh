#!/bin/bash

d=$(dirname $0)

cd $d/..
PREFIX=$HOME/testprefix

if [ $# -gt 0 ]; then
    tests="$*"
else
    tests="lib/replace lib/talloc lib/tevent lib/tdb source4/lib/ldb"
fi

echo "testing in dirs $tests"

for d in $tests; do
    echo "`date`: testing $d"
    pushd $d || exit 1
    rm -rf bin
    type waf
    waf dist || exit 1
    waf configure -C --enable-developer --prefix=$PREFIX || exit 1
    time waf build || exit 1
    time waf build || exit 1
    waf install || exit 1
    case $d in
	"source4/lib/ldb")
	    ldd bin/ldbadd || exit 1
	    ;;
	"lib/replace")
	    ldd bin/replace_testsuite || exit 1
	    ;;
	"lib/talloc")
	    ldd bin/talloc_testsuite || exit 1
	    ;;
	"lib/tdb")
	    ldd bin/tdbtool || exit 1
	    ;;
    esac
    popd
done
