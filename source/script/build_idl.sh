#!/bin/sh

FULLBUILD=$1

[ -d librpc/gen_ndr ] || mkdir -p librpc/gen_ndr || exit 1
[ -d librpc/gen_rpc ] || mkdir -p librpc/gen_rpc || exit 1

( cd build/pidl && make ) || exit 1

PIDL="build/pidl/pidl.pl --output librpc/gen_ndr/ndr_ --parse --header --parser --client librpc/gen_rpc/rpc_"

if [ x$FULLBUILD = xFULL ]; then
      echo Rebuilding all idl files in librpc/idl
      $PIDL librpc/idl/*.idl || exit 1
      exit 0
fi

list=""

for f in librpc/idl/*.idl; do
    basename=`basename $f .idl`
    if [ "$f" -nt librpc/gen_ndr/ndr_$basename.c ]; then
	list="$list $f"
    fi
done

if [ "x$list" != x ]; then
    $PIDL $list || exit 1
fi

exit 0
