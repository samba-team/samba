#!/bin/sh

FULLBUILD=$1

[ -d librpc/gen_ndr ] || mkdir -p librpc/gen_ndr || exit 1
[ -d librpc/gen_rpc ] || mkdir -p librpc/gen_rpc || exit 1

for f in librpc/idl/*.idl; do
    base=`basename $f .idl`
    ndr=librpc/gen_ndr/ndr_$base
    if [ x$FULLBUILD = xFULL -o "$f" -nt $ndr.c ]; then
      echo Processing $f
      pidl.pl --output $ndr --parse --header --parser --client librpc/gen_rpc/rpc_$base.c $f || exit 1
    fi
done

exit 0
