#!/bin/sh

FULLBUILD=$1

for f in librpc/idl/*.idl; do
    base=`basename $f .idl`
    ndr=librpc/ndr/ndr_$base
    if [ x$FULLBUILD = xFULL -o "$f" -nt $ndr.c ]; then
      echo Processing $f
      pidl.pl --output $ndr --parse --header --parser --client librpc/rpc/rpc_$base.c $f || exit 1
    fi
done

exit 0
