#!/bin/bash

for f in librpc/idl/*.idl; do
    echo Processing $f
    base=`basename $f .idl`
    ndr=librpc/ndr/ndr_$base
    $HOME/pidl/pidl.pl --output $ndr --parse --header --parser $f || exit 1
done

exit 0
