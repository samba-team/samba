#!/bin/sh
rm x.diff
for I in ./librpc/gen_ndr/*echo*.c ./librpc/gen_ndr/*echo*.h
do
	diff -u $1/$I $I >> x.diff
done
test -z "$VISUAL" && VISUAL=vi
$VISUAL -n x.diff
