#!/bin/sh

for f in man/man3/*.yo; do
    base=`basename $f .yo`;
    man=man/man3/$base.3;

    if test $f -nt $man; then
	echo Creating $man from $f
	yodl2man -o $man $f || rm -f $man
    fi
done
