#!/bin/bash

# rebuild our heimdal lex/yacc files. Run this manually if you update heimdal

yaccfiles="heimdal/lib/asn1/asn1parse.y heimdal/lib/hx509/sel-gram.y heimdal/lib/com_err/parse.y"

set -e

YACC="yacc"

top=$PWD

call_yacc() {
    yfile="$1"

    echo "Calling $YACC on $yfile"

    dir=$(dirname $yfile)
    base=$(basename $yfile .y)
    cfile=$base".c"
    yfile=$base".y"

    cd $dir

    # -l specified because line directives cause more bother than they solve (issues with lcov finding the source files)
    $YACC -l -d $yfile || exit 1
    if [ -r y.tab.h -a -r y.tab.c ];then
	cat y.tab.h > $base.h
	cat y.tab.c > $base.c
	rm -f y.tab.c y.tab.h
    elif [ ! -r $base.h -a ! -r $base.c]; then
	echo "$base.h nor $base.c generated."
	exit 1
    fi
    cd $top
}



for yfile in $yaccfiles; do
    call_yacc $yfile
done
