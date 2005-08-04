#!/bin/sh

LEX="$1"
SRC="$2"
DEST="$3"

dir=`dirname $SRC`
file=`basename $SRC`
base=`basename $SRC .l`
if [ -z "$LEX" ]; then
	echo "lex not found - not regenerating $DEST"
	return;
fi
if [ -r $DEST ]; then
    if [ x`find $SRC -newer $DEST -print` != x$SRC ]; then
	    return;
    fi
fi
TOP=`pwd`
if cd $dir && $LEX $file; then
    sed '/^#/ s|$base.yy\.c|$DEST|' $base.yy.c > $base.c
    rm -f $base.yy.c
fi
cd $TOP
