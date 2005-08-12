#!/bin/sh

YACC="$1"
SRC="$2"
DEST="$3"

dir=`dirname $SRC`
file=`basename $SRC`
base=`basename $SRC .y`
if [ -z "$YACC" ]; then
	echo "yacc not found"
	exit;
fi
if [ -r $DEST ]; then
	if [ x`find $SRC -newer $DEST -print` != x$SRC ]; then
		exit;
	fi
fi
TOP=`pwd`
if cd $dir && $YACC -d $file; then
	if [ -r y.tab.h -a -r y.tab.c ];then
		echo "move files"
		sed -e "/^#/!b" -e "s|y\.tab\.h|$base.h|" y.tab.h > $base.h
		sed '/^#/ s|y\.tab\.c|$base.c|' y.tab.c > $base.c
		rm -f y.tab.c y.tab.h
	fi
fi
cd $TOP
