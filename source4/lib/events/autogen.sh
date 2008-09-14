#!/bin/sh

rm -rf autom4te.cache
rm -f configure config.h.in

IPATHS="-I libreplace -I lib/replace -I ../libreplace -I ../replace"
IPATHS="$IPATHS -I lib/talloc -I talloc -I ../talloc"
autoconf $IPATHS || exit 1
autoheader $IPATHS || exit 1

rm -rf autom4te.cache

swig -O -Wall -python -keyword events.i # Ignore errors for now

echo "Now run ./configure and then make."
exit 0

