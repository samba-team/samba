#!/bin/sh

rm -rf autom4te.cache

autoheader || exit 1
autoconf || exit 1

echo "Now run ./configure and then make."
exit 0

