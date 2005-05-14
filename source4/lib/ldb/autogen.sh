#!/bin/sh

autoconf || exit 1
autoheader || exit 1

echo "Now run ./configure and then make."
exit 0

