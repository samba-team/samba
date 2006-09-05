#!/bin/sh

IPATHS="-I libreplace -I lib/replace -I ../libreplace -I ../replace"
autoconf $IPATHS || exit 1
autoheader $IPATHS || exit 1

echo "Now run ./configure and then make."
exit 0

