#!/bin/sh

(autoheader && autoconf) || exit 1

echo "Now run ./configure and then make."
exit 0

