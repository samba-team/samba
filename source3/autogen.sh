#! /bin/sh

# Run this script to build samba from CVS.

if which autoconf > /dev/null
then
    :
else
    echo "$0: need autoconf 2.53 or later to build samba from CVS" >&2
    exit 1
fi

echo "$0: running autoheader"
autoheader || exit 1

echo "$0: running autoconf"
autoconf || exit 1
echo "Now run ./configure and then make."
exit 0
