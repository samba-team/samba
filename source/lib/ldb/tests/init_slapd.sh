#!/bin/sh 

if [ -z "$LDBDIR" ]; then
    LDBDIR=`dirname $0`/..
    export LDBDIR
fi

rm -rf tests/tmp/db
mkdir -p tests/tmp/db

if pidof slapd > /dev/null; then
    killall slapd
fi
sleep 2
if pidof slapd > /dev/null; then
    killall -9 slapd
fi
slapadd -f $LDBDIR/tests/slapd.conf < $LDBDIR/tests/init.ldif || exit 1
