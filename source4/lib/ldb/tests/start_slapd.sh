#!/bin/sh

if [ -z "$LDBDIR" ]; then
    LDBDIR=`dirname $0`/..
    export LDBDIR
fi

mkdir -p $LDBDIR/tests/tmp/db

# not having slapd isn't considered a ldb test failure
slapd -f $LDBDIR/tests/slapd.conf -h "`$LDBDIR/tests/ldapi_url.sh`" $* || exit 0

sleep 2
