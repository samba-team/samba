#!/bin/sh

if [ -z "$LDBDIR" ]; then
    LDBDIR=`dirname $0`/..
    export LDBDIR
fi

mkdir -p $LDBDIR/tests/tmp/db

slapd -f $LDBDIR/tests/slapd.conf -h "`$LDBDIR/tests/ldapi_url.sh`" $*

sleep 2
