#!/bin/sh 

rm -rf tests/tmp/db
mkdir -p tests/tmp/db

if pidof slapd > /dev/null; then
    killall slapd
fi
sleep 2
if pidof slapd > /dev/null; then
    killall -9 slapd
fi
slapadd -f tests/slapd.conf < tests/init.ldif || exit 1
