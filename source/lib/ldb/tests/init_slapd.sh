#!/bin/sh

export PATH=/home/tridge/samba/openldap/prefix/sbin:/home/tridge/samba/openldap/prefix/bin:/home/tridge/samba/openldap/prefix/libexec:$PATH

rm -rf tests/tmp/db
mkdir -p tests/tmp/db

killall slapd
sleep 2
killall -9 slapd
slapadd -f tests/slapd.conf < tests/init.ldif || exit 1
