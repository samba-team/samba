#!/bin/sh

export PATH=/home/tridge/samba/openldap/prefix/sbin:/home/tridge/samba/openldap/prefix/bin:/home/tridge/samba/openldap/prefix/libexec:$PATH

mkdir -p tests/tmp/db

slapd -f tests/slapd.conf -h "`tests/ldapi_url.sh`" $*

