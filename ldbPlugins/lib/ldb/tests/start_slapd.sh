#!/bin/sh

export PATH=/usr/sbin:$PATH

mkdir -p tests/tmp/db

slapd -f tests/slapd.conf -h "`tests/ldapi_url.sh`" $*
