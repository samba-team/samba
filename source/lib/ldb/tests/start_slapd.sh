#!/bin/sh

mkdir -p tests/tmp/db

slapd -f tests/slapd.conf -h "`tests/ldapi_url.sh`" $*
