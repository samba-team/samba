#!/bin/sh

tests/init_slapd.sh
tests/start_slapd.sh

export LDB_URL=`tests/ldapi_url.sh`

. tests/test-generic.sh
