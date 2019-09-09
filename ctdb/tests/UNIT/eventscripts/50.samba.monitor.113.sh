#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "testparm times out on 2nd time through"

setup

ok_null
simple_test

export FAKE_TIMEOUT="yes"
ok <<EOF
WARNING: smb.conf cache update timed out - using old cache file
EOF
simple_test
