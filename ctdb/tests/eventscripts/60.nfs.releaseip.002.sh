#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "callout is 'false', causes releaseip to fail"

setup

setup_script_options <<EOF
CTDB_NFS_CALLOUT="echo releaseip ; false"
EOF

required_result 1 "releaseip"
simple_test
