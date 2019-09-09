#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "callout is 'false', causes startup to fail"

setup

setup_script_options <<EOF
CTDB_NFS_CALLOUT="echo startup ; false"
EOF

required_result 1 "startup"
simple_test
