#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "callout is 'false', causes shutdown to fail"

setup

setup_script_options <<EOF
CTDB_NFS_CALLOUT="echo shutdown ; false"
EOF

required_result 1 "shutdown"
simple_test
