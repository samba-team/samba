#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "callout is 'false', causes monitor-post to fail"

setup

setup_script_options <<EOF
CTDB_NFS_CALLOUT="echo monitor-post ; false"
EOF

required_result 1 "monitor-post"
simple_test
