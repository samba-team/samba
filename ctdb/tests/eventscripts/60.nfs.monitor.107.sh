#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "callout is 'true'"

setup

setup_script_options <<EOF
CTDB_NFS_CALLOUT="true"
EOF

ok_null
simple_test
