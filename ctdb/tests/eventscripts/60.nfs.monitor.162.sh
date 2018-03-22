#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "2nd share missing, skipping share checks"

setup

setup_script_options <<EOF
CTDB_NFS_SKIP_SHARE_CHECK="yes"
EOF

ok_null

simple_test
