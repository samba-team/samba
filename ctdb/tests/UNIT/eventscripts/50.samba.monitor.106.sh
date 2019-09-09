#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "non-existent share - not checked"

setup

setup_script_options <<EOF
CTDB_SAMBA_SKIP_SHARE_CHECK="yes"
EOF

ok_null

simple_test
