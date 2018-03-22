#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "callout is 'false', causes takeip to fail"

setup

setup_script_options <<EOF
CTDB_NFS_CALLOUT="echo takeip ; false"
EOF

required_result 1 "takeip"
simple_test
