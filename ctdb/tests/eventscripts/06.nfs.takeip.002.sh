#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "callout is 'false', causes takeip-pre to fail"

setup

setup_script_options "service" "60.nfs" <<EOF
CTDB_NFS_CALLOUT="echo takeip-pre ; false"
EOF

required_result 1 "takeip-pre"
simple_test
