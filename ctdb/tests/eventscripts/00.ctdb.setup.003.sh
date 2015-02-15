#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "setup, known and unknown tunables in config"

setup_ctdb

setup_config <<EOF
CTDB_SET_MonitorInterval=5
CTDB_SET_UnknownMagic=0
EOF

required_result 1 <<EOF
Set MonitorInterval to 5
Unable to set tunable variable 'UnknownMagic'
Failed to set CTDB tunables
EOF

simple_test
