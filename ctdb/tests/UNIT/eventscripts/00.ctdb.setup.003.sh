#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "setup, known and unknown tunables in config"

setup

setup_tunable_config <<EOF
MonitorInterval=5
UnknownMagic=0
EOF

required_result 1 <<EOF
Set MonitorInterval to 5
Unable to set tunable variable 'UnknownMagic'
Invalid tunable: UnknownMagic=0
Aborting setup due to invalid configuration - fix typos, remove unknown tunables
EOF

simple_test
