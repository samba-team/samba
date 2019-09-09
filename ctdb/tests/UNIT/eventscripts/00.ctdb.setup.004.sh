#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "setup, known and obsolete tunables in config"

setup

setup_tunable_config <<EOF
MonitorInterval=5
EventScriptUnhealthyOnTimeout=0
EOF

required_result 0 <<EOF
Set MonitorInterval to 5
Setting obsolete tunable variable 'EventScriptUnhealthyOnTimeout'
Set EventScriptUnhealthyOnTimeout to 0
EOF

simple_test
