#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "setup, known and obsolete tunables in config"

setup

setup_tunable_config <<EOF
MonitorInterval=5
EventScriptUnhealthyOnTimeout=0
EOF

required_result 0 <<EOF
Setting obsolete tunable variable 'EventScriptUnhealthyOnTimeout'
Set EventScriptUnhealthyOnTimeout to 0
Set MonitorInterval to 5
EOF

simple_test
