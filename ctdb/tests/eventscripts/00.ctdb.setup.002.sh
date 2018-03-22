#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "setup, known tunables in config"

setup

setup_tunable_config <<EOF
MonitorInterval=5
TDBMutexEnabled=0
EOF

required_result 0 <<EOF
Set MonitorInterval to 5
Set TDBMutexEnabled to 0
EOF

simple_test
