#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "Memory check (custom, both), good situation"

setup

setup_script_options <<EOF
CTDB_MONITOR_MEMORY_USAGE="80:90"
EOF

ok_null
simple_test
