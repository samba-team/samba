#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "missing nodes file"

setup_nodes <<EOF
192.168.20.41
192.168.20.42
192.168.20.43
EOF

f="${CTDB_BASE}/nodes"
rm -f "$f"

required_result 1 <<EOF
${TEST_DATE_STAMP}Failed to read nodes file "${f}"
EOF

simple_test
