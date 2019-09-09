#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "Memory check (default), warning situation"

setup

set_mem_usage 100 100
ok <<EOF
WARNING: System memory utilization 100% >= threshold 80%
EOF
simple_test
