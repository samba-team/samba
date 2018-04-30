#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "Filesystem use check, error situation, default checks enabled"

setup

set_fs_usage 100
ok <<EOF
WARNING: Filesystem ${CTDB_DBDIR_BASE} utilization 100% >= threshold 90%
EOF
simple_test
