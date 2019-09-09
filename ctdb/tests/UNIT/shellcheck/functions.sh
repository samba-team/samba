#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "functions file"

shellcheck_test -s sh "${CTDB_SCRIPTS_BASE}/functions"
