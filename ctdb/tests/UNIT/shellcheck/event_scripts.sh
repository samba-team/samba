#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "event scripts"

shellcheck_test "${CTDB_SCRIPTS_DATA_DIR}/events/"*/[0-9][0-9].*
