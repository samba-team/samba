#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "event scripts"

shellcheck_test "${CTDB_SCRIPTS_BASE}/events.d"/[0-9][0-9].*
