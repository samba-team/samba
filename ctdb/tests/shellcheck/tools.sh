#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "tools"

shellcheck_test \
	"${CTDB_SCRIPTS_TOOLS_BIN_DIR}/onnode" \
	"${CTDB_SCRIPTS_TOOLS_BIN_DIR}/ctdb_diagnostics"
