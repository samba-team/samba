#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "ctdb helpers"

shellcheck_test \
	"${CTDB_SCRIPTS_TOOLS_HELPER_DIR}/ctdb_lvs" \
	"${CTDB_SCRIPTS_TOOLS_HELPER_DIR}/ctdb_natgw"
