#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "base scripts"

shellcheck_test \
	"${CTDB_SCRIPTS_BASE}/ctdb-crash-cleanup.sh" \
	"${CTDB_SCRIPTS_BASE}/debug-hung-script.sh" \
	"${CTDB_SCRIPTS_BASE}/debug_locks.sh" \
	"${CTDB_SCRIPTS_BASE}/nfs-linux-kernel-callout" \
	"${CTDB_SCRIPTS_BASE}/statd-callout"
