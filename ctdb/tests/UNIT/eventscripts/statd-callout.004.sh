#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

if [ -z "$CTDB_STATD_CALLOUT_SHARED_STORAGE" ]; then
	CTDB_STATD_CALLOUT_SHARED_STORAGE="persistent_db"
fi
mode="$CTDB_STATD_CALLOUT_SHARED_STORAGE"

define_test "${mode} - single add-client, notify"

setup "$mode"

ok_null
simple_test_event "startup"
simple_test_event "add-client" "192.168.123.45"
simple_test_event "update"

check_shared_storage_statd_state

check_statd_callout_smnotify

check_shared_storage_statd_state
