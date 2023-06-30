#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

if [ -z "$CTDB_STATD_CALLOUT_SHARED_STORAGE" ]; then
	CTDB_STATD_CALLOUT_SHARED_STORAGE="persistent_db"
fi
mode="$CTDB_STATD_CALLOUT_SHARED_STORAGE"

define_test "${mode} - 2 x add-client to different nodes, notify on both"

setup "$mode"

ok_null
simple_test_event "startup"
simple_test_event "add-client" "192.168.123.45"
simple_test_event "update"

ctdb_set_pnn 1

ok_null
simple_test_event "startup"
simple_test_event "add-client" "192.168.123.46"
simple_test_event "update"

ctdb_set_pnn 0

check_statd_callout_smnotify "192.168.123.45"

ctdb_set_pnn 1

check_statd_callout_smnotify "192.168.123.46"

check_shared_storage_statd_state
