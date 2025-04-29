#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

if [ -z "$CTDB_STATD_CALLOUT_SHARED_STORAGE" ]; then
	CTDB_STATD_CALLOUT_SHARED_STORAGE="persistent_db"
fi
mode="$CTDB_STATD_CALLOUT_SHARED_STORAGE"

define_test "${mode} - add-client on different nodes, take 1 IP, notify on both"

setup "$mode"

ok_null
simple_test_event "startup"
ctdb_get_1_public_address |
	while read -r _ sip _; do
		simple_test_event "takeip" "$sip"
	done
simple_test_event "add-client" "192.168.123.45"
simple_test_event "update"

ctdb_set_pnn 1

ok_null
simple_test_event "startup"
ctdb_get_1_public_address |
	while read -r _ sip _; do
		simple_test_event "takeip" "$sip"
	done
simple_test_event "add-client" "192.168.123.46"
simple_test_event "update"

ctdb_set_pnn 0

check_statd_callout_smnotify

ctdb_set_pnn 1

check_statd_callout_smnotify

check_shared_storage_statd_state
