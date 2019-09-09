#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "single add-client, notify"

setup

ok_null
simple_test_event "add-client" "192.168.123.45"
simple_test_event "update"

check_ctdb_tdb_statd_state "192.168.123.45"

check_statd_callout_smnotify "192.168.123.45"

check_ctdb_tdb_statd_state
