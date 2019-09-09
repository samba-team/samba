#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "2 x add-client to different nodes, notify on 1"

setup

ok_null
simple_test_event "add-client" "192.168.123.45"
simple_test_event "update"

ctdb_set_pnn 1

ok_null
simple_test_event "add-client" "192.168.123.46"
simple_test_event "update"

ctdb_set_pnn 0

check_statd_callout_smnotify "192.168.123.45"

ctdb_set_pnn 1

check_ctdb_tdb_statd_state "192.168.123.46"
