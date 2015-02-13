#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "2 x add-client to different nodes, notify on both"

setup_ctdb

FAKE_DATE_OUTPUT="1234565789"

ok_null
simple_test_event "add-client" "192.168.123.45"
simple_test_event "update"

FAKE_CTDB_PNN=1

ok_null
simple_test_event "add-client" "192.168.123.46"
simple_test_event "update"

FAKE_CTDB_PNN=0

check_statd_callout_smnotify "192.168.123.45"

FAKE_CTDB_PNN=1

check_statd_callout_smnotify "192.168.123.46"

check_ctdb_tdb_statd_state
