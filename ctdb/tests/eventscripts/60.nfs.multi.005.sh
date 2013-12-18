#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "takeip, take reconfigure lock, monitor -> reconfigure, replay disabled"

setup_nfs

public_address=$(ctdb_get_1_public_address)

err=""

ok_null

simple_test_event "takeip" $public_address

ctdb_fake_scriptstatus -8 "DISABLED" "$err"

eventscript_call ctdb_reconfigure_take_lock

ok <<EOF
Replaying previous status for this script due to reconfigure...
[Replay of DISABLED scriptstatus - note incorrect return code.] $err
EOF

simple_test_event "monitor"
