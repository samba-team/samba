#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "reconfigure (synthetic), twice"
# This checks that the lock is released...

setup_nfs

public_address=$(ctdb_get_1_public_address)

err=""

ok <<EOF
Reconfiguring service "nfs"...
EOF

simple_test_event "reconfigure"
simple_test_event "reconfigure"
