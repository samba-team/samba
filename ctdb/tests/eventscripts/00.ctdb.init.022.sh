#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "Check public IP dropping, 1 assigned"

setup_ctdb

ctdb_get_1_public_address |
while read dev ip bits ; do
    ip addr add "${ip}/${bits}" dev "$dev"

    ok <<EOF
Removing public address ${ip}/${bits} from device ${dev}
EOF

    simple_test
done
