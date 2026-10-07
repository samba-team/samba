#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "Redundant update of IP on VLAN, VNN interface is __none__"

setup

ctdb_get_1_public_address |
	while read -r dev ip bits; do
		# ip prints the interface name as "${dev}@${realiface}"
		realiface="real0"
		ip link add link "$realiface" name "$dev" type vlan id 11
		ip link set "$dev" up

		ok_null
		simple_test_event "takeip" "$dev" "$ip" "$bits"

		ok <<EOF
WARNING: Public IP ${ip} hosted on interface ${dev} but VNN says __none__
Redundant "updateip" - ${ip} already on ${dev}
EOF
		simple_test_event "updateip" "__none__" "$dev" "$ip" "$bits"
	done
