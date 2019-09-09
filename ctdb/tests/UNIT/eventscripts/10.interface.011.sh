#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "Release 1 IP, 10 connections killed, 1 fails"

setup

ctdb_get_1_public_address |
while read dev ip bits ; do
	ok_null
	simple_test_event "takeip" $dev $ip $bits

	count=10
	setup_tcp_connections $count \
			      "$ip" 445 10.254.254.0 12300

	setup_tcp_connections_unkillable 1 \
					 "$ip" 445 10.254.254.0 43210

	ok <<EOF
Killed 10/11 TCP connections to released IP ${ip}
Remaining connections:
  ${ip}:445 10.254.254.1:43211
EOF

	simple_test_event "releaseip" $dev $ip $bits
done
