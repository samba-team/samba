#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "Release 1 IP, 10 connections killed, 3 fail"

setup_ctdb

ctdb_get_1_public_address |
while read dev ip bits ; do
	ip addr add "${ip}/${bits}" dev "$dev"

	count=10

	setup_tcp_connections $count \
			      "$ip" 445 10.254.254.0 12300

	setup_tcp_connections_unkillable 3 \
					 "$ip" 445 10.254.254.0 43210

	ok <<EOF
Killed 10/13 TCP connections to released IP 10.0.0.3
Remaining connections:
  10.0.0.3:445 10.254.254.1:43211
  10.0.0.3:445 10.254.254.2:43212
  10.0.0.3:445 10.254.254.3:43213
EOF

	simple_test $dev $ip $bits
done
