#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "Release 1 IP, 10 connections killed OK"

setup_ctdb

ctdb_get_1_public_address |
while read dev ip bits ; do
	ip addr add "${ip}/${bits}" dev "$dev"

	count=10
	setup_tcp_connections $count \
			      "$ip" 445 10.254.254.0 12300

	ok <<EOF
Killed ${count}/${count} TCP connections to released IP $ip
EOF

	simple_test $dev $ip $bits
done
