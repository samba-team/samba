#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "Release 1 IP, all 10 connections kills fail"

setup_ctdb

ctdb_get_1_public_address |
while read dev ip bits ; do
	ip addr add "${ip}/${bits}" dev "$dev"

	setup_tcp_connections 0

	count=10
	setup_tcp_connections_unkillable $count \
					 "$ip" 445 10.254.254.0 43210

	ok <<EOF
Killed 0/$count TCP connections to released IP 10.0.0.3
Remaining connections:
  10.0.0.3:445 10.254.254.1:43211
  10.0.0.3:445 10.254.254.2:43212
  10.0.0.3:445 10.254.254.3:43213
  10.0.0.3:445 10.254.254.4:43214
  10.0.0.3:445 10.254.254.5:43215
  10.0.0.3:445 10.254.254.6:43216
  10.0.0.3:445 10.254.254.7:43217
  10.0.0.3:445 10.254.254.8:43218
  10.0.0.3:445 10.254.254.9:43219
  10.0.0.3:445 10.254.254.10:43220
EOF

    simple_test $dev $ip $bits
done
