#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "Release 1 IP, all 10 connections kills fail"

setup

ctdb_get_1_public_address |
while read dev ip bits ; do
	ok_null
	simple_test_event "takeip" $dev $ip $bits

	setup_tcp_connections 0

	count=10
	setup_tcp_connections_unkillable $count \
					 "$ip" 445 10.254.254.0 43210

	ok <<EOF
Killed 0/$count TCP connections to released IP ${ip}
Remaining connections:
  ${ip}:445 10.254.254.1:43211
  ${ip}:445 10.254.254.2:43212
  ${ip}:445 10.254.254.3:43213
  ${ip}:445 10.254.254.4:43214
  ${ip}:445 10.254.254.5:43215
  ${ip}:445 10.254.254.6:43216
  ${ip}:445 10.254.254.7:43217
  ${ip}:445 10.254.254.8:43218
  ${ip}:445 10.254.254.9:43219
  ${ip}:445 10.254.254.10:43220
EOF

    simple_test_event "releaseip"  $dev $ip $bits
done
