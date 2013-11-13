#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "Release 1 IP, 10 connections killed OK"

setup_ctdb

ctdb_get_1_public_address |
while read dev ip bits ; do
    ip addr add "${ip}/${bits}" dev "$dev"

    # Setup 10 fake connections...
    count=10
    out=""
    nl="
"
    i=0
    while [ $i -lt $count ] ; do
	echo "${ip}:445 10.254.254.1:1230${i}"
	# Expected output for killing this connection
	out="${out}${out:+${nl}}Killing TCP connection 10.254.254.1:1230${i} ${ip}:445"
	i=$(($i + 1))
    done >"$FAKE_NETSTAT_TCP_ESTABLISHED_FILE"

    ok <<EOF
$out
Killed $count TCP connections to released IP $ip
EOF

    simple_test $dev $ip $bits
done
