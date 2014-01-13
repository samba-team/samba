#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "Release 1 IP, 10 connections killed, 1 fails"

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

    # Note that the fake TCP killing done by the "ctdb killtcp" stub
    # can only kill conections in the file, so killing this connection
    # will never succeed so it will look like a time out.
    FAKE_NETSTAT_TCP_ESTABLISHED="${ip}:445|10.254.254.1:43210"

    ok <<EOF
Killing TCP connection 10.254.254.1:43210 ${ip}:445
$out
Waiting for 1 connections to be killed for IP ${ip}
Waiting for 1 connections to be killed for IP ${ip}
Waiting for 1 connections to be killed for IP ${ip}
Timed out killing tcp connections for IP $ip (1 remaining)
EOF

    simple_test $dev $ip $bits
done
