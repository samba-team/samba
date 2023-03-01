#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "Ping and DNS checks, ping warning"

setup

setup_script_options <<EOF
CTDB_MONITOR_HOSTS="ping:192.168.123.45 dns:foo.example.com ns:bar.example.com"
EOF

set_ping_fail "192.168.123.45"

ok <<EOF
WARNING: Host check ping:192.168.123.45: fail count 1 >= threshold 1
PING 192.168.123.45 (192.168.123.45) 56(84) bytes of data.

--- 192.168.123.45 ping statistics ---
1 packets transmitted, 0 received, 100% packet loss, time 0ms
rtt min/avg/max/mdev = 0.789/0.789/0.789/0.000 ms
EOF
simple_test

ok_null
simple_test

setup_date_one_hour_from_now

ok <<EOF
WARNING: Host check ping:192.168.123.45: fail count 3 >= threshold 1
PING 192.168.123.45 (192.168.123.45) 56(84) bytes of data.

--- 192.168.123.45 ping statistics ---
1 packets transmitted, 0 received, 100% packet loss, time 0ms
rtt min/avg/max/mdev = 0.789/0.789/0.789/0.000 ms
EOF
simple_test
