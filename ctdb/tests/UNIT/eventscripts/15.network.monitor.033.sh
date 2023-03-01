#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "Ping and DNS checks, nameservers + ping timeout"

setup

setup_script_options <<EOF
CTDB_MONITOR_HOSTS="ping:192.168.123.45 dns:foo.example.com ns:bar.example.com:2:3"
EOF

timeout_trigger "host bar.example.com 192.168.53.2"
set_ping_fail "192.168.53.2"

ok_null
simple_test

ok <<EOF
WARNING: Host check ns:bar.example.com@192.168.53.2: fail count 2 >= threshold 2
Command timed out: host bar.example.com 192.168.53.2
PING 192.168.53.2 (192.168.53.2) 56(84) bytes of data.

--- 192.168.53.2 ping statistics ---
1 packets transmitted, 0 received, 100% packet loss, time 0ms
rtt min/avg/max/mdev = 0.789/0.789/0.789/0.000 ms
EOF
simple_test

required_result 1 <<EOF
ERROR: Host check ns:bar.example.com@192.168.53.2: fail count 3 >= threshold 3
Command timed out: host bar.example.com 192.168.53.2
PING 192.168.53.2 (192.168.53.2) 56(84) bytes of data.

--- 192.168.53.2 ping statistics ---
1 packets transmitted, 0 received, 100% packet loss, time 0ms
rtt min/avg/max/mdev = 0.789/0.789/0.789/0.000 ms
EOF
simple_test
