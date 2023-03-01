#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "Ping and DNS checks, multiple warnings, errors, recoveries"

setup

setup_script_options <<EOF
CTDB_MONITOR_HOSTS="ping:192.168.123.45:1:5 dns:foo.example.com:1:7 ns:bar.example.com:1:3"
EOF

set_ping_fail "192.168.123.45"
set_host_data "foo.example.com=ETIMEDOUT"
timeout_trigger "host bar.example.com 192.168.53.3"

ok <<EOF
WARNING: Host check ping:192.168.123.45: fail count 1 >= threshold 1
PING 192.168.123.45 (192.168.123.45) 56(84) bytes of data.

--- 192.168.123.45 ping statistics ---
1 packets transmitted, 0 received, 100% packet loss, time 0ms
rtt min/avg/max/mdev = 0.789/0.789/0.789/0.000 ms
WARNING: Host check dns:foo.example.com: fail count 1 >= threshold 1
;; communications error to #53: timed out
;; communications error to #53: timed out
;; no servers could be reached
WARNING: Host check ns:bar.example.com@192.168.53.3: fail count 1 >= threshold 1
Command timed out: host bar.example.com 192.168.53.3
EOF
simple_test

ok <<EOF
WARNING: Host check ping:192.168.123.45: fail count 2 >= threshold 1
WARNING: Host check dns:foo.example.com: fail count 2 >= threshold 1
WARNING: Host check ns:bar.example.com@192.168.53.3: fail count 2 >= threshold 1
EOF
simple_test

required_result 1 <<EOF
WARNING: Host check ping:192.168.123.45: fail count 3 >= threshold 1
WARNING: Host check dns:foo.example.com: fail count 3 >= threshold 1
ERROR: Host check ns:bar.example.com@192.168.53.3: fail count 3 >= threshold 3
Command timed out: host bar.example.com 192.168.53.3
EOF
simple_test

timeout_clear

ok <<EOF
WARNING: Host check ping:192.168.123.45: fail count 4 >= threshold 1
WARNING: Host check dns:foo.example.com: fail count 4 >= threshold 1
NOTICE: Host check ns:bar.example.com@192.168.53.3: no longer failing
EOF
simple_test

required_result 1 <<EOF
ERROR: Host check ping:192.168.123.45: fail count 5 >= threshold 5
PING 192.168.123.45 (192.168.123.45) 56(84) bytes of data.

--- 192.168.123.45 ping statistics ---
1 packets transmitted, 0 received, 100% packet loss, time 0ms
rtt min/avg/max/mdev = 0.789/0.789/0.789/0.000 ms
WARNING: Host check dns:foo.example.com: fail count 5 >= threshold 1
EOF
simple_test

set_ping_fail

ok <<EOF
NOTICE: Host check ping:192.168.123.45: no longer failing
WARNING: Host check dns:foo.example.com: fail count 6 >= threshold 1
EOF
simple_test

required_result 1 <<EOF
ERROR: Host check dns:foo.example.com: fail count 7 >= threshold 7
;; communications error to #53: timed out
;; communications error to #53: timed out
;; no servers could be reached
EOF
simple_test

set_host_data

ok <<EOF
NOTICE: Host check dns:foo.example.com: no longer failing
EOF
simple_test

ok_null
simple_test
