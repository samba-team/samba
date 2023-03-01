#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "Ping and DNS checks, nameservers warning/error"

setup

setup_script_options <<EOF
CTDB_MONITOR_HOSTS="ping:192.168.123.45 dns:foo.example.com ns:bar.example.com:2:3"
EOF

set_host_data "bar.example.com@192.168.53.1=ETIMEDOUT"

ok_null
simple_test

ok <<EOF
WARNING: Host check ns:bar.example.com@192.168.53.1: fail count 2 >= threshold 2
;; communications error to 192.168.53.1#53: timed out
;; communications error to 192.168.53.1#53: timed out
;; no servers could be reached
EOF
simple_test

required_result 1 <<EOF
ERROR: Host check ns:bar.example.com@192.168.53.1: fail count 3 >= threshold 3
;; communications error to 192.168.53.1#53: timed out
;; communications error to 192.168.53.1#53: timed out
;; no servers could be reached
EOF
simple_test
