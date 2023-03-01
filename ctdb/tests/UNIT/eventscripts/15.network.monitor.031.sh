#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "Ping and DNS checks, nameserver warning"

setup

setup_script_options <<EOF
CTDB_MONITOR_HOSTS="ping:192.168.123.45 dns:foo.example.com ns:bar.example.com"
EOF

set_host_data "bar.example.com@192.168.53.1=ETIMEDOUT"

ok <<EOF
WARNING: Host check ns:bar.example.com@192.168.53.1: fail count 1 >= threshold 1
;; communications error to 192.168.53.1#53: timed out
;; communications error to 192.168.53.1#53: timed out
;; no servers could be reached
EOF
simple_test

ok_null
simple_test

setup_date_one_hour_from_now

ok <<EOF
WARNING: Host check ns:bar.example.com@192.168.53.1: fail count 3 >= threshold 1
;; communications error to 192.168.53.1#53: timed out
;; communications error to 192.168.53.1#53: timed out
;; no servers could be reached
EOF
simple_test
