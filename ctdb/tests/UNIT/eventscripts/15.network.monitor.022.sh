#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "Ping and DNS checks, DNS warning/error"

setup

setup_script_options <<EOF
CTDB_MONITOR_HOSTS="ping:192.168.123.45 dns:foo.example.com:2:3 ns:bar.example.com"
EOF

set_host_data "foo.example.com=NXDOMAIN"

ok_null
simple_test

ok <<EOF
WARNING: Host check dns:foo.example.com: fail count 2 >= threshold 2
Host foo.example.com not found: 3(NXDOMAIN)
EOF
simple_test

required_result 1 <<EOF
ERROR: Host check dns:foo.example.com: fail count 3 >= threshold 3
Host foo.example.com not found: 3(NXDOMAIN)
EOF
simple_test
