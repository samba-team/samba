#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "Ping and DNS checks, DNS warning"

setup

setup_script_options <<EOF
CTDB_MONITOR_HOSTS="ping:192.168.123.45 dns:foo.example.com ns:bar.example.com"
EOF

set_host_data "foo.example.com=NXDOMAIN"

ok <<EOF
WARNING: Host check dns:foo.example.com: fail count 1 >= threshold 1
Host foo.example.com not found: 3(NXDOMAIN)
EOF
simple_test

ok_null
simple_test

setup_date_one_hour_from_now

ok <<EOF
WARNING: Host check dns:foo.example.com: fail count 3 >= threshold 1
Host foo.example.com not found: 3(NXDOMAIN)
EOF
simple_test
