#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "Ping and DNS checks, all OK"

setup

setup_script_options <<EOF
CTDB_MONITOR_HOSTS="ping:192.168.123.45 dns:foo.example.com ns:bar.example.com"
EOF

ok_null
simple_test
