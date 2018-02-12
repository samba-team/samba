#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "configured"

setup "10.1.1.201" "eth0" <<EOF
EOF

ipvsadm -A -t "$CTDB_LVS_PUBLIC_IP" -s lc -p 1999999
ipvsadm -A -u "$CTDB_LVS_PUBLIC_IP" -s lc -p 1999999
ip addr add $CTDB_LVS_PUBLIC_IP/32 dev lo

ok_null
simple_test

check_ipvsadm NULL
check_lvs_ip NULL
