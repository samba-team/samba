#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "nodes in config, this is master"

setup "10.1.1.201" "eth0" <<EOF
192.168.1.1	master
192.168.1.2
192.168.1.3
EOF

ok_null
simple_test

check_ipvsadm <<EOF
TCP  10.1.1.201:0 lc persistent 1999999
  -> 127.0.0.1:0                  Local   1      0          0         
  -> 192.168.1.2:0                Route   1      0          0         
  -> 192.168.1.3:0                Route   1      0          0         
UDP  10.1.1.201:0 lc persistent 1999999
  -> 127.0.0.1:0                  Local   1      0          0         
  -> 192.168.1.2:0                Route   1      0          0         
  -> 192.168.1.3:0                Route   1      0          0         
EOF

check_lvs_ip global
