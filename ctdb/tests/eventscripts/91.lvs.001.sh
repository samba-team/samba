#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "sanity check ipvsadm stub"

setup<<EOF
EOF

check_ipvsadm NULL

ipvsadm -A -u 10.1.1.201 -s lc -p 1999999
ipvsadm -a -u 10.1.1.201 -r 192.168.1.3 -g
ipvsadm -a -u 10.1.1.201 -r 192.168.1.1 -g
ipvsadm -a -u 10.1.1.201 -r 192.168.1.2:0 -g
ipvsadm -a -u 10.1.1.201 -r 127.0.0.1

check_ipvsadm <<EOF
UDP  10.1.1.201:0 lc persistent 1999999
  -> 127.0.0.1:0                  Local   1      0          0         
  -> 192.168.1.1:0                Route   1      0          0         
  -> 192.168.1.2:0                Route   1      0          0         
  -> 192.168.1.3:0                Route   1      0          0         
EOF

ipvsadm -A -t 10.1.1.201 -s lc -p 1999999
ipvsadm -a -t 10.1.1.201 -r 192.168.1.3 -g
ipvsadm -a -t 10.1.1.201 -r 192.168.1.1 -g
ipvsadm -a -t 10.1.1.201 -r 192.168.1.2:0 -g

check_ipvsadm <<EOF
TCP  10.1.1.201:0 lc persistent 1999999
  -> 192.168.1.1:0                Route   1      0          0         
  -> 192.168.1.2:0                Route   1      0          0         
  -> 192.168.1.3:0                Route   1      0          0         
UDP  10.1.1.201:0 lc persistent 1999999
  -> 127.0.0.1:0                  Local   1      0          0         
  -> 192.168.1.1:0                Route   1      0          0         
  -> 192.168.1.2:0                Route   1      0          0         
  -> 192.168.1.3:0                Route   1      0          0         
EOF

ipvsadm -D -u 10.1.1.201

check_ipvsadm <<EOF
TCP  10.1.1.201:0 lc persistent 1999999
  -> 192.168.1.1:0                Route   1      0          0         
  -> 192.168.1.2:0                Route   1      0          0         
  -> 192.168.1.3:0                Route   1      0          0         
EOF

ipvsadm -D -t 10.1.1.201

check_ipvsadm NULL
