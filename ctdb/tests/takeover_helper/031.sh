#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "3 nodes, all ok, IPs defined on 2, IPs all unassigned"

setup_ctdbd <<EOF
NODEMAP
0       192.168.20.41   0x0     CURRENT RECMASTER
1       192.168.20.42   0x0
2       192.168.20.43   0x0

IFACES
:Name:LinkStatus:References:
:eth2:1:2:
:eth1:1:4:

PUBLICIPS
10.0.0.31  -1 0,2
10.0.0.32  -1 0,2
10.0.0.33  -1 0,2
10.0.0.34  -1 0,2
EOF

HELPER_DEBUGLEVEL=INFO
ok <<EOF
Fetched public IPs from node 0
Fetched public IPs from node 1
Fetched public IPs from node 2
Fetched public IPs from node 0
Fetched public IPs from node 2
 10.0.0.34 -> 0 [+0]
 10.0.0.33 -> 2 [+0]
 10.0.0.31 -> 0 [+14884]
 10.0.0.32 -> 2 [+16129]
RELEASE_IP 10.0.0.34 succeeded on 1 nodes
RELEASE_IP 10.0.0.33 succeeded on 1 nodes
RELEASE_IP 10.0.0.32 succeeded on 1 nodes
RELEASE_IP 10.0.0.31 succeeded on 1 nodes
TAKEOVER_IP 10.0.0.34 succeeded on node 0
TAKEOVER_IP 10.0.0.33 succeeded on node 2
TAKEOVER_IP 10.0.0.32 succeeded on node 2
TAKEOVER_IP 10.0.0.31 succeeded on node 0
IPREALLOCATED succeeded on 3 nodes
EOF
test_takeover_helper

required_result 0 <<EOF
Public IPs on ALL nodes
10.0.0.31 0
10.0.0.32 2
10.0.0.33 2
10.0.0.34 0
EOF
test_ctdb_ip_all
