#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "toggle state of 2 interfaces"

setup_ctdbd <<EOF
NODEMAP
0       192.168.20.41   0x0     CURRENT RECMASTER
1       192.168.20.42   0x0
2       192.168.20.43   0x0

IFACES
:Name:LinkStatus:References:
:eth2:1:2:
:eth1:0:4:
EOF

# eth1: down -> down

ok_null
simple_test eth1 down

ok <<EOF
Interfaces on node 0
name:eth2 link:up references:2
name:eth1 link:down references:4
EOF
simple_test_other ifaces

# eth1: down -> up

ok_null
simple_test eth1 up

ok <<EOF
Interfaces on node 0
name:eth2 link:up references:2
name:eth1 link:up references:4
EOF
simple_test_other ifaces

# eth1: up -> down
ok_null
simple_test eth1 down

ok <<EOF
Interfaces on node 0
name:eth2 link:up references:2
name:eth1 link:down references:4
EOF
simple_test_other ifaces

# eth2: up -> down

ok_null
simple_test eth2 down

ok <<EOF
Interfaces on node 0
name:eth2 link:down references:2
name:eth1 link:down references:4
EOF
simple_test_other ifaces

# eth1: down -> up

ok_null
simple_test eth1 up

ok <<EOF
Interfaces on node 0
name:eth2 link:down references:2
name:eth1 link:up references:4
EOF
simple_test_other ifaces
