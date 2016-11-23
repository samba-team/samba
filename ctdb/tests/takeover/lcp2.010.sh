#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "2 disjoint groups of nodes/addresses, a node becomes healthy"

# This illustrates a bug in LCP2 when the the only candidate for a
# source node is chosen to be the "most imbalanced" node.  This means
# that nodes in the smaller group aren't necessarily (depends on sort
# order and addresses used) considered as candidates.  If the larger
# group has 6 addresses then the "necessarily" goes away and the
# smaller group won't be rebalanced.

export CTDB_TEST_LOGLEVEL=ERR

required_result <<EOF
192.168.209.102 3
192.168.209.101 2
192.168.140.4 1
192.168.140.3 1
192.168.140.2 0
192.168.140.1 0
EOF

simple_test 0,0,0,0 <<EOF
192.168.140.1		0	0,1
192.168.140.2		0	0,1
192.168.140.3		1	0,1
192.168.140.4		1	0,1
192.168.209.101		2	2,3
192.168.209.102		2	2,3
EOF
