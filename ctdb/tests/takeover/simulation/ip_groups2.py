#!/usr/bin/env python

# 2 groups of addresses, combined into 1 pool so the checking
# algorithm doesn't know about the groups, across 2 nodes.

from ctdb_takeover import Cluster, Node, process_args

process_args()

addresses20 = ['192.168.20.%d' % n for n in range(1, 13)]
addresses21 = ['192.168.21.%d' % n for n in range(1, 5)]

c = Cluster()

for i in range(2):
    c.add_node(Node(addresses20 + addresses21))

c.recover()

c.random_iterations()
