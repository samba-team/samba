#!/usr/bin/env python

# 2 IP groups, across 2 nodes, with each group on different
# interfaces.  4 addresses per group.  A nice little canonical 2 node
# configuration.

from ctdb_takeover import Cluster, Node, process_args

process_args()

addresses1 = ['192.168.1.%d' % n for n in range(1, 5)]
addresses2 = ['192.168.2.%d' % n for n in range(1, 5)]

# Try detecting imbalance with square root of number of nodes?  Or
# just with a parameter indicating how unbalanced you're willing to
# accept...

c = Cluster()

for i in range(2):
    c.add_node(Node([addresses1, addresses2]))

c.recover()

c.random_iterations()
