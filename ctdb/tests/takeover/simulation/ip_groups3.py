#!/usr/bin/env python

# 4 IP groups, across 10 nodes, with each group on different
# interfaces/VLANs.  80 addresses in total but not evenly balanced, to
# help check some of the more extreme behaviour.

from ctdb_takeover import Cluster, Node, process_args

process_args()

addresses1 = ['192.168.1.%d' % n for n in range(1, 41)]
addresses2 = ['192.168.2.%d' % n for n in range(1, 21)]
addresses3 = ['192.168.3.%d' % n for n in range(1, 11)]
addresses4 = ['192.168.4.%d' % n for n in range(1, 11)]

# Try detecting imbalance with square root of number of nodes?  Or
# just with a parameter indicating how unbalanced you're willing to
# accept...

c = Cluster()

for i in range(10):
    c.add_node(Node([addresses1, addresses2, addresses3, addresses4]))

c.recover()

c.random_iterations()
