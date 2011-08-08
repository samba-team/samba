#!/usr/bin/env python

# 1 IP group, to test backward compatibility of LCP2 algorithm.  16
# addresses across 4 nodes.

from ctdb_takeover import Cluster, Node, process_args

process_args()

addresses1 = ['192.168.1.%d' % n for n in range(1, 17)]

# Try detecting imbalance with square root of number of nodes?  Or
# just with a parameter indicating how unbalanced you're willing to
# accept...

c = Cluster()

for i in range(4):
    c.add_node(Node(addresses1))

c.recover()

c.random_iterations()
