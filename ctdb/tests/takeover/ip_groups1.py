#!/usr/bin/env python

# 2 IP groups, both on the same 5 nodes, with each group on different
# interfaces/VLANs.  One group has many more addresses to test how
# well an "imbalanced" configuration will balance...

from ctdb_takeover import Cluster, Node, process_args

process_args()

addresses20 = ['192.168.20.%d' % n for n in range(1, 13)]
addresses128 = ['192.168.128.%d' % n for n in range(1, 5)]

c = Cluster()

for i in range(5):
    c.add_node(Node([addresses20, addresses128]))

#for i in range(3):
#    c.add_node(Node([addresses20]))


c.recover()

c.random_iterations()
