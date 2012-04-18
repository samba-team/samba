#!/usr/bin/env python

# This is an example showing a current SONAS configuration with 3
# interface node and a management node.  When run with deterministic
# IPs there are gratuitous IP reassignments.

from ctdb_takeover import Cluster, Node, process_args

process_args()

addresses = ['A', 'B', 'C', 'D', 'E', 'F', 'G']

c = Cluster()

for i in range(3):
    c.add_node(Node(addresses))

c.add_node(Node([]))

c.recover()

c.random_iterations()
