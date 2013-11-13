#!/usr/bin/env python

# This example demonstrates a simple, sensible node group
# configuration.  When run with deterministic IPs (use "-d" to show
# the problem) it does many gratuitous IP reassignments.

from ctdb_takeover import Cluster, Node, process_args

process_args()

addresses1 = ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H']
addresses2 = ['I', 'J', 'K']

c = Cluster()

for i in range(4):
    c.add_node(Node(addresses1))

for i in range(3):
    c.add_node(Node(addresses2))

c.add_node(Node([]))

c.recover()

c.random_iterations()
