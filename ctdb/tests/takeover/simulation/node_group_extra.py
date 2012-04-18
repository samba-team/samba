#!/usr/bin/env python

# This example demonstrates a node group configuration.  Is it meant
# to be the same as node_group_simple.py, but with a couple of nodes
# added later, so they are listed after the management node.

# When run with deterministic IPs (use "-d" to show the problem) it
# does many gratuitous IP reassignments.

from ctdb_takeover import Cluster, Node, process_args

process_args()

addresses1 = ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H'] + ['P', 'Q', 'R', 'S', 'T', 'U']
addresses2 = ['I', 'J', 'K', 'L']

c = Cluster()

for i in range(4):
    c.add_node(Node(addresses1))

for i in range(3):
    c.add_node(Node(addresses2))

c.add_node(Node([]))
c.add_node(Node(addresses1))
c.add_node(Node(addresses2))

c.recover()

c.random_iterations()
