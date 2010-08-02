#!/usr/bin/env python

# This is a contrived example that makes the balancing algorithm fail
# for nondeterministic IPs (run with "-dv --nd" to see the failure).

from ctdb_takeover import Cluster, Node, process_args

process_args()

addresses1 = ['A', 'B', 'C', 'D']
addresses2 = ['B', 'E', 'F']

c = Cluster()

for i in range(2):
    c.add_node(Node(addresses1))

c.add_node(Node(addresses2))

c.recover()

c.unhealthy(1)
c.recover()
c.healthy(1)
c.recover()
