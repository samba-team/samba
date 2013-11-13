#!/usr/bin/env python

from ctdb_takeover import Cluster, Node, process_args

process_args()

addresses10 = ['10.4.20.%d' % n for n in range(154, 168)]
addresses172a = ['172.20.106.%d' % n for n in range(110, 124)]
addresses172b = ['172.20.107.%d' % n for n in range(110, 117)]

c = Cluster()

#for i in range(7):
#    c.add_node(Node([addresses10, addresses172]))


for i in range(4):
    c.add_node(Node([addresses172a, addresses172b]))
for i in range(3):
    c.add_node(Node(addresses10))

c.recover()

c.random_iterations()
