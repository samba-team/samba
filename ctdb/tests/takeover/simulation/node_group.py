#!/usr/bin/env python

# This demonstrates a node group configurations.
#
# Node groups can be defined with the syntax "-g N@IP0,IP1-IP2,IP3".
# This says to create a group of N nodes with IPs IP0, IP1, ..., IP2,
# IP3.  Run it with deterministic IPs causes lots of gratuitous IP
# reassignments.  Running with --nd fixes this.

import ctdb_takeover
import sys
from optparse import make_option
import string

ctdb_takeover.process_args([
        make_option("-g", "--group",
                    action="append", type="string", dest="groups",
                    help="define a node group using N@IPs syntax"),
        ])

def expand_range(r):
    sr = r.split("-", 1)
    if len(sr) == 2:
        all = string.ascii_uppercase + string.ascii_lowercase
        sr = list(all[all.index(sr[0]):all.index(sr[1])+1])
    return sr
            
def add_node_group(s):
    (count, ips_str) = s.split("@", 1)
    ips = [i for r in ips_str.split(",") \
               for i in expand_range(r) if r != ""]
    for i in range(int(count)):
        c.add_node(ctdb_takeover.Node(ips))

c = ctdb_takeover.Cluster()

if ctdb_takeover.options.groups is None:
    print "Error: no node groups defined."
    sys.exit(1)

for g in ctdb_takeover.options.groups:
    add_node_group(g)

c.recover()

c.random_iterations()
