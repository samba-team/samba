#!/usr/bin/env python3
#
# Filter out arcs in a dotty graph that are at or below a certain
# node.  This is useful for visualising parts of the dependency graph.
#

# Command line stuff

from __future__ import print_function
import sys
import re

if len(sys.argv) != 2:
    print('Usage: depfilter.py NODE')
    sys.exit(1)

top = sys.argv[1]

# Read in dot file

lines = sys.stdin.readlines()

graph = {}

for arc in lines[1:-1]:
    match = re.search('"(.*)" -> "(.*)"', arc)
    n1, n2 = match.group(1), match.group(2)
    if n1 not in graph:
        graph[n1] = []
    graph[n1].append(n2)

# Create subset of 'graph' rooted at 'top'

subgraph = {}


def add_deps(node):
    if node in graph and node not in subgraph:
        subgraph[node] = graph[node]
        for n in graph[node]:
            add_deps(n)


add_deps(top)

# Generate output

print(lines[0], end=' ')

for key, value in subgraph.items():
    for n in value:
        print('\t"%s" -> "%s"' % (key, n))

print(lines[-1], end=' ')
