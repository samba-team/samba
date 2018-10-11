# Unix SMB/CIFS implementation. Tests for kcc.graph_utils routines
# Copyright (C) Andrew Bartlett 2015
#
# Written by Douglas Bagnall <douglas.bagnall@catalyst.net.nz>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

"""Tests for samba.kcc.graph_utils"""

import samba
import samba.tests
from samba.kcc.graph_utils import GraphError
from samba.kcc.graph_utils import (verify_graph_complete,
                                   verify_graph_connected,
                                   verify_graph_connected_under_edge_failures,
                                   verify_graph_forest,
                                   verify_graph_connected_under_vertex_failures,
                                   verify_graph_no_lonely_vertices)

import itertools


def make_tree(vertices):
    if len(vertices) < 2:
        return ()
    remaining = set(vertices)
    used = set()
    edges = set()
    used.add(remaining.pop())
    used.add(remaining.pop())
    edges.add(tuple(used))
    while remaining:
        v = remaining.pop()
        w = used.pop()
        e = (w, v)
        edges.add(e)
        used.update(e)
    return tuple(edges)

# TODO: test directed graphs


class UndirectedGraphTests(samba.tests.TestCase):

    def setUp(self):
        super(UndirectedGraphTests, self).setUp()
        vertices = tuple('abcdefgh')
        vertices2 = tuple('ijk')
        edges = tuple(itertools.combinations(vertices, 2))
        edges2 = tuple(itertools.combinations(vertices2, 2))
        line_edges = list(zip(vertices[1:], vertices[:-1]))
        ring_edges = line_edges + [(vertices[0], vertices[-1])]

        tree = make_tree(vertices)
        tree2 = make_tree(vertices2)

        self.complete_graph = [edges, vertices, vertices]

        self.disconnected_clusters = [edges + edges2,
                                      vertices + vertices2,
                                      vertices + vertices2]

        self.graph_with_unreachables = [edges,
                                        vertices + vertices2,
                                        vertices]

        self.ring = [ring_edges, vertices, vertices]
        self.line = [line_edges, vertices, vertices]

        self.tree = [tree, vertices, vertices]
        self.forest = [tree + tree2,
                       vertices + vertices2,
                       vertices + vertices2]

        self.unconnected_graph = ((), vertices, ())

    def assertGraphError(self, fn, *args):
        return self.assertRaises(GraphError, fn, *args)

    def test_graph_complete(self):
        fn = verify_graph_complete

        self.assertGraphError(fn, *self.disconnected_clusters)
        self.assertGraphError(fn, *self.graph_with_unreachables)
        self.assertGraphError(fn, *self.ring)
        self.assertGraphError(fn, *self.tree)

        self.assertIsNone(fn(*self.complete_graph))

    def test_graph_connected(self):
        fn = verify_graph_connected

        self.assertGraphError(fn, *self.disconnected_clusters)
        self.assertGraphError(fn, *self.graph_with_unreachables)
        self.assertGraphError(fn, *self.forest)
        self.assertGraphError(fn, *self.unconnected_graph)

        self.assertIsNone(fn(*self.line))
        self.assertIsNone(fn(*self.ring))
        self.assertIsNone(fn(*self.complete_graph))
        self.assertIsNone(fn(*self.tree))

    def test_graph_forest(self):
        fn = verify_graph_forest

        self.assertGraphError(fn, *self.disconnected_clusters)
        self.assertGraphError(fn, *self.graph_with_unreachables)
        self.assertGraphError(fn, *self.ring)

        self.assertIsNone(fn(*self.line))
        self.assertIsNone(fn(*self.tree))
        self.assertIsNone(fn(*self.forest))
        self.assertIsNone(fn(*self.unconnected_graph))

    def test_graph_connected_under_edge_failures(self):
        fn = verify_graph_connected_under_edge_failures

        self.assertGraphError(fn, *self.line)
        self.assertGraphError(fn, *self.tree)
        self.assertGraphError(fn, *self.forest)
        self.assertGraphError(fn, *self.disconnected_clusters)

        self.assertIsNone(fn(*self.ring))
        self.assertIsNone(fn(*self.complete_graph))

    def test_graph_connected_under_vertex_failures(self):
        # XXX no tests to distinguish this from the edge_failures case
        fn = verify_graph_connected_under_vertex_failures

        self.assertGraphError(fn, *self.line)
        self.assertGraphError(fn, *self.tree)
        self.assertGraphError(fn, *self.forest)
        self.assertGraphError(fn, *self.disconnected_clusters)

        self.assertIsNone(fn(*self.ring))
        self.assertIsNone(fn(*self.complete_graph))

    def test_graph_multi_edge_forest(self):
        pass

    def test_graph_no_lonely_vertices(self):
        fn = verify_graph_no_lonely_vertices
        self.assertGraphError(fn, *self.unconnected_graph)
        self.assertGraphError(fn, *self.graph_with_unreachables)

        self.assertIsNone(fn(*self.ring))
        self.assertIsNone(fn(*self.complete_graph))
        self.assertIsNone(fn(*self.line))
        self.assertIsNone(fn(*self.tree))
        self.assertIsNone(fn(*self.forest))

    def test_graph_no_unknown_vertices(self):
        pass
