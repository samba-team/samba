# Graph topology utilities, used by KCC
#
# Copyright (C) Andrew Bartlett 2015
#
# Copyright goes to Andrew Bartlett, but the actual work was performed
# by Douglas Bagnall and Garming Sam.
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

from __future__ import print_function
import os
import itertools

from samba.graph import dot_graph


def write_dot_file(basename, edge_list, vertices=None, label=None,
                   dot_file_dir=None, debug=None, **kwargs):
    s = dot_graph(vertices, edge_list, title=label, **kwargs)
    if label:
        # sanitise DN and guid labels
        basename += '_' + label.replace(', ', '')

    filename = os.path.join(dot_file_dir, "%s.dot" % basename)
    if debug is not None:
        debug("writing graph to %s" % filename)
    f = open(filename, 'w')
    f.write(s)
    f.close()


class GraphError(Exception):
    pass


def verify_graph_complete(edges, vertices, edge_vertices):
    """The graph is complete, which is to say there is an edge between
    every pair of nodes."""
    for v in vertices:
        remotes = set()
        for a, b in edges:
            if a == v:
                remotes.add(b)
            elif b == v:
                remotes.add(a)
        if len(remotes) + 1 != len(vertices):
            raise GraphError("graph is not fully connected")


def verify_graph_connected(edges, vertices, edge_vertices):
    """There is a path between any two nodes."""
    if not edges:
        if len(vertices) <= 1:
            return
        raise GraphError("all vertices are disconnected because "
                         "there are no edges:")

    remaining_edges = list(edges)
    reached = set(remaining_edges.pop())
    while True:
        doomed = []
        for i, e in enumerate(remaining_edges):
            a, b = e
            if a in reached:
                reached.add(b)
                doomed.append(i)
            elif b in reached:
                reached.add(a)
                doomed.append(i)
        if not doomed:
            break
        for i in reversed(doomed):
            del remaining_edges[i]

    if remaining_edges or reached != set(vertices):
        s = ("the graph is not connected, "
             "as the following vertices are unreachable:\n ")
        s += '\n '.join(v for v in sorted(vertices)
                        if v not in reached)
        raise GraphError(s)


def verify_graph_connected_under_edge_failures(edges, vertices, edge_vertices):
    """The graph stays connected when any single edge is removed."""
    if len(edges) == 0:
        return verify_graph_connected(edges, vertices, edge_vertices)

    for subset in itertools.combinations(edges, len(edges) - 1):
        try:
            verify_graph_connected(subset, vertices, edge_vertices)
        except GraphError as e:
            for edge in edges:
                if edge not in subset:
                    raise GraphError("The graph will be disconnected when the "
                                     "connection from %s to %s fails" % edge)


def verify_graph_connected_under_vertex_failures(edges, vertices,
                                                 edge_vertices):
    """The graph stays connected when any single vertex is removed."""
    for v in vertices:
        sub_vertices = [x for x in vertices if x is not v]
        sub_edges = [x for x in edges if v not in x]
        verify_graph_connected(sub_edges, sub_vertices, sub_vertices)


def verify_graph_forest(edges, vertices, edge_vertices):
    """The graph contains no loops."""
    trees = [set(e) for e in edges]
    while True:
        for a, b in itertools.combinations(trees, 2):
            intersection = a & b
            if intersection:
                if len(intersection) == 1:
                    a |= b
                    trees.remove(b)
                    break
                else:
                    raise GraphError("there is a loop in the graph\n"
                                     " vertices %s\n edges %s\n"
                                     " intersection %s" %
                                     (vertices, edges, intersection))
        else:
            # no break in itertools.combinations loop means no
            # further mergers, so we're done.
            #
            # XXX here we also know whether it is a tree or a
            # forest by len(trees) but the connected test already
            # tells us that.
            return


def verify_graph_multi_edge_forest(edges, vertices, edge_vertices):
    """This allows a forest with duplicate edges. That is if multiple
    edges go between the same two vertices, they are treated as a
    single edge by this test.

    e.g.:
                        o
    pass: o-o=o  o=o   (|)             fail:  o-o
            `o          o                     `o'
    """
    unique_edges = set(edges)
    trees = [set(e) for e in unique_edges]
    while True:
        for a, b in itertools.combinations(trees, 2):
            intersection = a & b
            if intersection:
                if len(intersection) == 1:
                    a |= b
                    trees.remove(b)
                    break
                else:
                    raise GraphError("there is a loop in the graph")
        else:
            return


def verify_graph_no_lonely_vertices(edges, vertices, edge_vertices):
    """There are no vertices without edges."""
    lonely = set(vertices) - set(edge_vertices)
    if lonely:
        raise GraphError("some vertices are not connected:\n%s" %
                         '\n'.join(sorted(lonely)))


def verify_graph_no_unknown_vertices(edges, vertices, edge_vertices):
    """The edge endpoints contain no vertices that are otherwise unknown."""
    unknown = set(edge_vertices) - set(vertices)
    if unknown:
        raise GraphError("some edge vertices are seemingly unknown:\n%s" %
                         '\n'.join(sorted(unknown)))


def verify_graph_directed_double_ring(edges, vertices, edge_vertices):
    """Each node has at least two directed edges leaving it, and two
    arriving. The edges work in pairs that have the same end points
    but point in opposite directions. The pairs form a path that
    touches every vertex and form a loop.

    There might be other connections that *aren't* part of the ring.

    Deciding this for sure is NP-complete (the Hamiltonian path
    problem), but there are some easy failures that can be detected.
    So far we check for:
      - leaf nodes
      - disjoint subgraphs
      - robustness against edge and vertex failure
    """
    # a zero or one node graph is OK with no edges.
    # The two vertex case is special. Use
    # verify_graph_directed_double_ring_or_small() to allow that.
    if not edges and len(vertices) <= 1:
        return
    if len(edges) < 2 * len(vertices):
        raise GraphError("directed double ring requires at least twice "
                         "as many edges as vertices")

    # Reduce the problem space by looking only at bi-directional links.
    half_duplex = set(edges)
    duplex_links = set()
    for edge in edges:
        rev_edge = (edge[1], edge[0])
        if edge in half_duplex and rev_edge in half_duplex:
            duplex_links.add(edge)
            half_duplex.remove(edge)
            half_duplex.remove(rev_edge)

    # the Hamiltonian cycle problem is NP-complete in general, but we
    # can cheat a bit and prove a less strong result.
    #
    # We declutter the graph by replacing nodes with edges connecting
    # their neighbours.
    #
    #       A-B-C --> A-C
    #
    #    -A-B-C-   -->  -A--C-
    #       `D_           `D'_
    #
    # In the end there should be a single 2 vertex graph.

    edge_map = {}
    for a, b in duplex_links:
        edge_map.setdefault(a, set()).add(b)
        edge_map.setdefault(b, set()).add(a)

    # an easy to detect failure is a lonely leaf node
    for vertex, neighbours in edge_map.items():
        if len(neighbours) == 1:
            raise GraphError("wanted double directed ring, found a leaf node"
                             "(%s)" % vertex)

    for vertex in list(edge_map.keys()):
        nset = edge_map[vertex]
        if not nset:
            continue
        for n in nset:
            n_neighbours = edge_map[n]
            n_neighbours.remove(vertex)
            n_neighbours.update(x for x in nset if x != n)
        del edge_map[vertex]

    if len(edge_map) > 1:
        raise GraphError("wanted double directed ring, but "
                         "this looks like a split graph\n"
                         "(%s can't reach each other)" %
                         ', '.join(edge_map.keys()))

    verify_graph_connected_under_edge_failures(duplex_links, vertices,
                                               edge_vertices)
    verify_graph_connected_under_vertex_failures(duplex_links, vertices,
                                                 edge_vertices)


def verify_graph_directed_double_ring_or_small(edges, vertices, edge_vertices):
    """This performs the directed_double_ring test but makes special
    concessions for small rings where the strict rules don't really
    apply."""
    if len(vertices) < 2:
        return
    if len(vertices) == 2:
        """With 2 nodes there should be a single link in each directions."""
        if (len(edges) == 2 and
            edges[0][0] == edges[1][1] and
            edges[0][1] == edges[1][0]):
            return
        raise GraphError("A two vertex graph should have an edge each way.")

    return verify_graph_directed_double_ring(edges, vertices, edge_vertices)


def verify_graph(edges, vertices=None, directed=False, properties=()):
    errors = []
    properties = [x.replace(' ', '_') for x in properties]

    edge_vertices = set()
    for a, b in edges:
        edge_vertices.add(a)
        edge_vertices.add(b)

    if vertices is None:
        vertices = edge_vertices
    else:
        vertices = set(vertices)

    for p in properties:
        fn = 'verify_graph_%s' % p
        f = globals()[fn]
        try:
            f(edges, vertices, edge_vertices)
        except GraphError as e:
            errors.append((p, e, f.__doc__))

    return errors


def verify_and_dot(basename, edges, vertices=None, label=None,
                   reformat_labels=True, directed=False,
                   properties=(), fatal=True, debug=None,
                   verify=True, dot_file_dir=None,
                   edge_colors=None, edge_labels=None,
                   vertex_colors=None):

    if dot_file_dir is not None:
        write_dot_file(basename, edges, vertices=vertices, label=label,
                       dot_file_dir=dot_file_dir,
                       reformat_labels=reformat_labels, directed=directed,
                       debug=debug, edge_colors=edge_colors,
                       edge_labels=edge_labels, vertex_colors=vertex_colors)

    if verify:
        errors = verify_graph(edges, vertices,
                              properties=properties)
        if errors:
            title = '%s %s' % (basename, label or '')
            debug("%s FAILED:" % title)
            for p, e, doc in errors:
                debug(" %18s: %s" % (p, e))
            if fatal:
                raise GraphError("The '%s' graph lacks the following "
                                 "properties:\n%s" %
                                 (title, '\n'.join('%s: %s' % (p, e)
                                                   for p, e, doc in errors)))


def list_verify_tests():
    for k, v in sorted(globals().items()):
        if k.startswith('verify_graph_'):
            print(k.replace('verify_graph_', ''))
            if v.__doc__:
                print('    %s' % (v.__doc__.rstrip()))
            else:
                print()
