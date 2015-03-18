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

import sys
import itertools


def write_dot_file(basename, edge_list, vertices=None, label=None, destdir=None,
                   reformat_labels=True, directed=False, debug=None):
    from tempfile import NamedTemporaryFile
    if label:
        basename += '_' + label.translate(None, ', ') #fix DN, guid labels
    f = NamedTemporaryFile(suffix='.dot', prefix=basename + '_', delete=False, dir=destdir)
    if debug is not None:
        debug(f.name)
    graphname = ''.join(x for x in basename if x.isalnum())
    print >>f, '%s %s {' % ('digraph' if directed else 'graph', graphname)
    print >>f, 'label="%s";\nfontsize=20;' % (label or graphname)
    if vertices:
        for v in vertices:
            if reformat_labels:
                v = v.replace(',', '\\n')
            print >>f, '"%s";' % (v,)
    for a, b in edge_list:
        if reformat_labels:
            a = a.replace(',', '\\n')
            b = b.replace(',', '\\n')
        line = '->' if directed else '--'
        print >>f, '"%s" %s "%s";' % (a, line, b)
    print >>f, '}'
    f.close()



class KCCGraphError(Exception):
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
            raise KCCGraphError("graph is not fully connected")


def verify_graph_connected(edges, vertices, edge_vertices):
    """There is a path between any two nodes."""
    if not edges:
        if len(vertices) <= 1:
            return
        raise KCCGraphError("disconnected vertices were found:\nvertices: %s\n edges: %s" %
                            (sorted(vertices), sorted(edges)))

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

    if remaining_edges or reached != vertices:
        raise KCCGraphError("graph is not connected:\nvertices: %s\n edges: %s" %
                            (sorted(vertices), sorted(edges)))



def verify_graph_forest(edges, vertices, edge_vertices):
    """The graph contains no loops. A forest that is also connected is a
    tree."""
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
                    raise KCCGraphError("there is a loop in the graph")
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
                    raise KCCGraphError("there is a loop in the graph")
        else:
            return


def verify_graph_forest_of_rings(edges, vertices, edge_vertices):
    """The graph should consist of clusters of node connected in rings,
    with the connections between the cdlusters forming a forest."""
    pass


def verify_graph_no_lonely_vertices(edges, vertices, edge_vertices):
    """There are no vertices without edges."""
    lonely = vertices - edge_vertices
    if lonely:
        raise KCCGraphError("some vertices are not connected:\n%s" % '\n'.join(sorted(lonely)))


def verify_graph_no_unknown_vertices(edges, vertices, edge_vertices):
    """The edge endpoints contain no vertices that are otherwise unknown."""
    unknown = edge_vertices - vertices
    if unknown:
        raise KCCGraphError("some edge vertices are seemingly unknown:\n%s" % '\n'.join(sorted(unknown)))


def verify_graph_directed_double_ring(edges, vertices, edge_vertices):
    """Each node has at least two directed edges leaving it, and two
    arriving. The edges work in pairs that have the same end points
    but point in opposite directions. The pairs form a path that
    touches every vertex and form a loop.

    There might be other connections that *aren't* part of the ring.
    """
    #XXX possibly the 1 and 2 vertex cases are special cases.
    if not edges:
        return
    if len(edges) < 2* len(vertices):
        raise KCCGraphError("directed double ring requires at least twice as many edges as vertices")

    exits = {}
    for start, end in edges:
        s = exits.setdefault(start, [])
        s.append(end)

    try:
        #follow both paths at once -- they should be the same length
        #XXX there is probably a simpler way.
        forwards, backwards = exits[start]
        fprev, bprev = (start, start)
        f_path = [start]
        b_path = [start]
        for i in range(len(vertices)):
            a, b = exits[forwards]
            if a == fprev:
                fnext = b
            else:
                fnext = a
            f_path.append(forwards)
            fprev = forwards
            forwards = fnext

            a, b = exits[backwards]
            if a == bprev:
                bnext = b
            else:
                bnext = a
            b_path.append(backwards)
            bprev = backwards
            backwards = bnext

    except ValueError, e:
        raise KCCGraphError("wrong number of exits '%s'" % e)

    f_set = set(f_path)
    b_set = set(b_path)

    if (f_path != list(reversed(b_path)) or
        len(f_path) != len(f_set) + 1 or
        len(f_set) != len(vertices)):
        raise KCCGraphError("doesn't seem like a double ring to me!")


def verify_graph_directed_double_ring_or_small(edges, vertices, edge_vertices):
    if len(vertices) < 3:
        return
    return verify_graph_directed_double_ring(edges, vertices, edge_vertices)



def verify_graph(title, edges, vertices=None, directed=False, properties=(), fatal=True,
                 debug=None):
    errors = []
    if debug is None:
        def debug(*args): pass

    debug("%sStarting verify_graph for %s%s%s" % (PURPLE, MAGENTA, title, C_NORMAL))

    properties = [x.replace(' ', '_') for x in properties]

    edge_vertices = set()
    for a, b in edges:
        edge_vertices.add(a)
        edge_vertices.add(b)

    if vertices is None:
        vertices = edge_vertices
    else:
        vertices = set(vertices)
        if vertices != edge_vertices:
            debug("vertices in edges don't match given vertices:\n %s != %s" %
                  (sorted(edge_vertices), sorted(vertices)))

    for p in properties:
        fn = 'verify_graph_%s' % p
        try:
            f = globals()[fn]
        except KeyError:
            errors.append((p, "There is no verification check for '%s'" % p))
        try:
            f(edges, vertices, edge_vertices)
            debug(" %s%18s:%s verified!" % (DARK_GREEN, p, C_NORMAL))
        except KCCGraphError, e:
            errors.append((p, e))

    if errors:
        if fatal:
            raise KCCGraphError("The '%s' graph lacks the following properties:\n%s" %
                                (title, '\n'.join('%s: %s' % x for x in errors)))
        debug(("%s%s%s FAILED:" % (MAGENTA, title, RED)))
        for p, e in errors:
            debug(" %18s: %s%s%s" %(p, DARK_YELLOW, e, RED))
        debug(C_NORMAL)



def verify_and_dot(basename, edges, vertices=None, label=None, destdir=None,
                   reformat_labels=True, directed=False, properties=(), fatal=True,
                   debug=None, verify=True, dot_files=False):

    title = '%s %s' % (basename, label or '')
    if verify:
        verify_graph(title, edges, vertices, properties=properties, fatal=fatal,
                     debug=debug)
    if dot_files:
        write_dot_file(basename, edges, vertices=vertices, label=label, destdir=destdir,
                       reformat_labels=reformat_labels, directed=directed, debug=debug)

def list_verify_tests():
    for k, v in sorted(globals().items()):
        if k.startswith('verify_graph_'):
            print k.replace('verify_graph_', '')
            if v.__doc__:
                print '    %s%s%s' %(GREY, v.__doc__, C_NORMAL)
            else:
                print
