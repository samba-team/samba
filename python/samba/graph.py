# -*- coding: utf-8 -*-
# Graph topology utilities and dot file generation
#
# Copyright (C) Andrew Bartlett 2018.
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

from __future__ import print_function
from __future__ import division
from samba import colour
import sys
from itertools import cycle, groupby

FONT_SIZE = 10


def reformat_graph_label(s):
    """Break DNs over multiple lines, for better shaped and arguably more
    readable nodes. We try to split after commas, and if necessary
    after hyphens or failing that in arbitrary places."""
    if len(s) < 12:
        return s

    s = s.replace(',', ',\n')
    pieces = []
    for p in s.split('\n'):
        while len(p) > 20:
            if '-' in p[2:20]:
                q, p = p.split('-', 1)
            else:
                n = len(p) // 12
                b = len(p) // n
                q, p = p[:b], p[b:]
            pieces.append(q + '-')
        if p:
            pieces.append(p)

    return '\\n'.join(pieces)


def quote_graph_label(s, reformat=False):
    """Escape a string as graphvis requires."""
    # escaping inside quotes is simple in dot, because only " is escaped.
    # there is no need to count backslashes in sequences like \\\\"
    s = s.replace('"', '\"')
    if reformat:
        s = reformat_graph_label(s)
    return "%s" % s


def shorten_vertex_names(vertices, suffix=',...', aggressive=False):
    """Replace the common suffix (in practice, the base DN) of a number of
    vertices with a short string (default ",..."). If this seems
    pointless because the replaced string is very short or the results
    seem strange, the original vertices are retained.

    :param vertices: a sequence of vertices to shorten
    :param suffix: the replacement string [",..."]
    :param aggressive: replace certain common non-suffix strings

    :return: tuple of (rename map, replacements)

    The rename map is a dictionary mapping the old vertex names to
    their shortened versions. If no changes are made, replacements
    will be empty.
    """
    vmap = dict((v, v) for v in vertices)
    replacements = []

    if len(vmap) > 1:
        # walk backwards along all the strings until we meet a character
        # that is not shared by all.
        i = -1
        vlist = list(vmap.values())
        try:
            while True:
                c = set(x[i] for x in vlist)
                if len(c) > 1 or '*' in c:
                    break
                i -= 1
        except IndexError:
            # We have indexed beyond the start of a string, which should
            # only happen if one node is a strict suffix of all others.
            return vmap, replacements

        # add one to get to the last unanimous character.
        i += 1

        # now, we actually really want to split on a comma. So we walk
        # back to a comma.
        x = vlist[0]
        while i < len(x) and x[i] != ',':
            i += 1

        if i >= -len(suffix):
            # there is nothing to gain here
            return vmap, replacements

        replacements.append((suffix, x[i:]))

        for k, v in vmap.items():
            vmap[k] = v[:i] + suffix

    if aggressive:
        # Remove known common annoying strings
        for v in vmap.values():
            if ',CN=Servers,' not in v:
                break
        else:
            vmap = dict((k, v.replace(',CN=Servers,', ',**,', 1))
                        for k, v in vmap.items())
            replacements.append(('**', 'CN=Servers'))

        for v in vmap.values():
            if not v.startswith('CN=NTDS Settings,'):
                break
        else:
            vmap = dict((k, v.replace('CN=NTDS Settings,', '*,', 1))
                        for k, v in vmap.items())
            replacements.append(('*', 'CN=NTDS Settings'))

    return vmap, replacements


def compile_graph_key(key_items, nodes_above=[], elisions=None,
                      prefix='key_', width=2):
    """Generate a dot file snippet that acts as a legend for a graph.

    :param key_items: sequence of items (is_vertex, style, label)
    :param nodes_above: list of vertices (pushes key into right position)
    :param elision: tuple (short, full) indicating suffix replacement
    :param prefix: string used to generate key node names ["key_"]
    :param width: default width of node lines

    Each item in key_items is a tuple of (is_vertex, style, label).
    is_vertex is a boolean indicating whether the item is a vertex
    (True) or edge (False). Style is a dot style string for the edge
    or vertex. label is the text associated with the key item.
    """
    edge_lines = []
    edge_names = []
    vertex_lines = []
    vertex_names = []
    order_lines = []
    for i, item in enumerate(key_items):
        is_vertex, style, label = item
        tag = '%s%d_' % (prefix, i)
        label = quote_graph_label(label)
        name = '%s_label' % tag

        if is_vertex:
            order_lines.append(name)
            vertex_names.append(name)
            vertex_lines.append('%s[label="%s"; %s]' %
                                (name, label, style))
        else:
            edge_names.append(name)
            e1 = '%se1' % tag
            e2 = '%se2' % tag
            order_lines.append(name)
            edge_lines.append('subgraph cluster_%s {' % tag)
            edge_lines.append('%s[label=src; color="#000000"; group="%s_g"]' %
                              (e1, tag))
            edge_lines.append('%s[label=dest; color="#000000"; group="%s_g"]' %
                              (e2, tag))
            edge_lines.append('%s -> %s [constraint = false; %s]' % (e1, e2,
                                                                     style))
            edge_lines.append(('%s[shape=plaintext; style=solid; width=%f; '
                               'label="%s\\r"]') %
                              (name, width, label))
            edge_lines.append('}')

    elision_str = ''
    if elisions:
        for i, elision in enumerate(reversed(elisions)):
            order_lines.append('elision%d' % i)
            short, long = elision
            if short[0] == ',' and long[0] == ',':
                short = short[1:]
                long = long[1:]
            elision_str += ('\nelision%d[shape=plaintext; style=solid; '
                            'label="\“%s”  means  “%s”\\r"]\n'
                            % ((i, short, long)))

    above_lines = []
    if order_lines:
        for n in nodes_above:
            above_lines.append('"%s" -> %s [style=invis]' %
                               (n, order_lines[0]))

    s = ('subgraph cluster_key {\n'
         'label="Key";\n'
         'subgraph cluster_key_nodes {\n'
         'label="";\n'
         'color = "invis";\n'
         '%s\n'
         '}\n'
         'subgraph cluster_key_edges {\n'
         'label="";\n'
         'color = "invis";\n'
         '%s\n'
         '{%s}\n'
         '}\n'
         '%s\n'
         '}\n'
         '%s\n'
         '%s [style=invis; weight=9]'
         '\n'
         % (';\n'.join(vertex_lines),
            '\n'.join(edge_lines),
            ' '.join(edge_names),
            elision_str,
            ';\n'.join(above_lines),
            ' -> '.join(order_lines),
            ))

    return s


def dot_graph(vertices, edges,
              directed=False,
              title=None,
              reformat_labels=True,
              vertex_colors=None,
              edge_colors=None,
              edge_labels=None,
              vertex_styles=None,
              edge_styles=None,
              graph_name=None,
              shorten_names=False,
              key_items=None,
              vertex_clusters=None):
    """Generate a Graphviz representation of a list of vertices and edges.

    :param vertices: list of vertex names (optional).
    :param edges:    list of (vertex, vertex) pairs
    :param directed: bool: whether the graph is directed
    :param title: optional title for the graph
    :param reformat_labels: whether to wrap long vertex labels
    :param vertex_colors: if not None, a sequence of colours for the vertices
    :param edge_colors: if not None, colours for the edges
    :param edge_labels: if not None, labels for the edges
    :param vertex_styles: if not None, DOT style strings for vertices
    :param edge_styles: if not None, DOT style strings for edges
    :param graph_name: if not None, name of graph
    :param shorten_names: if True, remove common DN suffixes
    :param key: (is_vertex, style, description) tuples
    :param vertex_clusters: list of subgraph cluster names

    Colour, style, and label lists must be the same length as the
    corresponding list of edges or vertices (or None).

    Colours can be HTML RGB strings ("#FF0000") or common names
    ("red"), or some other formats you don't want to think about.

    If `vertices` is None, only the vertices mentioned in the edges
    are shown, and their appearance can be modified using the
    vertex_colors and vertex_styles arguments. Vertices appearing in
    the edges but not in the `vertices` list will be shown but their
    styles can not be modified.
    """
    out = []
    write = out.append

    if vertices is None:
        vertices = set(x[0] for x in edges) | set(x[1] for x in edges)

    if shorten_names:
        vlist = list(set(x[0] for x in edges) |
                     set(x[1] for x in edges) |
                     set(vertices))
        vmap, elisions = shorten_vertex_names(vlist)
        vertices = [vmap[x] for x in vertices]
        edges = [(vmap[a], vmap[b]) for a, b in edges]

    else:
        elisions = None

    if graph_name is None:
        graph_name = 'A_samba_tool_production'

    if directed:
        graph_type = 'digraph'
        connector = '->'
    else:
        graph_type = 'graph'
        connector = '--'

    write('/* generated by samba */')
    write('%s %s {' % (graph_type, graph_name))
    if title is not None:
        write('label="%s";' % (title,))
    write('fontsize=%s;\n' % (FONT_SIZE))
    write('node[fontname=Helvetica; fontsize=%s];\n' % (FONT_SIZE))

    prev_cluster = None
    cluster_n = 0
    quoted_vertices = []
    for i, v in enumerate(vertices):
        v = quote_graph_label(v, reformat_labels)
        quoted_vertices.append(v)
        attrs = []
        if vertex_clusters and vertex_clusters[i]:
            cluster = vertex_clusters[i]
            if cluster != prev_cluster:
                if prev_cluster is not None:
                    write("}")
                prev_cluster = cluster
                n = quote_graph_label(cluster)
                if cluster:
                    write('subgraph cluster_%d {' % cluster_n)
                    cluster_n += 1
                    write('style = "rounded,dotted";')
                    write('node [style="filled"; fillcolor=white];')
                    write('label = "%s";' % n)

        if vertex_styles and vertex_styles[i]:
            attrs.append(vertex_styles[i])
        if vertex_colors and vertex_colors[i]:
            attrs.append('color="%s"' % quote_graph_label(vertex_colors[i]))
        if attrs:
            write('"%s" [%s];' % (v, ', '.join(attrs)))
        else:
            write('"%s";' % (v,))

    if prev_cluster:
        write("}")

    for i, edge in enumerate(edges):
        a, b = edge
        if a is None:
            a = "Missing source value"
        if b is None:
            b = "Missing destination value"

        a = quote_graph_label(a, reformat_labels)
        b = quote_graph_label(b, reformat_labels)

        attrs = []
        if edge_labels:
            label = quote_graph_label(edge_labels[i])
            attrs.append('label="%s"' % label)
        if edge_colors:
            attrs.append('color="%s"' % quote_graph_label(edge_colors[i]))
        if edge_styles:
            attrs.append(edge_styles[i])  # no quoting
        if attrs:
            write('"%s" %s "%s" [%s];' % (a, connector, b, ', '.join(attrs)))
        else:
            write('"%s" %s "%s";' % (a, connector, b))

    if key_items:
        key = compile_graph_key(key_items, nodes_above=quoted_vertices,
                                elisions=elisions)
        write(key)

    write('}\n')
    return '\n'.join(out)


COLOUR_SETS = {
    'ansi': {
        'alternate rows': (colour.DARK_WHITE, colour.BLACK),
        'disconnected': colour.RED,
        'connected': colour.GREEN,
        'transitive': colour.DARK_YELLOW,
        'header': colour.UNDERLINE,
        'reset': colour.C_NORMAL,
    },
    'ansi-heatmap': {
        'alternate rows': (colour.DARK_WHITE, colour.BLACK),
        'disconnected': colour.REV_RED,
        'connected': colour.REV_GREEN,
        'transitive': colour.REV_DARK_YELLOW,
        'header': colour.UNDERLINE,
        'reset': colour.C_NORMAL,
    },
    'xterm-256color': {
        'alternate rows': (colour.xterm_256_colour(39),
                           colour.xterm_256_colour(45)),
        # 'alternate rows': (colour.xterm_256_colour(246),
        #                   colour.xterm_256_colour(247)),
        'disconnected': colour.xterm_256_colour(124, bg=True),
        'connected': colour.xterm_256_colour(112),
        'transitive': colour.xterm_256_colour(214),
        'transitive scale': (colour.xterm_256_colour(190),
                             colour.xterm_256_colour(184),
                             colour.xterm_256_colour(220),
                             colour.xterm_256_colour(214),
                             colour.xterm_256_colour(208),
                             ),
        'header': colour.UNDERLINE,
        'reset': colour.C_NORMAL,
    },
    'xterm-256color-heatmap': {
        'alternate rows': (colour.xterm_256_colour(171),
                           colour.xterm_256_colour(207)),
        # 'alternate rows': (colour.xterm_256_colour(246),
        #                    colour.xterm_256_colour(247)),
        'disconnected': colour.xterm_256_colour(124, bg=True),
        'connected': colour.xterm_256_colour(112, bg=True),
        'transitive': colour.xterm_256_colour(214, bg=True),
        'transitive scale': (colour.xterm_256_colour(190, bg=True),
                             colour.xterm_256_colour(184, bg=True),
                             colour.xterm_256_colour(220, bg=True),
                             colour.xterm_256_colour(214, bg=True),
                             colour.xterm_256_colour(208, bg=True),
                             ),
        'header': colour.UNDERLINE,
        'reset': colour.C_NORMAL,
    },
    None: {
        'alternate rows': ('',),
        'disconnected': '',
        'connected': '',
        'transitive': '',
        'header': '',
        'reset': '',
    }
}

CHARSETS = {
    'utf8': {
        'vertical': '│',
        'horizontal': '─',
        'corner': '╭',
        # 'diagonal': '╲',
        'diagonal': '·',
        # 'missing': '🕱',
        'missing': '-',
        'right_arrow': '←',
    },
    'ascii': {
        'vertical': '|',
        'horizontal': '-',
        'corner': ',',
        'diagonal': '0',
        'missing': '-',
        'right_arrow': '<-',
    }
}


def find_transitive_distance(vertices, edges):
    all_vertices = (set(vertices) |
                    set(e[0] for e in edges) |
                    set(e[1] for e in edges))

    if all_vertices != set(vertices):
        print("there are unknown vertices: %s" %
              (all_vertices - set(vertices)),
              file=sys.stderr)

    # with n vertices, we are always less than n hops away from
    # anywhere else.
    inf = len(all_vertices)
    distances = {}
    for v in all_vertices:
        distances[v] = {v: 0}

    for src, dest in edges:
        distances[src][dest] = distances[src].get(dest, 1)

    # This algorithm (and implementation) seems very suboptimal.
    # potentially O(n^4), though n is smallish.
    for i in range(inf):
        changed = False
        new_distances = {}
        for v, d in distances.items():
            new_d = d.copy()
            new_distances[v] = new_d
            for dest, cost in d.items():
                for leaf, cost2 in distances[dest].items():
                    new_cost = cost + cost2
                    old_cost = d.get(leaf, inf)
                    if new_cost < old_cost:
                        new_d[leaf] = new_cost
                        changed = True

        distances = new_distances
        if not changed:
            break

    # filter out unwanted vertices and infinite links
    answer = {}
    for v in vertices:
        answer[v] = {}
        for v2 in vertices:
            a = distances[v].get(v2, inf)
            if a < inf:
                answer[v][v2] = a

    return answer


def get_transitive_colourer(colours, n_vertices):
    if 'transitive scale' in colours:
        scale = colours['transitive scale']
        m = len(scale)
        n = 1 + int(n_vertices ** 0.5)

        def f(link):
            if not isinstance(link, int):
                return ''
            return scale[min(link * m // n, m - 1)]

    else:
        def f(link):
            return colours['transitive']

    return f


def distance_matrix(vertices, edges,
                    utf8=False,
                    colour=None,
                    shorten_names=False,
                    generate_key=False,
                    grouping_function=None,
                    row_comments=None):
    lines = []
    write = lines.append

    charset = CHARSETS['utf8' if utf8 else 'ascii']
    vertical = charset['vertical']
    horizontal = charset['horizontal']
    corner = charset['corner']
    diagonal = charset['diagonal']
    missing = charset['missing']
    right_arrow = charset['right_arrow']

    colours = COLOUR_SETS[colour]

    colour_cycle = cycle(colours.get('alternate rows', ('',)))

    if vertices is None:
        vertices = sorted(set(x[0] for x in edges) | set(x[1] for x in edges))

    if grouping_function is not None:
        # we sort and colour according to the grouping function
        # which can be used to e.g. alternate colours by site.
        vertices = sorted(vertices, key=grouping_function)
        colour_list = []
        for k, v in groupby(vertices, key=grouping_function):
            c = next(colour_cycle)
            colour_list.extend(c for x in v)
    else:
        colour_list = [next(colour_cycle) for v in vertices]

    if shorten_names:
        vlist = list(set(x[0] for x in edges) |
                     set(x[1] for x in edges) |
                     set(vertices))
        vmap, replacements = shorten_vertex_names(vlist, '+',
                                                  aggressive=True)
        vertices = [vmap[x] for x in vertices]
        edges = [(vmap[a], vmap[b]) for a, b in edges]

    vlen = max(6, max(len(v) for v in vertices))

    # first, the key for the columns
    c_header = colours.get('header', '')
    c_disconn = colours.get('disconnected', '')
    c_conn = colours.get('connected', '')
    c_reset = colours.get('reset', '')

    colour_transitive = get_transitive_colourer(colours, len(vertices))

    vspace = ' ' * vlen
    verticals = ''
    write("%*s %s  %sdestination%s" % (vlen, '',
                                       ' ' * len(vertices),
                                       c_header,
                                       c_reset))
    for i, v in enumerate(vertices):
        j = len(vertices) - i
        c = colour_list[i]
        if j == 1:
            start = '%s%ssource%s' % (vspace[:-6], c_header, c_reset)
        else:
            start = vspace
        write('%s %s%s%s%s%s %s%s' % (start,
                                      verticals,
                                      c_reset,
                                      c,
                                      corner,
                                      horizontal * j,
                                      v,
                                      c_reset
                                      ))
        verticals += c + vertical

    connections = find_transitive_distance(vertices, edges)

    for i, v in enumerate(vertices):
        c = colour_list[i]
        links = connections[v]
        row = []
        for v2 in vertices:
            link = links.get(v2)
            if link is None:
                row.append('%s%s' % (c_disconn, missing))
                continue
            if link == 0:
                row.append('%s%s%s%s' % (c_reset, c, diagonal, c_reset))
            elif link == 1:
                row.append('%s1%s' % (c_conn, c_reset))
            else:
                ct = colour_transitive(link)
                if link > 9:
                    link = '>'
                row.append('%s%s%s' % (ct, link, c_reset))

        if row_comments is not None and row_comments[i]:
            row.append('%s %s %s' % (c_reset, right_arrow, row_comments[i]))

        write('%s%*s%s %s%s' % (c, vlen, v, c_reset,
                                ''.join(row), c_reset))

    example_c = next(colour_cycle)
    if shorten_names:
        write('')
        for substitute, original in reversed(replacements):
            write("'%s%s%s' stands for '%s%s%s'" % (example_c,
                                                    substitute,
                                                    c_reset,
                                                    example_c,
                                                    original,
                                                    c_reset))
    if generate_key:
        write('')
        write("Data can get from %ssource%s to %sdestination%s in the "
              "indicated number of steps." % (c_header, c_reset,
                                              c_header, c_reset))
        write("%s%s%s means zero steps (it is the same DC)" %
              (example_c, diagonal, c_reset))
        write("%s1%s means a direct link" % (c_conn, c_reset))
        write("%s2%s means a transitive link involving two steps "
              "(i.e. one intermediate DC)" %
              (colour_transitive(2), c_reset))
        write("%s%s%s means there is no connection, even through other DCs" %
              (c_disconn, missing, c_reset))

    return '\n'.join(lines)


def pad_char(char, digits, padding=' '):
    if digits == 1:
        padding = ''
    return ' ' * (digits - 1) + char + padding


def transpose_dict_matrix(m):
    m2 = {}
    for k1, row in m.items():
        for k2, dist in row.items():
            m2.setdefault(k2, {})[k1] = dist
    return m2


def full_matrix(rows,
                utf8=False,
                colour=None,
                shorten_names=False,
                generate_key=False,
                grouping_function=None,
                row_comments=None,
                colour_scale=None,
                digits=1,
                ylabel='source',
                xlabel='destination',
                transpose=True):
    lines = []
    write = lines.append

    if transpose:
        rows = transpose_dict_matrix(rows)

    use_padding = digits > 1

    charset = CHARSETS['utf8' if utf8 else 'ascii']
    vertical = pad_char(charset['vertical'], digits)
    horizontal = charset['horizontal'] * (digits + use_padding)
    corner = pad_char(charset['corner'], digits,
                      charset['horizontal'])
    diagonal = pad_char(charset['diagonal'], digits)
    missing = pad_char(charset['missing'], digits)
    toobig = pad_char('>', digits)
    right_arrow = charset['right_arrow']
    empty = pad_char(' ', digits)

    colours = COLOUR_SETS[colour]

    colour_cycle = cycle(colours.get('alternate rows', ('',)))
    vertices = list(rows.keys())
    if grouping_function is not None:
        # we sort and colour according to the grouping function
        # which can be used to e.g. alternate colours by site.
        vertices.sort(key=grouping_function)
        colour_list = []
        for k, v in groupby(vertices, key=grouping_function):
            c = next(colour_cycle)
            colour_list.extend(c for x in v)
    else:
        colour_list = [next(colour_cycle) for v in vertices]

    if shorten_names:
        vmap, replacements = shorten_vertex_names(vertices, '+',
                                                  aggressive=True)
        rows2 = {}
        for vert, r in rows.items():
            rows2[vmap[vert]] = dict((vmap[k], v) for k, v in r.items())

        rows = rows2
        vertices = list(rows.keys())

    vlen = max(6, len(xlabel), max(len(v) for v in vertices))

    # first, the key for the columns
    c_header = colours.get('header', '')
    c_disconn = colours.get('disconnected', '')
    c_conn = colours.get('connected', '')
    c_reset = colours.get('reset', '')

    if colour_scale is None:
        colour_scale = len(rows)
    colour_transitive = get_transitive_colourer(colours, colour_scale)

    vspace = ' ' * vlen
    verticals = ''
    write("%s %s %s%s%s" % (vspace,
                            empty * (len(rows) + 1),
                            c_header,
                            xlabel,
                            c_reset))
    for i, v in enumerate(vertices):
        j = len(rows) - i
        c = colour_list[i]
        if j == 1:
            start = '%s%s%s%s' % (vspace[:-len(ylabel)],
                                  c_header,
                                  ylabel,
                                  c_reset)
        else:
            start = vspace
        write('%s %s%s%s%s%s %s%s' % (start,
                                      verticals,
                                      c_reset,
                                      c,
                                      corner,
                                      horizontal * j,
                                      v,
                                      c_reset
                                      ))
        verticals += '%s%s' % (c, vertical)

    end_cell = '%s%s' % (' ' * use_padding, c_reset)
    overflow = False
    for i, v in enumerate(vertices):
        links = rows[v]
        c = colour_list[i]
        row = []
        for v2 in vertices:
            if v2 not in links:
                row.append('%s%s%s' % (c_disconn, missing, c_reset))
            elif v == v2:
                row.append('%s%s%s%s' % (c_reset, c, diagonal, c_reset))
            else:
                link = links[v2]
                if link >= 10 ** digits:
                    ct = colour_transitive(link)
                    row.append('%s%s%s' % (ct, toobig, c_reset))
                    overflow = True
                    continue
                if link == 0:
                    ct = c_conn
                else:
                    ct = colour_transitive(link)
                row.append('%s%*s%s' % (ct, digits, link, end_cell))

        if row_comments is not None and row_comments[i]:
            row.append('%s %s %s' % (c_reset, right_arrow, row_comments[i]))

        write('%s%*s%s %s%s' % (c, vlen, v, c_reset,
                                ''.join(row), c_reset))

    if overflow or shorten_names:
        write('')

    if overflow:
            write("'%s%s%s' means greater than %d " %
                  (colour_transitive(10 ** digits),
                   toobig,
                   c_reset,
                   10 ** digits - 1))

    if shorten_names:
        example_c = next(colour_cycle)
        for substitute, original in reversed(replacements):
            write("'%s%s%s' stands for '%s%s%s'" % (example_c,
                                                    substitute,
                                                    c_reset,
                                                    example_c,
                                                    original,
                                                    c_reset))

    return '\n'.join(lines)
