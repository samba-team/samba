# Graph functions used by KCC intersite
#
# Copyright (C) Dave Craft 2011
# Copyright (C) Andrew Bartlett 2015
#
# Andrew Bartlett's alleged work performed by his underlings Douglas
# Bagnall and Garming Sam.
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

import itertools
import heapq

from samba.kcc.graph_utils import write_dot_file, verify_and_dot, verify_graph
from samba.kcc.kcc_utils import KCCError
from samba.ndr import ndr_pack
from samba.dcerpc import misc

from samba.kcc.debug import DEBUG, DEBUG_FN, WARN

MAX_DWORD = 2 ** 32 - 1


class ReplInfo(object):
    """Represents information about replication

    NTDSConnections use one representation a replication schedule, and
    graph vertices use another. This is the Vertex one.

    """
    def __init__(self):
        self.cost = 0
        self.interval = 0
        self.options = 0
        self.schedule = None
        self.duration = 84 * 8

    def set_repltimes_from_schedule(self, schedule):
        """Convert the schedule and calculate duration

        :param schdule: the schedule to convert
        """
        self.schedule = convert_schedule_to_repltimes(schedule)
        self.duration = total_schedule(self.schedule)


def total_schedule(schedule):
    """Return the total number of 15 minute windows in which the schedule
    is set to replicate in a week. If the schedule is None it is
    assumed that the replication will happen in every 15 minute
    window.

    This is essentially a bit population count.
    """

    if schedule is None:
        return 84 * 8  # 84 bytes = 84 * 8 bits

    total = 0
    for byte in schedule:
        while byte != 0:
            total += byte & 1
            byte >>= 1
    return total


def convert_schedule_to_repltimes(schedule):
    """Convert NTDS Connection schedule to replTime schedule.

    Schedule defined in  MS-ADTS 6.1.4.5.2
    ReplTimes defined in MS-DRSR 5.164.

    "Schedule" has 168 bytes but only the lower nibble of each is
    significant. There is one byte per hour. Bit 3 (0x08) represents
    the first 15 minutes of the hour and bit 0 (0x01) represents the
    last 15 minutes. The first byte presumably covers 12am - 1am
    Sunday, though the spec doesn't define the start of a week.

    "ReplTimes" has 84 bytes which are the 168 lower nibbles of
    "Schedule" packed together. Thus each byte covers 2 hours. Bits 7
    (i.e. 0x80) is the first 15 minutes and bit 0 is the last. The
    first byte covers Sunday 12am - 2am (per spec).

    Here we pack two elements of the NTDS Connection schedule slots
    into one element of the replTimes list.

    If no schedule appears in NTDS Connection then a default of 0x11
    is set in each replTimes slot as per behaviour noted in a Windows
    DC. That default would cause replication within the last 15
    minutes of each hour.
    """
    # note, NTDSConnection schedule == None means "once an hour"
    # repl_info == None means "always"
    if schedule is None or schedule.dataArray[0] is None:
        return [0x11] * 84

    times = []
    data = schedule.dataArray[0].slots

    for i in range(84):
        times.append((data[i * 2] & 0xF) << 4 | (data[i * 2 + 1] & 0xF))

    return times


def combine_repl_info(info_a, info_b):
    """Generate an repl_info combining two others

    The schedule is set to be the intersection of the two input schedules.
    The duration is set to be the duration of the new schedule.
    The cost is the sum of the costs (saturating at a huge value).
    The options are the intersection of the input options.
    The interval is the maximum of the two intervals.

    :param info_a: An input replInfo object
    :param info_b: An input replInfo object
    :return: a new ReplInfo combining the other 2
    """
    info_c = ReplInfo()
    info_c.interval = max(info_a.interval, info_b.interval)
    info_c.options = info_a.options & info_b.options

    # schedule of None defaults to "always"
    if info_a.schedule is None:
        info_a.schedule = [0xFF] * 84
    if info_b.schedule is None:
        info_b.schedule = [0xFF] * 84

    info_c.schedule = [a & b for a, b in zip(info_a.schedule, info_b.schedule)]
    info_c.duration = total_schedule(info_c.schedule)

    info_c.cost = min(info_a.cost + info_b.cost, MAX_DWORD)
    return info_c


def get_spanning_tree_edges(graph, my_site, label=None, verify=False,
                            dot_file_dir=None):
    """Find edges for the intersite graph

    From MS-ADTS 6.2.2.3.4.4

    :param graph: a kcc.kcc_utils.Graph object
    :param my_site: the topology generator's site
    :param label: a label for use in dot files and verification
    :param verify: if True, try to verify that graph properties are correct
    :param dot_file_dir: if not None, write Graphviz dot files here
    """
    # Phase 1: Run Dijkstra's to get a list of internal edges, which are
    # just the shortest-paths connecting colored vertices

    internal_edges = set()

    for e_set in graph.edge_set:
        edgeType = None
        for v in graph.vertices:
            v.edges = []

        # All con_type in an edge set is the same
        for e in e_set.edges:
            edgeType = e.con_type
            for v in e.vertices:
                v.edges.append(e)

        if verify or dot_file_dir is not None:
            graph_edges = [(a.site.site_dnstr, b.site.site_dnstr)
                           for a, b in
                           itertools.chain(
                               *(itertools.combinations(edge.vertices, 2)
                                 for edge in e_set.edges))]
            graph_nodes = [v.site.site_dnstr for v in graph.vertices]

            if dot_file_dir is not None:
                write_dot_file('edgeset_%s' % (edgeType,), graph_edges,
                               vertices=graph_nodes, label=label)

            if verify:
                errors = verify_graph(graph_edges, vertices=graph_nodes,
                                      properties=('complete', 'connected'))
                if errors:
                    DEBUG('spanning tree edge set %s FAILED' % edgeType)
                    for p, e, doc in errors:
                        DEBUG("%18s: %s" % (p, e))
                    raise KCCError("spanning tree failed")

        # Run dijkstra's algorithm with just the red vertices as seeds
        # Seed from the full replicas
        dijkstra(graph, edgeType, False)

        # Process edge set
        process_edge_set(graph, e_set, internal_edges)

        # Run dijkstra's algorithm with red and black vertices as the seeds
        # Seed from both full and partial replicas
        dijkstra(graph, edgeType, True)

        # Process edge set
        process_edge_set(graph, e_set, internal_edges)

    # All vertices have root/component as itself
    setup_vertices(graph)
    process_edge_set(graph, None, internal_edges)

    if verify or dot_file_dir is not None:
        graph_edges = [(e.v1.site.site_dnstr, e.v2.site.site_dnstr)
                       for e in internal_edges]
        graph_nodes = [v.site.site_dnstr for v in graph.vertices]
        verify_properties = ('multi_edge_forest',)
        verify_and_dot('prekruskal', graph_edges, graph_nodes, label=label,
                       properties=verify_properties, debug=DEBUG,
                       verify=verify, dot_file_dir=dot_file_dir)

    # Phase 2: Run Kruskal's on the internal edges
    output_edges, components = kruskal(graph, internal_edges)

    # This recalculates the cost for the path connecting the
    # closest red vertex. Ignoring types is fine because NO
    # suboptimal edge should exist in the graph
    dijkstra(graph, "EDGE_TYPE_ALL", False)  # TODO rename
    # Phase 3: Process the output
    for v in graph.vertices:
        if v.is_red():
            v.dist_to_red = 0
        else:
            v.dist_to_red = v.repl_info.cost

    if verify or dot_file_dir is not None:
        graph_edges = [(e.v1.site.site_dnstr, e.v2.site.site_dnstr)
                       for e in internal_edges]
        graph_nodes = [v.site.site_dnstr for v in graph.vertices]
        verify_properties = ('multi_edge_forest',)
        verify_and_dot('postkruskal', graph_edges, graph_nodes,
                       label=label, properties=verify_properties,
                       debug=DEBUG, verify=verify,
                       dot_file_dir=dot_file_dir)

    # Ensure only one-way connections for partial-replicas,
    # and make sure they point the right way.
    edge_list = []
    for edge in output_edges:
        # We know these edges only have two endpoints because we made
        # them.
        v, w = edge.vertices
        if v.site is my_site or w.site is my_site:
            if (((v.is_black() or w.is_black()) and
                 v.dist_to_red != MAX_DWORD)):
                edge.directed = True

                if w.dist_to_red < v.dist_to_red:
                    edge.vertices[:] = w, v
            edge_list.append(edge)

    if verify or dot_file_dir is not None:
        graph_edges = [[x.site.site_dnstr for x in e.vertices]
                       for e in edge_list]
        # add the reverse edge if not directed.
        graph_edges.extend([x.site.site_dnstr
                            for x in reversed(e.vertices)]
                           for e in edge_list if not e.directed)
        graph_nodes = [x.site.site_dnstr for x in graph.vertices]
        verify_properties = ()
        verify_and_dot('post-one-way-partial', graph_edges, graph_nodes,
                       label=label, properties=verify_properties,
                       debug=DEBUG, verify=verify,
                       directed=True,
                       dot_file_dir=dot_file_dir)

    # count the components
    return edge_list, components


def create_edge(con_type, site_link, guid_to_vertex):
    """Set up a MultiEdge for the intersite graph

    A MultiEdge can have multiple vertices.

    From MS-ADTS 6.2.2.3.4.4

    :param con_type: a transport type GUID
    :param  site_link: a kcc.kcc_utils.SiteLink object
    :param guid_to_vertex: a mapping between GUIDs and vertices
    :return: a MultiEdge
    """
    e = MultiEdge()
    e.site_link = site_link
    e.vertices = []
    for site_guid, site_dn in site_link.site_list:
        if str(site_guid) in guid_to_vertex:
            e.vertices.extend(guid_to_vertex.get(str(site_guid)))
    e.repl_info.cost = site_link.cost
    e.repl_info.options = site_link.options
    e.repl_info.interval = site_link.interval
    e.repl_info.set_repltimes_from_schedule(site_link.schedule)
    e.con_type = con_type
    e.directed = False
    return e


def create_auto_edge_set(graph, transport_guid):
    """Set up an automatic MultiEdgeSet for the intersite graph

    From within MS-ADTS 6.2.2.3.4.4

    :param graph: the intersite graph object
    :param transport_guid: a transport type GUID
    :return: a MultiEdgeSet
    """
    e_set = MultiEdgeSet()
    # use a NULL guid, not associated with a SiteLinkBridge object
    e_set.guid = misc.GUID()
    for site_link in graph.edges:
        if site_link.con_type == transport_guid:
            e_set.edges.append(site_link)

    return e_set


def setup_vertices(graph):
    """Initialise vertices in the graph for the Dijkstra's run.

    Part of MS-ADTS 6.2.2.3.4.4

    The schedule and options are set to all-on, so that intersections
    with real data defer to that data.

    Refer to the convert_schedule_to_repltimes() docstring for an
    explanation of the repltimes schedule values.

    :param graph: an IntersiteGraph object
    :return: None
    """
    for v in graph.vertices:
        if v.is_white():
            v.repl_info.cost = MAX_DWORD
            v.root = None
            v.component_id = None
        else:
            v.repl_info.cost = 0
            v.root = v
            v.component_id = v

        v.repl_info.interval = 0
        v.repl_info.options = 0xFFFFFFFF
        # repl_info.schedule == None means "always".
        v.repl_info.schedule = None
        v.repl_info.duration = 84 * 8
        v.demoted = False


def dijkstra(graph, edge_type, include_black):
    """Perform Dijkstra's algorithm on an intersite graph.

    :param graph: an IntersiteGraph object
    :param edge_type: a transport type GUID
    :param include_black: boolean, whether to include black vertices
    :return: None
    """
    queue = setup_dijkstra(graph, edge_type, include_black)
    while len(queue) > 0:
        cost, guid, vertex = heapq.heappop(queue)
        for edge in vertex.edges:
            for v in edge.vertices:
                if v is not vertex:
                    # add new path from vertex to v
                    try_new_path(graph, queue, vertex, edge, v)


def setup_dijkstra(graph, edge_type, include_black):
    """Create a vertex queue for Dijksta's algorithm.

    :param graph: an IntersiteGraph object
    :param edge_type: a transport type GUID
    :param include_black: boolean, whether to include black vertices
    :return: A heap queue of vertices
    """
    queue = []
    setup_vertices(graph)
    for vertex in graph.vertices:
        if vertex.is_white():
            continue

        if (((vertex.is_black() and not include_black)
             or edge_type not in vertex.accept_black
             or edge_type not in vertex.accept_red_red)):
            vertex.repl_info.cost = MAX_DWORD
            vertex.root = None  # NULL GUID
            vertex.demoted = True  # Demoted appears not to be used
        else:
            heapq.heappush(queue, (vertex.repl_info.cost, vertex.guid, vertex))

    return queue


def try_new_path(graph, queue, vfrom, edge, vto):
    """Helper function for Dijksta's algorithm.

    :param graph: an IntersiteGraph object
    :param queue: the empty queue to initialise.
    :param vfrom: Vertex we are coming from
    :param edge: an edge to try
    :param vto: the other Vertex
    :return: None
    """
    new_repl_info = combine_repl_info(vfrom.repl_info, edge.repl_info)

    # Cheaper or longer schedule goes in the heap

    if (new_repl_info.cost < vto.repl_info.cost or
        new_repl_info.duration > vto.repl_info.duration):
        vto.root = vfrom.root
        vto.component_id = vfrom.component_id
        vto.repl_info = new_repl_info
        heapq.heappush(queue, (vto.repl_info.cost, vto.guid, vto))


def check_demote_vertex(vertex, edge_type):
    """Demote non-white vertices that accept only white edges

    This makes them seem temporarily like white vertices.

    :param vertex: a Vertex()
    :param edge_type: a transport type GUID
    :return: None
    """
    if vertex.is_white():
        return

    # Accepts neither red-red nor black edges, demote
    if ((edge_type not in vertex.accept_black and
         edge_type not in vertex.accept_red_red)):
        vertex.repl_info.cost = MAX_DWORD
        vertex.root = None
        vertex.demoted = True  # Demoted appears not to be used


def undemote_vertex(vertex):
    """Un-demote non-white vertices

    Set a vertex's to an undemoted state.

    :param vertex: a Vertex()
    :return: None
    """
    if vertex.is_white():
        return

    vertex.repl_info.cost = 0
    vertex.root = vertex
    vertex.demoted = False


def process_edge_set(graph, e_set, internal_edges):
    """Find internal edges to pass to Kruskal's algorithm

    :param graph: an IntersiteGraph object
    :param e_set: an edge set
    :param internal_edges: a set that internal edges get added to
    :return: None
    """
    if e_set is None:
        for edge in graph.edges:
            for vertex in edge.vertices:
                check_demote_vertex(vertex, edge.con_type)
            process_edge(graph, edge, internal_edges)
            for vertex in edge.vertices:
                undemote_vertex(vertex)
    else:
        for edge in e_set.edges:
            process_edge(graph, edge, internal_edges)


def process_edge(graph, examine, internal_edges):
    """Find the set of all vertices touching an edge to examine

    :param graph: an IntersiteGraph object
    :param examine: an edge
    :param internal_edges: a set that internal edges get added to
    :return: None
    """
    vertices = []
    for v in examine.vertices:
        # Append a 4-tuple of color, repl cost, guid and vertex
        vertices.append((v.color, v.repl_info.cost, v.ndrpacked_guid, v))
    # Sort by color, lower
    DEBUG("vertices is %s" % vertices)
    vertices.sort()

    color, cost, guid, bestv = vertices[0]
    # Add to internal edges an edge from every colored vertex to bestV
    for v in examine.vertices:
        if v.component_id is None or v.root is None:
            continue

        # Only add edge if valid inter-tree edge - needs a root and
        # different components
        if ((bestv.component_id is not None and
             bestv.root is not None and
             v.component_id is not None and
             v.root is not None and
             bestv.component_id != v.component_id)):
            add_int_edge(graph, internal_edges, examine, bestv, v)


def add_int_edge(graph, internal_edges, examine, v1, v2):
    """Add edges between compatible red and black vertices

    Internal edges form the core of the tree -- white and RODC
    vertices attach to it as leaf nodes. An edge needs to have black
    or red endpoints with compatible replication schedules to be
    accepted as an internal edge.

    Here we examine an edge and add it to the set of internal edges if
    it looks good.

    :param graph: the graph object.
    :param internal_edges: a set of internal edges
    :param examine: an edge to examine for suitability.
    :param v1: a Vertex
    :param v2: the other Vertex
    """
    root1 = v1.root
    root2 = v2.root

    red_red = root1.is_red() and root2.is_red()

    if red_red:
        if (examine.con_type not in root1.accept_red_red
            or examine.con_type not in root2.accept_red_red):
            return
    elif (examine.con_type not in root1.accept_black
          or examine.con_type not in root2.accept_black):
        return

    # Create the transitive replInfo for the two trees and this edge
    ri = combine_repl_info(v1.repl_info, v2.repl_info)
    if ri.duration == 0:
        return

    ri2 = combine_repl_info(ri, examine.repl_info)
    if ri2.duration == 0:
        return

    # Order by vertex guid
    if root1.ndrpacked_guid > root2.ndrpacked_guid:
        root1, root2 = root2, root1

    newIntEdge = InternalEdge(root1, root2, red_red, ri2, examine.con_type,
                              examine.site_link)

    internal_edges.add(newIntEdge)


def kruskal(graph, edges):
    """Perform Kruskal's algorithm using the given set of edges

    The input edges are "internal edges" -- between red and black
    nodes. The output edges are a minimal spanning tree.

    :param graph: the graph object.
    :param edges: a set of edges
    :return: a tuple of a list of edges, and the number of components
    """
    for v in graph.vertices:
        v.edges = []

    components = set([x for x in graph.vertices if not x.is_white()])
    edges = list(edges)

    # Sorted based on internal comparison function of internal edge
    edges.sort()

    # XXX expected_num_tree_edges is never used
    expected_num_tree_edges = 0  # TODO this value makes little sense

    count_edges = 0
    output_edges = []
    index = 0
    while index < len(edges):  # TODO and num_components > 1
        e = edges[index]
        parent1 = find_component(e.v1)
        parent2 = find_component(e.v2)
        if parent1 is not parent2:
            count_edges += 1
            add_out_edge(graph, output_edges, e)
            parent1.component_id = parent2
            components.discard(parent1)

        index += 1

    return output_edges, len(components)


def find_component(vertex):
    """Kruskal helper to find the component a vertex belongs to.

    :param vertex: a Vertex
    :return: the Vertex object representing the component
    """
    if vertex.component_id is vertex:
        return vertex

    current = vertex
    while current.component_id is not current:
        current = current.component_id

    root = current
    current = vertex
    while current.component_id is not root:
        n = current.component_id
        current.component_id = root
        current = n

    return root


def add_out_edge(graph, output_edges, e):
    """Kruskal helper to add output edges

    :param graph: the InterSiteGraph
    :param output_edges: the list of spanning tree edges
    :param e: the edge to be added
    :return: None
    """
    v1 = e.v1
    v2 = e.v2

    # This multi-edge is a 'real' undirected 2-vertex edge with no
    # GUID. XXX It is not really the same thing at all as the
    # multi-vertex edges relating to site-links. We shouldn't really
    # be using the same class or storing them in the same list as the
    # other ones. But we do. Historical reasons.
    ee = MultiEdge()
    ee.directed = False
    ee.site_link = e.site_link
    ee.vertices.append(v1)
    ee.vertices.append(v2)
    ee.con_type = e.e_type
    ee.repl_info = e.repl_info
    output_edges.append(ee)

    v1.edges.append(ee)
    v2.edges.append(ee)


def setup_graph(part, site_table, transport_guid, sitelink_table,
                bridges_required):
    """Set up an IntersiteGraph based on intersite topology

    The graph will have a Vertex for each site, a MultiEdge for each
    siteLink object, and a MultiEdgeSet for each siteLinkBridge object
    (or implied siteLinkBridge).

    :param part: the partition we are dealing with
    :param site_table: a mapping of guids to sites (KCC.site_table)
    :param transport_guid: the GUID of the IP transport
    :param sitelink_table: a mapping of dnstrs to sitelinks
    :param bridges_required: boolean, asking in vain for something to do
         with site link bridges
    :return: a new IntersiteGraph
    """
    guid_to_vertex = {}
    # Create graph
    g = IntersiteGraph()
    # Add vertices
    for site_guid, site in site_table.items():
        vertex = Vertex(site, part)
        vertex.guid = site_guid
        vertex.ndrpacked_guid = ndr_pack(site.site_guid)
        g.vertices.add(vertex)
        guid_vertices = guid_to_vertex.setdefault(site_guid, [])
        guid_vertices.append(vertex)

    connected_vertices = set()

    for site_link_dn, site_link in sitelink_table.items():
        new_edge = create_edge(transport_guid, site_link,
                               guid_to_vertex)
        connected_vertices.update(new_edge.vertices)
        g.edges.add(new_edge)

    # XXX we are ignoring the bridges_required option and indeed the
    # whole concept of SiteLinkBridge objects.
    if bridges_required:
        WARN("Samba KCC ignores the bridges required option")

    g.edge_set.add(create_auto_edge_set(g, transport_guid))
    g.connected_vertices = connected_vertices

    return g


class VertexColor(object):
    """Enumeration of vertex colours"""
    (red, black, white, unknown) = range(0, 4)


class Vertex(object):
    """intersite graph representation of a Site.

    There is a separate vertex for each partition.

    :param site: the site to make a vertex of.
    :param part: the partition.
    """
    def __init__(self, site, part):
        self.site = site
        self.part = part
        self.color = VertexColor.unknown
        self.edges = []
        self.accept_red_red = []
        self.accept_black = []
        self.repl_info = ReplInfo()
        self.root = self
        self.guid = None
        self.component_id = self
        self.demoted = False
        self.options = 0
        self.interval = 0

    def color_vertex(self):
        """Color to indicate which kind of NC replica the vertex contains
        """
        # IF s contains one or more DCs with full replicas of the
        # NC cr!nCName
        #    SET v.Color to COLOR.RED
        # ELSEIF s contains one or more partial replicas of the NC
        #    SET v.Color to COLOR.BLACK
        # ELSE
        #    SET v.Color to COLOR.WHITE

        # set to minimum (no replica)
        self.color = VertexColor.white

        for dnstr, dsa in self.site.dsa_table.items():
            rep = dsa.get_current_replica(self.part.nc_dnstr)
            if rep is None:
                continue

            # We have a full replica which is the largest
            # value so exit
            if not rep.is_partial():
                self.color = VertexColor.red
                break
            else:
                self.color = VertexColor.black

    def is_red(self):
        assert(self.color != VertexColor.unknown)
        return (self.color == VertexColor.red)

    def is_black(self):
        assert(self.color != VertexColor.unknown)
        return (self.color == VertexColor.black)

    def is_white(self):
        assert(self.color != VertexColor.unknown)
        return (self.color == VertexColor.white)


class IntersiteGraph(object):
    """Graph for representing the intersite"""
    def __init__(self):
        self.vertices = set()
        self.edges = set()
        self.edge_set = set()
        # All vertices that are endpoints of edges
        self.connected_vertices = None


class MultiEdgeSet(object):
    """Defines a multi edge set"""
    def __init__(self):
        self.guid = 0  # objectGuid siteLinkBridge
        self.edges = []


class MultiEdge(object):
    """An "edge" between multiple vertices"""
    def __init__(self):
        self.site_link = None  # object siteLink
        self.vertices = []
        self.con_type = None  # interSiteTransport GUID
        self.repl_info = ReplInfo()
        self.directed = True


class InternalEdge(object):
    """An edge that forms part of the minimal spanning tree

    These are used in the Kruskal's algorithm. Their interesting
    feature isa that they are sortable, with the good edges sorting
    before the bad ones -- lower is better.
    """
    def __init__(self, v1, v2, redred, repl, eType, site_link):
        self.v1 = v1
        self.v2 = v2
        self.red_red = redred
        self.repl_info = repl
        self.e_type = eType
        self.site_link = site_link

    def __hash__(self):
        return hash((
            self.v1, self.v2, self.red_red, self.repl_info, self.e_type,
            self.site_link))

    def __eq__(self, other):
        return not self < other and not other < self

    def __ne__(self, other):
        return self < other or other < self

    def __gt__(self, other):
        return other < self

    def __ge__(self, other):
        return not self < other

    def __le__(self, other):
        return not other < self

    def __lt__(self, other):
        """Here "less than" means "better".

        From within MS-ADTS 6.2.2.3.4.4:

        SORT internalEdges by (descending RedRed,
                               ascending ReplInfo.Cost,
                               descending available time in ReplInfo.Schedule,
                               ascending V1ID,
                               ascending V2ID,
                               ascending Type)
        """
        if self.red_red != other.red_red:
            return self.red_red

        if self.repl_info.cost != other.repl_info.cost:
            return self.repl_info.cost < other.repl_info.cost

        if self.repl_info.duration != other.repl_info.duration:
            return self.repl_info.duration > other.repl_info.duration

        if self.v1.guid != other.v1.guid:
            return self.v1.ndrpacked_guid < other.v1.ndrpacked_guid

        if self.v2.guid != other.v2.guid:
            return self.v2.ndrpacked_guid < other.v2.ndrpacked_guid

        return self.e_type < other.e_type
