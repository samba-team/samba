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
from samba.ndr import ndr_pack
from samba.dcerpc import misc

from samba.kcc.debug import DEBUG, DEBUG_FN

from samba.kcc.kcc_utils import MAX_DWORD
from samba.kcc.kcc_utils import ReplInfo, combine_repl_info, total_schedule
from samba.kcc.kcc_utils import convert_schedule_to_repltimes


class VertexColor(object):
    (red, black, white, unknown) = range(0, 4)


class Vertex(object):
    """Class encapsulation of a Site Vertex in the
    intersite topology replication algorithm
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
        """Color each vertex to indicate which kind of NC
        replica it contains
        """
        # IF s contains one or more DCs with full replicas of the
        # NC cr!nCName
        #    SET v.Color to COLOR.RED
        # ELSEIF s contains one or more partial replicas of the NC
        #    SET v.Color to COLOR.BLACK
        #ELSE
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
    def __init__(self):
        self.site_link = None  # object siteLink
        self.vertices = []
        self.con_type = None  # interSiteTransport GUID
        self.repl_info = ReplInfo()
        self.directed = True


class InternalEdge(object):
    def __init__(self, v1, v2, redred, repl, eType, site_link):
        self.v1 = v1
        self.v2 = v2
        self.red_red = redred
        self.repl_info = repl
        self.e_type = eType
        self.site_link = site_link

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

    # TODO compare options and interval
    def __lt__(self, other):
        if self.red_red != other.red_red:
            return self.red_red

        if self.repl_info.cost != other.repl_info.cost:
            return self.repl_info.cost < other.repl_info.cost

        self_time = total_schedule(self.repl_info.schedule)
        other_time = total_schedule(other.repl_info.schedule)
        if self_time != other_time:
            return self_time > other_time

        #XXX guid comparison using ndr_pack
        if self.v1.guid != other.v1.guid:
            return self.v1.ndrpacked_guid < other.v1.ndrpacked_guid

        if self.v2.guid != other.v2.guid:
            return self.v2.ndrpacked_guid < other.v2.ndrpacked_guid

        return self.e_type < other.e_type
