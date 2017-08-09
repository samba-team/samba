# Visualisation tools
#
# Copyright (C) Andrew Bartlett 2015, 2018
#
# by Douglas Bagnall <douglas.bagnall@catalyst.net.nz>
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
import sys
from collections import defaultdict

import tempfile
import samba
import samba.getopt as options
from samba.netcmd import Command, SuperCommand, CommandError, Option
from samba.samdb import SamDB
from samba.graph import dot_graph
from samba.graph import distance_matrix, COLOUR_SETS
from ldb import SCOPE_BASE, SCOPE_SUBTREE, LdbError
import time
from samba.kcc import KCC
from samba.kcc.kcc_utils import KCCError

COMMON_OPTIONS = [
    Option("-H", "--URL", help="LDB URL for database or target server",
           type=str, metavar="URL", dest="H"),
    Option("-o", "--output", help="write here (default stdout)",
           type=str, metavar="FILE", default=None),
    Option("--dot", help="Graphviz dot output", dest='format',
           const='dot', action='store_const'),
    Option("--distance", help="Distance matrix graph output (default)",
           dest='format', const='distance', action='store_const'),
    Option("--utf8", help="Use utf-8 Unicode characters",
           action='store_true'),
    Option("--color", help="use color (yes, no, auto)",
           choices=['yes', 'no', 'auto']),
    Option("--color-scheme", help=("use this colour scheme "
                                   "(implies --color=yes)"),
           choices=COLOUR_SETS.keys()),
    Option("-S", "--shorten-names",
           help="don't print long common suffixes",
           action='store_true', default=False),
    Option("-r", "--talk-to-remote", help="query other DCs' databases",
           action='store_true', default=False),
    Option("--no-key", help="omit the explanatory key",
           action='store_false', default=True, dest='key'),
]

TEMP_FILE = '__temp__'


class GraphCommand(Command):
    """Base class for graphing commands"""

    synopsis = "%prog [options]"
    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "versionopts": options.VersionOptions,
        "credopts": options.CredentialsOptions,
    }
    takes_options = COMMON_OPTIONS
    takes_args = ()

    def get_db(self, H, sambaopts, credopts):
        lp = sambaopts.get_loadparm()
        creds = credopts.get_credentials(lp, fallback_machine=True)
        samdb = SamDB(url=H, credentials=creds, lp=lp)
        return samdb

    def get_kcc_and_dsas(self, H, lp, creds):
        """Get a readonly KCC object and the list of DSAs it knows about."""
        unix_now = int(time.time())
        kcc = KCC(unix_now, readonly=True)
        kcc.load_samdb(H, lp, creds)

        dsa_list = kcc.list_dsas()
        dsas = set(dsa_list)
        if len(dsas) != len(dsa_list):
            print("There seem to be duplicate dsas", file=sys.stderr)

        return kcc, dsas

    def write(self, s, fn=None, suffix='.dot'):
        """Decide whether we're dealing with a filename, a tempfile, or
        stdout, and write accordingly.

        :param s: the string to write
        :param fn: a destination
        :param suffix: suffix, if destination is a tempfile

        If fn is None or "-", write to stdout.
        If fn is visualize.TEMP_FILE, write to a temporary file
        Otherwise fn should be a filename to write to.
        """
        if fn is None or fn == '-':
            # we're just using stdout (a.k.a self.outf)
            print(s, file=self.outf)
            return

        if fn is TEMP_FILE:
            fd, fn = tempfile.mkstemp(prefix='samba-tool-visualise',
                                      suffix=suffix)
            f = open(fn, 'w')
            os.close(fd)
        else:
            f = open(fn, 'w')

        f.write(s)
        f.close()
        return fn

    def calc_output_format(self, format, output):
        """Heuristics to work out what output format was wanted."""
        if not format:
            # They told us nothing! We have to work it out for ourselves.
            if output and output.lower().endswith('.dot'):
                return 'dot'
            else:
                return 'distance'
        return format

    def calc_distance_color_scheme(self, color, color_scheme, output):
        """Heuristics to work out the colour scheme for distance matrices.
        Returning None means no colour, otherwise it sould be a colour
        from graph.COLOUR_SETS"""
        if color == 'no':
            return None

        if color == 'auto':
            if isinstance(output, str) and output != '-':
                return None
            if not hasattr(self.outf, 'isatty'):
                # not a real file, perhaps cStringIO in testing
                return None
            if not self.outf.isatty():
                return None

        if color_scheme is None:
            if '256color' in os.environ.get('TERM', ''):
                return 'xterm-256color-heatmap'
            return 'ansi'

        return color_scheme


def colour_hash(x):
    """Generate a randomish but consistent darkish colour based on the
    given object."""
    from hashlib import md5
    c = int(md5(str(x)).hexdigest()[:6], base=16) & 0x7f7f7f
    return '#%06x' % c


def get_partition_maps(samdb):
    """Generate dictionaries mapping short partition names to the
    appropriate DNs."""
    base_dn = samdb.domain_dn()
    short_to_long = {
        "DOMAIN": base_dn,
        "CONFIGURATION": str(samdb.get_config_basedn()),
        "SCHEMA": "CN=Schema,%s" % samdb.get_config_basedn(),
        "DNSDOMAIN": "DC=DomainDnsZones,%s" % base_dn,
        "DNSFOREST": "DC=ForestDnsZones,%s" % base_dn
    }
    long_to_short = {v: k for k, v in short_to_long.iteritems()}
    return short_to_long, long_to_short


class cmd_reps(GraphCommand):
    "repsFrom/repsTo from every DSA"

    takes_options = COMMON_OPTIONS + [
        Option("-p", "--partition", help="restrict to this partition",
               default=None),
    ]

    def run(self, H=None, output=None, shorten_names=False,
            key=True, talk_to_remote=False,
            sambaopts=None, credopts=None, versionopts=None,
            mode='self', partition=None, color=None, color_scheme=None,
            utf8=None, format=None):
        # We use the KCC libraries in readonly mode to get the
        # replication graph.
        lp = sambaopts.get_loadparm()
        creds = credopts.get_credentials(lp, fallback_machine=True)
        local_kcc, dsas = self.get_kcc_and_dsas(H, lp, creds)
        unix_now = local_kcc.unix_now

        # Allow people to say "--partition=DOMAIN" rather than
        # "--partition=DC=blah,DC=..."
        short_partitions, long_partitions = get_partition_maps(local_kcc.samdb)
        if partition is not None:
            partition = short_partitions.get(partition.upper(), partition)
            if partition not in long_partitions:
                raise CommandError("unknown partition %s" % partition)

        # nc_reps is an autovivifying dictionary of dictionaries of lists.
        # nc_reps[partition]['current' | 'needed'] is a list of
        # (dsa dn string, repsFromTo object) pairs.
        nc_reps = defaultdict(lambda: defaultdict(list))

        guid_to_dnstr = {}

        # We run a new KCC for each DSA even if we aren't talking to
        # the remote, because after kcc.run (or kcc.list_dsas) the kcc
        # ends up in a messy state.
        for dsa_dn in dsas:
            kcc = KCC(unix_now, readonly=True)
            if talk_to_remote:
                res = local_kcc.samdb.search(dsa_dn,
                                             scope=SCOPE_BASE,
                                             attrs=["dNSHostName"])
                dns_name = res[0]["dNSHostName"][0]
                print("Attempting to contact ldap://%s (%s)" %
                      (dns_name, dsa_dn),
                      file=sys.stderr)
                try:
                    kcc.load_samdb("ldap://%s" % dns_name, lp, creds)
                except KCCError as e:
                    print("Could not contact ldap://%s (%s)" % (dns_name, e),
                          file=sys.stderr)
                    continue

                kcc.run(H, lp, creds)
            else:
                kcc.load_samdb(H, lp, creds)
                kcc.run(H, lp, creds, forced_local_dsa=dsa_dn)

            dsas_from_here = set(kcc.list_dsas())
            if dsas != dsas_from_here:
                print("found extra DSAs:", file=sys.stderr)
                for dsa in (dsas_from_here - dsas):
                    print("   %s" % dsa, file=sys.stderr)
                print("missing DSAs (known locally, not by %s):" % dsa_dn,
                      file=sys.stderr)
                for dsa in (dsas - dsas_from_here):
                    print("   %s" % dsa, file=sys.stderr)

            for remote_dn in dsas_from_here:
                if mode == 'others' and remote_dn == dsa_dn:
                    continue
                elif mode == 'self' and remote_dn != dsa_dn:
                    continue

                remote_dsa = kcc.get_dsa('CN=NTDS Settings,' + remote_dn)
                kcc.translate_ntdsconn(remote_dsa)
                guid_to_dnstr[str(remote_dsa.dsa_guid)] = remote_dn
                # get_reps_tables() returns two dictionaries mapping
                # dns to NCReplica objects
                c, n = remote_dsa.get_rep_tables()
                for part, rep in c.iteritems():
                    if partition is None or part == partition:
                        nc_reps[part]['current'].append((dsa_dn, rep))
                for part, rep in n.iteritems():
                    if partition is None or part == partition:
                        nc_reps[part]['needed'].append((dsa_dn, rep))

        all_edges = {'needed':  {'to': [], 'from': []},
                     'current': {'to': [], 'from': []}}

        for partname, part in nc_reps.iteritems():
            for state, edgelists in all_edges.iteritems():
                for dsa_dn, rep in part[state]:
                    short_name = long_partitions.get(partname, partname)
                    for r in rep.rep_repsFrom:
                        edgelists['from'].append(
                            (dsa_dn,
                             guid_to_dnstr[str(r.source_dsa_obj_guid)],
                             short_name))
                    for r in rep.rep_repsTo:
                        edgelists['to'].append(
                            (guid_to_dnstr[str(r.source_dsa_obj_guid)],
                             dsa_dn,
                             short_name))

        # Here we have the set of edges. From now it is a matter of
        # interpretation and presentation.

        if self.calc_output_format(format, output) == 'distance':
            color_scheme = self.calc_distance_color_scheme(color,
                                                           color_scheme,
                                                           output)
            header_strings = {
                'from': "RepsFrom objects for %s",
                'to': "RepsTo objects for %s",
            }
            for state, edgelists in all_edges.iteritems():
                for direction, items in edgelists.iteritems():
                    part_edges = defaultdict(list)
                    for src, dest, part in items:
                        part_edges[part].append((src, dest))
                    for part, edges in part_edges.iteritems():
                        s = distance_matrix(None, edges,
                                            utf8=utf8,
                                            colour=color_scheme,
                                            shorten_names=shorten_names,
                                            generate_key=key)

                        s = "\n%s\n%s" % (header_strings[direction] % part, s)
                        self.write(s, output)
            return

        edge_colours = []
        edge_styles = []
        dot_edges = []
        dot_vertices = set()
        used_colours = {}
        key_set = set()
        for state, edgelist in all_edges.iteritems():
            for direction, items in edgelist.iteritems():
                for src, dest, part in items:
                    colour = used_colours.setdefault((part),
                                                     colour_hash((part,
                                                                  direction)))
                    linestyle = 'dotted' if state == 'needed' else 'solid'
                    arrow = 'open' if direction == 'to' else 'empty'
                    dot_vertices.add(src)
                    dot_vertices.add(dest)
                    dot_edges.append((src, dest))
                    edge_colours.append(colour)
                    style = 'style="%s"; arrowhead=%s' % (linestyle, arrow)
                    edge_styles.append(style)
                    key_set.add((part, 'reps' + direction.title(),
                                 colour, style))

        key_items = []
        if key:
            for part, direction, colour, linestyle in sorted(key_set):
                key_items.append((False,
                                  'color="%s"; %s' % (colour, linestyle),
                                  "%s %s" % (part, direction)))
            key_items.append((False,
                              'style="dotted"; arrowhead="open"',
                              "repsFromTo is needed"))
            key_items.append((False,
                              'style="solid"; arrowhead="open"',
                              "repsFromTo currently exists"))

        s = dot_graph(dot_vertices, dot_edges,
                      directed=True,
                      edge_colors=edge_colours,
                      edge_styles=edge_styles,
                      shorten_names=shorten_names,
                      key_items=key_items)

        self.write(s, output)


class NTDSConn(object):
    """Collects observation counts for NTDS connections, so we know
    whether all DSAs agree."""
    def __init__(self, src, dest):
        self.observations = 0
        self.src_attests = False
        self.dest_attests = False
        self.src = src
        self.dest = dest

    def attest(self, attester):
        self.observations += 1
        if attester == self.src:
            self.src_attests = True
        if attester == self.dest:
            self.dest_attests = True


class cmd_ntdsconn(GraphCommand):
    "Draw the NTDSConnection graph"
    def run(self, H=None, output=None, shorten_names=False,
            key=True, talk_to_remote=False,
            sambaopts=None, credopts=None, versionopts=None,
            color=None, color_scheme=None,
            utf8=None, format=None):
        lp = sambaopts.get_loadparm()
        creds = credopts.get_credentials(lp, fallback_machine=True)
        local_kcc, dsas = self.get_kcc_and_dsas(H, lp, creds)

        vertices = set()
        attested_edges = []
        for dsa_dn in dsas:
            if talk_to_remote:
                res = local_kcc.samdb.search(dsa_dn,
                                             scope=SCOPE_BASE,
                                             attrs=["dNSHostName"])
                dns_name = res[0]["dNSHostName"][0]
                try:
                    samdb = self.get_db("ldap://%s" % dns_name, sambaopts,
                                        credopts)
                except LdbError as e:
                    print("Could not contact ldap://%s (%s)" % (dns_name, e),
                          file=sys.stderr)
                    continue

                ntds_dn = samdb.get_dsServiceName()
                dn = samdb.domain_dn()
            else:
                samdb = self.get_db(H, sambaopts, credopts)
                ntds_dn = 'CN=NTDS Settings,' + dsa_dn
                dn = dsa_dn

            vertices.add(ntds_dn)
            # XXX we could also look at schedule
            res = samdb.search(dn,
                               scope=SCOPE_SUBTREE,
                               expression="(objectClass=nTDSConnection)",
                               attrs=['fromServer'],
                               # XXX can't be critical for ldif test
                               #controls=["search_options:1:2"],
                               controls=["search_options:0:2"],
            )

            for msg in res:
                msgdn = str(msg.dn)
                dest_dn = msgdn[msgdn.index(',') + 1:]
                attested_edges.append((msg['fromServer'][0],
                                       dest_dn, ntds_dn))

        # now we overlay all the graphs and generate styles accordingly
        edges = {}
        for src, dest, attester in attested_edges:
            k = (src, dest)
            if k in edges:
                e = edges[k]
            else:
                e = NTDSConn(*k)
                edges[k] = e
            e.attest(attester)

        if self.calc_output_format(format, output) == 'distance':
            color_scheme = self.calc_distance_color_scheme(color,
                                                           color_scheme,
                                                           output)
            if not talk_to_remote:
                # If we are not talking to remote servers, we list all
                # the connections.
                graph_edges = edges.keys()
                title = 'NTDS Connections known to %s' % dsa_dn
                epilog = ''

            else:
                # If we are talking to the remotes, there are
                # interesting cases we can discover. What matters most
                # is that the destination (i.e. owner) knowns about
                # the connection, but it would be worth noting if the
                # source doesn't. Another strange situation could be
                # when a DC thinks there is a connection elsewhere,
                # but the computers allegedly involved don't believe
                # it exists.
                #
                # With limited bandwidth in the table, we mark the
                # edges known to the destination, and note the other
                # cases in a list after the diagram.
                graph_edges = []
                source_denies = []
                dest_denies = []
                both_deny = []
                for e, conn in edges.iteritems():
                    if conn.dest_attests:
                        graph_edges.append(e)
                        if not conn.src_attests:
                            source_denies.append(e)
                    elif conn.src_attests:
                        dest_denies.append(e)
                    else:
                        both_deny.append(e)

                title = 'NTDS Connections known to each destination DC'
                epilog = []
                if both_deny:
                    epilog.append('The following connections are alleged by '
                                  'DCs other than the source and '
                                  'destination:\n')
                    for e in both_deny:
                        epilog.append('  %s -> %s\n' % e)
                if dest_denies:
                    epilog.append('The following connections are alleged by '
                                  'DCs other than the destination but '
                                  'including the source:\n')
                    for e in dest_denies:
                        epilog.append('  %s -> %s\n' % e)
                if source_denies:
                    epilog.append('The following connections '
                                  '(included in the chart) '
                                  'are not known to the source DC:\n')
                    for e in source_denies:
                        epilog.append('  %s -> %s\n' % e)
                epilog = ''.join(epilog)

            s = distance_matrix(sorted(vertices), graph_edges,
                                utf8=utf8,
                                colour=color_scheme,
                                shorten_names=shorten_names,
                                generate_key=key)
            self.write('\n%s\n%s\n%s' % (title, s, epilog), output)
            return

        dot_edges = []
        edge_colours = []
        edge_styles = []
        edge_labels = []
        n_servers = len(dsas)
        for k, e in sorted(edges.iteritems()):
            dot_edges.append(k)
            if e.observations == n_servers or not talk_to_remote:
                edge_colours.append('#000000')
                edge_styles.append('')
            elif e.dest_attests:
                edge_styles.append('')
                if e.src_attests:
                    edge_colours.append('#0000ff')
                else:
                    edge_colours.append('#cc00ff')
            elif e.src_attests:
                edge_colours.append('#ff0000')
                edge_styles.append('style=dashed')
            else:
                edge_colours.append('#ff0000')
                edge_styles.append('style=dotted')

        key_items = []
        if key:
            key_items.append((False,
                              'color="#000000"',
                              "NTDS Connection"))
            for colour, desc in (('#0000ff', "missing from some DCs"),
                                 ('#cc00ff', "missing from source DC")):
                if colour in edge_colours:
                    key_items.append((False, 'color="%s"' % colour, desc))

            for style, desc in (('style=dashed', "unknown to destination"),
                                ('style=dotted',
                                 "unknown to source and destination")):
                if style in edge_styles:
                    key_items.append((False,
                                      'color="#ff0000; %s"' % style,
                                      desc))

        if talk_to_remote:
            title = 'NTDS Connections'
        else:
            title = 'NTDS Connections known to %s' % dsa_dn

        s = dot_graph(sorted(vertices), dot_edges,
                      directed=True,
                      title=title,
                      edge_colors=edge_colours,
                      edge_labels=edge_labels,
                      edge_styles=edge_styles,
                      shorten_names=shorten_names,
                      key_items=key_items)
        self.write(s, output)


class cmd_visualize(SuperCommand):
    """Produces graphical representations of Samba network state"""
    subcommands = {}

    for k, v in globals().iteritems():
        if k.startswith('cmd_'):
            subcommands[k[4:]] = v()
