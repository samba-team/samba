# -*- coding: utf-8 -*-
# Tests for samba-tool visualize
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
#
"""Tests for samba-tool visualize ntdsconn using the test ldif
topologies.

We don't test samba-tool visualize reps here because repsTo and
repsFrom are not replicated, and there are actual remote servers to
query.
"""
from __future__ import print_function
import samba
import os
import tempfile
import re
from samba.tests.samba_tool.base import SambaToolCmdTest
from samba.kcc import ldif_import_export
from samba.graph import COLOUR_SETS
from samba.param import LoadParm

MULTISITE_LDIF = os.path.join(os.environ['SRCDIR_ABS'],
                              "testdata/ldif-utils-test-multisite.ldif")

# UNCONNECTED_LDIF is a single site, unconnected 5DC database that was
# created using samba-tool domain join in testenv.
UNCONNECTED_LDIF = os.path.join(os.environ['SRCDIR_ABS'],
                                "testdata/unconnected-intrasite.ldif")

DOMAIN = "DC=ad,DC=samba,DC=example,DC=com"
DN_TEMPLATE = "CN=%s,CN=Servers,CN=%s,CN=Sites,CN=Configuration," + DOMAIN

MULTISITE_LDIF_DSAS = [
    ("WIN01", "Default-First-Site-Name"),
    ("WIN08", "Site-4"),
    ("WIN07", "Site-4"),
    ("WIN06", "Site-3"),
    ("WIN09", "Site-5"),
    ("WIN10", "Site-5"),
    ("WIN02", "Site-2"),
    ("WIN04", "Site-2"),
    ("WIN03", "Site-2"),
    ("WIN05", "Site-2"),
]


def samdb_from_ldif(ldif, tempdir, lp, dsa=None, tag=''):
    if dsa is None:
        dsa_name = 'default-DSA'
    else:
        dsa_name = dsa[:5]
    dburl = os.path.join(tempdir,
                         ("ldif-to-sambdb-%s-%s" %
                          (tag, dsa_name)))
    samdb = ldif_import_export.ldif_to_samdb(dburl, lp, ldif,
                                             forced_local_dsa=dsa)
    return (samdb, dburl)


def collapse_space(s, keep_empty_lines=False):
    lines = []
    for line in s.splitlines():
        line = ' '.join(line.strip().split())
        if line or keep_empty_lines:
            lines.append(line)
    return '\n'.join(lines)


class SambaToolVisualizeLdif(SambaToolCmdTest):
    def setUp(self):
        super(SambaToolVisualizeLdif, self).setUp()
        self.lp = LoadParm()
        self.samdb, self.dbfile = samdb_from_ldif(MULTISITE_LDIF,
                                                  self.tempdir,
                                                  self.lp)
        self.dburl = 'tdb://' + self.dbfile

    def tearDown(self):
        self.remove_files(self.dbfile)
        super(SambaToolVisualizeLdif, self).tearDown()

    def remove_files(self, *files):
        for f in files:
            self.assertTrue(f.startswith(self.tempdir))
            os.unlink(f)

    def test_colour(self):
        """Ensure the colour output is the same as the monochrome output
        EXCEPT for the colours, of which the monochrome one should
        know nothing."""
        colour_re = re.compile('\033' r'\[[\d;]+m')
        result, monochrome, err = self.runsubcmd("visualize", "ntdsconn",
                                                 '-H', self.dburl,
                                                 '--color=no', '-S')
        self.assertCmdSuccess(result, monochrome, err)
        self.assertFalse(colour_re.findall(monochrome))

        colour_args = [['--color=yes']]
        colour_args += [['--color-scheme', x] for x in COLOUR_SETS
                        if x is not None]

        for args in colour_args:
            result, out, err = self.runsubcmd("visualize", "ntdsconn",
                                              '-H', self.dburl,
                                              '-S', *args)
            self.assertCmdSuccess(result, out, err)
            self.assertTrue(colour_re.search(out))
            uncoloured = colour_re.sub('', out)

            self.assertStringsEqual(monochrome, uncoloured, strip=True)

    def test_import_ldif_xdot(self):
        """We can't test actual xdot, but using the environment we can
        persuade samba-tool that a script we write is xdot and ensure
        it gets the right text.
        """
        result, expected, err = self.runsubcmd("visualize", "ntdsconn",
                                               '-H', self.dburl,
                                               '--color=no', '-S',
                                               '--dot')
        self.assertCmdSuccess(result, expected, err)

        # not that we're expecting anything here
        old_xdot_path = os.environ.get('SAMBA_TOOL_XDOT_PATH')

        tmpdir = tempfile.mkdtemp()
        fake_xdot = os.path.join(tmpdir, 'fake_xdot')
        content = os.path.join(tmpdir, 'content')
        f = open(fake_xdot, 'w')
        print('#!/bin/sh', file=f)
        print('cp $1 %s' % content, file=f)
        f.close()
        os.chmod(fake_xdot, 0o700)

        os.environ['SAMBA_TOOL_XDOT_PATH'] = fake_xdot
        result, empty, err = self.runsubcmd("visualize", "ntdsconn",
                                            '--importldif', MULTISITE_LDIF,
                                            '--color=no', '-S',
                                            '--xdot')

        f = open(content)
        xdot = f.read()
        f.close()
        os.remove(fake_xdot)
        os.remove(content)
        os.rmdir(tmpdir)

        if old_xdot_path is not None:
            os.environ['SAMBA_TOOL_XDOT_PATH'] = old_xdot_path
        else:
            del os.environ['SAMBA_TOOL_XDOT_PATH']

        self.assertCmdSuccess(result, xdot, err)
        self.assertStringsEqual(expected, xdot, strip=True)

    def test_import_ldif(self):
        """Make sure the samba-tool visualize --importldif option gives the
        same output as using the externally generated db from the same
        LDIF."""
        result, s1, err = self.runsubcmd("visualize", "ntdsconn",
                                         '-H', self.dburl,
                                         '--color=no', '-S')
        self.assertCmdSuccess(result, s1, err)

        result, s2, err = self.runsubcmd("visualize", "ntdsconn",
                                         '--importldif', MULTISITE_LDIF,
                                         '--color=no', '-S')
        self.assertCmdSuccess(result, s2, err)

        self.assertStringsEqual(s1, s2)

    def test_output_file(self):
        """Check that writing to a file works, with and without
        --color=auto."""
        # NOTE, we can't really test --color=auto works with a TTY.
        colour_re = re.compile('\033' r'\[[\d;]+m')
        result, expected, err = self.runsubcmd("visualize", "ntdsconn",
                                               '-H', self.dburl,
                                               '--color=auto', '-S')
        self.assertCmdSuccess(result, expected, err)
        # Not a TTY, so stdout output should be colourless
        self.assertFalse(colour_re.search(expected))
        expected = expected.strip()

        color_auto_file = os.path.join(self.tempdir, 'color-auto')

        result, out, err = self.runsubcmd("visualize", "ntdsconn",
                                          '-H', self.dburl,
                                          '--color=auto', '-S',
                                          '-o', color_auto_file)
        self.assertCmdSuccess(result, out, err)
        # We wrote to file, so stdout should be empty
        self.assertEqual(out, '')
        f = open(color_auto_file)
        color_auto = f.read()
        f.close()
        self.assertStringsEqual(color_auto, expected, strip=True)
        self.remove_files(color_auto_file)

        color_no_file = os.path.join(self.tempdir, 'color-no')
        result, out, err = self.runsubcmd("visualize", "ntdsconn",
                                          '-H', self.dburl,
                                          '--color=no', '-S',
                                          '-o', color_no_file)
        self.assertCmdSuccess(result, out, err)
        self.assertEqual(out, '')
        f = open(color_no_file)
        color_no = f.read()
        f.close()
        self.remove_files(color_no_file)

        self.assertStringsEqual(color_no, expected, strip=True)

        color_yes_file = os.path.join(self.tempdir, 'color-no')
        result, out, err = self.runsubcmd("visualize", "ntdsconn",
                                          '-H', self.dburl,
                                          '--color=yes', '-S',
                                          '-o', color_yes_file)
        self.assertCmdSuccess(result, out, err)
        self.assertEqual(out, '')
        f = open(color_yes_file)
        colour_yes = f.read()
        f.close()
        self.assertNotEqual(colour_yes.strip(), expected)

        self.remove_files(color_yes_file)

        # Try the magic filename "-", meaning stdout.
        # This doesn't exercise the case when stdout is a TTY
        for c, equal in [('no', True), ('auto', True), ('yes', False)]:
            result, out, err = self.runsubcmd("visualize", "ntdsconn",
                                              '-H', self.dburl,
                                              '--color', c,
                                              '-S', '-o', '-')
            self.assertCmdSuccess(result, out, err)
            self.assertEqual((out.strip() == expected), equal)

    def test_utf8(self):
        """Ensure that --utf8 adds at least some expected utf-8, and that it
        isn't there without --utf8."""
        result, utf8, err = self.runsubcmd("visualize", "ntdsconn",
                                           '-H', self.dburl,
                                           '--color=no', '-S', '--utf8')
        self.assertCmdSuccess(result, utf8, err)

        result, ascii, err = self.runsubcmd("visualize", "ntdsconn",
                                            '-H', self.dburl,
                                            '--color=no', '-S')
        self.assertCmdSuccess(result, ascii, err)
        for c in ('│', '─', '╭'):
            self.assertTrue(c in utf8, 'UTF8 should contain %s' % c)
            self.assertTrue(c not in ascii, 'ASCII should not contain %s' % c)

    def test_forced_local_dsa(self):
        # the forced_local_dsa shouldn't make any difference, except
        # for the title line.
        result, target, err = self.runsubcmd("visualize", "ntdsconn",
                                             '-H', self.dburl,
                                             '--color=no', '-S')
        self.assertCmdSuccess(result, target, err)
        files = []
        target = target.strip().split('\n', 1)[1]
        for cn, site in MULTISITE_LDIF_DSAS:
            dsa = DN_TEMPLATE % (cn, site)
            samdb, dbfile = samdb_from_ldif(MULTISITE_LDIF,
                                            self.tempdir,
                                            self.lp, dsa,
                                            tag=cn)

            result, out, err = self.runsubcmd("visualize", "ntdsconn",
                                              '-H', 'tdb://' + dbfile,
                                              '--color=no', '-S')
            self.assertCmdSuccess(result, out, err)
            # Separate out the title line, which will differ in the DN.
            title, body = out.strip().split('\n', 1)
            self.assertStringsEqual(target, body)
            self.assertIn(cn, title)
            files.append(dbfile)
        self.remove_files(*files)

    def test_short_names(self):
        """Ensure the colour ones are the same as the monochrome ones EXCEPT
        for the colours, of which the monochrome one should know nothing"""
        result, short, err = self.runsubcmd("visualize", "ntdsconn",
                                            '-H', self.dburl,
                                            '--color=no', '-S', '--no-key')
        self.assertCmdSuccess(result, short, err)
        result, long, err = self.runsubcmd("visualize", "ntdsconn",
                                           '-H', self.dburl,
                                           '--color=no', '--no-key')
        self.assertCmdSuccess(result, long, err)

        lines = short.split('\n')
        replacements = []
        key_lines = ['']
        short_without_key = []
        for line in lines:
            m = re.match(r"'(.{1,2})' stands for '(.+)'", line)
            if m:
                a, b = m.groups()
                replacements.append((len(a), a, b))
                key_lines.append(line)
            else:
                short_without_key.append(line)

        short = '\n'.join(short_without_key)
        # we need to replace longest strings first
        replacements.sort(reverse=True)
        short2long = short
        # we don't want to shorten the DC name in the header line.
        long_header, long2short = long.strip().split('\n', 1)
        for _, a, b in replacements:
            short2long = short2long.replace(a, b)
            long2short = long2short.replace(b, a)

        long2short = '%s\n%s' % (long_header, long2short)

        # The white space is going to be all wacky, so lets squish it down
        short2long = collapse_space(short2long)
        long2short = collapse_space(long2short)
        short = collapse_space(short)
        long = collapse_space(long)

        self.assertStringsEqual(short2long, long, strip=True)
        self.assertStringsEqual(short, long2short, strip=True)

    def test_disconnected_ldif_with_key(self):
        """Test that the 'unconnected' ldif shows up and exactly matches the
        expected output."""
        # This is not truly a disconnected graph because the
        # vampre/local/promoted DCs are in there and they have
        # relationships, and SERVER2 and SERVER3 for some reason refer
        # to them.

        samdb, dbfile = samdb_from_ldif(UNCONNECTED_LDIF,
                                        self.tempdir,
                                        self.lp, tag='disconnected')
        dburl = 'tdb://' + dbfile
        result, output, err = self.runsubcmd("visualize", "ntdsconn",
                                             '-H', dburl,
                                             '--color=no', '-S')
        self.remove_files(dbfile)
        self.assertCmdSuccess(result, output, err)
        self.assertStringsEqual(output,
                                EXPECTED_DISTANCE_GRAPH_WITH_KEY)

    def test_dot_ntdsconn(self):
        """Graphviz NTDS Connection output"""
        result, dot, err = self.runsubcmd("visualize", "ntdsconn",
                                          '-H', self.dburl,
                                          '--color=no', '-S', '--dot',
                                          '--no-key')
        self.assertCmdSuccess(result, dot, err)
        self.assertStringsEqual(EXPECTED_DOT_MULTISITE_NO_KEY, dot)

    def test_dot_ntdsconn_disconnected(self):
        """Graphviz NTDS Connection output from disconnected graph"""
        samdb, dbfile = samdb_from_ldif(UNCONNECTED_LDIF,
                                        self.tempdir,
                                        self.lp, tag='disconnected')

        result, dot, err = self.runsubcmd("visualize", "ntdsconn",
                                          '-H', 'tdb://' + dbfile,
                                          '--color=no', '-S', '--dot',
                                          '-o', '-')
        self.assertCmdSuccess(result, dot, err)
        self.remove_files(dbfile)
        self.assertStringsEqual(EXPECTED_DOT_NTDSCONN_DISCONNECTED, dot,
                                strip=True)

    def test_dot_ntdsconn_disconnected_to_file(self):
        """Graphviz NTDS Connection output into a file"""
        samdb, dbfile = samdb_from_ldif(UNCONNECTED_LDIF,
                                        self.tempdir,
                                        self.lp, tag='disconnected')

        dot_file = os.path.join(self.tempdir, 'dotfile')

        result, dot, err = self.runsubcmd("visualize", "ntdsconn",
                                          '-H', 'tdb://' + dbfile,
                                          '--color=no', '-S', '--dot',
                                          '-o', dot_file)
        self.assertCmdSuccess(result, dot, err)
        f = open(dot_file)
        dot = f.read()
        f.close()
        self.assertStringsEqual(EXPECTED_DOT_NTDSCONN_DISCONNECTED, dot)

        self.remove_files(dbfile, dot_file)


EXPECTED_DOT_MULTISITE_NO_KEY = r"""/* generated by samba */
digraph A_samba_tool_production {
label="NTDS Connections known to CN=WIN01,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=ad,DC=samba,DC=example,DC=com";
fontsize=10;

node[fontname=Helvetica; fontsize=10];

"CN=NTDS Settings,\nCN=WIN01,\nCN=Servers,\nCN=Default-\nFirst-Site-Name,\n...";
"CN=NTDS Settings,\nCN=WIN02,\nCN=Servers,\nCN=Site-2,\n...";
"CN=NTDS Settings,\nCN=WIN03,\nCN=Servers,\nCN=Site-2,\n...";
"CN=NTDS Settings,\nCN=WIN04,\nCN=Servers,\nCN=Site-2,\n...";
"CN=NTDS Settings,\nCN=WIN05,\nCN=Servers,\nCN=Site-2,\n...";
"CN=NTDS Settings,\nCN=WIN06,\nCN=Servers,\nCN=Site-3,\n...";
"CN=NTDS Settings,\nCN=WIN07,\nCN=Servers,\nCN=Site-4,\n...";
"CN=NTDS Settings,\nCN=WIN08,\nCN=Servers,\nCN=Site-4,\n...";
"CN=NTDS Settings,\nCN=WIN09,\nCN=Servers,\nCN=Site-5,\n...";
"CN=NTDS Settings,\nCN=WIN10,\nCN=Servers,\nCN=Site-5,\n...";
"CN=NTDS Settings,\nCN=WIN01,\nCN=Servers,\nCN=Default-\nFirst-Site-Name,\n..." -> "CN=NTDS Settings,\nCN=WIN03,\nCN=Servers,\nCN=Site-2,\n..." [color="#000000", ];
"CN=NTDS Settings,\nCN=WIN01,\nCN=Servers,\nCN=Default-\nFirst-Site-Name,\n..." -> "CN=NTDS Settings,\nCN=WIN06,\nCN=Servers,\nCN=Site-3,\n..." [color="#000000", ];
"CN=NTDS Settings,\nCN=WIN01,\nCN=Servers,\nCN=Default-\nFirst-Site-Name,\n..." -> "CN=NTDS Settings,\nCN=WIN07,\nCN=Servers,\nCN=Site-4,\n..." [color="#000000", ];
"CN=NTDS Settings,\nCN=WIN01,\nCN=Servers,\nCN=Default-\nFirst-Site-Name,\n..." -> "CN=NTDS Settings,\nCN=WIN08,\nCN=Servers,\nCN=Site-4,\n..." [color="#000000", ];
"CN=NTDS Settings,\nCN=WIN01,\nCN=Servers,\nCN=Default-\nFirst-Site-Name,\n..." -> "CN=NTDS Settings,\nCN=WIN10,\nCN=Servers,\nCN=Site-5,\n..." [color="#000000", ];
"CN=NTDS Settings,\nCN=WIN02,\nCN=Servers,\nCN=Site-2,\n..." -> "CN=NTDS Settings,\nCN=WIN04,\nCN=Servers,\nCN=Site-2,\n..." [color="#000000", ];
"CN=NTDS Settings,\nCN=WIN02,\nCN=Servers,\nCN=Site-2,\n..." -> "CN=NTDS Settings,\nCN=WIN05,\nCN=Servers,\nCN=Site-2,\n..." [color="#000000", ];
"CN=NTDS Settings,\nCN=WIN03,\nCN=Servers,\nCN=Site-2,\n..." -> "CN=NTDS Settings,\nCN=WIN04,\nCN=Servers,\nCN=Site-2,\n..." [color="#000000", ];
"CN=NTDS Settings,\nCN=WIN03,\nCN=Servers,\nCN=Site-2,\n..." -> "CN=NTDS Settings,\nCN=WIN05,\nCN=Servers,\nCN=Site-2,\n..." [color="#000000", ];
"CN=NTDS Settings,\nCN=WIN04,\nCN=Servers,\nCN=Site-2,\n..." -> "CN=NTDS Settings,\nCN=WIN01,\nCN=Servers,\nCN=Default-\nFirst-Site-Name,\n..." [color="#000000", ];
"CN=NTDS Settings,\nCN=WIN04,\nCN=Servers,\nCN=Site-2,\n..." -> "CN=NTDS Settings,\nCN=WIN02,\nCN=Servers,\nCN=Site-2,\n..." [color="#000000", ];
"CN=NTDS Settings,\nCN=WIN04,\nCN=Servers,\nCN=Site-2,\n..." -> "CN=NTDS Settings,\nCN=WIN03,\nCN=Servers,\nCN=Site-2,\n..." [color="#000000", ];
"CN=NTDS Settings,\nCN=WIN05,\nCN=Servers,\nCN=Site-2,\n..." -> "CN=NTDS Settings,\nCN=WIN02,\nCN=Servers,\nCN=Site-2,\n..." [color="#000000", ];
"CN=NTDS Settings,\nCN=WIN05,\nCN=Servers,\nCN=Site-2,\n..." -> "CN=NTDS Settings,\nCN=WIN03,\nCN=Servers,\nCN=Site-2,\n..." [color="#000000", ];
"CN=NTDS Settings,\nCN=WIN07,\nCN=Servers,\nCN=Site-4,\n..." -> "CN=NTDS Settings,\nCN=WIN01,\nCN=Servers,\nCN=Default-\nFirst-Site-Name,\n..." [color="#000000", ];
"CN=NTDS Settings,\nCN=WIN09,\nCN=Servers,\nCN=Site-5,\n..." -> "CN=NTDS Settings,\nCN=WIN10,\nCN=Servers,\nCN=Site-5,\n..." [color="#000000", ];
"CN=NTDS Settings,\nCN=WIN10,\nCN=Servers,\nCN=Site-5,\n..." -> "CN=NTDS Settings,\nCN=WIN01,\nCN=Servers,\nCN=Default-\nFirst-Site-Name,\n..." [color="#000000", ];
"CN=NTDS Settings,\nCN=WIN10,\nCN=Servers,\nCN=Site-5,\n..." -> "CN=NTDS Settings,\nCN=WIN09,\nCN=Servers,\nCN=Site-5,\n..." [color="#000000", ];
}

"""


EXPECTED_DOT_NTDSCONN_DISCONNECTED = r"""/* generated by samba */
digraph A_samba_tool_production {
label="NTDS Connections known to CN=LOCALDC,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=samba,DC=example,DC=com";
fontsize=10;

node[fontname=Helvetica; fontsize=10];

"CN=NTDS Settings,\nCN=CLIENT,\n...";
"CN=NTDS Settings,\nCN=LOCALDC,\n...";
"CN=NTDS Settings,\nCN=PROMOTEDVDC,\n...";
"CN=NTDS Settings,\nCN=SERVER1,\n...";
"CN=NTDS Settings,\nCN=SERVER2,\n...";
"CN=NTDS Settings,\nCN=SERVER3,\n...";
"CN=NTDS Settings,\nCN=SERVER4,\n...";
"CN=NTDS Settings,\nCN=SERVER5,\n...";
"CN=NTDS Settings,\nCN=LOCALDC,\n..." -> "CN=NTDS Settings,\nCN=PROMOTEDVDC,\n..." [color="#000000", ];
"CN=NTDS Settings,\nCN=PROMOTEDVDC,\n..." -> "CN=NTDS Settings,\nCN=LOCALDC,\n..." [color="#000000", ];
"CN=NTDS Settings,\nCN=SERVER2,\n..." -> "CN=NTDS Settings,\nCN=PROMOTEDVDC,\n..." [color="#000000", ];
"CN=NTDS Settings,\nCN=SERVER3,\n..." -> "CN=NTDS Settings,\nCN=LOCALDC,\n..." [color="#000000", ];
subgraph cluster_key {
label="Key";
subgraph cluster_key_nodes {
label="";
color = "invis";

}
subgraph cluster_key_edges {
label="";
color = "invis";
subgraph cluster_key_0_ {
key_0_e1[label=src; color="#000000"; group="key_0__g"]
key_0_e2[label=dest; color="#000000"; group="key_0__g"]
key_0_e1 -> key_0_e2 [constraint = false; color="#000000"]
key_0__label[shape=plaintext; style=solid; width=2.000000; label="NTDS Connection\r"]
}
{key_0__label}
}

elision0[shape=plaintext; style=solid; label="\“...”  means  “CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=samba,DC=example,DC=com”\r"]

}
"CN=NTDS Settings,\nCN=CLIENT,\n..." -> key_0__label [style=invis];
"CN=NTDS Settings,\nCN=LOCALDC,\n..." -> key_0__label [style=invis];
"CN=NTDS Settings,\nCN=PROMOTEDVDC,\n..." -> key_0__label [style=invis];
"CN=NTDS Settings,\nCN=SERVER1,\n..." -> key_0__label [style=invis];
"CN=NTDS Settings,\nCN=SERVER2,\n..." -> key_0__label [style=invis];
"CN=NTDS Settings,\nCN=SERVER3,\n..." -> key_0__label [style=invis];
"CN=NTDS Settings,\nCN=SERVER4,\n..." -> key_0__label [style=invis];
"CN=NTDS Settings,\nCN=SERVER5,\n..." -> key_0__label [style=invis]
key_0__label -> elision0 [style=invis; weight=9]

}
"""

EXPECTED_DISTANCE_GRAPH_WITH_KEY = """
NTDS Connections known to CN=LOCALDC,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=samba,DC=example,DC=com

                            destination
                  ,-------- *,CN=CLIENT+
                  |,------- *,CN=LOCALDC+
                  ||,------ *,CN=PROMOTEDVDC+
                  |||,----- *,CN=SERVER1+
                  ||||,---- *,CN=SERVER2+
                  |||||,--- *,CN=SERVER3+
                  ||||||,-- *,CN=SERVER4+
           source |||||||,- *,CN=SERVER5+
     *,CN=CLIENT+ 0-------
    *,CN=LOCALDC+ -01-----
*,CN=PROMOTEDVDC+ -10-----
    *,CN=SERVER1+ ---0----
    *,CN=SERVER2+ -21-0---
    *,CN=SERVER3+ -12--0--
    *,CN=SERVER4+ ------0-
    *,CN=SERVER5+ -------0

'*' stands for 'CN=NTDS Settings'
'+' stands for ',CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=samba,DC=example,DC=com'

Data can get from source to destination in the indicated number of steps.
0 means zero steps (it is the same DC)
1 means a direct link
2 means a transitive link involving two steps (i.e. one intermediate DC)
- means there is no connection, even through other DCs

"""
