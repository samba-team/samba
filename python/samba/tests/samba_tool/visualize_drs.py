# -*- coding: utf-8 -*-
# Originally based on tests for samba.kcc.ldif_import_export.
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
"""Tests for samba-tool visualize using the vampire DC and promoted DC
environments. For most tests we assume we can't assert much about what
state they are in, so we mainly check for command failure, but for
others we try to grasp control of replication and make more specific
assertions.
"""

from __future__ import print_function
import os
import re
import json
import random
import subprocess
from samba.tests.samba_tool.base import SambaToolCmdTest

VERBOSE = False

ENV_DSAS = {
    'promoted_dc': ['CN=PROMOTEDVDC,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=samba,DC=example,DC=com',
                    'CN=LOCALDC,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=samba,DC=example,DC=com'],
    'vampire_dc': ['CN=LOCALDC,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=samba,DC=example,DC=com',
                   'CN=LOCALVAMPIREDC,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=samba,DC=example,DC=com'],
}

PARTITION_NAMES = [
    "DOMAIN",
    "CONFIGURATION",
    "SCHEMA",
    "DNSDOMAIN",
    "DNSFOREST",
]

def adjust_cmd_for_py_version(parts):
    if os.getenv("PYTHON", None):
        parts.insert(0, os.environ["PYTHON"])
    return parts

def set_auto_replication(dc, allow):
    credstring = '-U%s%%%s' % (os.environ["USERNAME"], os.environ["PASSWORD"])
    on_or_off = '-' if allow else '+'

    for opt in ['DISABLE_INBOUND_REPL',
                'DISABLE_OUTBOUND_REPL']:
        cmd = adjust_cmd_for_py_version(['bin/samba-tool',
               'drs', 'options',
               credstring, dc,
               "--dsa-option=%s%s" % (on_or_off, opt)])

        subprocess.check_call(cmd)


def force_replication(src, dest, base):
    credstring = '-U%s%%%s' % (os.environ["USERNAME"], os.environ["PASSWORD"])
    cmd = adjust_cmd_for_py_version(['bin/samba-tool',
           'drs', 'replicate',
           dest, src, base,
           credstring,
           '--sync-forced'])

    subprocess.check_call(cmd)


def get_utf8_matrix(s):
    # parse the graphical table *just* well enough for our tests
    # decolourise first
    s = re.sub("\033" r"\[[^m]+m", '', s)
    lines = s.split('\n')
    # matrix rows have '·' on the diagonal
    rows = [x.strip().replace('·', '0') for x in lines if '·' in x]
    names = []
    values = []
    for r in rows:
        parts = r.rsplit(None, len(rows))
        k, v = parts[0], parts[1:]
        # we want the FOO in 'CN=FOO+' or 'CN=FOO,CN=x,DC=...'
        k = re.match(r'cn=([^+,]+)', k.lower()).group(1)
        names.append(k)
        if len(v) == 1:  # this is a single-digit matrix, no spaces
            v = list(v[0])
        values.append([int(x) if x.isdigit() else 1e999 for x in v])

    d = {}
    for n1, row in zip(names, values):
        d[n1] = {}
        for n2, v in zip(names, row):
            d[n1][n2] = v

    return d


class SambaToolVisualizeDrsTest(SambaToolCmdTest):
    def setUp(self):
        super(SambaToolVisualizeDrsTest, self).setUp()

    def test_ntdsconn(self):
        server = "ldap://%s" % os.environ["SERVER"]
        creds = "%s%%%s" % (os.environ["USERNAME"], os.environ["PASSWORD"])
        (result, out, err) = self.runsubcmd("visualize", "ntdsconn",
                                            '-H', server,
                                            '-U', creds,
                                            '--color=no', '-S')
        self.assertCmdSuccess(result, out, err)

    def test_ntdsconn_remote(self):
        server = "ldap://%s" % os.environ["SERVER"]
        creds = "%s%%%s" % (os.environ["USERNAME"], os.environ["PASSWORD"])
        (result, out, err) = self.runsubcmd("visualize", "ntdsconn",
                                            '-H', server,
                                            '-U', creds,
                                            '--color=no', '-S', '-r')
        self.assertCmdSuccess(result, out, err)

    def test_reps(self):
        server = "ldap://%s" % os.environ["SERVER"]
        creds = "%s%%%s" % (os.environ["USERNAME"], os.environ["PASSWORD"])
        (result, out, err) = self.runsubcmd("visualize", "reps",
                                            '-H', server,
                                            '-U', creds,
                                            '--color=no', '-S')
        self.assertCmdSuccess(result, out, err)

    def test_uptodateness_all_partitions(self):
        creds = "%s%%%s" % (os.environ["USERNAME"], os.environ["PASSWORD"])
        dc1 = os.environ["SERVER"]
        dc2 = os.environ["DC_SERVER"]
        # We will check that the visualisation works for the two
        # stopped DCs, but we can't make assertions that the output
        # will be the same because there may be replication between
        # the two calls. Stopping the replication on these ones is not
        # enough because there are other DCs about.
        (result, out, err) = self.runsubcmd("visualize", "uptodateness",
                                            "-r",
                                            '-H', "ldap://%s" % dc1,
                                            '-U', creds,
                                            '--color=no', '-S')
        self.assertCmdSuccess(result, out, err)

        (result, out, err) = self.runsubcmd("visualize", "uptodateness",
                                            "-r",
                                            '-H', "ldap://%s" % dc2,
                                            '-U', creds,
                                            '--color=no', '-S')
        self.assertCmdSuccess(result, out, err)

    def test_uptodateness_partitions(self):
        creds = "%s%%%s" % (os.environ["USERNAME"], os.environ["PASSWORD"])
        dc1 = os.environ["SERVER"]
        for part in PARTITION_NAMES:
            (result, out, err) = self.runsubcmd("visualize", "uptodateness",
                                                "-r",
                                                '-H', "ldap://%s" % dc1,
                                                '-U', creds,
                                                '--color=no', '-S',
                                                '--partition', part)
            self.assertCmdSuccess(result, out, err)

    def test_drs_uptodateness(self):
        """
        Test cmd `drs uptodateness`

        It should print info like this:

            DNSDOMAIN       failure: 4  median: 1.5  maximum: 2
            SCHEMA          failure: 4  median: 220.0  maximum: 439
            DOMAIN          failure: 1  median: 25  maximum: 25
            CONFIGURATION   failure: 1  median: 25  maximum: 25
            DNSFOREST       failure: 4  median: 1.5  maximum: 2

        """
        creds = "%s%%%s" % (os.environ["USERNAME"], os.environ["PASSWORD"])
        dc1 = os.environ["SERVER"]
        dc2 = os.environ["DC_SERVER"]
        for dc in [dc1, dc2]:
            (result, out, err) = self.runsubcmd("drs", "uptodateness",
                                                '-H', "ldap://%s" % dc,
                                                '-U', creds)
            self.assertCmdSuccess(result, out, err)
            # each partition name should be in output
            for part_name in PARTITION_NAMES:
                self.assertIn(part_name, out, msg=out)

            for line in out.splitlines():
                # check keyword in output
                for attr in ['maximum', 'median', 'failure']:
                    self.assertIn(attr, line)

    def test_drs_uptodateness_partition(self):
        """
        Test cmd `drs uptodateness --partition DOMAIN`

        It should print info like this:

            DOMAIN          failure: 1  median: 25  maximum: 25

        """
        creds = "%s%%%s" % (os.environ["USERNAME"], os.environ["PASSWORD"])
        dc1 = os.environ["SERVER"]
        dc2 = os.environ["DC_SERVER"]
        for dc in [dc1, dc2]:
            (result, out, err) = self.runsubcmd("drs", "uptodateness",
                                                '-H', "ldap://%s" % dc,
                                                '-U', creds,
                                                '--partition', 'DOMAIN')
            self.assertCmdSuccess(result, out, err)

            lines = out.splitlines()
            self.assertEqual(len(lines), 1)

            line = lines[0]
            self.assertTrue(line.startswith('DOMAIN'))

    def test_drs_uptodateness_json(self):
        """
        Test cmd `drs uptodateness --json`

        Example output:

            {
                "DNSDOMAIN": {
                    "failure": 0,
                    "median": 0.0,
                    "maximum": 0
                },
                ...
                "SCHEMA": {
                    "failure": 0,
                    "median": 0.0,
                    "maximum": 0
                }
            }
        """
        creds = "%s%%%s" % (os.environ["USERNAME"], os.environ["PASSWORD"])
        dc1 = os.environ["SERVER"]
        dc2 = os.environ["DC_SERVER"]
        for dc in [dc1, dc2]:
            (result, out, err) = self.runsubcmd("drs", "uptodateness",
                                                '-H', "ldap://%s" % dc,
                                                '-U', creds,
                                                '--json')
            self.assertCmdSuccess(result, out, err)
            # should be json format
            obj = json.loads(out)
            # each partition name should be in json obj
            for part_name in PARTITION_NAMES:
                self.assertIn(part_name, obj)
                summary_obj = obj[part_name]
                for attr in ['maximum', 'median', 'failure']:
                    self.assertIn(attr, summary_obj)

    def test_drs_uptodateness_json_median(self):
        """
        Test cmd `drs uptodateness --json --median`

            drs uptodateness --json --median

            {
                "DNSDOMAIN": {
                    "median": 0.0
                },
                ...
                "SCHEMA": {
                    "median": 0.0
                }
            }
        """
        creds = "%s%%%s" % (os.environ["USERNAME"], os.environ["PASSWORD"])
        dc1 = os.environ["SERVER"]
        dc2 = os.environ["DC_SERVER"]
        for dc in [dc1, dc2]:
            (result, out, err) = self.runsubcmd("drs", "uptodateness",
                                                '-H', "ldap://%s" % dc,
                                                '-U', creds,
                                                '--json', '--median')
            self.assertCmdSuccess(result, out, err)
            # should be json format
            obj = json.loads(out)
            # each partition name should be in json obj
            for part_name in PARTITION_NAMES:
                self.assertIn(part_name, obj)
                summary_obj = obj[part_name]
                self.assertIn('median', summary_obj)
                self.assertNotIn('maximum', summary_obj)
                self.assertNotIn('failure', summary_obj)

    def assert_matrix_validity(self, matrix, dcs=()):
        for dc in dcs:
            self.assertIn(dc, matrix)
        for k, row in matrix.items():
            self.assertEqual(row[k], 0)

    def test_uptodateness_stop_replication_domain(self):
        creds = "%s%%%s" % (os.environ["USERNAME"], os.environ["PASSWORD"])
        dc1 = os.environ["SERVER"]
        dc2 = os.environ["DC_SERVER"]
        self.addCleanup(set_auto_replication, dc1, True)
        self.addCleanup(set_auto_replication, dc2, True)

        def display(heading, out):
            if VERBOSE:
                print("========", heading, "=========")
                print(out)

        samdb1 = self.getSamDB("-H", "ldap://%s" % dc1, "-U", creds)
        samdb2 = self.getSamDB("-H", "ldap://%s" % dc2, "-U", creds)

        domain_dn = samdb1.domain_dn()
        self.assertTrue(domain_dn == samdb2.domain_dn(),
                        "We expected the same domain_dn across DCs")

        ou1 = "OU=dc1.%x,%s" % (random.randrange(1 << 64), domain_dn)
        ou2 = "OU=dc2.%x,%s" % (random.randrange(1 << 64), domain_dn)
        samdb1.add({
            "dn": ou1,
            "objectclass": "organizationalUnit"
        })
        samdb2.add({
            "dn": ou2,
            "objectclass": "organizationalUnit"
        })

        set_auto_replication(dc1, False)
        (result, out, err) = self.runsubcmd("visualize", "uptodateness",
                                            "-r",
                                            '-H', "ldap://%s" % dc1,
                                            '-U', creds,
                                            '--color=yes',
                                            '--utf8', '-S',
                                            '--partition', 'DOMAIN')
        display("dc1 replication is now off", out)
        self.assertCmdSuccess(result, out, err)
        matrix = get_utf8_matrix(out)
        self.assert_matrix_validity(matrix, [dc1, dc2])

        force_replication(dc2, dc1, domain_dn)
        (result, out, err) = self.runsubcmd("visualize", "uptodateness",
                                            "-r",
                                            '-H', "ldap://%s" % dc1,
                                            '-U', creds,
                                            '--color=yes',
                                            '--utf8', '-S',
                                            '--partition', 'DOMAIN')
        display("forced replication %s -> %s" % (dc2, dc1), out)
        self.assertCmdSuccess(result, out, err)
        matrix = get_utf8_matrix(out)
        self.assert_matrix_validity(matrix, [dc1, dc2])
        self.assertEqual(matrix[dc1][dc2], 0)

        force_replication(dc1, dc2, domain_dn)
        (result, out, err) = self.runsubcmd("visualize", "uptodateness",
                                            "-r",
                                            '-H', "ldap://%s" % dc1,
                                            '-U', creds,
                                            '--color=yes',
                                            '--utf8', '-S',
                                            '--partition', 'DOMAIN')
        display("forced replication %s -> %s" % (dc2, dc1), out)
        self.assertCmdSuccess(result, out, err)
        matrix = get_utf8_matrix(out)
        self.assert_matrix_validity(matrix, [dc1, dc2])
        self.assertEqual(matrix[dc2][dc1], 0)

        dn1 = 'cn=u1.%%d,%s' % (ou1)
        dn2 = 'cn=u2.%%d,%s' % (ou2)

        for i in range(10):
            samdb1.add({
                "dn": dn1 % i,
                "objectclass": "user"
            })

        (result, out, err) = self.runsubcmd("visualize", "uptodateness",
                                            "-r",
                                            '-H', "ldap://%s" % dc1,
                                            '-U', creds,
                                            '--color=yes',
                                            '--utf8', '-S',
                                            '--partition', 'DOMAIN')
        display("added 10 users on %s" % dc1, out)
        self.assertCmdSuccess(result, out, err)
        matrix = get_utf8_matrix(out)
        self.assert_matrix_validity(matrix, [dc1, dc2])
        # dc2's view of dc1 should now be 10 changes out of date
        self.assertEqual(matrix[dc2][dc1], 10)

        for i in range(10):
            samdb2.add({
                "dn": dn2 % i,
                "objectclass": "user"
            })

        (result, out, err) = self.runsubcmd("visualize", "uptodateness",
                                            "-r",
                                            '-H', "ldap://%s" % dc1,
                                            '-U', creds,
                                            '--color=yes',
                                            '--utf8', '-S',
                                            '--partition', 'DOMAIN')
        display("added 10 users on %s" % dc2, out)
        self.assertCmdSuccess(result, out, err)
        matrix = get_utf8_matrix(out)
        self.assert_matrix_validity(matrix, [dc1, dc2])
        # dc1's view of dc2 is probably 11 changes out of date
        self.assertGreaterEqual(matrix[dc1][dc2], 10)

        for i in range(10, 101):
            samdb1.add({
                "dn": dn1 % i,
                "objectclass": "user"
            })
            samdb2.add({
                "dn": dn2 % i,
                "objectclass": "user"
            })

        (result, out, err) = self.runsubcmd("visualize", "uptodateness",
                                            "-r",
                                            '-H', "ldap://%s" % dc1,
                                            '-U', creds,
                                            '--color=yes',
                                            '--utf8', '-S',
                                            '--partition', 'DOMAIN')
        display("added 91 users on both", out)
        self.assertCmdSuccess(result, out, err)
        matrix = get_utf8_matrix(out)
        self.assert_matrix_validity(matrix, [dc1, dc2])
        # the difference here should be ~101.
        self.assertGreaterEqual(matrix[dc1][dc2], 100)
        self.assertGreaterEqual(matrix[dc2][dc1], 100)

        (result, out, err) = self.runsubcmd("visualize", "uptodateness",
                                            "-r",
                                            '-H', "ldap://%s" % dc1,
                                            '-U', creds,
                                            '--color=yes',
                                            '--utf8', '-S',
                                            '--partition', 'DOMAIN',
                                            '--max-digits', '2')
        display("with --max-digits 2", out)
        self.assertCmdSuccess(result, out, err)
        matrix = get_utf8_matrix(out)
        self.assert_matrix_validity(matrix, [dc1, dc2])
        # visualising with 2 digits mean these overflow into infinity
        self.assertGreaterEqual(matrix[dc1][dc2], 1e99)
        self.assertGreaterEqual(matrix[dc2][dc1], 1e99)

        (result, out, err) = self.runsubcmd("visualize", "uptodateness",
                                            "-r",
                                            '-H', "ldap://%s" % dc1,
                                            '-U', creds,
                                            '--color=yes',
                                            '--utf8', '-S',
                                            '--partition', 'DOMAIN',
                                            '--max-digits', '1')
        display("with --max-digits 1", out)
        self.assertCmdSuccess(result, out, err)
        matrix = get_utf8_matrix(out)
        self.assert_matrix_validity(matrix, [dc1, dc2])
        # visualising with 1 digit means these overflow into infinity
        self.assertGreaterEqual(matrix[dc1][dc2], 1e99)
        self.assertGreaterEqual(matrix[dc2][dc1], 1e99)

        force_replication(dc2, dc1, samdb1.domain_dn())
        (result, out, err) = self.runsubcmd("visualize", "uptodateness",
                                            "-r",
                                            '-H', "ldap://%s" % dc1,
                                            '-U', creds,
                                            '--color=yes',
                                            '--utf8', '-S',
                                            '--partition', 'DOMAIN')

        display("forced replication %s -> %s" % (dc2, dc1), out)
        self.assertCmdSuccess(result, out, err)
        matrix = get_utf8_matrix(out)
        self.assert_matrix_validity(matrix, [dc1, dc2])
        self.assertEqual(matrix[dc1][dc2], 0)

        force_replication(dc1, dc2, samdb2.domain_dn())
        (result, out, err) = self.runsubcmd("visualize", "uptodateness",
                                            "-r",
                                            '-H', "ldap://%s" % dc1,
                                            '-U', creds,
                                            '--color=yes',
                                            '--utf8', '-S',
                                            '--partition', 'DOMAIN')

        display("forced replication %s -> %s" % (dc1, dc2), out)
        self.assertCmdSuccess(result, out, err)
        matrix = get_utf8_matrix(out)
        self.assert_matrix_validity(matrix, [dc1, dc2])
        self.assertEqual(matrix[dc2][dc1], 0)

        samdb1.delete(ou1, ['tree_delete:1'])
        samdb2.delete(ou2, ['tree_delete:1'])

        (result, out, err) = self.runsubcmd("visualize", "uptodateness",
                                            "-r",
                                            '-H', "ldap://%s" % dc1,
                                            '-U', creds,
                                            '--color=yes',
                                            '--utf8', '-S',
                                            '--partition', 'DOMAIN')
        display("tree delete both ous on %s" % (dc1,), out)
        self.assertCmdSuccess(result, out, err)
        matrix = get_utf8_matrix(out)
        self.assert_matrix_validity(matrix, [dc1, dc2])
        self.assertGreaterEqual(matrix[dc1][dc2], 100)
        self.assertGreaterEqual(matrix[dc2][dc1], 100)

        set_auto_replication(dc1, True)
        (result, out, err) = self.runsubcmd("visualize", "uptodateness",
                                            "-r",
                                            '-H', "ldap://%s" % dc1,
                                            '-U', creds,
                                            '--color=yes',
                                            '--utf8', '-S',
                                            '--partition', 'DOMAIN')
        display("replication is now on", out)
        self.assertCmdSuccess(result, out, err)
        matrix = get_utf8_matrix(out)
        self.assert_matrix_validity(matrix, [dc1, dc2])
        # We can't assert actual values after this because
        # auto-replication is on and things will change underneath us.

        (result, out, err) = self.runsubcmd("visualize", "uptodateness",
                                            "-r",
                                            '-H', "ldap://%s" % dc2,
                                            '-U', creds,
                                            '--color=yes',
                                            '--utf8', '-S',
                                            '--partition', 'DOMAIN')

        display("%s's view" % dc2, out)
        self.assertCmdSuccess(result, out, err)
        matrix = get_utf8_matrix(out)
        self.assert_matrix_validity(matrix, [dc1, dc2])

        force_replication(dc1, dc2, samdb2.domain_dn())
        (result, out, err) = self.runsubcmd("visualize", "uptodateness",
                                            "-r",
                                            '-H', "ldap://%s" % dc1,
                                            '-U', creds,
                                            '--color=yes',
                                            '--utf8', '-S',
                                            '--partition', 'DOMAIN')

        display("forced replication %s -> %s" % (dc1, dc2), out)
        self.assertCmdSuccess(result, out, err)
        matrix = get_utf8_matrix(out)
        self.assert_matrix_validity(matrix, [dc1, dc2])

        force_replication(dc2, dc1, samdb2.domain_dn())
        (result, out, err) = self.runsubcmd("visualize", "uptodateness",
                                            "-r",
                                            '-H', "ldap://%s" % dc1,
                                            '-U', creds,
                                            '--color=yes',
                                            '--utf8', '-S',
                                            '--partition', 'DOMAIN')
        display("forced replication %s -> %s" % (dc2, dc1), out)
        self.assertCmdSuccess(result, out, err)
        matrix = get_utf8_matrix(out)
        self.assert_matrix_validity(matrix, [dc1, dc2])

        (result, out, err) = self.runsubcmd("visualize", "uptodateness",
                                            "-r",
                                            '-H', "ldap://%s" % dc2,
                                            '-U', creds,
                                            '--color=yes',
                                            '--utf8', '-S',
                                            '--partition', 'DOMAIN')
        display("%s's view" % dc2, out)

        self.assertCmdSuccess(result, out, err)
        matrix = get_utf8_matrix(out)
        self.assert_matrix_validity(matrix, [dc1, dc2])

    def test_reps_remote(self):
        server = "ldap://%s" % os.environ["SERVER"]
        creds = "%s%%%s" % (os.environ["USERNAME"], os.environ["PASSWORD"])
        (result, out, err) = self.runsubcmd("visualize", "reps",
                                            '-H', server,
                                            '-U', creds,
                                            '--color=no', '-S', '-r')
        self.assertCmdSuccess(result, out, err)

    def test_ntdsconn_dot(self):
        server = "ldap://%s" % os.environ["SERVER"]
        creds = "%s%%%s" % (os.environ["USERNAME"], os.environ["PASSWORD"])
        (result, out, err) = self.runsubcmd("visualize", "ntdsconn",
                                            '-H', server,
                                            '-U', creds, '--dot',
                                            '--color=no', '-S')
        self.assertCmdSuccess(result, out, err)

    def test_ntdsconn_remote_dot(self):
        server = "ldap://%s" % os.environ["SERVER"]
        creds = "%s%%%s" % (os.environ["USERNAME"], os.environ["PASSWORD"])
        (result, out, err) = self.runsubcmd("visualize", "ntdsconn",
                                            '-H', server,
                                            '-U', creds, '--dot',
                                            '--color=no', '-S', '-r')
        self.assertCmdSuccess(result, out, err)

    def test_reps_dot(self):
        server = "ldap://%s" % os.environ["SERVER"]
        creds = "%s%%%s" % (os.environ["USERNAME"], os.environ["PASSWORD"])
        (result, out, err) = self.runsubcmd("visualize", "reps",
                                            '-H', server,
                                            '-U', creds, '--dot',
                                            '--color=no', '-S')
        self.assertCmdSuccess(result, out, err)

    def test_reps_remote_dot(self):
        server = "ldap://%s" % os.environ["SERVER"]
        creds = "%s%%%s" % (os.environ["USERNAME"], os.environ["PASSWORD"])
        (result, out, err) = self.runsubcmd("visualize", "reps",
                                            '-H', server,
                                            '-U', creds, '--dot',
                                            '--color=no', '-S', '-r')
        self.assertCmdSuccess(result, out, err)
