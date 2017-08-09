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
environments. We can't assert much about what state they are in, so we
mainly check for cmmand failure.
"""

import os
from samba.tests.samba_tool.base import SambaToolCmdTest

ENV_DSAS = {
    'promoted_dc': ['CN=PROMOTEDVDC,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=samba,DC=example,DC=com',
                    'CN=LOCALDC,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=samba,DC=example,DC=com'],
    'vampire_dc': ['CN=LOCALDC,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=samba,DC=example,DC=com',
                   'CN=LOCALVAMPIREDC,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=samba,DC=example,DC=com'],
}


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
