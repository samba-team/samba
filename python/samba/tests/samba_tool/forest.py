# Unix SMB/CIFS implementation.
# Copyright (C) William Brown <william@blackhats.net.au> 2018
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

import os
import ldb
from samba.tests.samba_tool.base import SambaToolCmdTest


class ForestCmdTestCase(SambaToolCmdTest):
    """Tests for samba-tool dsacl subcommands"""
    samdb = None

    def setUp(self):
        super(ForestCmdTestCase, self).setUp()
        self.samdb = self.getSamDB("-H", "ldap://%s" % os.environ["DC_SERVER"],
                                   "-U%s%%%s" % (os.environ["DC_USERNAME"], os.environ["DC_PASSWORD"]))
        self.domain_dn = self.samdb.domain_dn()

    def tearDown(self):
        super(ForestCmdTestCase, self).tearDown()
        # Reset the values we might have changed.
        ds_dn = "CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration"
        m = ldb.Message()
        m.dn = ldb.Dn(self.samdb, "%s,%s" % (ds_dn, self.domain_dn))
        m['dsheuristics'] = ldb.MessageElement(
            '0000000', ldb.FLAG_MOD_REPLACE, 'dsheuristics')

        self.samdb.modify(m)

    def test_display(self):
        """Tests that we can display forest settings"""
        (result, out, err) = self.runsublevelcmd("forest", ("directory_service",
                                                            "show"),
                                                 "-H", "ldap://%s" % os.environ["DC_SERVER"],
                                                 "-U%s%%%s" % (os.environ["DC_USERNAME"],
                                                               os.environ["DC_PASSWORD"]))

        self.assertCmdSuccess(result, out, err)
        self.assertEqual(err, "", "Shouldn't be any error messages")
        self.assertIn("dsheuristics: <NO VALUE>", out)

    def test_modify_dsheuristics(self):
        """Test that we can modify the dsheuristics setting"""

        (result, out, err) = self.runsublevelcmd("forest", ("directory_service",
                                                            "dsheuristics"), "0000002",
                                                 "-H", "ldap://%s" % os.environ["DC_SERVER"],
                                                 "-U%s%%%s" % (os.environ["DC_USERNAME"],
                                                               os.environ["DC_PASSWORD"]))

        self.assertCmdSuccess(result, out, err)
        self.assertEqual(err, "", "Shouldn't be any error messages")
        self.assertIn("set dsheuristics: 0000002", out)
