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


class SchemaCmdTestCase(SambaToolCmdTest):
    """Tests for samba-tool dsacl subcommands"""
    samdb = None

    def setUp(self):
        super(SchemaCmdTestCase, self).setUp()
        self.samdb = self.getSamDB("-H", "ldap://%s" % os.environ["DC_SERVER"],
                                   "-U%s%%%s" % (os.environ["DC_USERNAME"], os.environ["DC_PASSWORD"]))

    def tearDown(self):
        super(SchemaCmdTestCase, self).tearDown()

    def test_display_attribute(self):
        """Tests that we can display schema attributes"""
        (result, out, err) = self.runsublevelcmd("schema", ("attribute",
                                                            "show"), "uid",
                                                 "-H", "ldap://%s" % os.environ["DC_SERVER"],
                                                 "-U%s%%%s" % (os.environ["DC_USERNAME"],
                                                               os.environ["DC_PASSWORD"]))

        self.assertCmdSuccess(result, out, err)
        self.assertEqual(err, "", "Shouldn't be any error messages")
        self.assertIn("dn: CN=uid,CN=Schema,CN=Configuration,", out)

    def test_modify_attribute_searchflags(self):
        """Tests that we can modify searchFlags of an attribute"""
        (result, out, err) = self.runsublevelcmd("schema", ("attribute",
                                                            "modify"), "uid", "--searchflags=9",
                                                 "-H", "ldap://%s" % os.environ["DC_SERVER"],
                                                 "-U%s%%%s" % (os.environ["DC_USERNAME"],
                                                               os.environ["DC_PASSWORD"]))

        self.assertCmdFail(result, 'Unknown flag 9, please see --help')

        (result, out, err) = self.runsublevelcmd("schema", ("attribute",
                                                            "modify"), "uid", "--searchflags=fATTINDEX",
                                                 "-H", "ldap://%s" % os.environ["DC_SERVER"],
                                                 "-U%s%%%s" % (os.environ["DC_USERNAME"],
                                                               os.environ["DC_PASSWORD"]))

        self.assertCmdSuccess(result, out, err)
        self.assertEqual(err, "", "Shouldn't be any error messages")
        self.assertIn("modified cn=uid,CN=Schema,CN=Configuration,", out)

        (result, out, err) = self.runsublevelcmd("schema", ("attribute",
                                                            "modify"), "uid",
                                                 "--searchflags=fATTINDEX,fSUBTREEATTINDEX",
                                                 "-H", "ldap://%s" % os.environ["DC_SERVER"],
                                                 "-U%s%%%s" % (os.environ["DC_USERNAME"],
                                                               os.environ["DC_PASSWORD"]))

        self.assertCmdSuccess(result, out, err)
        self.assertEqual(err, "", "Shouldn't be any error messages")
        self.assertIn("modified cn=uid,CN=Schema,CN=Configuration,", out)

        (result, out, err) = self.runsublevelcmd("schema", ("attribute",
                                                            "modify"), "uid",
                                                 "--searchflags=fAtTiNdEx,fPRESERVEONDELETE",
                                                 "-H", "ldap://%s" % os.environ["DC_SERVER"],
                                                 "-U%s%%%s" % (os.environ["DC_USERNAME"],
                                                               os.environ["DC_PASSWORD"]))

        self.assertCmdSuccess(result, out, err)
        self.assertEqual(err, "", "Shouldn't be any error messages")
        self.assertIn("modified cn=uid,CN=Schema,CN=Configuration,", out)

    def test_show_oc_attribute(self):
        """Tests that we can modify searchFlags of an attribute"""
        (result, out, err) = self.runsublevelcmd("schema", ("attribute",
                                                            "show_oc"), "cn",
                                                 "-H", "ldap://%s" % os.environ["DC_SERVER"],
                                                 "-U%s%%%s" % (os.environ["DC_USERNAME"],
                                                               os.environ["DC_PASSWORD"]))

        self.assertCmdSuccess(result, out, err)
        self.assertEqual(err, "", "Shouldn't be any error messages")
        self.assertIn("--- MAY contain ---", out)
        self.assertIn("--- MUST contain ---", out)

    def test_display_objectclass(self):
        """Tests that we can display schema objectclasses"""
        (result, out, err) = self.runsublevelcmd("schema", ("objectclass",
                                                            "show"), "person",
                                                 "-H", "ldap://%s" % os.environ["DC_SERVER"],
                                                 "-U%s%%%s" % (os.environ["DC_USERNAME"],
                                                               os.environ["DC_PASSWORD"]))

        self.assertCmdSuccess(result, out, err)
        self.assertEqual(err, "", "Shouldn't be any error messages")
        self.assertIn("dn: CN=Person,CN=Schema,CN=Configuration,", out)
