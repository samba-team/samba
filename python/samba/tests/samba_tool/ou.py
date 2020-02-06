# Unix SMB/CIFS implementation.
#
# Copyright (C) Bjoern Baumbach <bb@sernet.de> 2018
#
# based on group.py:
# Copyright (C) Michael Adam 2012
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


class OUCmdTestCase(SambaToolCmdTest):
    """Tests for samba-tool ou subcommands"""
    ous = []
    samdb = None

    def setUp(self):
        super(OUCmdTestCase, self).setUp()
        self.samdb = self.getSamDB("-H", "ldap://%s" % os.environ["DC_SERVER"],
                                   "-U%s%%%s" % (os.environ["DC_USERNAME"], os.environ["DC_PASSWORD"]))
        self.ous = []
        self.ous.append(self._randomOU({"name": "testou1"}))
        self.ous.append(self._randomOU({"name": "testou2"}))
        self.ous.append(self._randomOU({"name": "testou3"}))
        self.ous.append(self._randomOU({"name": "testou4"}))

        # setup the 4 ous and ensure they are correct
        for ou in self.ous:
            (result, out, err) = self._create_ou(ou)

            self.assertCmdSuccess(result, out, err)
            self.assertEqual(err, "", "There shouldn't be any error message")
            full_ou_dn = self.samdb.normalize_dn_in_domain("OU=%s" % ou["name"])
            self.assertIn('Created ou "%s"' % full_ou_dn, out)

            found = self._find_ou(ou["name"])

            self.assertIsNotNone(found)

            self.assertEqual("%s" % found.get("name"), ou["name"])
            self.assertEqual("%s" % found.get("description"),
                              ou["description"])

    def tearDown(self):
        super(OUCmdTestCase, self).tearDown()
        # clean up all the left over ous, just in case
        for ou in self.ous:
            if self._find_ou(ou["name"]):
                (result, out, err) = self.runsubcmd("ou", "delete",
                                                    "OU=%s" % ou["name"])
                self.assertCmdSuccess(result, out, err,
                                      "Failed to delete ou '%s'" % ou["name"])

    def test_newou(self):
        """This tests the "ou create" and "ou delete" commands"""
        # try to create all the ous again, this should fail
        for ou in self.ous:
            (result, out, err) = self._create_ou(ou)
            self.assertCmdFail(result, "Succeeded to create existing ou")
            self.assertIn("already exists", err)

        # try to delete all the ous we just created
        for ou in self.ous:
            (result, out, err) = self.runsubcmd("ou", "delete", "OU=%s" %
                                                ou["name"])
            self.assertCmdSuccess(result, out, err,
                                  "Failed to delete ou '%s'" % ou["name"])
            found = self._find_ou(ou["name"])
            self.assertIsNone(found,
                              "Deleted ou '%s' still exists" % ou["name"])

        # test creating ous
        for ou in self.ous:
            (result, out, err) = self.runsubcmd(
                "ou", "create", "OU=%s" % ou["name"],
                "--description=%s" % ou["description"])

            self.assertCmdSuccess(result, out, err)
            self.assertEqual(err, "", "There shouldn't be any error message")
            full_ou_dn = self.samdb.normalize_dn_in_domain("OU=%s" % ou["name"])
            self.assertIn('Created ou "%s"' % full_ou_dn, out)

            found = self._find_ou(ou["name"])

            self.assertEqual("%s" % found.get("ou"),
                              "%s" % ou["name"])

        # try to delete all the ous we just created (with full dn)
        for ou in self.ous:
            full_ou_dn = self.samdb.normalize_dn_in_domain("OU=%s" % ou["name"])
            (result, out, err) = self.runsubcmd("ou", "delete", str(full_ou_dn))
            self.assertCmdSuccess(result, out, err,
                                  "Failed to delete ou '%s'" % ou["name"])
            found = self._find_ou(ou["name"])
            self.assertIsNone(found,
                              "Deleted ou '%s' still exists" % ou["name"])

        # test creating ous (with full dn)
        for ou in self.ous:
            full_ou_dn = self.samdb.normalize_dn_in_domain("OU=%s" % ou["name"])
            (result, out, err) = self.runsubcmd(
                "ou", "create", str(full_ou_dn),
                "--description=%s" % ou["description"])

            self.assertCmdSuccess(result, out, err)
            self.assertEqual(err, "", "There shouldn't be any error message")
            full_ou_dn = self.samdb.normalize_dn_in_domain("OU=%s" % ou["name"])
            self.assertIn('Created ou "%s"' % full_ou_dn, out)

            found = self._find_ou(ou["name"])

            self.assertEqual("%s" % found.get("ou"),
                              "%s" % ou["name"])

    def test_list(self):
        (result, out, err) = self.runsubcmd("ou", "list")
        self.assertCmdSuccess(result, out, err, "Error running list")

        search_filter = "(objectClass=organizationalUnit)"

        oulist = self.samdb.search(base=self.samdb.domain_dn(),
                                   scope=ldb.SCOPE_SUBTREE,
                                   expression=search_filter,
                                   attrs=["name"])

        self.assertTrue(len(oulist) > 0, "no ous found in samdb")

        for ouobj in oulist:
            name = ouobj.get("name", idx=0)
            found = self.assertMatch(out, str(name),
                                     "ou '%s' not found" % name)

    def test_list_base_dn(self):
        base_dn = str(self.samdb.domain_dn())
        (result, out, err) = self.runsubcmd("ou", "list", "-b", base_dn)
        self.assertCmdSuccess(result, out, err, "Error running list")

        search_filter = "(objectClass=organizationalUnit)"

        oulist = self.samdb.search(base=base_dn,
                                   scope=ldb.SCOPE_SUBTREE,
                                   expression=search_filter,
                                   attrs=["name"])

        self.assertTrue(len(oulist) > 0, "no ous found in samdb")

        for ouobj in oulist:
            name = ouobj.get("name", idx=0)
            found = self.assertMatch(out, str(name),
                                     "ou '%s' not found" % name)

    def test_rename(self):
        for ou in self.ous:
            ousuffix = "RenameTest"
            newouname = ou["name"] + ousuffix
            (result, out, err) = self.runsubcmd("ou", "rename",
                                                "OU=%s" % ou["name"],
                                                "OU=%s" % newouname)
            self.assertCmdSuccess(result, out, err,
                                  "Failed to rename ou '%s'" % ou["name"])
            found = self._find_ou(ou["name"])
            self.assertIsNone(found,
                              "Renamed ou '%s' still exists" % ou["name"])
            found = self._find_ou(newouname)
            self.assertIsNotNone(found,
                                 "Renamed ou '%s' does not exist" % newouname)

            (result, out, err) = self.runsubcmd("ou", "rename",
                                                "OU=%s" % newouname,
                                                "OU=%s" % ou["name"])
            self.assertCmdSuccess(result, out, err,
                                  "Failed to rename ou '%s'" % newouname)

    def test_move(self):
        parentou = self._randomOU({"name": "parentOU"})
        (result, out, err) = self._create_ou(parentou)
        self.assertCmdSuccess(result, out, err)

        for ou in self.ous:
            olddn = self._find_ou(ou["name"]).get("dn")

            (result, out, err) = self.runsubcmd("ou", "move",
                                                "OU=%s" % ou["name"],
                                                "OU=%s" % parentou["name"])
            self.assertCmdSuccess(result, out, err,
                                  "Failed to move ou '%s'" % ou["name"])
            self.assertEqual(err, "", "There shouldn't be any error message")
            full_ou_dn = self.samdb.normalize_dn_in_domain("OU=%s" % ou["name"])
            self.assertIn('Moved ou "%s"' % full_ou_dn, out)

            found = self._find_ou(ou["name"])
            self.assertNotEquals(found.get("dn"), olddn,
                                 "Moved ou '%s' still exists with the same dn" %
                                 ou["name"])
            newexpecteddn = ldb.Dn(self.samdb,
                                   "OU=%s,OU=%s,%s" %
                                   (ou["name"], parentou["name"],
                                    self.samdb.domain_dn()))
            self.assertEqual(found.get("dn"), newexpecteddn,
                              "Moved ou '%s' does not exist" %
                              ou["name"])

            (result, out, err) = self.runsubcmd("ou", "move",
                                                "%s" % newexpecteddn,
                                                "%s" % olddn.parent())
            self.assertCmdSuccess(result, out, err,
                                  "Failed to move ou '%s'" % ou["name"])

        (result, out, err) = self.runsubcmd("ou", "delete",
                                            "OU=%s" % parentou["name"])
        self.assertCmdSuccess(result, out, err,
                              "Failed to delete ou '%s'" % parentou["name"])

    def test_listobjects(self):
        (result, out, err) = self.runsubcmd("ou", "listobjects",
                                            "%s" % self.samdb.domain_dn(),
                                            "--full-dn")
        self.assertCmdSuccess(result, out, err,
                              "Failed to list ou's objects")
        self.assertEqual(err, "", "There shouldn't be any error message")

        objlist = self.samdb.search(base=self.samdb.domain_dn(),
                                    scope=ldb.SCOPE_ONELEVEL,
                                    attrs=[])
        self.assertTrue(len(objlist) > 0, "no objects found")

        for obj in objlist:
            found = self.assertMatch(out, str(obj.dn),
                                     "object '%s' not found" % obj.dn)

    def test_list_full_dn(self):
        (result, out, err) = self.runsubcmd("ou", "list",
                                            "--full-dn")
        self.assertCmdSuccess(result, out, err,
                              "Failed to list ous")
        self.assertEqual(err, "", "There shouldn't be any error message")

        filter = "(objectClass=organizationalUnit)"
        objlist = self.samdb.search(base=self.samdb.domain_dn(),
                                    scope=ldb.SCOPE_SUBTREE,
                                    expression=filter,
                                    attrs=[])
        self.assertTrue(len(objlist) > 0, "no ou objects found")

        for obj in objlist:
            found = self.assertMatch(out, str(obj.dn),
                                     "object '%s' not found" % obj.dn)

    def _randomOU(self, base={}):
        """create an ou with random attribute values, you can specify base
        attributes"""

        ou = {
            "name": self.randomName(),
            "description": self.randomName(count=100),
        }
        ou.update(base)
        return ou

    def _create_ou(self, ou):
        return self.runsubcmd("ou", "create", "OU=%s" % ou["name"],
                              "--description=%s" % ou["description"])

    def _find_ou(self, name):
        search_filter = ("(&(name=%s)(objectCategory=%s,%s))" %
                         (ldb.binary_encode(name),
                          "CN=Organizational-Unit,CN=Schema,CN=Configuration",
                          self.samdb.domain_dn()))
        oulist = self.samdb.search(base=self.samdb.domain_dn(),
                                   scope=ldb.SCOPE_SUBTREE,
                                   expression=search_filter)
        if oulist:
            return oulist[0]
        else:
            return None
