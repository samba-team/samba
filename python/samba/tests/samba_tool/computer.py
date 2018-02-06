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
from samba import dsdb

class ComputerCmdTestCase(SambaToolCmdTest):
    """Tests for samba-tool computer subcommands"""
    computers = []
    samdb = None

    def setUp(self):
        super(ComputerCmdTestCase, self).setUp()
        self.samdb = self.getSamDB("-H", "ldap://%s" % os.environ["DC_SERVER"],
            "-U%s%%%s" % (os.environ["DC_USERNAME"], os.environ["DC_PASSWORD"]))
        self.computers = []
        self.computers.append(self._randomComputer({"name": "testcomputer1"}))
        self.computers.append(self._randomComputer({"name": "testcomputer2"}))
        self.computers.append(self._randomComputer({"name": "testcomputer3$"}))
        self.computers.append(self._randomComputer({"name": "testcomputer4$"}))

        # setup the 4 computers and ensure they are correct
        for computer in self.computers:
            (result, out, err) = self._create_computer(computer)

            self.assertCmdSuccess(result, out, err)
            self.assertEquals(err, "", "There shouldn't be any error message")
            self.assertIn("Computer '%s' created successfully" %
                          computer["name"], out)

            found = self._find_computer(computer["name"])

            self.assertIsNotNone(found)

            expectedname = computer["name"].rstrip('$')
            expectedsamaccountname = computer["name"]
            if not computer["name"].endswith('$'):
                expectedsamaccountname = "%s$" % computer["name"]
            self.assertEquals("%s" % found.get("name"), expectedname)
            self.assertEquals("%s" % found.get("sAMAccountName"),
                              expectedsamaccountname)
            self.assertEquals("%s" % found.get("description"),
                              computer["description"])

    def tearDown(self):
        super(ComputerCmdTestCase, self).tearDown()
        # clean up all the left over computers, just in case
        for computer in self.computers:
            if self._find_computer(computer["name"]):
                (result, out, err) = self.runsubcmd("computer", "delete",
                                                    "%s" % computer["name"])
                self.assertCmdSuccess(result, out, err,
                                      "Failed to delete computer '%s'" %
                                      computer["name"])


    def test_newcomputer(self):
        """This tests the "computer create" and "computer delete" commands"""
        # try to create all the computers again, this should fail
        for computer in self.computers:
            (result, out, err) = self._create_computer(computer)
            self.assertCmdFail(result, "Succeeded to create existing computer")
            self.assertIn("already exists", err)

        # try to delete all the computers we just created
        for computer in self.computers:
            (result, out, err) = self.runsubcmd("computer", "delete", "%s" %
                                                computer["name"])
            self.assertCmdSuccess(result, out, err,
                                  "Failed to delete computer '%s'" %
                                  computer["name"])
            found = self._find_computer(computer["name"])
            self.assertIsNone(found,
                              "Deleted computer '%s' still exists" %
                              computer["name"])

        # test creating computers
        for computer in self.computers:
            (result, out, err) = self.runsubcmd(
                "computer", "create", "%s" % computer["name"],
                 "--description=%s" % computer["description"])

            self.assertCmdSuccess(result, out, err)
            self.assertEquals(err, "", "There shouldn't be any error message")
            self.assertIn("Computer '%s' created successfully" %
                          computer["name"], out)

            found = self._find_computer(computer["name"])

            expectedname = computer["name"].rstrip('$')
            expectedsamaccountname = computer["name"]
            if not computer["name"].endswith('$'):
                expectedsamaccountname = "%s$" % computer["name"]
            self.assertEquals("%s" % found.get("name"), expectedname)
            self.assertEquals("%s" % found.get("sAMAccountName"),
                              expectedsamaccountname)
            self.assertEquals("%s" % found.get("description"),
                              computer["description"])

    def test_list(self):
        (result, out, err) = self.runsubcmd("computer", "list")
        self.assertCmdSuccess(result, out, err, "Error running list")

        search_filter = ("(sAMAccountType=%u)" %
                         dsdb.ATYPE_WORKSTATION_TRUST)

        computerlist = self.samdb.search(base=self.samdb.domain_dn(),
                                      scope=ldb.SCOPE_SUBTREE,
                                      expression=search_filter,
                                      attrs=["samaccountname"])

        self.assertTrue(len(computerlist) > 0, "no computers found in samdb")

        for computerobj in computerlist:
            name = computerobj.get("samaccountname", idx=0)
            found = self.assertMatch(out, name,
                                     "computer '%s' not found" % name)

    def test_move(self):
        parentou = self._randomOU({"name": "parentOU"})
        (result, out, err) = self._create_ou(parentou)
        self.assertCmdSuccess(result, out, err)

        for computer in self.computers:
            olddn = self._find_computer(computer["name"]).get("dn")

            (result, out, err) = self.runsubcmd("computer", "move",
                                                "%s" % computer["name"],
                                                "OU=%s" % parentou["name"])
            self.assertCmdSuccess(result, out, err,
                                  "Failed to move computer '%s'" %
                                  computer["name"])
            self.assertEquals(err, "", "There shouldn't be any error message")
            self.assertIn('Moved computer "%s"' % computer["name"], out)

            found = self._find_computer(computer["name"])
            self.assertNotEquals(found.get("dn"), olddn,
                                 ("Moved computer '%s' still exists with the "
                                  "same dn" % computer["name"]))
            computername = computer["name"].rstrip('$')
            newexpecteddn = ldb.Dn(self.samdb,
                                   "CN=%s,OU=%s,%s" %
                                   (computername, parentou["name"],
                                    self.samdb.domain_dn()))
            self.assertEquals(found.get("dn"), newexpecteddn,
                              "Moved computer '%s' does not exist" %
                              computer["name"])

            (result, out, err) = self.runsubcmd("computer", "move",
                                                "%s" % computer["name"],
                                                "%s" % olddn.parent())
            self.assertCmdSuccess(result, out, err,
                                  "Failed to move computer '%s'" %
                                  computer["name"])

        (result, out, err) = self.runsubcmd("ou", "delete",
                                            "OU=%s" % parentou["name"])
        self.assertCmdSuccess(result, out, err,
                              "Failed to delete ou '%s'" % parentou["name"])

    def _randomComputer(self, base={}):
        """create a computer with random attribute values, you can specify base
        attributes"""

        computer = {
            "name": self.randomName(),
            "description": self.randomName(count=100),
            }
        computer.update(base)
        return computer

    def _randomOU(self, base={}):
        """create an ou with random attribute values, you can specify base
        attributes"""

        ou = {
            "name": self.randomName(),
            "description": self.randomName(count=100),
            }
        ou.update(base)
        return ou

    def _create_computer(self, computer):
        return self.runsubcmd("computer", "create", "%s" % computer["name"],
                              "--description=%s" % computer["description"])

    def _create_ou(self, ou):
        return self.runsubcmd("ou", "create", "OU=%s" % ou["name"],
                              "--description=%s" % ou["description"])

    def _find_computer(self, name):
        samaccountname = name
        if not name.endswith('$'):
            samaccountname = "%s$" % name
        search_filter = ("(&(sAMAccountName=%s)(objectCategory=%s,%s))" %
                         (ldb.binary_encode(samaccountname),
                         "CN=Computer,CN=Schema,CN=Configuration",
                         self.samdb.domain_dn()))
        computerlist = self.samdb.search(base=self.samdb.domain_dn(),
                                  scope=ldb.SCOPE_SUBTREE,
                                  expression=search_filter, attrs=[])
        if computerlist:
            return computerlist[0]
        else:
            return None
