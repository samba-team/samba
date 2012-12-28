# Unix SMB/CIFS implementation.
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
import time
import ldb
from samba.tests.samba_tool.base import SambaToolCmdTest
from samba import (
        nttime2unix,
        dsdb
        )

class GroupCmdTestCase(SambaToolCmdTest):
    """Tests for samba-tool group subcommands"""
    groups = []
    samdb = None

    def setUp(self):
        super(GroupCmdTestCase, self).setUp()
        self.samdb = self.getSamDB("-H", "ldap://%s" % os.environ["DC_SERVER"],
            "-U%s%%%s" % (os.environ["DC_USERNAME"], os.environ["DC_PASSWORD"]))
        self.groups = []
        self.groups.append(self._randomGroup({"name": "testgroup1"}))
        self.groups.append(self._randomGroup({"name": "testgroup2"}))
        self.groups.append(self._randomGroup({"name": "testgroup3"}))
        self.groups.append(self._randomGroup({"name": "testgroup4"}))

        # setup the 4 groups and ensure they are correct
        for group in self.groups:
            (result, out, err) = self._create_group(group)

            self.assertCmdSuccess(result)
            self.assertEquals(err, "", "There shouldn't be any error message")
            self.assertIn("Added group %s" % group["name"], out)

            found = self._find_group(group["name"])

            self.assertIsNotNone(found)

            self.assertEquals("%s" % found.get("name"), group["name"])
            self.assertEquals("%s" % found.get("description"), group["description"])

    def tearDown(self):
        super(GroupCmdTestCase, self).tearDown()
        # clean up all the left over groups, just in case
        for group in self.groups:
            if self._find_group(group["name"]):
                self.runsubcmd("group", "delete", group["name"])


    def test_newgroup(self):
        """This tests the "group add" and "group delete" commands"""
        # try to add all the groups again, this should fail
        for group in self.groups:
            (result, out, err) = self._create_group(group)
            self.assertCmdFail(result, "Succeeded to create existing group")
            self.assertIn("LDAP error 68 LDAP_ENTRY_ALREADY_EXISTS", err)

        # try to delete all the groups we just added
        for group in self.groups:
            (result, out, err) = self.runsubcmd("group", "delete", group["name"])
            self.assertCmdSuccess(result,
                                  "Failed to delete group '%s'" % group["name"])
            found = self._find_group(group["name"])
            self.assertIsNone(found,
                              "Deleted group '%s' still exists" % group["name"])

        # test adding groups
        for group in self.groups:
            (result, out, err) =  self.runsubcmd("group", "add", group["name"],
                                                 "--description=%s" % group["description"],
                                                 "-H", "ldap://%s" % os.environ["DC_SERVER"],
                                                 "-U%s%%%s" % (os.environ["DC_USERNAME"],
                                                 os.environ["DC_PASSWORD"]))

            self.assertCmdSuccess(result)
            self.assertEquals(err,"","There shouldn't be any error message")
            self.assertIn("Added group %s" % group["name"], out)

            found = self._find_group(group["name"])

            self.assertEquals("%s" % found.get("samaccountname"),
                              "%s" % group["name"])


    def test_list(self):
        (result, out, err) = self.runsubcmd("group", "list",
                                            "-H", "ldap://%s" % os.environ["DC_SERVER"],
                                            "-U%s%%%s" % (os.environ["DC_USERNAME"],
                                                          os.environ["DC_PASSWORD"]))
        self.assertCmdSuccess(result, "Error running list")

        search_filter = "(objectClass=group)"

        grouplist = self.samdb.search(base=self.samdb.domain_dn(),
                                      scope=ldb.SCOPE_SUBTREE,
                                      expression=search_filter,
                                      attrs=["samaccountname"])

        self.assertTrue(len(grouplist) > 0, "no groups found in samdb")

        for groupobj in grouplist:
            name = groupobj.get("samaccountname", idx=0)
            found = self.assertMatch(out, name,
                                     "group '%s' not found" % name)

    def test_listmembers(self):
        (result, out, err) = self.runsubcmd("group", "listmembers", "Domain Users",
                                            "-H", "ldap://%s" % os.environ["DC_SERVER"],
                                            "-U%s%%%s" % (os.environ["DC_USERNAME"],
                                                          os.environ["DC_PASSWORD"]))
        self.assertCmdSuccess(result, "Error running listmembers")

        search_filter = "(|(primaryGroupID=513)(memberOf=CN=Domain Users,CN=Users,%s))" % self.samdb.domain_dn()

        grouplist = self.samdb.search(base=self.samdb.domain_dn(),
                                      scope=ldb.SCOPE_SUBTREE,
                                      expression=search_filter,
                                      attrs=["samAccountName"])

        self.assertTrue(len(grouplist) > 0, "no groups found in samdb")

        for groupobj in grouplist:
            name = groupobj.get("samAccountName", idx=0)
            found = self.assertMatch(out, name, "group '%s' not found" % name)

    def _randomGroup(self, base={}):
        """create a group with random attribute values, you can specify base attributes"""
        group = {
            "name": self.randomName(),
            "description": self.randomName(count=100),
            }
        group.update(base)
        return group

    def _create_group(self, group):
        return self.runsubcmd("group", "add", group["name"],
                              "--description=%s" % group["description"],
                              "-H", "ldap://%s" % os.environ["DC_SERVER"],
                              "-U%s%%%s" % (os.environ["DC_USERNAME"],
                                            os.environ["DC_PASSWORD"]))

    def _find_group(self, name):
        search_filter = ("(&(sAMAccountName=%s)(objectCategory=%s,%s))" %
                         (ldb.binary_encode(name),
                         "CN=Group,CN=Schema,CN=Configuration",
                         self.samdb.domain_dn()))
        grouplist = self.samdb.search(base=self.samdb.domain_dn(),
                                      scope=ldb.SCOPE_SUBTREE,
                                      expression=search_filter,
                                      attrs=[])
        if grouplist:
            return grouplist[0]
        else:
            return None
