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
        self.groups.append(self._randomGroup({"name": "testgroup5 (with brackets)"}))
        self.groups.append(self._randomPosixGroup({"name": "posixgroup1"}))
        self.groups.append(self._randomPosixGroup({"name": "posixgroup2"}))
        self.groups.append(self._randomPosixGroup({"name": "posixgroup3"}))
        self.groups.append(self._randomPosixGroup({"name": "posixgroup4"}))
        self.groups.append(self._randomPosixGroup({"name": "posixgroup5 (with brackets)"}))
        self.groups.append(self._randomUnixGroup({"name": "unixgroup1"}))
        self.groups.append(self._randomUnixGroup({"name": "unixgroup2"}))
        self.groups.append(self._randomUnixGroup({"name": "unixgroup3"}))
        self.groups.append(self._randomUnixGroup({"name": "unixgroup4"}))
        self.groups.append(self._randomUnixGroup({"name": "unixgroup5 (with brackets)"}))

        # setup the 12 groups and ensure they are correct
        for group in self.groups:
            (result, out, err) = group["createGroupFn"](group)

            self.assertCmdSuccess(result, out, err)
            self.assertEqual(err, "", "There shouldn't be any error message")

            if 'unix' in group["name"]:
                self.assertIn("Modified Group '%s' successfully"
                              % group["name"], out)
            else:
                self.assertIn("Added group %s" % group["name"], out)

            group["checkGroupFn"](group)

            found = self._find_group(group["name"])

            self.assertIsNotNone(found)

            self.assertEqual("%s" % found.get("name"), group["name"])
            self.assertEqual("%s" % found.get("description"), group["description"])

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
            self.assertCmdSuccess(result, out, err,
                                  "Failed to delete group '%s'" % group["name"])
            found = self._find_group(group["name"])
            self.assertIsNone(found,
                              "Deleted group '%s' still exists" % group["name"])

        # test adding groups
        for group in self.groups:
            (result, out, err) = self.runsubcmd("group", "add", group["name"],
                                                "--description=%s" % group["description"],
                                                "-H", "ldap://%s" % os.environ["DC_SERVER"],
                                                "-U%s%%%s" % (os.environ["DC_USERNAME"],
                                                              os.environ["DC_PASSWORD"]))

            self.assertCmdSuccess(result, out, err)
            self.assertEqual(err, "", "There shouldn't be any error message")
            self.assertIn("Added group %s" % group["name"], out)

            found = self._find_group(group["name"])

            self.assertEqual("%s" % found.get("samaccountname"),
                              "%s" % group["name"])

    def test_list(self):
        (result, out, err) = self.runsubcmd("group", "list",
                                            "-H", "ldap://%s" % os.environ["DC_SERVER"],
                                            "-U%s%%%s" % (os.environ["DC_USERNAME"],
                                                          os.environ["DC_PASSWORD"]))
        self.assertCmdSuccess(result, out, err, "Error running list")

        search_filter = "(objectClass=group)"

        grouplist = self.samdb.search(base=self.samdb.domain_dn(),
                                      scope=ldb.SCOPE_SUBTREE,
                                      expression=search_filter,
                                      attrs=["samaccountname"])

        self.assertTrue(len(grouplist) > 0, "no groups found in samdb")

        for groupobj in grouplist:
            name = str(groupobj.get("samaccountname", idx=0))
            found = self.assertMatch(out, name,
                                     "group '%s' not found" % name)

    def test_list_verbose(self):
        (result, out, err) = self.runsubcmd("group", "list", "--verbose",
                                            "-H", "ldap://%s" % os.environ["DC_SERVER"],
                                            "-U%s%%%s" % (os.environ["DC_USERNAME"],
                                                          os.environ["DC_PASSWORD"]))
        self.assertCmdSuccess(result, out, err, "Error running list --verbose")

        # use the output to build a dictionary, where key=group-name,
        # value=num-members
        output_memberships = {}

        # split the output by line, skipping the first 2 header lines
        group_lines = out.split('\n')[2:-1]
        for line in group_lines:
            # split line by column whitespace (but keep the group name together
            # if it contains spaces)
            values = line.split("   ")
            name = values[0]
            num_members = int(values[-1])
            output_memberships[name] = num_members

        # build up a similar dict using an LDAP search
        search_filter = "(objectClass=group)"
        grouplist = self.samdb.search(base=self.samdb.domain_dn(),
                                      scope=ldb.SCOPE_SUBTREE,
                                      expression=search_filter,
                                      attrs=["samaccountname", "member"])
        self.assertTrue(len(grouplist) > 0, "no groups found in samdb")

        ldap_memberships = {}
        for groupobj in grouplist:
            name = str(groupobj.get("samaccountname", idx=0))
            num_members = len(groupobj.get("member", default=[]))
            ldap_memberships[name] = num_members

        # check the command output matches LDAP
        self.assertTrue(output_memberships == ldap_memberships,
                        "Command output doesn't match LDAP results.\n" +
                        "Command='%s'\nLDAP='%s'" %(output_memberships,
                                                    ldap_memberships))

    def test_list_full_dn(self):
        (result, out, err) = self.runsubcmd("group", "list", "--full-dn",
                                            "-H", "ldap://%s" % os.environ["DC_SERVER"],
                                            "-U%s%%%s" % (os.environ["DC_USERNAME"],
                                                          os.environ["DC_PASSWORD"]))
        self.assertCmdSuccess(result, out, err, "Error running list")

        search_filter = "(objectClass=group)"

        grouplist = self.samdb.search(base=self.samdb.domain_dn(),
                                      scope=ldb.SCOPE_SUBTREE,
                                      expression=search_filter,
                                      attrs=[])

        self.assertTrue(len(grouplist) > 0, "no groups found in samdb")

        for groupobj in grouplist:
            name = str(groupobj.get("dn", idx=0))
            found = self.assertMatch(out, name,
                                     "group '%s' not found" % name)

    def test_list_base_dn(self):
        base_dn = "CN=Users"
        (result, out, err) = self.runsubcmd("group", "list", "--base-dn", base_dn,
                                            "-H", "ldap://%s" % os.environ["DC_SERVER"],
                                            "-U%s%%%s" % (os.environ["DC_USERNAME"],
                                                          os.environ["DC_PASSWORD"]))
        self.assertCmdSuccess(result, out, err, "Error running list")

        search_filter = "(objectClass=group)"

        grouplist = self.samdb.search(base=self.samdb.normalize_dn_in_domain(base_dn),
                                      scope=ldb.SCOPE_SUBTREE,
                                      expression=search_filter,
                                      attrs=["name"])

        self.assertTrue(len(grouplist) > 0, "no groups found in samdb")

        for groupobj in grouplist:
            name = str(groupobj.get("name", idx=0))
            found = self.assertMatch(out, name,
                                     "group '%s' not found" % name)

    def test_listmembers(self):
        (result, out, err) = self.runsubcmd("group", "listmembers", "Domain Users",
                                            "-H", "ldap://%s" % os.environ["DC_SERVER"],
                                            "-U%s%%%s" % (os.environ["DC_USERNAME"],
                                                          os.environ["DC_PASSWORD"]))
        self.assertCmdSuccess(result, out, err, "Error running listmembers")

        search_filter = "(|(primaryGroupID=513)(memberOf=CN=Domain Users,CN=Users,%s))" % self.samdb.domain_dn()

        grouplist = self.samdb.search(base=self.samdb.domain_dn(),
                                      scope=ldb.SCOPE_SUBTREE,
                                      expression=search_filter,
                                      attrs=["samAccountName"])

        self.assertTrue(len(grouplist) > 0, "no groups found in samdb")

        for groupobj in grouplist:
            name = str(groupobj.get("samAccountName", idx=0))
            found = self.assertMatch(out, name, "group '%s' not found" % name)


    def test_listmembers_full_dn(self):
        (result, out, err) = self.runsubcmd("group", "listmembers", "Domain Users",
                                            "--full-dn",
                                            "-H", "ldap://%s" % os.environ["DC_SERVER"],
                                            "-U%s%%%s" % (os.environ["DC_USERNAME"],
                                                          os.environ["DC_PASSWORD"]))
        self.assertCmdSuccess(result, out, err, "Error running listmembers")

        search_filter = "(|(primaryGroupID=513)(memberOf=CN=Domain Users,CN=Users,%s))" % self.samdb.domain_dn()

        grouplist = self.samdb.search(base=self.samdb.domain_dn(),
                                      scope=ldb.SCOPE_SUBTREE,
                                      expression=search_filter,
                                      attrs=["dn"])

        self.assertTrue(len(grouplist) > 0, "no groups found in samdb")

        for groupobj in grouplist:
            name = str(groupobj.get("dn", idx=0))
            found = self.assertMatch(out, name, "group '%s' not found" % name)


    def test_move(self):
        full_ou_dn = str(self.samdb.normalize_dn_in_domain("OU=movetest"))
        (result, out, err) = self.runsubcmd("ou", "create", full_ou_dn)
        self.assertCmdSuccess(result, out, err)
        self.assertEqual(err, "", "There shouldn't be any error message")
        self.assertIn('Created ou "%s"' % full_ou_dn, out)

        for group in self.groups:
            (result, out, err) = self.runsubcmd(
                "group", "move", group["name"], full_ou_dn)
            self.assertCmdSuccess(result, out, err, "Error running move")
            self.assertIn('Moved group "%s" into "%s"' %
                          (group["name"], full_ou_dn), out)

        # Should fail as groups objects are in OU
        (result, out, err) = self.runsubcmd("ou", "delete", full_ou_dn)
        self.assertCmdFail(result)
        self.assertIn(("subtree_delete: Unable to delete a non-leaf node "
                       "(it has %d children)!") % len(self.groups), err)

        for group in self.groups:
            new_dn = "CN=Users,%s" % self.samdb.domain_dn()
            (result, out, err) = self.runsubcmd(
                "group", "move", group["name"], new_dn)
            self.assertCmdSuccess(result, out, err, "Error running move")
            self.assertIn('Moved group "%s" into "%s"' %
                          (group["name"], new_dn), out)

        (result, out, err) = self.runsubcmd("ou", "delete", full_ou_dn)
        self.assertCmdSuccess(result, out, err,
                              "Failed to delete ou '%s'" % full_ou_dn)

    def test_show(self):
        """Assert that we can show a group correctly."""
        (result, out, err) = self.runsubcmd("group", "show", "Domain Users",
                                            "-H", "ldap://%s" % os.environ["DC_SERVER"],
                                            "-U%s%%%s" % (os.environ["DC_USERNAME"],
                                                          os.environ["DC_PASSWORD"]))
        self.assertCmdSuccess(result, out, err)
        self.assertEqual(err, "", "Shouldn't be any error messages")
        self.assertIn("dn: CN=Domain Users,CN=Users,DC=addom,DC=samba,DC=example,DC=com", out)

    def _randomGroup(self, base={}):
        """create a group with random attribute values, you can specify base
 attributes"""
        group = {
            "name": self.randomName(),
            "description": self.randomName(count=100),
            "createGroupFn": self._create_group,
            "checkGroupFn": self._check_group,
        }
        group.update(base)
        return group

    def _randomPosixGroup(self, base={}):
        """create a group with random attribute values and additional RFC2307
        attributes, you can specify base attributes"""
        group = self._randomGroup({})
        group.update(base)
        posixAttributes = {
            "unixdomain": self.randomName(),
            "gidNumber": self.randomXid(),
            "createGroupFn": self._create_posix_group,
            "checkGroupFn": self._check_posix_group,
        }
        group.update(posixAttributes)
        group.update(base)
        return group

    def _randomUnixGroup(self, base={}):
        """create a group with random attribute values and additional RFC2307
        attributes, you can specify base attributes"""
        group = self._randomGroup({})
        group.update(base)
        posixAttributes = {
            "gidNumber": self.randomXid(),
            "createGroupFn": self._create_unix_group,
            "checkGroupFn": self._check_unix_group,
        }
        group.update(posixAttributes)
        group.update(base)
        return group

    def _check_group(self, group):
        """ check if a group from SamDB has the same attributes as
 its template """
        found = self._find_group(group["name"])

        self.assertEqual("%s" % found.get("name"), group["name"])
        self.assertEqual("%s" % found.get("description"), group["description"])

    def _check_posix_group(self, group):
        """ check if a posix_group from SamDB has the same attributes as
 its template """
        found = self._find_group(group["name"])

        self.assertEqual("%s" % found.get("gidNumber"), "%s" %
                          group["gidNumber"])
        self._check_group(group)

    def _check_unix_group(self, group):
        """ check if a unix_group from SamDB has the same attributes as its
template """
        found = self._find_group(group["name"])

        self.assertEqual("%s" % found.get("gidNumber"), "%s" %
                          group["gidNumber"])
        self._check_group(group)

    def _create_group(self, group):
        return self.runsubcmd("group", "add", group["name"],
                              "--description=%s" % group["description"],
                              "-H", "ldap://%s" % os.environ["DC_SERVER"],
                              "-U%s%%%s" % (os.environ["DC_USERNAME"],
                                            os.environ["DC_PASSWORD"]))

    def _create_posix_group(self, group):
        """ create a new group with RFC2307 attributes """
        return self.runsubcmd("group", "add", group["name"],
                              "--description=%s" % group["description"],
                              "--nis-domain=%s" % group["unixdomain"],
                              "--gid-number=%s" % group["gidNumber"],
                              "-H", "ldap://%s" % os.environ["DC_SERVER"],
                              "-U%s%%%s" % (os.environ["DC_USERNAME"],
                              os.environ["DC_PASSWORD"]))

    def _create_unix_group(self, group):
        """ Add RFC2307 attributes to a group"""
        self._create_group(group)
        return self.runsubcmd("group", "addunixattrs", group["name"],
                              "%s" % group["gidNumber"],
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
                                      expression=search_filter)
        if grouplist:
            return grouplist[0]
        else:
            return None

    def test_stats(self):
        (result, out, err) = self.runsubcmd("group", "stats",
                                            "-H", "ldap://%s" % os.environ["DC_SERVER"],
                                            "-U%s%%%s" % (os.environ["DC_USERNAME"],
                                                          os.environ["DC_PASSWORD"]))
        self.assertCmdSuccess(result, out, err, "Error running stats")

        # sanity-check the command reports 'total groups' correctly
        search_filter = "(objectClass=group)"
        grouplist = self.samdb.search(base=self.samdb.domain_dn(),
                                      scope=ldb.SCOPE_SUBTREE,
                                      expression=search_filter,
                                      attrs=[])

        total_groups = len(grouplist)
        self.assertTrue("Total groups: {0}".format(total_groups) in out,
                        "Total groups not reported correctly")
