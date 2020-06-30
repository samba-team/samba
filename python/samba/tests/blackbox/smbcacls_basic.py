# Blackbox tests for smbcaclcs
#
# Copyright (C) Noel Power noel.power@suse.com
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
from __future__ import print_function
from samba.tests.blackbox.smbcacls import SmbCaclsBlockboxTestBase
from samba.tests import BlackboxProcessError

class BasicSmbCaclsTests(SmbCaclsBlockboxTestBase):

    def setUp(self):
        super(BasicSmbCaclsTests, self).setUp()

    def test_simple_single_set(self):
        """test smbcacls '--set' attempts to overwrite the ACL for the file

        before:

        +-test_dir/
          +-file.1            (I)(F)

        after/expected:

        +-test_dir/
          +-file.1            (F)"""

        file1 = "file-1"
        try:
            filepath = self.create_remote_test_file(file1)
        except BlackboxProcessError as e:
            self.fail(str(e))

        acl = ("ACL:%s:ALLOWED/0x0/FULL" % self.user)
        command = "bin/smbcacls -U%s%%%s --set %s //%s/%s %s" % (self.user, self.passwd, acl, self.server, self.share, filepath)

        try:
            result = self.check_output(command)
        except BlackboxProcessError as e:
            self.fail(str(e))

        ace = self.ace_parse_str(acl)
        self.assertTrue(self.file_ace_check(filepath, ace))

    def test_simple_single_mod(self):

        """test smbcacls '--modify' attempts to modify the ACL for the file
        (note: first part of the test 'set' ACL to (F) then attempts to modify
        before:

        +-test_dir/
          +-file.1            (F)

        after/expected:

        +-test_dir/
          +-file.1            (READ)"""

        acl_str = "ACL:%s:ALLOWED/0x0/FULL" % self.user
        try:
            remotepath = self.create_remote_test_file("file-1")

            self.smb_cacls(["--set", acl_str, remotepath])

            ace = self.ace_parse_str(acl_str)
            self.assertTrue(self.file_ace_check(remotepath, ace))

            # overwrite existing entry
            acl_str = "ACL:%s:ALLOWED/0x0/READ" % self.user
            self.smb_cacls(["--modify", acl_str, remotepath])

            ace = self.ace_parse_str(acl_str)
            self.assertTrue(self.file_ace_check(remotepath, ace))
        except BlackboxProcessError as e:
            self.fail(str(e))

    def test_simple_single_del(self):
        """test smbcacls '--delete' attempts to delete the ACL for the file
        (note: first part of the test 'set' ACL to (F) then attempts to delete
        before:

        +-tar_test_dir/
          +-file.1            (F)

        after/expected:

        +-tar_test_dir/
          +-file.1            (none) - meaning no (F) ACL for this user"""

        acl_str = "ACL:%s:ALLOWED/0x0/FULL" % self.user

        try:
            remotepath = self.create_remote_test_file("file-1")

            # only a single ACE string in the ACL
            ace = self.ace_parse_str(acl_str)
            self.assertTrue(self.file_ace_check(remotepath, ace))

            self.smb_cacls(["--delete", acl_str, remotepath])
            self.assertFalse(self.file_ace_check(remotepath, ace))
        except BlackboxProcessError as e:
            self.fail(str(e))


    def test_simple_single_add(self):
        acl_str = "ACL:%s:ALLOWED/0x0/FULL" % self.user
        dny_str = "ACL:%s:DENIED/0x0/READ" % self.user

        try:
            remotepath = self.create_remote_test_file("file-1")

            self.smb_cacls(["--set", acl_str, remotepath])

            ace = self.ace_parse_str(acl_str)
            self.assertTrue(self.file_ace_check(remotepath, ace))

            self.smb_cacls(["--set", dny_str, remotepath])
            ace = self.ace_parse_str(dny_str)
            self.assertTrue(self.file_ace_check(remotepath, ace))
        except BlackboxProcessError as e:
            self.fail(str(e))
