# Blackbox tests for smbcacls
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
from samba.tests import BlackboxProcessError
import os
from samba.tests.blackbox.smbcacls_propagate_inhertance import InheritanceSmbCaclsTests
from samba.tests.blackbox.smbcacls import SmbCaclsBlockboxTestBase

class DfsInheritanceSmbCaclsTests(InheritanceSmbCaclsTests):

    def setUp(self):
        # This is some intentional trickery to ensure we skip
        # InheritanceSmbCaclsTests.setUp so we can create a new
        # test directory & file hierarchy (including a nested dfs link)
        SmbCaclsBlockboxTestBase.setUp(self)
        smbclient_args = self.build_test_cmd("smbclient", ["//%s/%s" % (self.server, self.share), "-c", "mkdir %s" % os.getenv("TESTDIR", "smbcacls")])
        self.check_output(smbclient_args)

        # create toplevel testdir structure with desired ACL(s)
        #
        #      +-tar_test_dir/    (OI)(CI)(I)(F)
        #      +-oi_dir/        (OI)(CI)(I)(F)
        #      | +-file.1            (I)(F)
        #      | +-nested/      (OI)(CI)(I)(F)
        #      |   +-file.2          (I)(F)
        # DFS=>|   +-nested_again/     (OI)(CI)(I)(F)
        #      |     +-file.3          (I)(F)

        self.toplevel = self.create_remote_test_file("tar_test_dir/file-0")
        self.dfs_target_share = os.getenv("DFS_TARGET_SHARE", "smbcacls_sharedir_dfs")
        self.f1 = self.create_remote_test_file("tar_test_dir/oi_dir/file-1")
        self.f2 = self.create_remote_test_file("tar_test_dir/oi_dir/nested/file-2")
#        self.f3 = self.create_remote_test_file("tar_test_dir/oi_dir/nested/nested_again/file-3")


        self.tar_dir = os.path.split(self.toplevel)[0]
        self.oi_dir = os.path.split(self.f1)[0]
        self.nested_dir = os.path.split(self.f2)[0]

        self.nested_again_dir = os.path.join(self.nested_dir, "nested_again")

        # dfs link
        link_val = "msdfs:%s\\%s" % (self.server, self.dfs_target_share)
        dfs_share_path = "smbcacls_share"
        local_link_path =  os.path.join(os.environ["LOCAL_PATH"], dfs_share_path)
        link_source = link_val
        link_dest = os.path.join(local_link_path, self.nested_again_dir)


        # unfortunately os.link won't work with a source file that doesn't
        # exist, we need to run 'ln' directly
        #os.link(link_source, link_dest)
        link_args = ["ln", "-s", link_source, link_dest]
        out = self.check_output(link_args)

        self.f3 = self.create_remote_test_file("tar_test_dir/oi_dir/nested/nested_again/file-3")



        dir_acl_str = "ACL:%s:ALLOWED/OI|CI/FULL" % self.user
        inherited_dir_acl_str = "ACL:%s:ALLOWED/OI|CI|I/FULL" % self.user
        file_acl_str = "ACL:%s:ALLOWED/I/FULL" % self.user

        self.smb_cacls(["--modify", dir_acl_str, self.tar_dir])
        self.smb_cacls(["--modify", inherited_dir_acl_str, self.oi_dir])
        self.smb_cacls(["--modify", inherited_dir_acl_str, self.nested_dir])
        self.smb_cacls(["--modify", inherited_dir_acl_str, self.nested_again_dir])
        self.smb_cacls(["--modify", file_acl_str, self.f1])
        self.smb_cacls(["--modify", file_acl_str, self.f2])
        self.smb_cacls(["--modify", file_acl_str, self.f3])

    def tearDown(self):
        super(DfsInheritanceSmbCaclsTests, self).tearDown()
