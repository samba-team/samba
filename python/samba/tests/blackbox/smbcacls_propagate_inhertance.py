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
from samba.tests.blackbox.smbcacls import SmbCaclsBlockboxTestBase
from samba.tests import BlackboxProcessError
import os

class InheritanceSmbCaclsTests(SmbCaclsBlockboxTestBase):

    def setUp(self):
        super(InheritanceSmbCaclsTests, self).setUp()

        # create toplevel testdir structure with desired ACL(s)
        #
        #  +-tar_test_dir/    (OI)(CI)(I)(F)
        #  +-oi_dir/        (OI)(CI)(I)(F)
        #  | +-file.1            (I)(F)
        #  | +-nested/      (OI)(CI)(I)(F)
        #  |   +-file.2          (I)(F)
        #  |   +-nested_again/     (OI)(CI)(I)(F)
        #  |     +-file.3          (I)(F)

        self.toplevel = self.create_remote_test_file("tar_test_dir/file-0")
        self.f1 = self.create_remote_test_file("tar_test_dir/oi_dir/file-1")
        self.f2 = self.create_remote_test_file("tar_test_dir/oi_dir/nested/file-2")
        self.f3 = self.create_remote_test_file("tar_test_dir/oi_dir/nested/nested_again/file-3")
        self.tar_dir = os.path.split(self.toplevel)[0]
        self.oi_dir = os.path.split(self.f1)[0]
        self.nested_dir = os.path.split(self.f2)[0]
        self.nested_again_dir = os.path.split(self.f3)[0]

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
        # tmp is the default share which has an existing testdir smbcacls
        # we need to be prepared to deal with a 'custom' share (which also
        # would have an existing testdir)
        if self.share != "tmp":
            self.dirpath = os.path.join(os.environ["LOCAL_PATH"],self.share)
            self.dirpath = os.path.join(self.dirpath,self.testdir)
        super(InheritanceSmbCaclsTests, self).tearDown()

    def test_simple_oi_add(self):
        """test smbcacls '--propagate-inheritance --add' which attempts to add the ACL
        for the file and additionally use inheritance rules to propagate appropriate
        changes to children

        This test adds an ACL with (OI)(READ)

        before:

        +-tar_test_dir/    (OI)(CI)(I)(F)
          +-oi_dir/        (OI)(CI)(I)(F)
          | +-file.1            (I)(F)
          | +-nested/      (OI)(CI)(I)(F)
          |   +-file.2          (I)(F)
          |   +-nested_again/     (OI)(CI)(I)(F)
          |     +-file.3          (I)(F)

        after/expected:

        +-tar_test_dir/    (OI)(CI)(I)(F)
          +-oi_dir/        (OI)(CI)(I)(F), (OI)(READ)
          | +-file.1            (I)(F), (I)(READ)
          | +-nested/      (OI)(CI)(I)(F), (OI)(IO)(I)(READ)
          |   +-file.2          (I)(F), (I)(READ)
          |   +-nested_again/     (OI)(CI)(I)(F), (OI)(IO)(I)(READ)
          |     +-file.3          (I)(F), (I)(READ)"""

        dir_add_acl_str = "ACL:%s:ALLOWED/OI/READ" % self.user
        obj_inherited_ace_str = "ACL:%s:ALLOWED/I/READ" % self.user
        dir_inherited_ace_str = "ACL:%s:ALLOWED/OI|IO|I/READ" % self.user

        try:

            self.smb_cacls(["--propagate-inheritance", "--add",
                            dir_add_acl_str, self.oi_dir])

            # check top level container 'oi_dir' has OI/READ
            dir_ace = self.ace_parse_str(dir_add_acl_str)
            self.assertTrue(self.file_ace_check(self.oi_dir, dir_ace))

            # file 'oi_dir/file-1' should  have inherited I/READ
            child_file_ace = self.ace_parse_str(obj_inherited_ace_str)
            self.assertTrue(self.file_ace_check(self.f1, child_file_ace))

            # nested dir  'oi_dir/nested/' should have OI|IO/READ
            child_dir_ace = self.ace_parse_str(dir_inherited_ace_str)
            self.assertTrue(self.file_ace_check(self.nested_dir, child_dir_ace))

            # nested file 'oi_dir/nested/file-2' should  have inherited I/READ
            self.assertTrue(self.file_ace_check(self.f2, child_file_ace))

            # nested_again dir  'oi_dir/nested/nested_again' should have OI|IO/READ
            child_dir_ace = self.ace_parse_str(dir_inherited_ace_str)
            self.assertTrue(self.file_ace_check(self.nested_again_dir, child_dir_ace))
            # nested_again file 'oi_dir/nested/nested_again/file-3' should  have inherited I/READ
            self.assertTrue(self.file_ace_check(self.f3, child_file_ace))
        except BlackboxProcessError as e:
            self.fail(str(e))

    def test_simple_oi_delete(self):
        """test smbcacls '--propagate-inheritance --add' which attempts to add the ACL
        for the file and additionally use inheritance rules to propagate appropriate
        changes to children

        This test adds an ACL with (OI)(READ)

        before:

        +-tar_test_dir/    (OI)(CI)(I)(F)
          +-oi_dir/        (OI)(CI)(I)(F), (OI)(IO)(READ)
          | +-file.1            (I)(F), (I)(READ)
          | +-nested/      (OI)(CI)(I)(F), (OI)(IO)(I)(READ)
          |   +-file.2          (I)(F), (I)(READ)
          |   +-nested_again/     (OI)(CI)(I)(F)
          |     +-file.3          (I)(F)

        after/expected:

        +-tar_test_dir/    (OI)(CI)(I)(F)
          +-oi_dir/        (OI)(CI)(I)(F)
          | +-file.1            (I)(F)
          | +-nested/      (OI)(CI)(I)(F)
          |   +-file.2          (I)(F)
          |   +-nested_again/     (OI)(CI)(I)(F)
          |     +-file.3          (I)(F)"""

        dir_acl_str = "ACL:%s:ALLOWED/OI/READ" % self.user
        obj_inherited_ace_str = "ACL:%s:ALLOWED/I/READ" % self.user
        dir_inherited_ace_str = "ACL:%s:ALLOWED/OI|IO|I/READ" % self.user
        try:

            # add flags on oi_dir
            self.smb_cacls([ "--add", dir_acl_str, self.oi_dir])

            # add flags on oi_dir/nested
            self.smb_cacls([ "--add", dir_inherited_ace_str, self.nested_dir])

            # add flags on oi_dir/nested/nested_again
            self.smb_cacls([ "--add", dir_inherited_ace_str, self.nested_again_dir])

            # add flags on oi_dir/file-1
            self.smb_cacls(["--add", obj_inherited_ace_str, self.f1])

            # add flags on oi_dir/nested/file-2
            self.smb_cacls([ "--add", obj_inherited_ace_str, self.f2])

            # add flags on oi_dir/nested/nested_again/file-3
            self.smb_cacls([ "--add", obj_inherited_ace_str, self.f3])

            self.smb_cacls(["--propagate-inheritance",
                            "--delete", dir_acl_str, self.oi_dir])

            # check top level container 'oi_dir' no longer has OI/READ
            dir_ace = self.ace_parse_str(dir_acl_str)
            self.assertTrue(self.file_ace_check(self.oi_dir, dir_ace) == False)

            # file 'oi_dir/file-1' should  no longer have inherited I/READ
            child_file_ace = self.ace_parse_str(obj_inherited_ace_str)
            self.assertTrue(self.file_ace_check(self.f1, child_file_ace) == False)

            # nested dir  'oi_dir/nested/' should no longer have OI|IO/READ
            child_dir_ace = self.ace_parse_str(dir_inherited_ace_str)
            self.assertTrue(self.file_ace_check(self.nested_dir, child_dir_ace) == False)

            # nested file 'oi_dir/nested/file-2' should no longer have inherited I/READ
            self.assertTrue(self.file_ace_check(self.f2, child_file_ace) == False)

            # nested dir  'oi_dir/nested/nested_agin' should no longer have OI|IO/READ
            child_dir_ace = self.ace_parse_str(dir_inherited_ace_str)
            self.assertTrue(self.file_ace_check(self.nested_again_dir, child_dir_ace) == False)

            # nested file 'oi_dir/nested/nested_again/file-3' should no longer have inherited I/READ
            self.assertTrue(self.file_ace_check(self.f3, child_file_ace) == False)

        except BlackboxProcessError as e:
            self.fail(str(e))

    def test_simple_oi_modify(self):
        """test smbcacls '--propagate-inheritance --modify' which attempts to modify ACL
        for the file and additionally use inheritance rules to propagate appropriate
        changes to children

        This test first adds an ACL with (OI)(R), then it modifies that acl to be
        (OI)(D) - where D == 0x00110000

        before:

        +-tar_test_dir/    (OI)(CI)(I)(F)
          +-oi_dir/        (OI)(IO)(R)
          | +-file.1       (I)(R)
          | +-nested/      (OI)(IO)(I)(R)
          |   +-file.2     (I)(R)
          |   +-nested_again/     (OI)(IO)(I)(R)
          |     +-file.3          (I)(R)

        after/expected:

        +-tar_test_dir/    (OI)(CI)(I)(F)
          +-oi_dir/        (OI)(IO)(CHANGE)
          | +-file.1       (I)(CHANGED)
          | +-nested/      (OI)(IO)(I)(CHANGED)
          |   +-file.2     (I)(CHANGED)
          |   +-nested_again/     (OI)(IO)(I)(CHANGE)
          |     +-file.3          (I)(CHANGE)"""

        explict_access_ace_str = "ACL:%s:ALLOWED/0x0/RWD" % self.user
        dir_mod_acl_str = "ACL:%s:ALLOWED/OI/CHANGE" % self.user
        file_mod_inherited_ace_str = "ACL:%s:ALLOWED/I/CHANGE" % self.user
        dir_mod_inherited_ace_str = "ACL:%s:ALLOWED/OI|IO|I/CHANGE" % self.user

        try:
            # add flags on oi_dir

            # This is somewhat artificial, we need to add a new acl to the directory
            # so that the following modify operation doesn't fail. Previously
            # '--modify' was used in place of '--add' but that resulted in failure
            # to access the directory ( or even modify the acl ).
            # Note: when running this test against a windows server it seems that
            # running as Administrator ensures best results

            # add flags on oi_dir/oi_dir
            self.smb_cacls(["--add", explict_access_ace_str, self.oi_dir])

            # add flags on oi_dir/nested
            self.smb_cacls(["--add", explict_access_ace_str, self.nested_dir])

            # add flags on oi_dir/nested/nested_again
            self.smb_cacls(["--add", explict_access_ace_str, self.nested_again_dir])

            # add flags on oi_dir/file-1
            self.smb_cacls([ "--add", explict_access_ace_str, self.f1])

            # add flags on oi_dir/nested/file-2
            self.smb_cacls(["--add", explict_access_ace_str, self.f2])

            # add flags on oi_dir/nested/nested_again/file-3
            self.smb_cacls(["--add", explict_access_ace_str, self.f3])

            self.smb_cacls(["--propagate-inheritance", "--modify",
                            dir_mod_acl_str, self.oi_dir])


            # check top level container 'oi_dir' has OI/CHANGE
            dir_ace = self.ace_parse_str(dir_mod_acl_str)
            self.assertTrue(self.file_ace_check(self.oi_dir, dir_ace))

            # file 'oi_dir/file-1' should  have inherited I/CHANGE
            child_file_ace = self.ace_parse_str(file_mod_inherited_ace_str)
            self.assertTrue(self.file_ace_check(self.f1, child_file_ace))

            # nested dir  'oi_dir/nested/' should have OI|IO/CHANGE
            child_dir_ace = self.ace_parse_str(dir_mod_inherited_ace_str)
            self.assertTrue(self.file_ace_check(self.nested_dir, child_dir_ace))

            # nested file 'oi_dir/nested/file-2' should  have inherited I/CHANGE
            self.assertTrue(self.file_ace_check(self.f2, child_file_ace))

            # nested dir  'oi_dir/nested/nested_again' should have OI|IO/CHANGE
            child_dir_ace = self.ace_parse_str(dir_mod_inherited_ace_str)
            self.assertTrue(self.file_ace_check(self.nested_again_dir, child_dir_ace))

            # nested file 'oi_dir/nested/nested_agsin/file-3' should  have inherited I/CHANGE
            self.assertTrue(self.file_ace_check(self.f3, child_file_ace))

        except BlackboxProcessError as e:
            self.fail(str(e))

    def test_simple_ci_add(self):
        """test smbcacls '--propagate-inheritance --add' which attempts to add the ACL
        for the file and additionally use inheritance rules to propagate appropriate
        changes to children

        This test adds an ACL with (CI)(READ)

        before:

        +-tar_test_dir/    (OI)(CI)(I)(F)
          +-oi_dir/        (OI)(CI)(I)(F)
          | +-file.1            (I)(F)
          | +-nested/      (OI)(CI)(I)(F)
          |   +-file.2          (I)(F)
          |   +-nested_again/     (OI)(CI)(I)(F)
          |     +-file.3          (I)(F)

        after/expected:

        +-tar_test_dir/    (OI)(CI)(I)(F)
          +-oi_dir/        (OI)(CI)(I)(F), (CI)(READ)
          | +-file.1            (I)(F)
          | +-nested/      (OI)(CI)(I)(F), (CI)((I)(READ)
          |   +-file.2          (I)(F)
          |   +-nested_again/     (OI)(CI)(I)(F), (CI)((I)(READ)
          |     +-file.3          (I)(F)"""
        try:
            dir_add_acl_str = "ACL:%s:ALLOWED/CI/READ" % self.user
            file_inherited_ace_str = "ACL:%s:ALLOWED/I/READ" % self.user
            dir_inherited_ace_str = "ACL:%s:ALLOWED/CI|I/READ" % self.user

            self.smb_cacls(["--propagate-inheritance", "--add",
                           dir_add_acl_str, self.oi_dir])

            # check top level container 'oi_dir' has CI/READ
            dir_ace = self.ace_parse_str(dir_add_acl_str)
            self.assertTrue(self.file_ace_check(self.oi_dir, dir_ace))

            # nested file 'oi_dir/file-1' should NOT have inherited I/READ
            child_file_ace = self.ace_parse_str(file_inherited_ace_str)
            self.assertTrue(self.file_ace_check(self.f1, child_file_ace) == False)

            # nested dir  'oi_dir/nested/' should have CI|I|READ
            child_dir_ace = self.ace_parse_str(dir_inherited_ace_str);
            self.assertTrue(self.file_ace_check(self.nested_dir, child_dir_ace))

            # nested file 'oi_dir/nested/file-2' should NOT have inherited I/READ
            child_file_ace = self.ace_parse_str(file_inherited_ace_str)
            self.assertTrue(self.file_ace_check(self.f2, child_file_ace) == False)

            # nested dir  'oi_dir/nested/nested_again' should have CI|I|READ
            child_dir_ace = self.ace_parse_str(dir_inherited_ace_str);
            self.assertTrue(self.file_ace_check(self.nested_again_dir, child_dir_ace))

            # nested file 'oi_dir/nested/nested_again/file-3' should NOT have inherited I/READ
            child_file_ace = self.ace_parse_str(file_inherited_ace_str)
            self.assertTrue(self.file_ace_check(self.f3, child_file_ace) == False)

        except BlackboxProcessError as e:
            self.fail(str(e))

    def test_simple_ci_delete(self):
        """test smbcacls '--propagate-inheritance --add' which attempts to add the ACL
        for the file and additionally use inheritance rules to propagate appropriate
        changes to children

        This test delete an ACL with (CI)(READ)

        before:

        +-tar_test_dir/    (OI)(CI)(I)(F)
           +-oi_dir/        (OI)(CI)(I)(F), (CI)(READ)
           | +-file.1            (I)(F)
           | +-nested/      (OI)(CI)(I)(F), (CI)((I)(READ)
           |   +-file.2          (I)(F)
           |   +-nested_again/     (OI)(CI)(I)(F), (CI)((I)(READ)
           |     +-file.3          (I)(F)

        after/expected:

        +-tar_test_dir/    (OI)(CI)(I)(F)
           +-oi_dir/        (OI)(CI)(I)(F)
           | +-file.1            (I)(F)
           | +-nested/      (OI)(CI)(I)(F)
           |   +-file.2          (I)(F)
           |   +-nested_again/     (OI)(CI)(I)(F)
           |     +-file.3          (I)(F)"""

        dir_acl_str = "ACL:%s:ALLOWED/CI/READ" % self.user
        file_inherited_ace_str = "ACL:%s:ALLOWED/I/READ" % self.user
        dir_inherited_ace_str = "ACL:%s:ALLOWED/CI|I/READ" % self.user
        try:

            # add flags on oi_dir
            self.smb_cacls(["--add", dir_acl_str, self.oi_dir])

            # add flags on oi_dir/nested
            self.smb_cacls(["--add", dir_inherited_ace_str, self.nested_dir])

            # add flags on oi_dir/nested/nested_again
            self.smb_cacls(["--add", dir_inherited_ace_str, self.nested_dir])

            # make sure no (I|READ) flags on oi_dir/file-1
            self.smb_cacls(["--delete", file_inherited_ace_str, self.f1])

            # make sure no (I|READ) flags on oi_dir/nested/file-2
            self.smb_cacls(["--delete", file_inherited_ace_str, self.f2])

            # make sure no (I|READ) flags on oi_dir/nested/nested_again/file-3
            self.smb_cacls(["--delete", file_inherited_ace_str, self.f2])

            self.smb_cacls(["--propagate-inheritance",
                            "--delete",
                            dir_acl_str, self.oi_dir])

            # check top level container 'oi_dir' no longer has CI/READ
            dir_ace = self.ace_parse_str(dir_acl_str)
            self.assertTrue(self.file_ace_check(self.oi_dir, dir_ace) == False)

            child_file_ace = self.ace_parse_str(file_inherited_ace_str);
            # nested file 'oi_dir/file-1' should NOT have inherited I/READ
            self.assertTrue(self.file_ace_check(self.f1, child_file_ace) == False)

            child_dir_ace = self.ace_parse_str(dir_inherited_ace_str)
            # nested dir  'oi_dir/nested/' should no longer have CI|I|READ
            self.assertTrue(self.file_ace_check(self.nested_dir, child_dir_ace) == False)

            # nested dir  'oi_dir/nested/nested_again' should no longer have CI|I|READ
            self.assertTrue(self.file_ace_check(self.nested_again_dir, child_dir_ace) == False)

        except BlackboxProcessError as e:
            self.fail(str(e))

    def test_simple_ci_modify(self):
        """test smbcacls '--propagate-inheritance --modify' which attempts to modify ACL
        for the file and additionally use inheritance rules to propagate appropriate
        changes to children

        This test first adds an ACL with (CI)(R), then it modifies that acl to be
        (CI)(D) - where D == 0x00110000

        before:

        +-tar_test_dir/    (OI)(CI)(I)(F)
          +-oi_dir/        (CI)(R)
          | +-file.1            (I)(F)
          | +-nested/      (CI)(I)(R)
          |   +-file.2          (I)(F)
          |   +-nested_again/     (CI)(I)(R)
          |     +-file.3          (I)(F)


        after/expected:

        +-tar_test_dir/    (OI)(CI)(I)(F)
          +-oi_dir/        (CI)(CHANGE)
          | +-file.1            (I)(F)
          | +-nested/      (CI)(I)(CHANGE)
          |   +-file.2          (I)(F)
          |   +-nested_again/     (CI)(I)(CHANGE)
          |     +-file.3          (I)(F)"""

        dir_acl_str = "ACL:%s:ALLOWED/CI/READ" % self.user
        file_inherited_ace_str = "ACL:%s:ALLOWED/I/READ" % self.user
        dir_inherited_ace_str = "ACL:%s:ALLOWED/CI|I/READ" % self.user
        dir_mod_acl_str = "ACL:%s:ALLOWED/CI/CHANGE" % self.user
        file_mod_inherited_ace_str = "ACL:%s:ALLOWED/I/CHANGE" % self.user
        dir_mod_inherited_ace_str = "ACL:%s:ALLOWED/CI|I/CHANGE" % self.user
        delete_ace_str = "ACL:%s:ALLOWED/0x0/RWD" % self.user

        try:
            # This is somewhat artificial, we need to add a new acl to the
            # directory so that the following modify operation doesn't fail.
            # Previously '--modify' was used in place of '--add' but that
            # resulted in failure to access the directory ( or even modify
            # the acl ).
            # Note: when running this test against a windows server it seems
            # that running as Administrator ensures best results
            self.smb_cacls(["--add", dir_acl_str, self.oi_dir])

            # add flags on oi_dir/nested
            self.smb_cacls(["--add", dir_inherited_ace_str, self.nested_dir])

            # add flags on oi_dir/nested/nested_again
            self.smb_cacls(["--add", dir_inherited_ace_str, self.nested_again_dir])

            self.smb_cacls(["--propagate-inheritance", "--modify",
                            dir_mod_acl_str, self.oi_dir])

            # check top level container 'oi_dir' has CI/CHANGE
            dir_ace = self.ace_parse_str(dir_mod_acl_str);
            self.assertTrue(self.file_ace_check(self.oi_dir, dir_ace))

            # nested file 'oi_dir/file-1' should NOT have inherited I/CHANGE
            child_file_ace = self.ace_parse_str(file_mod_inherited_ace_str)
            self.assertTrue(self.file_ace_check(self.f1, child_file_ace) == False)

            # nested dir  'oi_dir/nested/' should have OI|I/CHANGE
            child_dir_ace = self.ace_parse_str(dir_mod_inherited_ace_str)
            self.assertTrue(self.file_ace_check(self.nested_dir, child_dir_ace))

            # nested file 'oi_dir/nested/file-2' should NOT have inherited I/CHANGE
            child_file_ace = self.ace_parse_str(file_mod_inherited_ace_str)
            self.assertTrue(self.file_ace_check(self.f2, child_file_ace) == False)

            # nested dir  'oi_dir/nested/nested_again' should have OI|I/CHANGE
            child_dir_ace = self.ace_parse_str(dir_mod_inherited_ace_str)
            self.assertTrue(self.file_ace_check(self.nested_again_dir, child_dir_ace))

            # nested file 'oi_dir/nested/nested_again/file-3' should NOT have inherited I/CHANGE
            child_file_ace = self.ace_parse_str(file_mod_inherited_ace_str)
            self.assertTrue(self.file_ace_check(self.f3, child_file_ace) == False)

            # set some flags to allow us to delete the files
            self.smb_cacls(["--set", delete_ace_str, self.f1])
            self.smb_cacls(["--set", delete_ace_str, self.f2])
            self.smb_cacls(["--set", delete_ace_str, self.f3])

        except BlackboxProcessError as e:
            self.fail(str(e))

    def test_simple_cioi_add(self):
        """test smbcacls '--propagate-inheritance --add' which attempts to add the ACL
        for the file and additionally use inheritance rules to propagate appropriate
        changes to children

        This test adds an ACL with (CI)(OI)(READ)

        before:

        +-tar_test_dir/    (OI)(CI)(I)(F)
          +-oi_dir/        (OI)(CI)(I)(F)
          | +-file.1            (I)(F)
          | +-nested/      (OI)(CI)(I)(F)
          |   +-file.2          (I)(F)
          |   +-nested_again/     (OI)(CI)(I)(F)
          |     +-file.3          (I)(F)

        after/expected:

        +-tar_test_dir/    (OI)(CI)(I)(F)
          +-oi_dir/        (OI)(CI)(I)(F), (CI)(OI)READ)
          | +-file.1            (I)(F), (I)(READ)
          | +-nested/      (OI)(CI)(I)(F), (CI)(OI)(I)(READ)
          |   +-file.2          (I)(F), (I)(READ)
          |   +-nested_again/     (OI)(CI)(I)(F), (CI)(OI)(I)(READ)
          |     +-file.3          (I)(F), (I)(READ)"""

        dir_add_acl_str = "ACL:%s:ALLOWED/OI|CI/READ" % self.user
        file_inherited_ace_str = "ACL:%s:ALLOWED/I/READ" % self.user
        dir_inherited_ace_str = "ACL:%s:ALLOWED/OI|CI|I/READ" % self.user

        try:

            self.smb_cacls(["--propagate-inheritance", "--add",
                           dir_add_acl_str, self.oi_dir])

            # check top level container 'oi_dir' has OI|CI/READ
            dir_ace = self.ace_parse_str(dir_add_acl_str)
            self.assertTrue(self.file_ace_check(self.oi_dir, dir_ace))

            # nested file 'oi_dir/file-1' should have inherited I/READ
            child_file_ace = self.ace_parse_str(file_inherited_ace_str);
            self.assertTrue(self.file_ace_check(self.f1, child_file_ace))

            # nested dir  'oi_dir/nested/' should have OI|CI|I|READ
            child_dir_ace = self.ace_parse_str(dir_inherited_ace_str);
            self.assertTrue(self.file_ace_check(self.nested_dir, child_dir_ace))

            # nested file 'oi_dir/nested/file-2' should have inherited I/READ
            child_file_ace = self.ace_parse_str(file_inherited_ace_str);
            self.assertTrue(self.file_ace_check(self.f2, child_file_ace))

            # nested dir  'oi_dir/nested/nested_again' should have OI|CI|I|READ
            child_dir_ace = self.ace_parse_str(dir_inherited_ace_str);
            self.assertTrue(self.file_ace_check(self.nested_again_dir, child_dir_ace))

            # nested file 'oi_dir/nested/nested_again/file-3' should have inherited I/READ
            child_file_ace = self.ace_parse_str(file_inherited_ace_str);
            self.assertTrue(self.file_ace_check(self.f3, child_file_ace))

        except BlackboxProcessError as e:
            self.fail(str(e))

    def test_simple_cioi_delete(self):
        """test smbcacls '--propagate-inheritance --delete' which attempts to delete the
        ACL for the file and additionally use inheritance rules to propagate
        appropriate changes to children

        This test deletes an ACL with (CI)(OI)(READ)

        before:

        +-tar_test_dir/    (OI)(CI)(I)(F)
          +-oi_dir/        (OI)(CI)(I)(F), (CI)(OI)(READ)
          | +-file.1            (I)(F), (I)(READ)
          | +-nested/      (OI)(CI)(I)(F), (CI)(OI)(I)(READ)
          |   +-file.2          (I)(F), (I)(READ)
          |   +-nested_again/     (OI)(CI)(I)(F), (CI)(OI)(I)(READ)
          |     +-file.3          (I)(F), (I)(READ)

        after/expected:

        +-tar_test_dir/    (OI)(CI)(I)(F)
          +-oi_dir/        (OI)(CI)(I)(F)
          | +-file.1            (I)(F)
          | +-nested/      (OI)(CI)(I)(F)
          |   +-file.2          (I)(F)
          |   +-nested_again/     (OI)(CI)(I)(F)
          |     +-file.3          (I)(F)"""


        dir_acl_str = "ACL:%s:ALLOWED/OI|CI/READ" % self.user
        file_inherited_ace_str = "ACL:%s:ALLOWED/I/READ" % self.user
        dir_inherited_ace_str = "ACL:%s:ALLOWED/OI|CI|I/READ" % self.user

        try:

            # add flags on oi_dir
            self.smb_cacls(["--add", dir_acl_str, self.oi_dir])

            # add flags on oi_dir/nested
            self.smb_cacls(["--add", dir_inherited_ace_str, self.nested_dir])

            # add flags on oi_dir/file-1
            self.smb_cacls(["--add", file_inherited_ace_str, self.f1])

            # add flags on oi_dir/nested/file-2
            self.smb_cacls(["--add", file_inherited_ace_str, self.f2])

            # add flags on oi_dir/nested/nested_again/file-3
            self.smb_cacls(["--add", file_inherited_ace_str, self.f2])

            self.smb_cacls(["--propagate-inheritance", "--delete",
                                dir_acl_str, self.oi_dir])

            # check top level container 'oi_dir' no longer has OI|CI/READ
            dir_ace = self.ace_parse_str(dir_acl_str)
            self.assertTrue(self.file_ace_check(self.oi_dir, dir_ace) == False)

            # nested file 'oi_dir/file-1' should NOT have inherited I/READ
            child_file_ace = self.ace_parse_str(file_inherited_ace_str)
            self.assertTrue(self.file_ace_check(self.f1, child_file_ace) == False)

            # nested dir  'oi_dir/nested/' should no longer have OI|CI|I|READ
            child_dir_ace = self.ace_parse_str(dir_inherited_ace_str)
            self.assertTrue(self.file_ace_check(self.nested_dir, child_dir_ace) == False)
            # nested file 'oi_dir/nested/file-2' should NOT have inherited I/READ
            child_file_ace = self.ace_parse_str(file_inherited_ace_str)
            self.assertTrue(self.file_ace_check(self.f2, child_file_ace) == False)
            # nested dir  'oi_dir/nested/nested_again' should no longer have OI|CI|I|READ
            child_dir_ace = self.ace_parse_str(dir_inherited_ace_str)
            self.assertTrue(self.file_ace_check(self.nested_again_dir, child_dir_ace) == False)
            # nested file 'oi_dir/nested/nested_againfile-2' should NOT have inherited I/READ
            child_file_ace = self.ace_parse_str(file_inherited_ace_str)
            self.assertTrue(self.file_ace_check(self.f3, child_file_ace) == False)
        except BlackboxProcessError as e:
            self.fail(str(e))

    def test_simple_cioi_modify(self):
        """test smbcacls '--propagate-inheritance --modify' which attempts to modify the
        ACLfor the file and additionally use inheritance rules to propagate
        appropriate changes to children

        This test first adds an ACL with (CI)(OI)(R), then it modifies that acl to be
        (CI)(OI)(D) - where D == 0x00110000

        before:

        +-tar_test_dir/    (OI)(CI)(I)(F)
          +-oi_dir/        (CI)(OI)(R)
          | +-file.1       (I)(R)
          | +-nested/      (CI)(OI)(I)(R)
          |   +-file.2     (I)(R)
          |   +-nested_again/     (CI)(OI)(I)(R)
          |     +-file.3          (I)(R)

        after/expected:

        +-tar_test_dir/    (OI)(CI)(I)(F)
          +-oi_dir/        (CI)(OI)(CHANGE)
          | +-file.1       (I)(CHANGE)
          | +-nested/      (CI)(OI)(I)(CHANGE)
          |   +-file.2     (I)(CHANGE)
          |   +-nested_again/     (CI)(OI)(I)(CHANGE)
          |     +-file.3          (I)(CHANGE)"""

        dir_acl_str = "ACL:%s:ALLOWED/OI|CI/R" % self.user
        file_inherited_ace_str = "ACL:%s:ALLOWED/I/R" % self.user
        dir_inherited_ace_str = "ACL:%s:ALLOWED/OI|CI|I/R" % self.user

        dir_mod_acl_str = "ACL:%s:ALLOWED/OI|CI/CHANGE" % self.user
        file_mod_inherited_ace_str = "ACL:%s:ALLOWED/I/CHANGE" % self.user
        dir_mod_inherited_ace_str = "ACL:%s:ALLOWED/OI|CI|I/CHANGE" % self.user
        try:
            # add flags on oi_dir

            # This is somewhat artificial, we need to add a new acl to the
            # directory so that the following modify operation doesn't fail.
            # Previously '--modify' was used in place of '--add' but that
            # resulted in failure to access the directory ( or even modify
            # the acl ). Note: when running this test against a windows server
            # it seems that running as Administrator ensures best results

            self.smb_cacls(["--add", dir_acl_str, self.oi_dir])

            # add flags on oi_dir/nested
            self.smb_cacls(["--add", dir_inherited_ace_str, self.nested_dir])

            # add flags on oi_dir/nested/nested_again
            self.smb_cacls(["--add", dir_inherited_ace_str, self.nested_again_dir])

            # add flags on oi_dir/file-1
            self.smb_cacls(["--add", file_inherited_ace_str, self.f1])

            # add flags on oi_dir/nested/file-2
            self.smb_cacls(["--add", file_inherited_ace_str, self.f2])

            # add flags on oi_dir/nested/nested_again/file-2
            self.smb_cacls(["--add", file_inherited_ace_str, self.f3])

            self.smb_cacls(["--propagate-inheritance", "--modify",
                            dir_mod_acl_str, self.oi_dir])

            # check top level container 'oi_dir' has OI|CI/CHANGE
            dir_ace = self.ace_parse_str(dir_mod_acl_str)
            self.assertTrue(self.file_ace_check(self.oi_dir, dir_ace))

            # nested file 'oi_dir/file-1' should have inherited I|CHANGE
            child_file_ace = self.ace_parse_str(file_mod_inherited_ace_str);
            self.assertTrue(self.file_ace_check(self.f1, child_file_ace));

            # nested dir  'oi_dir/nested/' should have OI|CI|I|CHANGE
            child_dir_ace = self.ace_parse_str(dir_mod_inherited_ace_str)
            self.file_ace_check(self.nested_dir, child_dir_ace)

            # nested file 'oi_dir/nested/file-2' should have inherited I|CHANGE
            child_file_ace = self.ace_parse_str(file_mod_inherited_ace_str);
            self.assertTrue(self.file_ace_check(self.f2, child_file_ace));

            # nested dir  'oi_dir/nested/nested_again' should have OI|CI|I|CHANGE
            child_dir_ace = self.ace_parse_str(dir_mod_inherited_ace_str)
            self.file_ace_check(self.nested_again_dir, child_dir_ace)

            # nested file 'oi_dir/nested/nested_again/file-3' should have inherited I|CHANGE
            child_file_ace = self.ace_parse_str(file_mod_inherited_ace_str);
            self.assertTrue(self.file_ace_check(self.f3, child_file_ace));

        except BlackboxProcessError as e:
            self.fail(str(e))

    def test_simple_set_fail(self):
        """test smbcacls '--propagate-inheritance --set' which attempts to set the ACL
        for the file and additionally use inheritance rules to propagate appropriate
        changes to children

        This test adds an ACL with (CI)(OI)(READ)

        before:

        +-tar_test_dir/    (OI)(CI)(I)(F)
          +-oi_dir/        (OI)(CI)(I)(F)
          | +-file.1            (I)(F)
          | +-nested/      (OI)(CI)(I)(F)
          |   +-file.2          (I)(F)
          |   +-nested_again/     (OI)(CI)(I)(F)
          |     +-file.3          (I)(F)

        after/expected:
        fail, oid_dir has inheritance enabled, set should fail and exit with '1'"""
        dir_acl_str = "ACL:%s:ALLOWED/OI|CI/R" % self.user
        file_inherited_ace_str = "ACL:%s:ALLOWED/I/R" % self.user
        dir_inherited_ace_str = "ACL:%s:ALLOWED/OI|CI|I/R" % self.user

        try:
            f1 = self.create_remote_test_file("oi_dir/file-1")
            f2 = self.create_remote_test_file("oi_dir/nested/file-2")
            oi_dir = os.path.split(f1)[0]
            nested_dir = os.path.split(f2)[0]

            try:
                self.smb_cacls(["--propagate-inheritance", "--set",
                               dir_acl_str, oi_dir])
                self.fail("%s succeeded unexpectedly while processing container with inheritance enabled")
            except BlackboxProcessError as e:
                pass

        except BlackboxProcessError as e:
            self.fail(str(e))

    def test_simple_oici_set(self):
        """test smbcacls '--propagate-inheritance --set' which attempts to set the ACL
        for the file and additionally use inheritance rules to propagate appropriate
        changes to children

        This test adds an ACL with (CI)(OI)(RWD) additionally it removes
        inheritance from oi_dir

        before:

        +-tar_test_dir/    (OI)(CI)(I)(F)
          +-oi_dir/        (OI)(CI)(I)(F)
          | +-file.1            (I)(F)
          | +-nested/      (OI)(CI)(I)(F)
          |   +-file.2          (I)(F)
          |   +-nested_again/     (OI)(CI)(I)(F)
          |     +-file.3          (I)(F)

        after/expected:

        +-tar_test_dir/    (OI)(CI)(I)(F)
          +-oi_dir/        (OI)(CI)(RWD)
          | +-file.1            (I)(RWD)
          | +-nested/      (OI)(CI)(I)(RWD)
          |   +-file.2          (I)(RWD)
          |   +-nested_again/     (OI)(CI)(I)(RWD)
          |     +-file.3          (I)(RWD)"""

        dir_acl_str = "ACL:%s:ALLOWED/OI|CI/RWD" % self.user
        file_inherited_ace_str = "ACL:%s:ALLOWED/I/RWD" % self.user
        dir_inherited_ace_str = "ACL:%s:ALLOWED/OI|CI|I/RWD" % self.user

        try:
            # smb_cacls --inherit=copy
            self.smb_cacls(["--inherit=copy", self.oi_dir])

            self.smb_cacls(["--propagate-inheritance", "--set",
                            dir_acl_str, self.oi_dir])

            # check top level container 'oi_dir' has OI|CI/RWD
            dir_ace = self.ace_parse_str(dir_acl_str)
            self.assertTrue(self.file_ace_check(self.oi_dir, dir_ace))

            # check nested file oi_dir/file-1 has I/RWD
            child_file_ace = self.ace_parse_str(file_inherited_ace_str)
            self.assertTrue(self.file_ace_check(self.f1, child_file_ace))

            # check nested dir oi_dir/nested has OI|CI|I/RWD
            child_dir_ace = self.ace_parse_str(dir_inherited_ace_str)
            self.assertTrue(self.file_ace_check(self.nested_dir, child_dir_ace))

            # check nested file oi_dir/nested/file-2 has I/RWD
            child_file_ace = self.ace_parse_str(file_inherited_ace_str)
            self.assertTrue(self.file_ace_check(self.f2, child_file_ace))

            # check nested dir oi_dir/nested/nested_again has OI|CI|I/RWD
            child_dir_ace = self.ace_parse_str(dir_inherited_ace_str)
            self.assertTrue(self.file_ace_check(self.nested_again_dir, child_dir_ace))

            # check nested file oi_dir/nested/nested_again/file-3 has I/RWD
            child_file_ace = self.ace_parse_str(file_inherited_ace_str)
            self.assertTrue(self.file_ace_check(self.f3, child_file_ace))

        except BlackboxProcessError as e:
            self.fail(str(e))

    def test_simple_ci_set(self):
        """test smbcacls '--propagate-inheritance --set' which attempts to set the ACL
        for the file and additionally use inheritance rules to propagate appropriate
        changes to children

        This test adds an ACL with (CI)(RWD) additionally it removes
        inheritance from oi_dir

        before:

        +-tar_test_dir/    (OI)(CI)(I)(F)
          +-oi_dir/        (OI)(CI)(I)(F)
          | +-file.1            (I)(F)
          | +-nested/      (OI)(CI)(I)(F)
          |   +-file.2          (I)(F)
          |   +-nested_again/     (OI)(CI)(I)(F)
          |     +-file.3          (I)(F)

        after/expected:

        +-tar_test_dir/    (OI)(CI)(I)(RWD)
          +-oi_dir/        (CI)(RWD)
          | +-file.1
          | +-nested/      (CI)(I)(RWD)
          |   +-file.2
          |   +-nested_again/     (CI)(I)(RWD)
          |     +-file.3          """
        dir_acl_str = "ACL:%s:ALLOWED/CI/RWD" % self.user
        file_inherited_ace_str = "ACL:%s:ALLOWED/I/RWD" % self.user
        dir_inherited_ace_str = "ACL:%s:ALLOWED/CI|I/RWD" % self.user
        delete_ace_str = "ACL:%s:ALLOWED/0x0/RWD" % self.user

        try:
            # smb_cacls --inherit=copy
            self.smb_cacls(["--inherit=copy", self.oi_dir])

            self.smb_cacls(["--propagate-inheritance", "--set",
                            dir_acl_str, self.oi_dir])

            out = self.smb_cacls([self.oi_dir])
            #count the ACL(s)
            nacls = len([i for i in out.decode().split("\n") if i.startswith("ACL")])

            # Although there maybe a couple of users with associated acl(s)
            # before set, after set there should only be 1 acl

            self.assertEqual(nacls, 1)

            # check top level container 'oi_dir' has OI|CI/RWD
            dir_ace = self.ace_parse_str(dir_acl_str)
            self.assertTrue(self.file_ace_check(self.oi_dir, dir_ace))

            # note can't check file because it has no ACL ( due to CI )
            # check nested dir 'oi_dir/nested' has CI|I/RWD
            child_dir_ace = self.ace_parse_str(dir_inherited_ace_str)
            self.assertTrue(self.file_ace_check(self.nested_dir, child_dir_ace))

            # check nested dir 'oi_dir/nested/nested_again' has CI|I/RWD
            child_dir_ace = self.ace_parse_str(dir_inherited_ace_str)
            self.assertTrue(self.file_ace_check(self.nested_dir, child_dir_ace))
            self.smb_cacls(["--set", delete_ace_str, self.f1])
            self.smb_cacls(["--set", delete_ace_str, self.f2])
            self.smb_cacls(["--set", delete_ace_str, self.f3])
        except BlackboxProcessError as e:
            self.fail(str(e))

    def test_simple_cioinp_add(self):
        """test smbcacls '--propagate-inheritance --add' which attempts to add the ACL
        for the file and additionally use inheritance rules to propagate appropriate
        changes to children

        This test adds an ACL with (CI)(OI)(NP)(CHANGE)
        (NP) - no propagation should not propagate the changes any further containers

        before:

        +-tar_test_dir/    (OI)(CI)(I)(F)
          +-oi_dir/        (OI)(CI)(I)(F)
          | +-file.1            (I)(F)
          | +-nested/      (OI)(CI)(I)(F)
          |   +-file.2          (I)(F)
          |   +-nested_again/     (OI)(CI)(I)(F)
          |     +-file.3          (I)(F)

        after/expected:

        +-tar_test_dir/    (OI)(CI)(I)(F)
          +-oi_dir/        (OI)(CI)(I)(F), (CI)(OI)(NP)(CHANGE)
          | +-file.1            (I)(F), (I)(CHANGE)
          | +-nested/      (OI)(CI)(I)(F), (I)(M)
          |   +-file.2          (I)(F)
          |   +-nested_again/     (OI)(CI)(I)(F)
          |     +-file.3          (I)(F)"""

        dir_add_acl_str = "ACL:%s:ALLOWED/OI|CI|NP/CHANGE" % self.user
        inherited_ace_str = "ACL:%s:ALLOWED/I/CHANGE" % self.user
        try:
            self.smb_cacls(["--propagate-inheritance", "--add",
                            dir_add_acl_str, self.oi_dir])

            # check top level container 'oi_dir' has OI|CI|NP/READ
            dir_ace = self.ace_parse_str(dir_add_acl_str)
            self.assertTrue(self.file_ace_check(self.oi_dir, dir_ace))

            child_file_ace = self.ace_parse_str(inherited_ace_str)
            # nested file 'oi_dir/file-1' should have inherited I/CHANGE
            self.assertTrue(self.file_ace_check(self.f1, child_file_ace))

            # nested dir  'oi_dir/nested' should have inherited I/CHANGE
            child_dir_ace = self.ace_parse_str(inherited_ace_str)
            self.assertTrue(self.file_ace_check(self.nested_dir, child_dir_ace))
            # nested file  'oi_dir/nested/file-2' should NOT have I/CHANGE
            child_dir_ace = self.ace_parse_str(inherited_ace_str)
            self.assertTrue(self.file_ace_check(self.f2, child_dir_ace) == False)
            # nested dir  'oi_dir/nested/nested_again/' should NOT have I/CHANGE
            child_dir_ace = self.ace_parse_str(inherited_ace_str)
            self.assertTrue(self.file_ace_check(self.nested_again_dir, child_dir_ace) == False)
            # nested file  'oi_dir/nested/nested_again/file-3' should NOT have I/CHANGE
            child_dir_ace = self.ace_parse_str(inherited_ace_str)
            self.assertTrue(self.file_ace_check(self.f3, child_dir_ace) == False)

        except BlackboxProcessError as e:
            self.fail(str(e))

    def test_simple_oinp_add(self):
        """test smbcacls '--propagate-inheritance --add' which attempts to add the ACL
        for the file and additionally use inheritance rules to propagate appropriate
        changes to children

        This test adds an ACL with (OI)(NP)(CHANGE)
        (NP) - no propagation should not propagate the changes any further containers

        before:

        +-tar_test_dir/    (OI)(CI)(I)(F)
          +-oi_dir/        (OI)(CI)(I)(F)
          | +-file.1            (I)(F)
          | +-nested/      (OI)(CI)(I)(F)
          |   +-file.2          (I)(F)
          |   +-nested_again/     (OI)(CI)(I)(F)
          |     +-file.3          (I)(F)

        after/expected:

        +-tar_test_dir/    (OI)(CI)(I)(F)
          +-oi_dir/        (OI)(CI)(I)(F), (OI)(NP)(CHANGE)
          | +-file.1            (I)(F), (I)(CHANGE)
          | +-nested/      (OI)(CI)(I)(F)
          |   +-file.2          (I)(F)
          |   +-nested_again/     (OI)(CI)(I)(F)
          |     +-file.3          (I)(F)"""

        dir_add_acl_str = "ACL:%s:ALLOWED/OI|NP/CHANGE" % self.user
        inherited_ace_str = "ACL:%s:ALLOWED/I/CHANGE" % self.user
        try:
            self.smb_cacls(["--propagate-inheritance",
                            "--add",
                            dir_add_acl_str, self.oi_dir])

            # check top level container 'oi_dir' has OI|NP/CHANGE
            dir_ace = self.ace_parse_str(dir_add_acl_str)
            self.assertTrue(self.file_ace_check(self.oi_dir, dir_ace))

            child_file_ace = self.ace_parse_str(inherited_ace_str)
            # nested file 'oi_dir/file-1' should have inherited I/CHANGE
            self.assertTrue(self.file_ace_check(self.f1, child_file_ace))

            # nested dir  'oi_dir/nested' should NOT have I/CHANGE
            child_dir_ace = self.ace_parse_str(inherited_ace_str)
            self.assertTrue(self.file_ace_check(self.nested_dir, child_dir_ace) == False)

            child_file_ace = self.ace_parse_str(inherited_ace_str)
            # nested file 'oi_dir/nested/file-1' should NOT have inherited I/CHANGE
            self.assertTrue(self.file_ace_check(self.f2, child_file_ace) == False)

        except BlackboxProcessError as e:
            self.fail(str(e))

    def test_simple_cinp_add(self):
        """# test smbcacls '--propagate-inheritance --add' which attempts to add the ACL
        for the file and additionally use inheritance rules to propagate appropriate
        changes to children

        This test adds an ACL with (CI)(NP)(CHANGE)
        (NP) - no propagation should not propagate the changes any further containers

        before:

        +-tar_test_dir/    (OI)(CI)(I)(F)
          +-oi_dir/        (OI)(CI)(I)(F)
          | +-file.1            (I)(F)
          | +-nested/      (OI)(CI)(I)(F)
          |   +-file.2          (I)(F)
          |   +-nested_again/     (OI)(CI)(I)(F)
          |     +-file.3          (I)(F)

        after/expected:

        +-tar_test_dir/    (OI)(CI)(I)(F)
          +-oi_dir/        (OI)(CI)(I)(F), (CI)(NP)(CHANGE)
          | +-file.1            (I)(F)
          | +-nested/      (OI)(CI)(I)(F), (I)(CHANGE)
          |   +-file.2          (I)(F)
          |   +-nested_again/     (OI)(CI)(I)(F)
          |     +-file.3          (I)(F)"""

        dir_add_acl_str = "ACL:%s:ALLOWED/CI|NP/CHANGE" % self.user
        inherited_ace_str = "ACL:%s:ALLOWED/I/CHANGE" % self.user
        try:
            self.smb_cacls(["--propagate-inheritance", "--add",
                            dir_add_acl_str, self.oi_dir])

            # check top level container 'oi_dir' has CI|NP/READ
            dir_ace = self.ace_parse_str(dir_add_acl_str)
            self.assertTrue(self.file_ace_check(self.oi_dir, dir_ace))

            # nested file 'oi_dir/file-1' should NOT have inherited I/CHANGE
            child_file_ace = self.ace_parse_str(inherited_ace_str)
            self.assertTrue(self.file_ace_check(self.f1, child_file_ace) == False)

            # nested dir  'oi_dir/nested' should have I/CHANGE
            child_dir_ace = self.ace_parse_str(inherited_ace_str)
            self.assertTrue(self.file_ace_check(self.nested_dir, child_dir_ace))

            # nested file 'oi_dir/nested/file-2' should NOT have inherited I/CHANGE
            child_file_ace = self.ace_parse_str(inherited_ace_str)
            self.assertTrue(self.file_ace_check(self.f2, child_file_ace) == False)

            # nested dir  'oi_dir/nested/nested_again' should have NOT I/CHANGE
            child_dir_ace = self.ace_parse_str(inherited_ace_str)
            self.assertTrue(self.file_ace_check(self.nested_again_dir, child_dir_ace) == False)
            # nested file 'oi_dir/nested/nested_again/file-3' should NOT have inherited I/CHANGE
            child_file_ace = self.ace_parse_str(inherited_ace_str)
            self.assertTrue(self.file_ace_check(self.f3, child_file_ace) == False)

        except BlackboxProcessError as e:
            self.fail(str(e))

    def test_simple_cioinp_delete(self):
        """test smbcacls '--propagate-inheritance --delete' which attempts to delete
        the ACL for the file and additionally use inheritance rules to propagate
        appropriate changes to children

        This test adds an ACL with (CI)(OI)(NP)(CHANGE)
        (NP) - no propagation should not propagate the changes any further containers

        before:

        +-tar_test_dir/    (OI)(CI)(I)(F)
          +-oi_dir/        (OI)(CI)(I)(F), (CI)(OI)(NP)(CHANGE)
          | +-file.1            (I)(F), (I)(CHANGE)
          | +-nested/      (OI)(CI)(I)(F), (I)(CHANGE)
          |   +-file.2          (I)(F)

        after/expected:

        +-tar_test_dir/    (OI)(CI)(I)(F)
          +-oi_dir/        (OI)(CI)(I)(F)
          | +-file.1            (I)(F)
          | +-nested/      (OI)(CI)(I)(F)
          |   +-file.2          (I)(F)"""

        dir_add_acl_str = "ACL:%s:ALLOWED/OI|CI|NP/CHANGE" % self.user
        inherited_ace_str = "ACL:%s:ALLOWED/I/CHANGE" % self.user

        try:
            self.smb_cacls(["--add", dir_add_acl_str, self.oi_dir])

            self.smb_cacls(["--add", inherited_ace_str, self.f1])

            self.smb_cacls(["--add", inherited_ace_str, self.nested_dir])

            self.smb_cacls(["--propagate-inheritance", "--delete",
                            dir_add_acl_str, self.oi_dir])

            # check top level container 'oi_dir' does NOT have OI|CI|NP/READ
            dir_ace = self.ace_parse_str(dir_add_acl_str)
            self.assertTrue(self.file_ace_check(self.oi_dir, dir_ace) == False)

            # nested file 'oi_dir/file-1' should NOT have inherited I/CHANGE
            child_file_ace = self.ace_parse_str(inherited_ace_str)
            self.assertTrue(self.file_ace_check(self.f1, child_file_ace) == False)

            # nested dir 'oi_dir/nested' should NOT have inherited I/CHANGE
            child_dir_ace = self.ace_parse_str(inherited_ace_str)
            self.assertTrue(self.file_ace_check(self.nested_dir, child_dir_ace) == False)
        except BlackboxProcessError as e:
            self.fail(str(e))

    def test_simple_oinp_delete(self):
        """test smbcacls '--propagate-inheritance --delete' which attempts to delete the
        ACL for the file and additionally use inheritance rules to propagate
        appropriate changes to children

        This test adds an ACL with (OI)(NP)(CHANGE)
        (NP) - no propagation should not propagate the changes any further containers

        before:

        +-tar_test_dir/    (OI)(CI)(I)(F)
        +-oi_dir/        (OI)(CI)(I)(F), (OI)(NP)(CHANGE)
        | +-file.1            (I)(F), (I)(CHANGE)
        | +-nested/      (OI)(CI)(I)(F)
        |   +-file.2          (I)(F)

        after/expected:

        +-tar_test_dir/    (OI)(CI)(I)(F)
          +-oi_dir/        (OI)(CI)(I)(F)
          | +-file.1            (I)(F)
          | +-nested/      (OI)(CI)(I)(F)
          |   +-file.2          (I)(F)"""

        dir_add_acl_str = "ACL:%s:ALLOWED/OI|NP/CHANGE" % self.user
        inherited_ace_str = "ACL:%s:ALLOWED/I/CHANGE" % self.user
        try:

            # set up 'before' permissions
            self.smb_cacls(["--add", dir_add_acl_str, self.oi_dir])

            self.smb_cacls(["--add", inherited_ace_str, self.f1])

            self.smb_cacls(["--propagate-inheritance", "--delete",
                            dir_add_acl_str, self.oi_dir])

            # check top level container 'oi_dir' does NOT have OI|NP/READ
            dir_ace = self.ace_parse_str(dir_add_acl_str)
            self.assertTrue(self.file_ace_check(self.oi_dir, dir_ace) == False)

            child_file_ace = self.ace_parse_str(inherited_ace_str)
            # nested file 'oi_dir/file-1' should NOT have inherited I/CHANGE
            self.assertTrue(self.file_ace_check(self.f1, child_file_ace) == False)

        except BlackboxProcessError as e:
            self.fail(str(e))

    def test_simple_cinp_delete(self):
        """test smbcacls '--propagate-inheritance --delete' which attempts to delete the
        ACL for the file and additionally use inheritance rules to propagate
        appropriate changes to children

        This test adds an ACL with (CI)(NP)(CHANGE)
        (NP) - no propagation should not propagate the changes any further containers

        before:

        +-tar_test_dir/    (OI)(CI)(I)(F)
          +-oi_dir/        (OI)(CI)(I)(F), (CI)(NP)(CHANGE)
          | +-file.1            (I)(F)
          | +-nested/      (OI)(CI)(I)(F), (I)(CHANGE)
          |   +-file.2          (I)(F)

        after/expected:

        +-tar_test_dir/    (OI)(CI)(I)(F)
          +-oi_dir/        (OI)(CI)(I)(F)
          | +-file.1            (I)(F)
          | +-nested/      (OI)(CI)(I)(F)
          |   +-file.2          (I)(F)"""

        dir_add_acl_str = "ACL:%s:ALLOWED/CI|NP/CHANGE" % self.user
        inherited_ace_str = "ACL:%s:ALLOWED/I/CHANGE" % self.user

        try:
            self.smb_cacls(["--add", dir_add_acl_str, self.oi_dir])

            self.smb_cacls(["--add", inherited_ace_str, self.nested_dir])

            self.smb_cacls(["--propagate-inheritance", "--delete",
                            dir_add_acl_str, self.oi_dir])

            # check top level container 'oi_dir' doesn't have CI|NP/READ
            dir_ace = self.ace_parse_str(dir_add_acl_str)
            self.assertTrue(self.file_ace_check(self.oi_dir, dir_ace) == False)

            child_file_ace = self.ace_parse_str(inherited_ace_str)
            # nested file 'oi_dir/file-1' should NOT have inherited I/CHANGE
            self.assertTrue(self.file_ace_check(self.f1, child_file_ace) == False)

            # nested dir  'oi_dir/nested' should NOT have I/CHANGE
            child_dir_ace = self.ace_parse_str(inherited_ace_str)
            self.assertTrue(self.file_ace_check(self.nested_dir, child_dir_ace) == False)

        except BlackboxProcessError as e:
            self.fail(str(e))

    def test_simple_cioi_inhibit(self):
        """test smbcacls '--propagate-inheritance --add' which attempts to add the ACL
        for the file and additionally use inheritance rules to propagate appropriate
        changes to children. In particular it tests that inheritance removed does
        indeed prevent inheritance propagation

        This test adds an ACL with (CI)(OI)(CHANGE) at oi_dir

        Note: Inheritance has been removed ( and ace(s) copied ) at
        tar_test_dir/oi_dir/nested

        before:

        +-tar_test_dir/    (OI)(CI)(I)(F)
          +-oi_dir/        (OI)(CI)(I)(F)
          | +-file.1            (I)(F)
          | +-nested/      (OI)(CI)(F)
          |   +-file.2          (I)(F)

        after/expected:

        +-tar_test_dir/    (OI)(CI)(I)(F)
          +-oi_dir/        (OI)(CI)(I)(F), (CI)(OI)(CHANGE)
          | +-file.1            (I)(F), (I)((CHANGE)
          | +-nested/      (OI)(CI)(F)
          |   +-file.2          (I)(F)"""
        dir_add_acl_str = "ACL:%s:ALLOWED/OI|CI/CHANGE" % self.user
        file_inherited_ace_str = "ACL:%s:ALLOWED/I/CHANGE" % self.user
        dir_inherited_ace_str = "ACL:%s:ALLOWED/OI|CI|I/CHANGE" % self.user

        try:
            # smb_cacls --inherit=copy
            self.smb_cacls(["--inherit=copy", self.nested_dir])

            self.smb_cacls(["--propagate-inheritance", "--add",
                           dir_add_acl_str, self.oi_dir])

            # check top level container 'oi_dir' has OI|CI/CHANGE
            dir_ace = self.ace_parse_str(dir_add_acl_str)
            self.assertTrue(self.file_ace_check(self.oi_dir, dir_ace))

            # nested file 'oi_dir/file-1' should have inherited I/CHANGE
            child_file_ace = self.ace_parse_str(file_inherited_ace_str)
            self.assertTrue(self.file_ace_check(self.f1, child_file_ace))

            # nested dir  'oi_dir/nested/' should NOT have OI|CI|I/CHANGE
            child_dir_ace = self.ace_parse_str(dir_inherited_ace_str)
            self.assertTrue(self.file_ace_check(self.nested_dir, child_dir_ace) == False)

            # nested file  'oi_dir/nested/file-2' should NOT have I/CHANGE
            child_dir_ace = self.ace_parse_str(dir_inherited_ace_str)
            self.assertTrue(self.file_ace_check(self.f2, child_dir_ace) == False)

        except BlackboxProcessError as e:
            self.fail(str(e))
