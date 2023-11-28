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

class SaveRestoreSmbCaclsTests(SmbCaclsBlockboxTestBase):

    def setUp(self):
        super().setUp()

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
        super().tearDown()

    def test_simple_save_dir(self):
        try:
            # simple test to just store dacl of directory
            with self.mktemp() as tmpfile:
                out = self.smb_cacls(["--save", tmpfile,
                            self.oi_dir])
                with open(tmpfile, 'rb') as infile:
                    contents = infile.read().decode('utf16')
                    lines = contents.splitlines()
                    # should be 2 lines
                    self.assertEqual(len(lines), 2)
                    # first line should be the path
                    self.assertEqual(self.oi_dir.replace('/','\\'), lines[0])

        except BlackboxProcessError as e:
            self.fail(str(e))

    def test_simple_save_dir_r(self):
        try:
            # simple test to just store dacl of directory (recursively)
            with self.mktemp() as tmpfile:
                out = self.smb_cacls(["--recurse", "--save", tmpfile,
                            self.oi_dir])
                with open(tmpfile, 'rb') as infile:
                    contents = infile.read().decode('utf16')
                    print("contents = %s" % contents)
                    lines = contents.splitlines()
                    # should be 12 lines
                    self.assertEqual(len(lines), 12)
                    paths = [
                            self.oi_dir.replace('/','\\'),
                            self.f1.replace('/','\\'),
                            self.nested_dir.replace('/','\\'),
                            self.f2.replace('/','\\'),
                            self.nested_again_dir.replace('/','\\'),
                            self.f3.replace('/','\\')
                            ]
                    i = 0
                    for line in lines:
                        if not i % 2:
                            paths.remove(line)
                        i = i + 1
                    self.assertEqual(0, len(paths))

        except BlackboxProcessError as e:
            self.fail(str(e))

    def test_simple_restore_dir(self):
        try:
            # simple test to just store dacl of directory
            orig_saved = None
            modified = None
            restored = None
            with self.mktemp() as tmpfile:
                self.smb_cacls(["--save", tmpfile,
                            self.oi_dir])
                with open(tmpfile, 'rb') as infile:
                    orig_saved = infile.read()

            # modify directory structure
            dir_add_acl_str = "ACL:%s:ALLOWED/OI|CI/READ" % self.user
            self.smb_cacls(["--propagate-inheritance", "--add",
                           dir_add_acl_str, self.oi_dir])

            # save modified directory dacls to file
            with self.mktemp() as tmpfile:
                self.smb_cacls(["--save", tmpfile,
                            self.oi_dir])
                with open(tmpfile, 'rb') as infile:
                    modified = infile.read()

            # compare orig and unmodified dacls
            # they shouldn't match
            self.assertNotEqual(orig_saved.decode('utf16'), modified.decode('utf16'))
            # restore original dacls from file
            with self.mktemp() as tmpfile:
                with open(tmpfile, 'wb') as outfile:
                    outfile.write(orig_saved)
                    outfile.close()
                    out = self.smb_cacls([".", "--restore", tmpfile])

            # save newly restored dacls to file
            with self.mktemp() as tmpfile:
                self.smb_cacls(["--save", tmpfile,
                            self.oi_dir])
                with open(tmpfile, 'rb') as infile:
                    restored = infile.read()

            # after restoring the dalcs, orig unmodified dacls should match
            # restored dacls
            self.assertEqual(orig_saved.decode('utf16'), restored.decode('utf16'))

        except BlackboxProcessError as e:
            self.fail(str(e))

    def test_simple_restore_dir_r(self):
        try:
            # simple test to just store dacl(s) of directory recursively
            orig_saved = None
            modified = None
            restored = None
            with self.mktemp() as tmpfile:
                self.smb_cacls(["--recurse", "--save", tmpfile,
                            self.oi_dir])
                with open(tmpfile, 'rb') as infile:
                    orig_saved = infile.read()

            # modify directory's dacls recursively
            dir_add_acl_str = "ACL:%s:ALLOWED/OI|CI/READ" % self.user
            self.smb_cacls(["--propagate-inheritance", "--add",
                           dir_add_acl_str, self.oi_dir])

            # save modified directories dacls recursively
            with self.mktemp() as tmpfile:
                self.smb_cacls(["--recurse", "--save", tmpfile,
                            self.oi_dir])
                with open(tmpfile, 'rb') as infile:
                    modified = infile.read()

            # the unmodified stringified dacls shouldn't match
            # modified
            self.assertNotEqual(orig_saved.decode('utf16'), modified.decode('utf16'))
            # restore original dacls from file
            with self.mktemp() as tmpfile:
                with open(tmpfile, 'wb') as outfile:
                    outfile.write(orig_saved)
                    outfile.close()
                    out = self.smb_cacls([".", "--restore", tmpfile])

            with self.mktemp() as tmpfile:
                out = self.smb_cacls(["--recurse", "--save", tmpfile,
                            self.oi_dir])
                with open(tmpfile, 'rb') as infile:
                    restored = infile.read()
            # after restoring the dalcs orig unmodified dacls should match
            # current dacls
            self.assertEqual(orig_saved.decode('utf16'), restored.decode('utf16'))
        except BlackboxProcessError as e:
            self.fail(str(e))
