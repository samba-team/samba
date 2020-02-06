# -*- coding: utf-8 -*-
# Unix SMB/CIFS implementation. Tests for smb manipulation
# Copyright (C) David Mulder <dmulder@suse.com> 2018
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

import samba
import os
import random
import sys
from samba import NTSTATUSError
from samba.ntstatus import (NT_STATUS_OBJECT_NAME_NOT_FOUND,
                            NT_STATUS_OBJECT_PATH_NOT_FOUND)
from samba.samba3 import libsmb_samba_internal as libsmb
from samba.samba3 import param as s3param

PY3 = sys.version_info[0] == 3
realm = os.environ.get('REALM')
domain_dir = realm.lower() + '/'
test_contents = 'abcd' * 256
utf_contents = u'Süßigkeiten Äpfel ' * 128
test_literal_bytes_embed_nulls = b'\xff\xfe\x14\x61\x00\x00\x62\x63\x64' * 256
binary_contents = b'\xff\xfe'
binary_contents = binary_contents + "Hello cruel world of python3".encode('utf8') * 128
test_dir = os.path.join(domain_dir, 'testing_%d' % random.randint(0, 0xFFFF))
test_file = os.path.join(test_dir, 'testing').replace('/', '\\')


class SMBTests(samba.tests.TestCase):
    def setUp(self):
        super(SMBTests, self).setUp()
        self.server = os.environ["SERVER"]
        creds = self.insta_creds(template=self.get_credentials())

        # create an SMB connection to the server
        lp = s3param.get_context()
        lp.load(os.getenv("SMB_CONF_PATH"))
        self.smb_conn = libsmb.Conn(self.server, "sysvol", lp, creds)

        self.smb_conn.mkdir(test_dir)

    def tearDown(self):
        super(SMBTests, self).tearDown()
        try:
            self.smb_conn.deltree(test_dir)
        except:
            pass

    def test_list(self):
        # check a basic listing returns the items we expect
        ls = [f['name'] for f in self.smb_conn.list(domain_dir)]
        self.assertIn('scripts', ls,
                      msg='"scripts" directory not found in sysvol')
        self.assertIn('Policies', ls,
                      msg='"Policies" directory not found in sysvol')
        self.assertNotIn('..', ls,
                         msg='Parent (..) found in directory listing')
        self.assertNotIn('.', ls,
                         msg='Current dir (.) found in directory listing')

        # using a '*' mask should be the same as using no mask
        ls_wildcard = [f['name'] for f in self.smb_conn.list(domain_dir, "*")]
        self.assertEqual(ls, ls_wildcard)

        # applying a mask should only return items that match that mask
        ls_pol = [f['name'] for f in self.smb_conn.list(domain_dir, "Pol*")]
        expected = ["Policies"]
        self.assertEqual(ls_pol, expected)

        # each item in the listing is a has with expected keys
        expected_keys = ['attrib', 'mtime', 'name', 'short_name', 'size']
        for item in self.smb_conn.list(domain_dir):
            for key in expected_keys:
                self.assertIn(key, item,
                              msg="Key '%s' not in listing '%s'" % (key, item))

    def test_deltree(self):
        """The smb.deltree API should delete files and sub-dirs"""
        # create some test sub-dirs
        dirpaths = []
        empty_dirs = []
        cur_dir = test_dir

        for subdir in ["subdir-X", "subdir-Y", "subdir-Z"]:
            path = self.make_sysvol_path(cur_dir, subdir)
            self.smb_conn.mkdir(path)
            dirpaths.append(path)
            cur_dir = path

            # create another empty dir just for kicks
            path = self.make_sysvol_path(cur_dir, "another")
            self.smb_conn.mkdir(path)
            empty_dirs.append(path)

        # create some files in these directories
        filepaths = []
        for subdir in dirpaths:
            for i in range(1, 4):
                contents = "I'm file {0} in dir {1}!".format(i, subdir)
                path = self.make_sysvol_path(subdir, "file-{0}.txt".format(i))
                self.smb_conn.savefile(path, test_contents.encode('utf8'))
                filepaths.append(path)

        # sanity-check these dirs/files exist
        for subdir in dirpaths + empty_dirs:
            self.assertTrue(self.smb_conn.chkpath(subdir),
                            "Failed to create {0}".format(subdir))
        for path in filepaths:
            self.assertTrue(self.file_exists(path),
                            "Failed to create {0}".format(path))

        # try using deltree to remove a single empty directory
        path = empty_dirs.pop(0)
        self.smb_conn.deltree(path)
        self.assertFalse(self.smb_conn.chkpath(path),
                         "Failed to delete {0}".format(path))

        # try using deltree to remove a single file
        path = filepaths.pop(0)
        self.smb_conn.deltree(path)
        self.assertFalse(self.file_exists(path),
                         "Failed to delete {0}".format(path))

        # delete the top-level dir
        self.smb_conn.deltree(test_dir)

        # now check that all the dirs/files are no longer there
        for subdir in dirpaths + empty_dirs:
            self.assertFalse(self.smb_conn.chkpath(subdir),
                             "Failed to delete {0}".format(subdir))
        for path in filepaths:
            self.assertFalse(self.file_exists(path),
                             "Failed to delete {0}".format(path))

    def file_exists(self, filepath):
        """Returns whether a regular file exists (by trying to open it)"""
        try:
            self.smb_conn.loadfile(filepath)
            exists = True;
        except NTSTATUSError as err:
            if (err.args[0] == NT_STATUS_OBJECT_NAME_NOT_FOUND or
                err.args[0] == NT_STATUS_OBJECT_PATH_NOT_FOUND):
                exists = False
            else:
                raise err
        return exists

    def test_unlink(self):
        """
        The smb.unlink API should delete file
        """
        # create the test file
        self.assertFalse(self.file_exists(test_file))
        self.smb_conn.savefile(test_file, binary_contents)
        self.assertTrue(self.file_exists(test_file))

        # delete it and check that it's gone
        self.smb_conn.unlink(test_file)
        self.assertFalse(self.file_exists(test_file))

    def test_chkpath(self):
        """Tests .chkpath determines whether or not a directory exists"""

        self.assertTrue(self.smb_conn.chkpath(test_dir))

        # should return False for a non-existent directory
        bad_dir = self.make_sysvol_path(test_dir, 'dont_exist')
        self.assertFalse(self.smb_conn.chkpath(bad_dir))

        # should return False for files (because they're not directories)
        self.smb_conn.savefile(test_file, binary_contents)
        self.assertFalse(self.smb_conn.chkpath(test_file))

        # check correct result after creating and then deleting a new dir
        new_dir = self.make_sysvol_path(test_dir, 'test-new')
        self.smb_conn.mkdir(new_dir)
        self.assertTrue(self.smb_conn.chkpath(new_dir))
        self.smb_conn.rmdir(new_dir)
        self.assertFalse(self.smb_conn.chkpath(new_dir))

    def test_save_load_text(self):

        self.smb_conn.savefile(test_file, test_contents.encode('utf8'))

        contents = self.smb_conn.loadfile(test_file)
        self.assertEqual(contents.decode('utf8'), test_contents,
                          msg='contents of test file did not match what was written')

        # check we can overwrite the file with new contents
        new_contents = 'wxyz' * 128
        self.smb_conn.savefile(test_file, new_contents.encode('utf8'))
        contents = self.smb_conn.loadfile(test_file)
        self.assertEqual(contents.decode('utf8'), new_contents,
                          msg='contents of test file did not match what was written')

    # with python2 this will save/load str type (with embedded nulls)
    # with python3 this will save/load bytes type
    def test_save_load_string_bytes(self):
        self.smb_conn.savefile(test_file, test_literal_bytes_embed_nulls)

        contents = self.smb_conn.loadfile(test_file)
        self.assertEqual(contents, test_literal_bytes_embed_nulls,
                          msg='contents of test file did not match what was written')

    # python3 only this will save/load unicode
    def test_save_load_utfcontents(self):
        if PY3:
            self.smb_conn.savefile(test_file, utf_contents.encode('utf8'))

            contents = self.smb_conn.loadfile(test_file)
            self.assertEqual(contents.decode('utf8'), utf_contents,
                              msg='contents of test file did not match what was written')

    # with python2 this will save/load str type
    # with python3 this will save/load bytes type
    def test_save_binary_contents(self):
        self.smb_conn.savefile(test_file, binary_contents)

        contents = self.smb_conn.loadfile(test_file)
        self.assertEqual(contents, binary_contents,
                          msg='contents of test file did not match what was written')

    def make_sysvol_path(self, dirpath, filename):
        # return the dir + filename as a sysvol path
        return os.path.join(dirpath, filename).replace('/', '\\')
