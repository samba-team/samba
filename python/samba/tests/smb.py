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

import samba, os, random, sys
from samba import smb

PY3 = sys.version_info[0] == 3
addom = 'addom.samba.example.com/'
test_contents = 'abcd'*256
utf_contents = u'Süßigkeiten Äpfel '*128
test_literal_bytes_embed_nulls = b'\xff\xfe\x14\x61\x00\x00\x62\x63\x64'*256
binary_contents = b'\xff\xfe'
binary_contents = binary_contents + "Hello cruel world of python3".encode('utf8')*128
test_dir = os.path.join(addom, 'testing_%d' % random.randint(0,0xFFFF))
test_file = os.path.join(test_dir, 'testing').replace('/', '\\')

class SMBTests(samba.tests.TestCase):
    def setUp(self):
        super(SMBTests, self).setUp()
        self.server = os.environ["SERVER"]
        creds = self.insta_creds(template=self.get_credentials())
        self.conn = smb.SMB(self.server,
                            "sysvol",
                            lp=self.get_loadparm(),
                            creds=creds)
        self.conn.mkdir(test_dir)

    def tearDown(self):
        super(SMBTests, self).tearDown()
        try:
            self.conn.deltree(test_dir)
        except:
            pass

    def test_list(self):
        ls = [f['name'] for f in self.conn.list(addom)]
        self.assertIn('scripts', ls,
            msg='"scripts" directory not found in sysvol')
        self.assertIn('Policies',ls,
            msg='"Policies" directory not found in sysvol')

    def test_unlink(self):
        """
        The smb.unlink API should delete file
        """
        self.conn.savefile(test_file, binary_contents);
        self.conn.unlink(test_file)
        self.assertFalse(self.conn.chkpath(test_file))

    def test_save_load_text(self):

        self.conn.savefile(test_file, test_contents.encode('utf8'))

        contents = self.conn.loadfile(test_file)
        self.assertEquals(contents.decode('utf8'), test_contents,
            msg='contents of test file did not match what was written')

    # with python2 this will save/load str type (with embedded nulls)
    # with python3 this will save/load bytes type
    def test_save_load_string_bytes(self):
        self.conn.savefile(test_file, test_literal_bytes_embed_nulls)

        contents = self.conn.loadfile(test_file)
        self.assertEquals(contents, test_literal_bytes_embed_nulls,
            msg='contents of test file did not match what was written')

    # python3 only this will save/load unicode
    def test_save_load_utfcontents(self):
        if PY3:
            self.conn.savefile(test_file, utf_contents.encode('utf8'))

            contents = self.conn.loadfile(test_file)
            self.assertEquals(contents.decode('utf8'), utf_contents,
                msg='contents of test file did not match what was written')

    # with python2 this will save/load str type
    # with python3 this will save/load bytes type
    def test_save_binary_contents(self):
        self.conn.savefile(test_file, binary_contents);

        contents = self.conn.loadfile(test_file)
        self.assertEquals(contents, binary_contents,
            msg='contents of test file did not match what was written')
