# Unix SMB/CIFS implementation.
# Copyright (C) David Mulder <dmulder@suse.com> 2019
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

"""Tests for cred option parsing.

"""

import optparse
import os
from contextlib import contextmanager
from samba.getopt import CredentialsOptions
import samba.tests
import setproctitle
import sys

password_opt = '--password=super_secret_password'
clear_password_opt = '--password=xxx'

@contextmanager
def auth_fle_opt(auth_file_path, long_opt=True):
    old_argv = list(sys.argv)
    try:
        if long_opt:
            sys.argv.append('--authentication-file=%s' % auth_file_path)
        else:
            sys.argv.append('-A')
            sys.argv.append(auth_file_path)
        yield
    finally:
        sys.argv = old_argv

class CredentialsOptionsTests(samba.tests.TestCase):

    def setUp(self):
        super(samba.tests.TestCase, self).setUp()
        self.old_proctitle = setproctitle.getproctitle()
        setproctitle.setproctitle('%s %s' % (self.old_proctitle, password_opt))
        sys.argv.append(password_opt)

    def test_clear_proctitle_password(self):
        parser = optparse.OptionParser()
        credopts = CredentialsOptions(parser)
        parser.add_option_group(credopts)
        (opts, args) = parser.parse_args()
        self.assertNotIn(password_opt, setproctitle.getproctitle())
        self.assertIn(clear_password_opt, setproctitle.getproctitle())

    def tearDown(self):
        super(samba.tests.TestCase, self).tearDown()
        setproctitle.setproctitle(self.old_proctitle)
        sys.argv.pop()

class AuthenticationFileTests(samba.tests.TestCaseInTempDir):

    def setUp(self):
        super(AuthenticationFileTests, self).setUp()

        self.parser = optparse.OptionParser()
        self.credopts = CredentialsOptions(self.parser)
        self.parser.add_option_group(self.credopts)

        self.auth_file_name = os.path.join(self.tempdir, 'auth.txt')

        self.realm = 'realm.example.com'
        self.domain = 'dom'
        self.password = 'pass'
        self.username = 'user'

        auth_file_fd = open(self.auth_file_name, 'x')
        auth_file_fd.write('realm=%s\n' % self.realm)
        auth_file_fd.write('domain=%s\n' % self.domain)
        auth_file_fd.write('username=%s\n' % self.username)
        auth_file_fd.write('password=%s\n' % self.password)
        auth_file_fd.close()

    def tearDown(self):
        super(AuthenticationFileTests, self).tearDown()

        os.unlink(self.auth_file_name)

    def test_long_option_valid_path(self):
        with auth_fle_opt(self.auth_file_name):
            self.parser.parse_args()
            credopts = self.credopts
            creds = credopts.creds

            self.assertFalse(credopts.ask_for_password)
            self.assertFalse(credopts.machine_pass)

            self.assertEqual(self.username, creds.get_username())
            self.assertEqual(self.password, creds.get_password())
            self.assertEqual(self.domain.upper(), creds.get_domain())
            self.assertEqual(self.realm.upper(), creds.get_realm())

    def test_long_option_invalid_path(self):
        with auth_fle_opt(self.auth_file_name + '.dontexist'):
            self.parser.parse_args()
            credopts = self.credopts
            creds = credopts.creds

            self.assertTrue(credopts.ask_for_password)
            self.assertFalse(credopts.machine_pass)

            self.assertIsNone(creds.get_username())
            self.assertIsNone(creds.get_password())
            self.assertIsNone(creds.get_domain())
            self.assertIsNone(creds.get_realm())

    def test_short_option_valid_path(self):
        with auth_fle_opt(self.auth_file_name, long_opt=False):
            self.parser.parse_args()
            credopts = self.credopts
            creds = credopts.creds

            self.assertFalse(credopts.ask_for_password)
            self.assertFalse(credopts.machine_pass)

            self.assertEqual(self.username, creds.get_username())
            self.assertEqual(self.password, creds.get_password())
            self.assertEqual(self.domain.upper(), creds.get_domain())
            self.assertEqual(self.realm.upper(), creds.get_realm())

    def test_short_option_invalid_path(self):
        with auth_fle_opt(self.auth_file_name + '.dontexist', long_opt=False):
            self.parser.parse_args()
            credopts = self.credopts
            creds = credopts.creds

            self.assertTrue(credopts.ask_for_password)
            self.assertFalse(credopts.machine_pass)

            self.assertIsNone(creds.get_username())
            self.assertIsNone(creds.get_password())
            self.assertIsNone(creds.get_domain())
            self.assertIsNone(creds.get_realm())
