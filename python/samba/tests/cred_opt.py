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
from samba.getopt import CredentialsOptions
import samba.tests
import setproctitle
import sys

password_opt = '--password=super_secret_password'
clear_password_opt = '--password=xxx'

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
