# Unix SMB/CIFS implementation. Common code for smbd python bindings tests
# Copyright (C) Catalyst.Net Ltd 2019
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
from samba.tests import TestCaseInTempDir
import os

TEST_UMASK = 0o042

class SmbdBaseTests(TestCaseInTempDir):

    def get_umask(self):
        # we can only get the umask by setting it to something
        curr_umask = os.umask(0)
        # restore the old setting
        os.umask(curr_umask)
        return curr_umask

    def setUp(self):
        super(SmbdBaseTests, self).setUp()
        self.orig_umask = self.get_umask()

        # set an arbitrary umask - the underlying smbd code should override
        # this, but it allows us to check if umask is left unset
        os.umask(TEST_UMASK)

    def tearDown(self):
        # the current umask should be what we set it to earlier - if it's not,
        # it indicates the code has changed it and not restored it
        self.assertEqual(self.get_umask(), TEST_UMASK,
                         "umask unexpectedly overridden by test")

        # restore the original umask value (before we interferred with it)
        os.umask(self.orig_umask)

        super(SmbdBaseTests, self).tearDown()
