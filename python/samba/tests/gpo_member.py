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

import os
from samba import tests
from samba.gp.gpclass import GPOStorage
from samba.param import LoadParm
from samba.gp.gp_sec_ext import gp_access_ext

class GPOTests(tests.TestCase):
    def setUp(self):
        super(GPOTests, self).setUp()
        self.server = os.environ["SERVER"]
        self.dc_account = self.server.upper() + '$'
        self.lp = LoadParm()
        self.lp.load_default()
        self.creds = self.insta_creds(template=self.get_credentials())

    def tearDown(self):
        super(GPOTests, self).tearDown()

    def test_sec_ext_load_on_member(self):
        cache_dir = self.lp.get('cache directory')
        store = GPOStorage(os.path.join(cache_dir, 'gpo.tdb'))
        try:
            gp_access_ext(self.lp, self.creds,
                          self.creds.get_username(), store)
        except Exception:
            self.fail('Initializing gp_access_ext should not require ad-dc')
