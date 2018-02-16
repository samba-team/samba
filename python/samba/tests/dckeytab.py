# Tests for source4/libnet/py_net_dckeytab.c
#
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
#

import os, sys, string
from samba.net import Net
import samba.dckeytab
from samba import tests
from samba.param import LoadParm

def open_bytes(filename):
    if sys.version_info[0] == 3:
        return open(filename, errors='ignore')
    else:
        return open(filename, 'rb')

class DCKeytabTests(tests.TestCase):
    def setUp(self):
        super(DCKeytabTests, self).setUp()
        self.lp = LoadParm()
        self.lp.load_default()
        self.creds = self.insta_creds(template=self.get_credentials())
        self.ktfile = os.path.join(self.lp.get('private dir'), 'test.keytab')
        self.principal = self.creds.get_principal()

    def tearDown(self):
        super(DCKeytabTests, self).tearDown()
        os.remove(self.ktfile)

    def test_export_keytab(self):
        net = Net(None, self.lp)
        net.export_keytab(keytab=self.ktfile, principal=self.principal)
        assert os.path.exists(self.ktfile), 'keytab was not created'
        with open_bytes(self.ktfile) as bytes_kt:
            result = ''
            for c in bytes_kt.read():
                if c in string.printable:
                    result += c
            principal_parts = self.principal.split('@')
            assert principal_parts[0] in result and \
                   principal_parts[1] in result, \
                        'Principal not found in generated keytab'
