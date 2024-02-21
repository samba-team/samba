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

import os
import sys
import string
from samba.net import Net
from samba import enable_net_export_keytab

from samba import tests
from samba.dcerpc import krb5ccache
from samba.ndr import ndr_unpack
from samba.param import LoadParm
from samba.tests import TestCaseInTempDir

enable_net_export_keytab()


class DCKeytabTests(TestCaseInTempDir):
    def setUp(self):
        super().setUp()
        self.lp = LoadParm()
        self.lp.load_default()
        self.creds = self.insta_creds(template=self.get_credentials())
        self.ktfile = os.path.join(self.tempdir, 'test.keytab')
        self.principal = self.creds.get_principal()

    def tearDown(self):
        super().tearDown()

    def test_export_keytab(self):
        net = Net(None, self.lp)
        net.export_keytab(keytab=self.ktfile, principal=self.principal)
        self.assertTrue(os.path.exists(self.ktfile), 'keytab was not created')

        # Parse the first entry in the keytab
        with open(self.ktfile, 'rb') as bytes_kt:
            keytab_bytes = bytes_kt.read()

        self.rm_files('test.keytab')

        keytab = ndr_unpack(krb5ccache.KEYTAB, keytab_bytes)

        # Confirm that the principal is as expected

        principal_parts = self.principal.split('@')

        self.assertEqual(keytab.entry.principal.component_count, 1)
        self.assertEqual(keytab.entry.principal.realm, principal_parts[1])
        self.assertEqual(keytab.entry.principal.components[0], principal_parts[0])
