# Unix SMB/CIFS implementation.
#
#   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2017
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

"""Smoke test for encrypted secrets

A quick test to confirm that the secret attributes are being stored
encrypted on disk.
"""


import os
import ldb
import samba
from samba.tests import TestCase
from samba.credentials import Credentials
from samba.samdb import SamDB
from samba.auth import system_session
from samba.ndr import ndr_unpack
from samba.dcerpc import drsblobs


class EncryptedSecretsTests(TestCase):

    def setUp(self):
        super(EncryptedSecretsTests, self).setUp()
        self.lp = samba.tests.env_loadparm()
        self.creds = Credentials()
        self.session = system_session()
        self.creds.guess(self.lp)
        self.session = system_session()
        self.ldb = SamDB(session_info=self.session,
                         credentials=self.creds,
                         lp=self.lp)

    def test_encrypted_secrets(self):
        """Test that secret attributes are stored encrypted on disk"""
        basedn = self.ldb.domain_dn()
        backend_filename = "%s.ldb" % basedn.upper()
        backend_subpath = os.path.join("sam.ldb.d",
                                       backend_filename)
        backend_path = self.lp.private_path(backend_subpath)
        backenddb = ldb.Ldb("ldb://" + backend_path, flags=ldb.FLG_DONT_CREATE_DB)

        dn = "CN=Administrator,CN=Users,%s" % basedn

        res = backenddb.search(scope=ldb.SCOPE_BASE,
                               base=dn,
                               attrs=["unicodePwd"])
        self.assertIs(True, len(res) > 0)
        obj = res[0]
        blob = obj["unicodePwd"][0]
        self.assertTrue(len(blob) > 30)
        # Now verify that the header contains the correct magic value.
        encrypted = ndr_unpack(drsblobs.EncryptedSecret, blob)
        magic = 0xca5caded
        self.assertEqual(magic, encrypted.header.magic)

    def test_required_features(self):
        """Test that databases are provisioned with encryptedSecrets as a
           required feature
        """
        res = self.ldb.search(scope=ldb.SCOPE_BASE,
                              base="@SAMBA_DSDB",
                              attrs=["requiredFeatures"])
        self.assertTrue(len(res) > 0)
        self.assertTrue("requiredFeatures" in res[0])
        required_features = res[0]["requiredFeatures"]
        self.assertTrue(b"encryptedSecrets" in required_features)
