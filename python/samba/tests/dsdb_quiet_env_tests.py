# Unix SMB/CIFS implementation. Tests for dsdb
# Copyright (C) Andrew Bartlett <abartlet@samba.org> 2024
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

"""These tests want to be run on a freshly provisioned domain that has
not been greatly modified by other tests (which at the time of writing
probably means 'chgdcpass').

Tests here should only read the database.

This is to avoid flapping tests.
"""

from samba.credentials import Credentials
from samba.samdb import SamDB
from samba.auth import system_session
from samba.tests import TestCase
import ldb
import samba

class DsdbQuietEnvTests(TestCase):

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.lp = samba.tests.env_loadparm()
        cls.creds = Credentials()
        cls.creds.guess(cls.lp)
        cls.session = system_session()
        cls.samdb = SamDB(session_info=cls.session,
                          credentials=cls.creds,
                          lp=cls.lp)

    def test_gkdi_create_root_key_wrong_version(self):

        server_config_dn = self.samdb.get_config_basedn()
        server_config_dn.add_child("CN=Group Key Distribution Service Server Configuration," +
                                   "CN=Server Configuration," +
                                   "CN=Group Key Distribution Service," +
                                   "CN=Services")
        res = self.samdb.search(base=server_config_dn,
                                scope=ldb.SCOPE_BASE,
                                attrs=["msKds-Version"])

        self.assertEqual(len(res), 1)

        msg = res[0]
        version = int(msg["msKds-Version"][0])
        self.assertEqual(version, 1)

        self.addCleanup(self.samdb.modify,
                        ldb.Message.from_dict(self.samdb,
                                              {"dn": msg["dn"],
                                               "msKds-Version": [str(version)]},
                                              ldb.FLAG_MOD_REPLACE))
        self.samdb.modify(ldb.Message.from_dict(self.samdb,
                                                {"dn": msg["dn"],
                                                 "msKds-Version": ["2"]},
                                                ldb.FLAG_MOD_REPLACE))

        try:
            self.samdb.new_gkdi_root_key()
            self.fail("Creating key with invalid version should fail")
        except ldb.LdbError as e:
            (enum, estr) = e.args
            self.assertEqual(enum, ldb.ERR_CONSTRAINT_VIOLATION)

    def test_gkdi_create_root_key_4096(self):

        server_config_dn = self.samdb.get_config_basedn()
        server_config_dn.add_child("CN=Group Key Distribution Service Server Configuration," +
                                   "CN=Server Configuration," +
                                   "CN=Group Key Distribution Service," +
                                   "CN=Services")
        res = self.samdb.search(base=server_config_dn,
                                scope=ldb.SCOPE_BASE,
                                attrs=["msKds-PublicKeyLength"])

        self.assertEqual(len(res), 1)

        msg = res[0]
        if "msKds-PublicKeyLength" in msg:
            keylen = msg[0]["msKds-PublicKeyLength"]
            # Ensure test still tests something in the future, if the default changes
            self.assertNotEqual(keylen, 4096)
            self.addCleanup(self.samdb.modify,
                            ldb.Message.from_dict(self.samdb,
                                                  {"dn": msg["dn"],
                                                   "msKds-PublicKeyLength": [str(keylen)]},
                                                  ldb.FLAG_MOD_REPLACE))
        else:
            self.addCleanup(self.samdb.modify,
                            ldb.Message.from_dict(self.samdb,
                                                  {"dn": msg["dn"],
                                                   "msKds-PublicKeyLength": []},
                                                  ldb.FLAG_MOD_DELETE))

        self.samdb.modify(ldb.Message.from_dict(self.samdb,
                                                {"dn": msg["dn"],
                                                 "msKds-PublicKeyLength": ["4096"]},
                                                ldb.FLAG_MOD_REPLACE))

        dn = self.samdb.new_gkdi_root_key()

        root_key_res = self.samdb.search(base=dn,
                                         scope=ldb.SCOPE_BASE)
        self.assertEqual(len(root_key_res), 1)
        root_key = root_key_res[0]

        self.assertEqual(int(root_key["msKds-PublicKeyLength"][0]), 4096)
        self.assertEqual(str(root_key["msKds-KDFAlgorithmID"][0]), "SP800_108_CTR_HMAC")
        self.assertEqual(str(root_key["msKds-SecretAgreementAlgorithmID"][0]), "DH")
        self.assertEqual(int(root_key["msKds-Version"][0]), 1)

    def test_gkdi_create_root_key_priv_1024(self):

        server_config_dn = self.samdb.get_config_basedn()
        server_config_dn.add_child("CN=Group Key Distribution Service Server Configuration," +
                                   "CN=Server Configuration," +
                                   "CN=Group Key Distribution Service," +
                                   "CN=Services")
        res = self.samdb.search(base=server_config_dn,
                                scope=ldb.SCOPE_BASE,
                                attrs=["msKds-PrivateKeyLength"])

        self.assertEqual(len(res), 1)

        msg = res[0]
        if "msKds-PrivateKeyLength" in msg:
            keylen = msg["msKds-PrivateKeyLength"]
            # Ensure test still tests something in the future, if the default changes
            self.assertNotEqual(keylen, 1024)
            self.addCleanup(self.samdb.modify,
                            ldb.Message.from_dict(self.samdb,
                                                  {"dn": msg["dn"],
                                                   "msKds-PrivateKeyLength": [str(keylen)]},
                                                  ldb.FLAG_MOD_REPLACE))
        else:
            self.addCleanup(self.samdb.modify,
                            ldb.Message.from_dict(self.samdb,
                                                  {"dn": msg["dn"],
                                                   "msKds-PrivateKeyLength": []},
                                                  ldb.FLAG_MOD_DELETE))

        self.samdb.modify(ldb.Message.from_dict(self.samdb,
                                                {"dn": msg["dn"],
                                                 "msKds-PrivateKeyLength": ["1024"]},
                                                ldb.FLAG_MOD_REPLACE))

        dn = self.samdb.new_gkdi_root_key()

        root_key_res = self.samdb.search(base=dn,
                                         scope=ldb.SCOPE_BASE)
        self.assertEqual(len(root_key_res), 1)
        root_key = root_key_res[0]

        self.assertEqual(int(root_key["msKds-PrivateKeyLength"][0]), 1024)
        self.assertEqual(str(root_key["msKds-KDFAlgorithmID"][0]), "SP800_108_CTR_HMAC")
        self.assertEqual(str(root_key["msKds-SecretAgreementAlgorithmID"][0]), "DH")
        self.assertEqual(int(root_key["msKds-Version"][0]), 1)

    def test_gkdi_create_root_key_bad_alg(self):
        server_config_dn = self.samdb.get_config_basedn()
        server_config_dn.add_child("CN=Group Key Distribution Service Server Configuration," +
                                   "CN=Server Configuration," +
                                   "CN=Group Key Distribution Service," +
                                   "CN=Services")
        res = self.samdb.search(base=server_config_dn,
                                scope=ldb.SCOPE_BASE,
                                attrs=["msKds-KDFAlgorithmID"])

        self.assertEqual(len(res), 1)

        msg = res[0]
        if "msKds-KDFAlgorithmID" in msg:
            alg = msg["msKds-KDFAlgorithmID"][0]
            self.addCleanup(self.samdb.modify,
                            ldb.Message.from_dict(self.samdb,
                                                  {"dn": msg["dn"],
                                                   "msKds-KDFAlgorithmID": [alg]},
                                                  ldb.FLAG_MOD_REPLACE))
        else:
            self.addCleanup(self.samdb.modify,
                            ldb.Message.from_dict(self.samdb,
                                                  {"dn": msg["dn"],
                                                   "msKds-KDFAlgorithmID": []},
                                                  ldb.FLAG_MOD_DELETE))

        self.samdb.modify(ldb.Message.from_dict(self.samdb,
                                                {"dn": msg["dn"],
                                                 "msKds-KDFAlgorithmID": ["NO_AN_ALG"]},
                                                ldb.FLAG_MOD_REPLACE))

        try:
            self.samdb.new_gkdi_root_key()
            self.fail("Creating key with invalid algorithm should fail")
        except ldb.LdbError as e:
            (enum, estr) = e.args
            self.assertEqual(enum, ldb.ERR_CONSTRAINT_VIOLATION)

    def test_gkdi_create_root_key_good_alg(self):
        server_config_dn = self.samdb.get_config_basedn()
        server_config_dn.add_child("CN=Group Key Distribution Service Server Configuration," +
                                   "CN=Server Configuration," +
                                   "CN=Group Key Distribution Service," +
                                   "CN=Services")
        res = self.samdb.search(base=server_config_dn,
                                scope=ldb.SCOPE_BASE,
                                attrs=["msKds-KDFAlgorithmID"])

        self.assertEqual(len(res), 1)

        msg = res[0]
        if "msKds-KDFAlgorithmID" in msg:
            alg = msg["msKds-KDFAlgorithmID"][0]
            self.addCleanup(self.samdb.modify,
                            ldb.Message.from_dict(self.samdb,
                                                  {"dn": msg["dn"],
                                                   "msKds-KDFAlgorithmID": [alg]},
                                                  ldb.FLAG_MOD_REPLACE))
        else:
            self.addCleanup(self.samdb.modify,
                            ldb.Message.from_dict(self.samdb,
                                                  {"dn": msg["dn"],
                                                   "msKds-KDFAlgorithmID": []},
                                                  ldb.FLAG_MOD_DELETE))

        self.samdb.modify(ldb.Message.from_dict(self.samdb,
                                                {"dn": msg["dn"],
                                                 "msKds-KDFAlgorithmID": ["SP800_108_CTR_HMAC"]},
                                                ldb.FLAG_MOD_REPLACE))

        dn = self.samdb.new_gkdi_root_key()

        root_key_res = self.samdb.search(base=dn,
                                         scope=ldb.SCOPE_BASE)
        self.assertEqual(len(root_key_res), 1)
        root_key = root_key_res[0]

        self.assertEqual(int(root_key["msKds-PublicKeyLength"][0]), 2048)
        self.assertEqual(str(root_key["msKds-KDFAlgorithmID"][0]), "SP800_108_CTR_HMAC")
        self.assertEqual(str(root_key["msKds-SecretAgreementAlgorithmID"][0]), "DH")
        self.assertEqual(int(root_key["msKds-Version"][0]), 1)
