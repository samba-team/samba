#!/usr/bin/env python3
# Tests for the samba.key_credential_link module
#
# Copyright (C) Douglas Bagnall <douglas.bagnall@catalyst.net.nz>
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
import re
import sys
import time
from itertools import permutations

sys.path.insert(0, "bin/python")
os.environ["PYTHONUNBUFFERED"] = "1"

from samba import param

from samba.auth import system_session
from samba.credentials import Credentials
from samba.samdb import SamDB, BinaryDn
from samba import key_credential_link as kcl
from samba.tests import TestCase, env_get_var_value

class KeyCredentialLinkWrapperTests(TestCase):
    """Testing the samba.key_credential_link module"""
    maxDiff = 9999
    # A bytestring that contains a DER encoded 2048 bit RSA public key
    # borrowed from the key_credential_link.test_unpack_der_key_material
    # test.
    _der_encoded_key = bytes.fromhex(
            "30 82 01 22"  # Sequence 290 bytes, 2 elements
            "30 0d"  # Sequence 13 bytes, 2 elements
            # OID 9 bytes, 1.2.840.113549.1.1.1
            "06 09 2a 86 48 86 f7 0d 01 01 01"
            "05 00"  # Null
            "03 82 01 0f 00"  # Bit string, 2160 bits, 0 unused bits
            "30 82 01 0a"  # Sequence 266 bytes, 2 elements
            "02 82 01 01"  # Integer 2048 bit, 257 bytes
            # MODULUS is 257 bytes as it's most significant byte
            # is 0xbd 0b10111101 and has bit 8 set,
            # which DER Integer encoding uses as the sign bit,
            # so need the leading 00 byte to prevent the value
            # being interpreted as a negative integer
            "00 bd ae 45 8b 17 cd 3e 62 71 66 67 7f a2 46 c4"
            "47 78 79 f2 8c d4 2e 0c a0 90 1c f6 33 e1 94 89"
            "b9 44 15 e3 29 e7 b6 91 ca ab 7e c6 25 60 e3 7a"
            "c4 09 97 8a 4e 79 cb a6 1f f8 29 3f 8a 0d 45 58"
            "9b 0e bf a5 fa 1c a2 5e 31 a1 e7 ba 7e 17 62 03"
            "79 c0 07 48 11 8b fa 58 17 56 1a a1 62 d2 02 02"
            "2a 64 8d 8c 53 fa 28 7c 89 18 34 70 64 a7 08 10"
            "c9 3b 1b 2c 23 88 9c 35 50 78 d1 89 33 ce 82 b2"
            "84 f4 99 d8 3e 67 11 a1 5c 1a 64 b8 6a 3e e6 95"
            "2e 47 33 51 7e b7 62 b4 08 2c c4 87 52 00 9e 28"
            "f2 16 9f 1b c1 3a 93 6d a3 38 9b 34 39 88 85 ea"
            "38 ad c2 2b c3 7c 15 cb 8f 15 37 ed 88 62 5c 34"
            "75 6f b0 eb 5c 42 6a cd 03 cc 49 bc b4 78 14 e1"
            "5e 98 83 6f e7 19 a8 43 cb ca 07 b2 4e a4 36 60"
            "95 ac 6f e2 1d 3a 33 f6 0e 94 ae fb d2 ac 9f c2"
            "9f 5b 77 8f 46 3c ee 13 27 19 8e 68 71 27 3f 50"
            "59"
            "02 03 01 00 01"  # Integer 3 bytes EXPONENT
        )

    _kcl_prefix = ("B:772:000200002000012548213C16B0B6CEEB2A5C67B30744"
                   "01BCBA6394A7C310713AF7314FEBCDF082200002B12C51275D"
                   "E353EBD3117BA405F3A00131740B8938C572127DD6F045D63D"
                   "43F326010330820122300D06092A864886F70D010101050003"
                   "82010F003082010A0282010100BDAE458B17CD3E627166677F"
                   "A246C4477879F28CD42E0CA0901CF633E19489B94415E329E7"
                   "B691CAAB7EC62560E37AC409978A4E79CBA61FF8293F8A0D45"
                   "589B0EBFA5FA1CA25E31A1E7BA7E17620379C00748118BFA58"
                   "17561AA162D202022A648D8C53FA287C8918347064A70810C9"
                   "3B1B2C23889C355078D18933CE82B284F499D83E6711A15C1A"
                   "64B86A3EE6952E4733517EB762B4082CC48752009E28F2169F"
                   "1BC13A936DA3389B34398885EA38ADC22BC37C15CB8F1537ED"
                   "88625C34756FB0EB5C426ACD03CC49BCB47814E15E98836FE7"
                   "19A843CBCA07B24EA4366095AC6FE21D3A33F60E94AEFBD2AC"
                   "9FC29F5B778F463CEE1327198E6871273F5059020301000101"
                   "000401080009805811AFEF07DC01:")

    _kcl_fingerprint = ("25:48:21:3C:16:B0:B6:CE:EB:2A:5C:67:B3:07:44:01:"
                        "BC:BA:63:94:A7:C3:10:71:3A:F7:31:4F:EB:CD:F0:82")

    @classmethod
    def setUpClass(cls):
        super().setUpClass()

        server = os.environ['DC_SERVER']
        host = f'ldap://{server}'

        lp = param.LoadParm()
        lp.load(os.environ['SMB_CONF_PATH'])

        creds = Credentials()
        creds.guess(lp)
        creds.set_username(env_get_var_value('DC_USERNAME'))
        creds.set_password(env_get_var_value('DC_PASSWORD'))

        cls.ldb = SamDB(host, credentials=creds,
                        session_info=system_session(lp), lp=lp)
        cls.base_dn = cls.ldb.domain_dn()
        cls.schema_dn = cls.ldb.get_schema_basedn().get_linearized()
        cls.domain_sid = cls.ldb.get_domain_sid()

    def test_key_credential_link_description(self):
        before = time.strftime('%Y-%m-%d %H:%M:%S')
        k = kcl.create_key_credential_link(self.ldb,
                                           self.base_dn,
                                           self._der_encoded_key)
        after = time.strftime('%Y-%m-%d %H:%M:%S')
        level_0 = k.description(0)
        level_1 = k.description(1)
        level_2 = k.description(2)
        level_3 = k.description(3)
        level_4 = k.description(4)
        # we should get more text with increasing verbosity
        self.assertLessEqual(len(level_0), len(level_1))
        self.assertLessEqual(len(level_1), len(level_2))
        self.assertLessEqual(len(level_2), len(level_3))
        # but verbosity maxes out at 3, so 4 and 3 are identical text
        self.assertEqual(level_4, level_3)
        lines = level_4.split('\n')
        self.assertEqual(lines[0], f'Link target: {self.base_dn}')
        self.assertRegex(lines[1],
                         r'^Binary Dn: B:772:0002000020000125482[\dA-F]+:'
                         f'{self.base_dn}$')

        key_entries = lines.index("Key entries:")
        key_properties = lines.index("RSA public key properties:")
        self.assertGreater(key_entries, 2)
        self.assertGreater(key_properties, key_entries + 1)
        entries = {}
        for line in lines[key_entries + 1 : key_properties]:
            m = re.match(r'^  ([^:]+):\s+(.+)$', line)
            self.assertIsNotNone(m)
            k, v = m.groups()
            entries[k] = v

        self.assertEqual(entries["Device GUID (DeviceId)"], "not found")
        self.assertEqual(entries["last logon (KeyApproximateLastLogonTimeStamp)"],
                         "not found")

        self.assertLessEqual(before, entries["creation time (KeyCreationTime)"])
        self.assertLessEqual(entries["creation time (KeyCreationTime)"], after)

        properties = {}
        for line in lines[key_properties + 1:]:
            m = re.match(r'^  ([^:]+):\s+(.+)$', line)
            self.assertIsNotNone(m)
            k, v = m.groups()
            properties[k] = v
        self.assertEqual(properties["key size"], "2048")
        # fingerprint should be the known constant, and the same as the entry.
        self.assertEqual(properties["fingerprint"], self._kcl_fingerprint)
        self.assertEqual(properties["fingerprint"],
                         entries["key material fingerprint (KeyID)"])

    def test_key_credential_link_fingerprint(self):
        k = kcl.create_key_credential_link(self.ldb,
                                           self.base_dn,
                                           self._der_encoded_key)
        self.assertEqual(k.fingerprint(), self._kcl_fingerprint)

    def test_key_credential_link_as_pem(self):
        k1 = kcl.create_key_credential_link(self.ldb,
                                           self.base_dn,
                                           self._der_encoded_key)
        pem1 = k1.as_pem()
        self.assertTrue(pem1.startswith('-----BEGIN PUBLIC KEY-----'))
        k2 = kcl.create_key_credential_link(self.ldb,
                                            self.base_dn,
                                            pem1.encode())
        pem2 = k2.as_pem()
        self.assertEqual(pem1, pem2)
        # we can't quite assert that the binary part of k1 and k2 is
        # the same, because the creation date could have changed, but
        # we can exclude just the bits that might be affected by that.
        dnstr1 = str(k1)
        dnstr2 = str(k2)
        self.assertEqual(dnstr1[:90], dnstr2[:90])
        # 90 to 154 is the hash of various fields, including time
        self.assertEqual(dnstr1[154:762], dnstr2[154:762])
        # 762-778 is creation time in nttime
        self.assertEqual(dnstr1[778:], dnstr2[778:])

    def test_create_key_credential_link_damaged(self):
        """self._der_encoded_key is a valid key, but if we make
        slightly altered versions we should see failures from
        kcl.create_key_credential_link. Not all changes we cause
        trouble (e.g. we could just be changing the modulus to match a
        different private key) but we try some that should.
        """
        orig = self._der_encoded_key
        for start, end, replacement in [
             (0, 1, b'a'),       # bad start
             (-2, -1, b''),      # eat a byte
             (7, 8, b'x'),       # change OID interpretation
             (31, 32, b'\x88'),  # make the modulus negative
             (0, len(orig), b' ' * len(orig))
             # what we don't catch is invalid values qua key,
             # like a zero exponent
             # (-3, 9999, b'\x00\x00\x00'),
             # or adding extra bytes at the end
             # (-1, -1, b'xxxx')
        ]:
            der = orig[:start] + replacement + orig[end:]
            with self.assertRaises(ValueError):
                kcl.create_key_credential_link(self.ldb,
                                               self.base_dn,
                                               der)

    def _good_kcl(self):
         return f"{self._kcl_prefix}{self.base_dn}"

    def _bad_kcl(self, start, replacement, end=None):
        """We don't use create_key_credential_link(), because it tries
        to check the key is properly encoded.
        """
        good = self._good_kcl()
        if end is None:
            end = start + len(replacement)

        bdn = BinaryDn(self.ldb, good)

        bdn.binary = bdn.binary[:start] + replacement + bdn.binary[end:]
        return str(bdn)

    def test_bad_key_credential_links(self):
        for start, replacement, end in [
                (0, b'1234', None),            #  bad version 0x34333231
                (100, b'', 1000),              #  truncated
                (10, b'', 1000),               #  truncated
                (1000, b'\x01' * 20, None),    #  extra bytes
        ]:
            bad_dn = self._bad_kcl(start, replacement, end)
            self.assertRaises(ValueError,
                              kcl.KeyCredentialLinkDn,
                              self.ldb,
                              bad_dn)

    def test_bad_key_credential_links_one_byte_damage(self):
        """If we poke the wrong byte in certain places, the ndr pull
        should fail."""
        for i in [3, 4, 5, 6, 39, 40, 41, 75, 76, 371, 372, 373, 375, 376, 377]:
            bad = self._bad_kcl(i, b'*')
            self.assertRaises(ValueError,
                              kcl.KeyCredentialLinkDn,
                              self.ldb,
                              bad)

    def test_bad_key_credential_link_keys(self):
        """Parsing as a KeyCredentialLink is OK, but the resultant RSA
        key is broken."""
        for i in [77, 78, 79, 80, 81, 82, 83, 84, 86, 87, 88, 89, 90, 91,
                   93, 94, 95, 96, 98, 99, 101, 102, 105, 106, 107, 108,
                   366, 367]:
            bad = self._bad_kcl(i, b'*')
            k = kcl.KeyCredentialLinkDn(self.ldb, bad)
            self.assertRaises(ValueError, k.as_pem)

    def test_good_key_credential_link_case_sensitivity(self):
        """Do kcl DNs compare and normalise as expected, in the same
        way as binary DNs?."""
        mixed = self._good_kcl()
        lc = mixed[0] + mixed[1:].lower()  # we need to keep initial 'B:'
        uc = mixed.upper()
        kcldn_mixed = kcl.KeyCredentialLinkDn(self.ldb, mixed)
        kcldn_lower = kcl.KeyCredentialLinkDn(self.ldb, lc)
        kcldn_upper = kcl.KeyCredentialLinkDn(self.ldb, uc)
        bdn_mixed = BinaryDn(self.ldb, mixed)
        bdn_lower = BinaryDn(self.ldb, lc)
        bdn_upper = BinaryDn(self.ldb, uc)
        dns = [kcldn_mixed, kcldn_lower, kcldn_upper,
               bdn_mixed, bdn_lower, bdn_upper]
        for a, b in permutations(dns, 2):
            self.assertEqual(a, b)
            self.assertEqual(a.binary, b.binary)
            self.assertEqual(a.prefix, b.prefix)
            self.assertEqual(a.dn, b.dn)

        strings = [str(x).upper() for x in dns]
        for s in strings:
            self.assertEqual(uc, s)

        # prefixes are normalised by str()
        prefixes = [str(x).rsplit(':', 1)[0] for x in dns]
        op = mixed.rsplit(':', 1)[0]
        for p in prefixes:
            self.assertEqual(p, op)


if __name__ == "__main__":
    import unittest
    unittest.main()
