# Tests for Tests for source4/dsdb/samdb/ldb_modules/password_hash.c
#
# Copyright (C) Catalyst IT Ltd. 2017
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

"""
Tests for source4/dsdb/samdb/ldb_modules/password_hash.c

These tests need to be run in an environment in which
io->ac->gpg_key_ids == NULL, so that the gpg supplemental credentials
are not generated. And also need to be in an environment with a
functional level less than 2008 to ensure the kerberos newer keys are not
generated
"""

from samba.tests.password_hash import (
    PassWordHashTests,
    get_package,
    USER_PASS
)
from samba.ndr import ndr_unpack
from samba.dcerpc import drsblobs
import binascii


class PassWordHashFl2003Tests(PassWordHashTests):

    def setUp(self):
        super(PassWordHashFl2003Tests, self).setUp()

    def test_default_supplementalCredentials(self):
        self.add_user(options=[("password hash userPassword schemes", "")])

        sc = self.get_supplemental_creds()

        # Check that we got all the expected supplemental credentials
        # And they are in the expected order.
        size = len(sc.sub.packages)
        self.assertEqual(3, size)

        (pos, package) = get_package(sc, "Primary:Kerberos")
        self.assertEqual(1, pos)
        self.assertEqual("Primary:Kerberos", package.name)

        (pos, package) = get_package(sc, "Packages")
        self.assertEqual(2, pos)
        self.assertEqual("Packages", package.name)

        (pos, package) = get_package(sc, "Primary:WDigest")
        self.assertEqual(3, pos)
        self.assertEqual("Primary:WDigest", package.name)

        # Check that the WDigest values are correct.
        #
        digests = ndr_unpack(drsblobs.package_PrimaryWDigestBlob,
                             binascii.a2b_hex(package.data))
        self.check_wdigests(digests)

    def test_userPassword_sha256(self):
        self.add_user(options=[("password hash userPassword schemes",
                                "CryptSHA256")])

        sc = self.get_supplemental_creds()

        # Check that we got all the expected supplemental credentials
        # And they are in the expected order.
        size = len(sc.sub.packages)
        self.assertEqual(4, size)

        (pos, package) = get_package(sc, "Primary:Kerberos")
        self.assertEqual(1, pos)
        self.assertEqual("Primary:Kerberos", package.name)

        (pos, wd_package) = get_package(sc, "Primary:WDigest")
        self.assertEqual(2, pos)
        self.assertEqual("Primary:WDigest", wd_package.name)

        (pos, package) = get_package(sc, "Packages")
        self.assertEqual(3, pos)
        self.assertEqual("Packages", package.name)

        (pos, up_package) = get_package(sc, "Primary:userPassword")
        self.assertEqual(4, pos)
        self.assertEqual("Primary:userPassword", up_package.name)

        # Check that the WDigest values are correct.
        #
        digests = ndr_unpack(drsblobs.package_PrimaryWDigestBlob,
                             binascii.a2b_hex(wd_package.data))
        self.check_wdigests(digests)

        # Check that the userPassword hashes are computed correctly
        #
        up = ndr_unpack(drsblobs.package_PrimaryUserPasswordBlob,
                        binascii.a2b_hex(up_package.data))

        self.checkUserPassword(up, [("{CRYPT}", "5", None)])
        self.checkNtHash(USER_PASS, up.current_nt_hash.hash)

    def test_supplementalCredentials_cleartext(self):
        self.add_user(clear_text=True,
                      options=[("password hash userPassword schemes", "")])

        sc = self.get_supplemental_creds()

        # Check that we got all the expected supplemental credentials
        # And they are in the expected order.
        size = len(sc.sub.packages)
        self.assertEqual(4, size)

        (pos, package) = get_package(sc, "Primary:Kerberos")
        self.assertEqual(1, pos)
        self.assertEqual("Primary:Kerberos", package.name)

        (pos, wd_package) = get_package(sc, "Primary:WDigest")
        self.assertEqual(2, pos)
        self.assertEqual("Primary:WDigest", wd_package.name)

        (pos, package) = get_package(sc, "Packages")
        self.assertEqual(3, pos)
        self.assertEqual("Packages", package.name)

        (pos, ct_package) = get_package(sc, "Primary:CLEARTEXT")
        self.assertEqual(4, pos)
        self.assertEqual("Primary:CLEARTEXT", ct_package.name)

        # Check that the WDigest values are correct.
        #
        digests = ndr_unpack(drsblobs.package_PrimaryWDigestBlob,
                             binascii.a2b_hex(wd_package.data))
        self.check_wdigests(digests)

        # Check the clear text  value is correct.
        ct = ndr_unpack(drsblobs.package_PrimaryCLEARTEXTBlob,
                        binascii.a2b_hex(ct_package.data))
        self.assertEqual(USER_PASS.encode('utf-16-le'), ct.cleartext)

    def test_userPassword_cleartext_sha512(self):
        self.add_user(clear_text=True,
                      options=[("password hash userPassword schemes",
                                "CryptSHA512:rounds=10000")])

        sc = self.get_supplemental_creds()

        # Check that we got all the expected supplemental credentials
        # And they are in the expected order.
        size = len(sc.sub.packages)
        self.assertEqual(5, size)

        (pos, package) = get_package(sc, "Primary:Kerberos")
        self.assertEqual(1, pos)
        self.assertEqual("Primary:Kerberos", package.name)

        (pos, wd_package) = get_package(sc, "Primary:WDigest")
        self.assertEqual(2, pos)
        self.assertEqual("Primary:WDigest", wd_package.name)

        (pos, ct_package) = get_package(sc, "Primary:CLEARTEXT")
        self.assertEqual(3, pos)
        self.assertEqual("Primary:CLEARTEXT", ct_package.name)

        (pos, package) = get_package(sc, "Packages")
        self.assertEqual(4, pos)
        self.assertEqual("Packages", package.name)

        (pos, up_package) = get_package(sc, "Primary:userPassword")
        self.assertEqual(5, pos)
        self.assertEqual("Primary:userPassword", up_package.name)

        # Check that the WDigest values are correct.
        #
        digests = ndr_unpack(drsblobs.package_PrimaryWDigestBlob,
                             binascii.a2b_hex(wd_package.data))
        self.check_wdigests(digests)

        # Check the clear text  value is correct.
        ct = ndr_unpack(drsblobs.package_PrimaryCLEARTEXTBlob,
                        binascii.a2b_hex(ct_package.data))
        self.assertEqual(USER_PASS.encode('utf-16-le'), ct.cleartext)

        # Check that the userPassword hashes are computed correctly
        #
        up = ndr_unpack(drsblobs.package_PrimaryUserPasswordBlob,
                        binascii.a2b_hex(up_package.data))
        self.checkUserPassword(up, [("{CRYPT}", "6", 10000)])
        self.checkNtHash(USER_PASS, up.current_nt_hash.hash)
