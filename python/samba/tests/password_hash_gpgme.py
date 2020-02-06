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
io->ac->gpg_key_ids != NULL, so that the gpg supplemental credentials
are generated. The functional level needs to be >= 2008 so that the
kerberos newer keys are generated.
"""


from samba.tests.password_hash import (
    PassWordHashTests,
    get_package,
    USER_PASS,
    USER_NAME
)
from samba.ndr import ndr_unpack
from samba.dcerpc import drsblobs
import binascii
from samba.tests.pso import PasswordSettings
import samba


class PassWordHashGpgmeTests(PassWordHashTests):

    def setUp(self):
        super(PassWordHashGpgmeTests, self).setUp()

    def test_default_supplementalCredentials(self):
        self.add_user()
        if not self.lp.get("password hash gpg key ids"):
            self.skipTest("No password hash gpg key ids, " +
                          "Primary:SambaGPG will not be generated")

        sc = self.get_supplemental_creds()

        # Check that we got all the expected supplemental credentials
        # And they are in the expected order.
        size = len(sc.sub.packages)
        self.assertEqual(5, size)
        (pos, package) = get_package(sc, "Primary:Kerberos-Newer-Keys")
        self.assertEqual(1, pos)
        self.assertEqual("Primary:Kerberos-Newer-Keys", package.name)

        (pos, package) = get_package(sc, "Primary:Kerberos")
        self.assertEqual(2, pos)
        self.assertEqual("Primary:Kerberos", package.name)

        (pos, wd_package) = get_package(sc, "Primary:WDigest")
        self.assertEqual(3, pos)
        self.assertEqual("Primary:WDigest", wd_package.name)

        (pos, package) = get_package(sc, "Packages")
        self.assertEqual(4, pos)
        self.assertEqual("Packages", package.name)

        (pos, package) = get_package(sc, "Primary:SambaGPG")
        self.assertEqual(5, pos)
        self.assertEqual("Primary:SambaGPG", package.name)

        # Check that the WDigest values are correct.
        #
        digests = ndr_unpack(drsblobs.package_PrimaryWDigestBlob,
                             binascii.a2b_hex(wd_package.data))
        self.check_wdigests(digests)

    def test_supplementalCredentials_cleartext(self):
        self.add_user(clear_text=True)
        if not self.lp.get("password hash gpg key ids"):
            self.skipTest("No password hash gpg key ids, " +
                          "Primary:SambaGPG will not be generated")

        sc = self.get_supplemental_creds()

        # Check that we got all the expected supplemental credentials
        # And they are in the expected order.
        size = len(sc.sub.packages)
        self.assertEqual(6, size)
        (pos, package) = get_package(sc, "Primary:Kerberos-Newer-Keys")
        self.assertEqual(1, pos)
        self.assertEqual("Primary:Kerberos-Newer-Keys", package.name)

        (pos, package) = get_package(sc, "Primary:Kerberos")
        self.assertEqual(2, pos)
        self.assertEqual("Primary:Kerberos", package.name)

        (pos, wd_package) = get_package(sc, "Primary:WDigest")
        self.assertEqual(3, pos)
        self.assertEqual("Primary:WDigest", wd_package.name)

        (pos, ct_package) = get_package(sc, "Primary:CLEARTEXT")
        self.assertEqual(4, pos)
        self.assertEqual("Primary:CLEARTEXT", ct_package.name)

        (pos, package) = get_package(sc, "Packages")
        self.assertEqual(5, pos)
        self.assertEqual("Packages", package.name)

        (pos, package) = get_package(sc, "Primary:SambaGPG")
        self.assertEqual(6, pos)
        self.assertEqual("Primary:SambaGPG", package.name)

        # Check that the WDigest values are correct.
        #
        digests = ndr_unpack(drsblobs.package_PrimaryWDigestBlob,
                             binascii.a2b_hex(wd_package.data))
        self.check_wdigests(digests)

        # Check the clear text  value is correct.
        ct = ndr_unpack(drsblobs.package_PrimaryCLEARTEXTBlob,
                        binascii.a2b_hex(ct_package.data))
        self.assertEqual(USER_PASS.encode('utf-16-le'), ct.cleartext)

    def assert_cleartext(self, expect_cleartext, password=None):
        """Checks cleartext is (or isn't) returned as expected"""
        sc = self.get_supplemental_creds()
        if expect_cleartext:
            (pos, ct_package) = get_package(sc, "Primary:CLEARTEXT")
            self.assertTrue(ct_package is not None, "Failed to retrieve cleartext")

            # Check the clear-text value is correct.
            ct = ndr_unpack(drsblobs.package_PrimaryCLEARTEXTBlob,
                            binascii.a2b_hex(ct_package.data))
            self.assertEqual(password.encode('utf-16-le'), ct.cleartext)
        else:
            ct_package = get_package(sc, "Primary:CLEARTEXT")
            self.assertTrue(ct_package is None,
                            "Got cleartext when we shouldn't have")

    def test_supplementalCredentials_cleartext_pso(self):
        """Checks that a PSO's cleartext setting can override the domain's"""

        # create a user that stores plain-text passwords
        self.add_user(clear_text=True)

        # check that clear-text is present in the supplementary-credentials
        self.assert_cleartext(expect_cleartext=True, password=USER_PASS)

        # create a PSO overriding the plain-text setting & apply it to the user
        no_plaintext_pso = PasswordSettings("no-plaintext-PSO", self.ldb,
                                            precedence=200,
                                            store_plaintext=False)
        self.addCleanup(self.ldb.delete, no_plaintext_pso.dn)
        userdn = "cn=" + USER_NAME + ",cn=users," + self.base_dn
        no_plaintext_pso.apply_to(userdn)

        # set the password to update the cleartext password stored
        new_password = samba.generate_random_password(32, 32)
        self.ldb.setpassword("(sAMAccountName=%s)" % USER_NAME, new_password)

        # this time cleartext shouldn't be in the supplementary creds
        self.assert_cleartext(expect_cleartext=False)

        # unapply PSO, update password, and check we get the cleartext again
        no_plaintext_pso.unapply(userdn)
        new_password = samba.generate_random_password(32, 32)
        self.ldb.setpassword("(sAMAccountName=%s)" % USER_NAME, new_password)
        self.assert_cleartext(expect_cleartext=True, password=new_password)

        # Now update the domain setting and check we no longer get cleartext
        self.set_store_cleartext(False)
        new_password = samba.generate_random_password(32, 32)
        self.ldb.setpassword("(sAMAccountName=%s)" % USER_NAME, new_password)
        self.assert_cleartext(expect_cleartext=False)

        # create a PSO overriding the domain setting & apply it to the user
        plaintext_pso = PasswordSettings("plaintext-PSO", self.ldb,
                                         precedence=100, store_plaintext=True)
        self.addCleanup(self.ldb.delete, plaintext_pso.dn)
        plaintext_pso.apply_to(userdn)
        new_password = samba.generate_random_password(32, 32)
        self.ldb.setpassword("(sAMAccountName=%s)" % USER_NAME, new_password)
        self.assert_cleartext(expect_cleartext=True, password=new_password)

    def test_userPassword_multiple_hashes(self):
        self.add_user(options=[(
            "password hash userPassword schemes",
            "CryptSHA512 CryptSHA256 CryptSHA512")])

        sc = self.get_supplemental_creds()

        # Check that we got all the expected supplemental credentials
        # And they are in the expected order.
        size = len(sc.sub.packages)
        self.assertEqual(6, size)

        (pos, package) = get_package(sc, "Primary:Kerberos-Newer-Keys")
        self.assertEqual(1, pos)
        self.assertEqual("Primary:Kerberos-Newer-Keys", package.name)

        (pos, package) = get_package(sc, "Primary:Kerberos")
        self.assertEqual(2, pos)
        self.assertEqual("Primary:Kerberos", package.name)

        (pos, wp_package) = get_package(sc, "Primary:WDigest")
        self.assertEqual(3, pos)
        self.assertEqual("Primary:WDigest", wp_package.name)

        (pos, up_package) = get_package(sc, "Primary:userPassword")
        self.assertEqual(4, pos)
        self.assertEqual("Primary:userPassword", up_package.name)

        (pos, package) = get_package(sc, "Packages")
        self.assertEqual(5, pos)
        self.assertEqual("Packages", package.name)

        (pos, package) = get_package(sc, "Primary:SambaGPG")
        self.assertEqual(6, pos)
        self.assertEqual("Primary:SambaGPG", package.name)

        # Check that the WDigest values are correct.
        #
        digests = ndr_unpack(drsblobs.package_PrimaryWDigestBlob,
                             binascii.a2b_hex(wp_package.data))
        self.check_wdigests(digests)

        # Check that the userPassword hashes are computed correctly
        # Expect three hashes to be calculated
        up = ndr_unpack(drsblobs.package_PrimaryUserPasswordBlob,
                        binascii.a2b_hex(up_package.data))
        self.checkUserPassword(up, [
            ("{CRYPT}", "6", None),
            ("{CRYPT}", "5", None),
            ("{CRYPT}", "6", None)
        ])
        self.checkNtHash(USER_PASS, up.current_nt_hash.hash)

    def test_userPassword_multiple_hashes_rounds_specified(self):
        self.add_user(options=[(
            "password hash userPassword schemes",
            "CryptSHA512:rounds=5120 CryptSHA256:rounds=2560 CryptSHA512:rounds=5122")])

        sc = self.get_supplemental_creds()

        # Check that we got all the expected supplemental credentials
        # And they are in the expected order.
        size = len(sc.sub.packages)
        self.assertEqual(6, size)

        (pos, package) = get_package(sc, "Primary:Kerberos-Newer-Keys")
        self.assertEqual(1, pos)
        self.assertEqual("Primary:Kerberos-Newer-Keys", package.name)

        (pos, package) = get_package(sc, "Primary:Kerberos")
        self.assertEqual(2, pos)
        self.assertEqual("Primary:Kerberos", package.name)

        (pos, wp_package) = get_package(sc, "Primary:WDigest")
        self.assertEqual(3, pos)
        self.assertEqual("Primary:WDigest", wp_package.name)

        (pos, up_package) = get_package(sc, "Primary:userPassword")
        self.assertEqual(4, pos)
        self.assertEqual("Primary:userPassword", up_package.name)

        (pos, package) = get_package(sc, "Packages")
        self.assertEqual(5, pos)
        self.assertEqual("Packages", package.name)

        (pos, package) = get_package(sc, "Primary:SambaGPG")
        self.assertEqual(6, pos)
        self.assertEqual("Primary:SambaGPG", package.name)

        # Check that the WDigest values are correct.
        #
        digests = ndr_unpack(drsblobs.package_PrimaryWDigestBlob,
                             binascii.a2b_hex(wp_package.data))
        self.check_wdigests(digests)

        # Check that the userPassword hashes are computed correctly
        # Expect three hashes to be calculated
        up = ndr_unpack(drsblobs.package_PrimaryUserPasswordBlob,
                        binascii.a2b_hex(up_package.data))
        self.checkUserPassword(up, [
            ("{CRYPT}", "6", 5120),
            ("{CRYPT}", "5", 2560),
            ("{CRYPT}", "6", 5122)
        ])
        self.checkNtHash(USER_PASS, up.current_nt_hash.hash)
