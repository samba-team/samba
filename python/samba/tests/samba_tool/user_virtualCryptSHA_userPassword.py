# Tests for the samba-tool user sub command reading Primary:userPassword
#
# Copyright (C) Andrew Bartlett <abartlet@samba.org> 2017
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

from samba.tests.samba_tool.user_virtualCryptSHA_base import UserCmdCryptShaTestCase, _get_attribute

class UserCmdCryptShaTestCaseUserPassword(UserCmdCryptShaTestCase):
    # gpg decryption not enabled.
    # both virtual attributes specified, no rounds option
    # no hashes stored in supplementalCredentials
    # Should not get values
    def test_no_gpg_both_hashes_no_rounds(self):
        self.add_user()
        out = self._get_password("virtualCryptSHA256,virtualCryptSHA512")

        self.assertTrue("virtualCryptSHA256:" not in out)
        self.assertTrue("virtualCryptSHA512:" not in out)
        self.assertTrue("rounds=" not in out)

    # gpg decryption not enabled.
    # SHA256 specified
    # no hashes stored in supplementalCredentials
    # No rounds
    #
    # Should not get values
    def test_no_gpg_sha256_no_rounds(self):
        self.add_user()
        out = self._get_password("virtualCryptSHA256")

        self.assertTrue("virtualCryptSHA256:" not in out)
        self.assertTrue("virtualCryptSHA512:" not in out)
        self.assertTrue("rounds=" not in out)

    # gpg decryption not enabled.
    # SHA512 specified
    # no hashes stored in supplementalCredentials
    # No rounds
    #
    # Should not get values
    def test_no_gpg_sha512_no_rounds(self):
        self.add_user()
        out = self._get_password("virtualCryptSHA512")

        self.assertTrue("virtualCryptSHA256:" not in out)
        self.assertTrue("virtualCryptSHA512:" not in out)
        self.assertTrue("rounds=" not in out)

    # gpg decryption not enabled.
    # SHA128 specified, i.e. invalid/unknown algorithm
    # no hashes stored in supplementalCredentials
    # No rounds
    #
    # Should not get values
    def test_no_gpg_invalid_alg_no_rounds(self):
        self.add_user()
        out = self._get_password("virtualCryptSHA128")

        self.assertTrue("virtualCryptSHA256:" not in out)
        self.assertTrue("virtualCryptSHA512:" not in out)
        self.assertTrue("rounds=" not in out)

    # gpg decryption not enabled.
    # both virtual attributes specified, no rounds option
    # both hashes stored in supplementalCredentials
    # Should get values
    def test_no_gpg_both_hashes_no_rounds_stored_hashes(self):
        self.add_user("CryptSHA512 CryptSHA256")

        out = self._get_password("virtualCryptSHA256,virtualCryptSHA512")

        self.assertTrue("virtualCryptSHA256:" in out)
        self.assertTrue("virtualCryptSHA512:" in out)
        self.assertTrue("rounds=" not in out)

        # Should be using the pre computed hash in supplementalCredentials
        # so it should not change between calls.
        sha256 = _get_attribute(out, "virtualCryptSHA256")
        sha512 = _get_attribute(out, "virtualCryptSHA512")

        out = self._get_password("virtualCryptSHA256,virtualCryptSHA512")
        self.assertEquals(sha256, _get_attribute(out, "virtualCryptSHA256"))
        self.assertEquals(sha512, _get_attribute(out, "virtualCryptSHA512"))

    # gpg decryption not enabled.
    # both virtual attributes specified, rounds specified
    # both hashes stored in supplementalCredentials, with not rounds
    # Should get hashes for the first matching scheme entry
    def test_no_gpg_both_hashes_rounds_stored_hashes(self):
        self.add_user("CryptSHA512 CryptSHA256")

        out = self._get_password("virtualCryptSHA256;rounds=2561," +
                                 "virtualCryptSHA512;rounds=5129")

        self.assertTrue("virtualCryptSHA256:" in out)
        self.assertTrue("virtualCryptSHA512:" in out)
        self.assertTrue("rounds=" not in out)

        # Should be using the pre computed hash in supplementalCredentials
        # so it should not change between calls.
        sha256 = _get_attribute(out, "virtualCryptSHA256")
        sha512 = _get_attribute(out, "virtualCryptSHA512")

        out = self._get_password("virtualCryptSHA256,virtualCryptSHA512")
        self.assertEquals(sha256, _get_attribute(out, "virtualCryptSHA256"))
        self.assertEquals(sha512, _get_attribute(out, "virtualCryptSHA512"))

    # gpg decryption not enabled.
    # both virtual attributes specified, rounds specified
    # both hashes stored in supplementalCredentials, with rounds
    # Should get values
    def test_no_gpg_both_hashes_rounds_stored_hashes_with_rounds(self):
        self.add_user("CryptSHA512 " +
                      "CryptSHA256 " +
                      "CryptSHA512:rounds=5129 " +
                      "CryptSHA256:rounds=2561")

        out = self._get_password("virtualCryptSHA256;rounds=2561," +
                                 "virtualCryptSHA512;rounds=5129")

        self.assertTrue("virtualCryptSHA256:" in out)
        self.assertTrue("virtualCryptSHA512:" in out)
        self.assertTrue("rounds=" in out)

        # Should be using the pre computed hash in supplementalCredentials
        # so it should not change between calls.
        sha256 = _get_attribute(out, "virtualCryptSHA256")
        sha512 = _get_attribute(out, "virtualCryptSHA512")

        out = self._get_password("virtualCryptSHA256;rounds=2561," +
                                 "virtualCryptSHA512;rounds=5129")
        self.assertEquals(sha256, _get_attribute(out, "virtualCryptSHA256"))
        self.assertEquals(sha512, _get_attribute(out, "virtualCryptSHA512"))

        # Number of rounds should match that specified
        self.assertTrue(sha256.startswith("{CRYPT}$5$rounds=2561"))
        self.assertTrue(sha512.startswith("{CRYPT}$6$rounds=5129"))

    # gpg decryption not enabled.
    # both virtual attributes specified, rounds specified
    # both hashes stored in supplementalCredentials, with rounds
    # number of rounds stored/requested do not match
    # Should get the precomputed hashes for CryptSHA512 and CryptSHA256
    def test_no_gpg_both_hashes_rounds_stored_hashes_with_rounds_no_match(self):
        self.add_user("CryptSHA512 " +
                      "CryptSHA256 " +
                      "CryptSHA512:rounds=5129 " +
                      "CryptSHA256:rounds=2561")

        out = self._get_password("virtualCryptSHA256;rounds=4000," +
                                 "virtualCryptSHA512;rounds=5000")

        self.assertTrue("virtualCryptSHA256:" in out)
        self.assertTrue("virtualCryptSHA512:" in out)
        self.assertTrue("rounds=" not in out)

        # Should be using the pre computed hash in supplementalCredentials
        # so it should not change between calls.
        sha256 = _get_attribute(out, "virtualCryptSHA256")
        sha512 = _get_attribute(out, "virtualCryptSHA512")

        out = self._get_password("virtualCryptSHA256;rounds=4000," +
                                 "virtualCryptSHA512;rounds=5000")
        self.assertEquals(sha256, _get_attribute(out, "virtualCryptSHA256"))
        self.assertEquals(sha512, _get_attribute(out, "virtualCryptSHA512"))

        # As the number of rounds did not match, should have returned the
        # first hash of the coresponding scheme
        out = self._get_password("virtualCryptSHA256," +
                                 "virtualCryptSHA512")
        self.assertEquals(sha256, _get_attribute(out, "virtualCryptSHA256"))
        self.assertEquals(sha512, _get_attribute(out, "virtualCryptSHA512"))
