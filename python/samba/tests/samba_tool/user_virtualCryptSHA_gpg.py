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

class UserCmdCryptShaTestCaseGPG(UserCmdCryptShaTestCase):
    """
    Tests for samba-tool user subcommands generation of the virtualCryptSHA256
    and virtualCryptSHA512 attributes
    """

    # gpg decryption enabled.
    # both virtual attributes specified, no rounds option
    # no hashes stored in supplementalCredentials
    # Should get values
    def test_gpg_both_hashes_no_rounds(self):
        self.add_user()
        out = self._get_password("virtualCryptSHA256,virtualCryptSHA512", True)

        self.assertTrue("virtualCryptSHA256:" in out)
        self.assertTrue("virtualCryptSHA512:" in out)
        self.assertTrue("rounds=" not in out)

    # gpg decryption enabled.
    # SHA256 specified
    # no hashes stored in supplementalCredentials
    # No rounds
    #
    # Should get values
    def test_gpg_sha256_no_rounds(self):
        self.add_user()
        out = self._get_password("virtualCryptSHA256", True)

        self.assertTrue("virtualCryptSHA256:" in out)
        self.assertTrue("virtualCryptSHA512:" not in out)
        self.assertTrue("rounds=" not in out)

    # gpg decryption enabled.
    # SHA512 specified
    # no hashes stored in supplementalCredentials
    # No rounds
    #
    # Should get values
    def test_gpg_sha512_no_rounds(self):
        self.add_user()
        out = self._get_password("virtualCryptSHA512", True)

        self.assertTrue("virtualCryptSHA256:" not in out)
        self.assertTrue("virtualCryptSHA512:" in out)
        self.assertTrue("rounds=" not in out)

    # gpg decryption enabled.
    # SHA128 specified, i.e. invalid/unknown algorithm
    # no hashes stored in supplementalCredentials
    # No rounds
    #
    # Should not get values
    def test_gpg_invalid_alg_no_rounds(self):
        self.add_user()
        out = self._get_password("virtualCryptSHA128", True)

        self.assertTrue("virtualCryptSHA256:" not in out)
        self.assertTrue("virtualCryptSHA512:" not in out)
        self.assertTrue("rounds=" not in out)

    # gpg decryption enabled.
    # both virtual attributes specified, no rounds option
    # no hashes stored in supplementalCredentials
    # underlying windows password changed, so plain text password is
    # invalid.
    # Should not get values
    def test_gpg_both_hashes_no_rounds_pwd_changed(self):
        self.add_user()
        self._change_nt_hash()
        out = self._get_password("virtualCryptSHA256,virtualCryptSHA512", True)

        self.assertTrue("virtualCryptSHA256:" not in out)
        self.assertTrue("virtualCryptSHA512:" not in out)
        self.assertTrue("rounds=" not in out)

    # gpg decryption enabled.
    # SHA256 specified, no rounds option
    # no hashes stored in supplementalCredentials
    # underlying windows password changed, so plain text password is
    # invalid.
    # Should not get values
    def test_gpg_sha256_no_rounds_pwd_changed(self):
        self.add_user()
        self._change_nt_hash()
        out = self._get_password("virtualCryptSHA256", True)

        self.assertTrue("virtualCryptSHA256:" not in out)
        self.assertTrue("virtualCryptSHA512:" not in out)
        self.assertTrue("rounds=" not in out)

    # gpg decryption enabled.
    # SHA512 specified, no rounds option
    # no hashes stored in supplementalCredentials
    # underlying windows password changed, so plain text password is
    # invalid.
    # Should not get values
    def test_gpg_sha512_no_rounds_pwd_changed(self):
        self.add_user()
        self._change_nt_hash()
        out = self._get_password("virtualCryptSHA256", True)

        self.assertTrue("virtualCryptSHA256:" not in out)
        self.assertTrue("virtualCryptSHA512:" not in out)
        self.assertTrue("rounds=" not in out)

    # gpg decryption enabled.
    # both virtual attributes specified, rounds specified
    # no hashes stored in supplementalCredentials
    # Should get values reflecting the requested rounds
    def test_gpg_both_hashes_both_rounds(self):
        self.add_user()
        out = self._get_password(
            "virtualCryptSHA256;rounds=10123,virtualCryptSHA512;rounds=10456",
            True)

        self.assertTrue("virtualCryptSHA256:" in out)
        self.assertTrue("virtualCryptSHA512:" in out)

        sha256 = _get_attribute(out, "virtualCryptSHA256")
        self.assertTrue(sha256.startswith("{CRYPT}$5$rounds=10123$"))

        sha512 = _get_attribute(out, "virtualCryptSHA512")
        self.assertTrue(sha512.startswith("{CRYPT}$6$rounds=10456$"))

    # gpg decryption enabled.
    # both virtual attributes specified, rounds specified
    # invalid rounds for sha256
    # no hashes stored in supplementalCredentials
    # Should get values, no rounds for sha256, rounds for sha 512
    def test_gpg_both_hashes_sha256_rounds_invalid(self):
        self.add_user()
        out = self._get_password(
            "virtualCryptSHA256;rounds=invalid,virtualCryptSHA512;rounds=3125",
            True)

        self.assertTrue("virtualCryptSHA256:" in out)
        self.assertTrue("virtualCryptSHA512:" in out)

        sha256 = _get_attribute(out, "virtualCryptSHA256")
        self.assertTrue(sha256.startswith("{CRYPT}$5$"))
        self.assertTrue("rounds" not in sha256)

        sha512 = _get_attribute(out, "virtualCryptSHA512")
        self.assertTrue(sha512.startswith("{CRYPT}$6$rounds=3125$"))

    # gpg decryption enabled.
    # both virtual attributes specified, rounds specified
    # both hashes stored in supplementalCredentials, with no rounds
    # Should get calculated hashed with the correct number of rounds
    def test_gpg_both_hashes_rounds_stored_hashes(self):
        self.add_user("CryptSHA512 CryptSHA256")

        out = self._get_password("virtualCryptSHA256;rounds=2561," +
                                 "virtualCryptSHA512;rounds=5129",
                                 True)

        self.assertTrue("virtualCryptSHA256:" in out)
        self.assertTrue("virtualCryptSHA512:" in out)
        self.assertTrue("rounds=" in out)

        # Should be calculating the hashes
        # so they should change between calls.
        sha256 = _get_attribute(out, "virtualCryptSHA256")
        sha512 = _get_attribute(out, "virtualCryptSHA512")

        out = self._get_password("virtualCryptSHA256;rounds=2561," +
                                 "virtualCryptSHA512;rounds=5129",
                                 True)
        self.assertFalse(sha256 == _get_attribute(out, "virtualCryptSHA256"))
        self.assertFalse(sha512 == _get_attribute(out, "virtualCryptSHA512"))

        # The returned hashes should specify the correct number of rounds
        self.assertTrue(sha256.startswith("{CRYPT}$5$rounds=2561"))
        self.assertTrue(sha512.startswith("{CRYPT}$6$rounds=5129"))

    # gpg decryption enabled.
    # both virtual attributes specified, rounds specified
    # both hashes stored in supplementalCredentials, with rounds
    # Should get values
    def test_gpg_both_hashes_rounds_stored_hashes_with_rounds(self):
        self.add_user("CryptSHA512 " +
                      "CryptSHA256 " +
                      "CryptSHA512:rounds=5129 " +
                      "CryptSHA256:rounds=2561")

        out = self._get_password("virtualCryptSHA256;rounds=2561," +
                                 "virtualCryptSHA512;rounds=5129",
                                 True)

        self.assertTrue("virtualCryptSHA256:" in out)
        self.assertTrue("virtualCryptSHA512:" in out)
        self.assertTrue("rounds=" in out)

        # Should be using the pre computed hash in supplementalCredentials
        # so it should not change between calls.
        sha256 = _get_attribute(out, "virtualCryptSHA256")
        sha512 = _get_attribute(out, "virtualCryptSHA512")

        out = self._get_password("virtualCryptSHA256;rounds=2561," +
                                 "virtualCryptSHA512;rounds=5129",
                                 True)
        self.assertEquals(sha256, _get_attribute(out, "virtualCryptSHA256"))
        self.assertEquals(sha512, _get_attribute(out, "virtualCryptSHA512"))

        # The returned hashes should specify the correct number of rounds
        self.assertTrue(sha256.startswith("{CRYPT}$5$rounds=2561"))
        self.assertTrue(sha512.startswith("{CRYPT}$6$rounds=5129"))

    # gpg decryption enabled.
    # both virtual attributes specified, rounds specified
    # both hashes stored in supplementalCredentials, with rounds
    # number of rounds stored/requested do not match
    # Should get calculated hashes with the correct number of rounds
    def test_gpg_both_hashes_rounds_stored_hashes_with_rounds_no_match(self):
        self.add_user("CryptSHA512 " +
                      "CryptSHA256 " +
                      "CryptSHA512:rounds=5129 " +
                      "CryptSHA256:rounds=2561")

        out = self._get_password("virtualCryptSHA256;rounds=4000," +
                                 "virtualCryptSHA512;rounds=5000",
                                 True)

        self.assertTrue("virtualCryptSHA256:" in out)
        self.assertTrue("virtualCryptSHA512:" in out)
        self.assertTrue("rounds=" in out)

        # Should be calculating the hashes
        # so they should change between calls.
        sha256 = _get_attribute(out, "virtualCryptSHA256")
        sha512 = _get_attribute(out, "virtualCryptSHA512")

        out = self._get_password("virtualCryptSHA256;rounds=4000," +
                                 "virtualCryptSHA512;rounds=5000",
                                 True)
        self.assertFalse(sha256 == _get_attribute(out, "virtualCryptSHA256"))
        self.assertFalse(sha512 == _get_attribute(out, "virtualCryptSHA512"))

        # The calculated hashes should specify the correct number of rounds
        self.assertTrue(sha256.startswith("{CRYPT}$5$rounds=4000"))
        self.assertTrue(sha512.startswith("{CRYPT}$6$rounds=5000"))
