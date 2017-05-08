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

import os
import time
import base64
import ldb
import samba
from samba.tests.samba_tool.base import SambaToolCmdTest
from samba.credentials import Credentials
from samba.samdb import SamDB
from samba.auth import system_session
from samba.ndr import ndr_unpack
from samba.dcerpc import drsblobs
from samba import dsdb
import binascii
import md5
import re

USER_NAME = "CyyptSHATestUser"
USER_PASS = samba.generate_random_password(32,32)

# Get the value of an attribute from the output string
# Note: Does not correctly handle values spanning multiple lines,
#       which is acceptable for it's usage in these tests.
def _get_attribute(out, name):
    p = re.compile("^"+name+":\s+(\S+)")
    for line in out.split("\n"):
        m = p.match(line)
        if m:
            return m.group(1)
    return ""

class UserCmdCryptShaTestCase(SambaToolCmdTest):
    """
    Tests for samba-tool user subcommands generation of the virtualCryptSHA256
    and virtualCryptSHA512 attributes
    """
    users = []
    samdb = None

    def setUp(self):
        super(UserCmdCryptShaTestCase, self).setUp()

    def add_user(self, options = None):
        self.lp = samba.tests.env_loadparm()
        # set any needed options
        if options is not None:
            for (option,value) in options:
                self.lp.set(option, value)

        self.creds = Credentials()
        self.session = system_session()
        self.ldb = SamDB(
            session_info=self.session,
            credentials=self.creds,
            lp=self.lp)

        self.runsubcmd("user",
                       "create",
                       USER_NAME,
                       USER_PASS)

    def tearDown(self):
        super(UserCmdCryptShaTestCase, self).tearDown()
        self.runsubcmd("user", "delete", USER_NAME)

    def _get_password(self, attributes, decrypt = False):
        command = ["user",
                   "getpassword",
                   USER_NAME,
                   "--attributes",
                   attributes]
        if decrypt:
            command.append("--decrypt-samba-gpg")

        (result, out, err) = self.runsubcmd(*command)
        self.assertCmdSuccess(result,
                              out,
                              err,
                              "Ensure getpassword runs")
        self.assertEqual(err, "", "getpassword")
        self.assertMatch(out,
                         "Got password OK",
                         "getpassword out[%s]" % out)
        return out

    # Change the just the NT password hash, as would happen if the password
    # was updated by Windows, the userPassword values are now obsolete.
    #
    def _change_nt_hash(self):
        res = self.ldb.search(expression = "cn=%s" % USER_NAME,
                              scope      = ldb.SCOPE_SUBTREE)
        msg = ldb.Message()
        msg.dn = res[0].dn
        msg["unicodePwd"] = ldb.MessageElement(b"ABCDEF1234567890",
                                                ldb.FLAG_MOD_REPLACE,
                                                "unicodePwd")
        self.ldb.modify(
            msg,
            controls=["local_oid:%s:0" %
                dsdb.DSDB_CONTROL_BYPASS_PASSWORD_HASH_OID])

    # gpg decryption not enabled.
    # both virtual attributes specified, no rounds option
    # Should not get values
    def test_no_gpg_both_hashes_no_rounds(self):
        self.add_user()
        out = self._get_password("virtualCryptSHA256,virtualCryptSHA512")

        self.assertTrue("virtualCryptSHA256:" not in out)
        self.assertTrue("virtualCryptSHA512:" not in out)
        self.assertTrue("rounds=" not in out)

    # gpg decryption not enabled.
    # SHA256 specified
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
    # No rounds
    #
    # Should not get values
    def test_no_gpg_invalid_alg_no_rounds(self):
        self.add_user()
        out = self._get_password("virtualCryptSHA128")

        self.assertTrue("virtualCryptSHA256:" not in out)
        self.assertTrue("virtualCryptSHA512:" not in out)
        self.assertTrue("rounds=" not in out)

    # gpg decryption enabled.
    # both virtual attributes specified, no rounds option
    # Should get values
    def test_gpg_both_hashes_no_rounds(self):
        self.add_user()
        out = self._get_password("virtualCryptSHA256,virtualCryptSHA512", True)

        self.assertTrue("virtualCryptSHA256:" in out)
        self.assertTrue("virtualCryptSHA512:" in out)
        self.assertTrue("rounds=" not in out)

    # gpg decryption enabled.
    # SHA256 specified
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
