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
Base class for tests for source4/dsdb/samdb/ldb_modules/password_hash.c
"""

from samba.credentials import Credentials
from samba.samdb import SamDB
from samba.auth import system_session
from samba.tests import TestCase
from samba.ndr import ndr_unpack
from samba.dcerpc import drsblobs
from samba.dcerpc.samr import DOMAIN_PASSWORD_STORE_CLEARTEXT
from samba.dsdb import UF_ENCRYPTED_TEXT_PASSWORD_ALLOWED
from samba.tests import delete_force
from samba.tests.password_test import PasswordCommon
import ldb
import samba
import binascii
from hashlib import md5
import crypt
from samba.compat import text_type


USER_NAME = "PasswordHashTestUser"
USER_PASS = samba.generate_random_password(32, 32)
UPN       = "PWHash@User.Principle"

# Get named package from the passed supplemental credentials
#
# returns the package and it's position within the supplemental credentials


def get_package(sc, name):
    if sc is None:
        return None

    idx = 0
    for p in sc.sub.packages:
        idx += 1
        if name == p.name:
            return (idx, p)

    return None

# Calculate the MD5 password digest from the supplied user, realm and password
#


def calc_digest(user, realm, password):

    data = "%s:%s:%s" % (user, realm, password)
    if isinstance(data, text_type):
        data = data.encode('utf8')

    return md5(data).hexdigest()


class PassWordHashTests(TestCase):

    def setUp(self):
        self.lp = samba.tests.env_loadparm()
        super(PassWordHashTests, self).setUp()

    def set_store_cleartext(self, cleartext):
        # get the current pwdProperties
        pwdProperties = self.ldb.get_pwdProperties()
        # update the clear-text properties flag
        props = int(pwdProperties)
        if cleartext:
            props |= DOMAIN_PASSWORD_STORE_CLEARTEXT
        else:
            props &= ~DOMAIN_PASSWORD_STORE_CLEARTEXT
        self.ldb.set_pwdProperties(str(props))

    # Add a user to ldb, this will exercise the password_hash code
    # and calculate the appropriate supplemental credentials
    def add_user(self, options=None, clear_text=False, ldb=None):
        # set any needed options
        if options is not None:
            for (option, value) in options:
                self.lp.set(option, value)

        if ldb is None:
            self.creds = Credentials()
            self.session = system_session()
            self.creds.guess(self.lp)
            self.session = system_session()
            self.ldb = SamDB(session_info=self.session,
                             credentials=self.creds,
                             lp=self.lp)
        else:
            self.ldb = ldb

        res = self.ldb.search(base=self.ldb.get_config_basedn(),
                              expression="ncName=%s" % self.ldb.get_default_basedn(),
                              attrs=["nETBIOSName"])
        self.netbios_domain = str(res[0]["nETBIOSName"][0])
        self.dns_domain = self.ldb.domain_dns_name()

        # Gets back the basedn
        base_dn = self.ldb.domain_dn()

        # Gets back the configuration basedn
        configuration_dn = self.ldb.get_config_basedn().get_linearized()

        # permit password changes during this test
        PasswordCommon.allow_password_changes(self, self.ldb)

        self.base_dn = self.ldb.domain_dn()

        account_control = 0
        if clear_text:
            # Restore the current domain setting on exit.
            pwdProperties = self.ldb.get_pwdProperties()
            self.addCleanup(self.ldb.set_pwdProperties, pwdProperties)
            # Update the domain setting
            self.set_store_cleartext(clear_text)
            account_control |= UF_ENCRYPTED_TEXT_PASSWORD_ALLOWED

        # (Re)adds the test user USER_NAME with password USER_PASS
        # and userPrincipalName UPN
        delete_force(self.ldb, "cn=" + USER_NAME + ",cn=users," + self.base_dn)
        self.ldb.add({
             "dn": "cn=" + USER_NAME + ",cn=users," + self.base_dn,
             "objectclass": "user",
             "sAMAccountName": USER_NAME,
             "userPassword": USER_PASS,
             "userPrincipalName": UPN,
             "userAccountControl": str(account_control)
        })

    # Get the supplemental credentials for the user under test
    def get_supplemental_creds(self):
        base = "cn=" + USER_NAME + ",cn=users," + self.base_dn
        res = self.ldb.search(scope=ldb.SCOPE_BASE,
                              base=base,
                              attrs=["supplementalCredentials"])
        self.assertIs(True, len(res) > 0)
        obj = res[0]
        sc_blob = obj["supplementalCredentials"][0]
        sc = ndr_unpack(drsblobs.supplementalCredentialsBlob, sc_blob)
        return sc

    # Calculate and validate a Wdigest value
    def check_digest(self, user, realm, password, digest):
        expected = calc_digest(user, realm, password)
        actual = binascii.hexlify(bytearray(digest)).decode('utf8')
        error = "Digest expected[%s], actual[%s], " \
                "user[%s], realm[%s], pass[%s]" % \
                (expected, actual, user, realm, password)
        self.assertEqual(expected, actual, error)

    # Check all of the 29 expected WDigest values
    #
    def check_wdigests(self, digests):

        self.assertEqual(29, digests.num_hashes)

        # Using the n-1 pattern in the array indexes to make it easier
        # to check the tests against the spec and the samba-tool user tests.
        self.check_digest(USER_NAME,
                          self.netbios_domain,
                          USER_PASS,
                          digests.hashes[1 - 1].hash)
        self.check_digest(USER_NAME.lower(),
                          self.netbios_domain.lower(),
                          USER_PASS,
                          digests.hashes[2 - 1].hash)
        self.check_digest(USER_NAME.upper(),
                          self.netbios_domain.upper(),
                          USER_PASS,
                          digests.hashes[3 - 1].hash)
        self.check_digest(USER_NAME,
                          self.netbios_domain.upper(),
                          USER_PASS,
                          digests.hashes[4 - 1].hash)
        self.check_digest(USER_NAME,
                          self.netbios_domain.lower(),
                          USER_PASS,
                          digests.hashes[5 - 1].hash)
        self.check_digest(USER_NAME.upper(),
                          self.netbios_domain.lower(),
                          USER_PASS,
                          digests.hashes[6 - 1].hash)
        self.check_digest(USER_NAME.lower(),
                          self.netbios_domain.upper(),
                          USER_PASS,
                          digests.hashes[7 - 1].hash)
        self.check_digest(USER_NAME,
                          self.dns_domain,
                          USER_PASS,
                          digests.hashes[8 - 1].hash)
        self.check_digest(USER_NAME.lower(),
                          self.dns_domain.lower(),
                          USER_PASS,
                          digests.hashes[9 - 1].hash)
        self.check_digest(USER_NAME.upper(),
                          self.dns_domain.upper(),
                          USER_PASS,
                          digests.hashes[10 - 1].hash)
        self.check_digest(USER_NAME,
                          self.dns_domain.upper(),
                          USER_PASS,
                          digests.hashes[11 - 1].hash)
        self.check_digest(USER_NAME,
                          self.dns_domain.lower(),
                          USER_PASS,
                          digests.hashes[12 - 1].hash)
        self.check_digest(USER_NAME.upper(),
                          self.dns_domain.lower(),
                          USER_PASS,
                          digests.hashes[13 - 1].hash)
        self.check_digest(USER_NAME.lower(),
                          self.dns_domain.upper(),
                          USER_PASS,
                          digests.hashes[14 - 1].hash)
        self.check_digest(UPN,
                          "",
                          USER_PASS,
                          digests.hashes[15 - 1].hash)
        self.check_digest(UPN.lower(),
                          "",
                          USER_PASS,
                          digests.hashes[16 - 1].hash)
        self.check_digest(UPN.upper(),
                          "",
                          USER_PASS,
                          digests.hashes[17 - 1].hash)

        name = "%s\\%s" % (self.netbios_domain, USER_NAME)
        self.check_digest(name,
                          "",
                          USER_PASS,
                          digests.hashes[18 - 1].hash)

        name = "%s\\%s" % (self.netbios_domain.lower(), USER_NAME.lower())
        self.check_digest(name,
                          "",
                          USER_PASS,
                          digests.hashes[19 - 1].hash)

        name = "%s\\%s" % (self.netbios_domain.upper(), USER_NAME.upper())
        self.check_digest(name,
                          "",
                          USER_PASS,
                          digests.hashes[20 - 1].hash)
        self.check_digest(USER_NAME,
                          "Digest",
                          USER_PASS,
                          digests.hashes[21 - 1].hash)
        self.check_digest(USER_NAME.lower(),
                          "Digest",
                          USER_PASS,
                          digests.hashes[22 - 1].hash)
        self.check_digest(USER_NAME.upper(),
                          "Digest",
                          USER_PASS,
                          digests.hashes[23 - 1].hash)
        self.check_digest(UPN,
                          "Digest",
                          USER_PASS,
                          digests.hashes[24 - 1].hash)
        self.check_digest(UPN.lower(),
                          "Digest",
                          USER_PASS,
                          digests.hashes[25 - 1].hash)
        self.check_digest(UPN.upper(),
                          "Digest",
                          USER_PASS,
                          digests.hashes[26 - 1].hash)
        name = "%s\\%s" % (self.netbios_domain, USER_NAME)
        self.check_digest(name,
                          "Digest",
                          USER_PASS,
                          digests.hashes[27 - 1].hash)

        name = "%s\\%s" % (self.netbios_domain.lower(), USER_NAME.lower())
        self.check_digest(name,
                          "Digest",
                          USER_PASS,
                          digests.hashes[28 - 1].hash)

        name = "%s\\%s" % (self.netbios_domain.upper(), USER_NAME.upper())
        self.check_digest(name,
                          "Digest",
                          USER_PASS,
                          digests.hashes[29 - 1].hash)

    def checkUserPassword(self, up, expected):

        # Check we've received the correct number of hashes
        self.assertEqual(len(expected), up.num_hashes)

        i = 0
        for (tag, alg, rounds) in expected:
            self.assertEqual(tag, up.hashes[i].scheme)

            data = up.hashes[i].value.decode('utf8').split("$")
            # Check we got the expected crypt algorithm
            self.assertEqual(alg, data[1])

            if rounds is None:
                cmd = "$%s$%s" % (alg, data[2])
            else:
                cmd = "$%s$rounds=%d$%s" % (alg, rounds, data[3])

            # Calculate the expected hash value
            expected = crypt.crypt(USER_PASS, cmd)
            self.assertEqual(expected, up.hashes[i].value.decode('utf8'))
            i += 1

    # Check that the correct nt_hash was stored for userPassword
    def checkNtHash(self, password, nt_hash):
        creds = Credentials()
        creds.set_anonymous()
        creds.set_password(password)
        expected = creds.get_nt_hash()
        actual = bytearray(nt_hash)
        self.assertEqual(expected, actual)
