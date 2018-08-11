# Tests for the samba-tool user sub command reading Primary:WDigest
#
# Copyright (C) Andrew Bartlett <abartlet@samba.org> 2017
#
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
from samba import (
        credentials,
        nttime2unix,
        dsdb
        )
from samba.ndr import ndr_unpack
from samba.dcerpc import drsblobs
from hashlib import md5
import random
import string
from samba.compat import text_type

USER_NAME = "WdigestTestUser"
# Create a random 32 character password, containing only letters and
# digits to avoid issues when used on the command line.
USER_PASS = ''.join(random.choice(string.ascii_uppercase +
                                  string.ascii_lowercase +
                                  string.digits) for _ in range(32))

# Calculate the MD5 password digest from the supplied user, realm and password
#


def calc_digest(user, realm, password):
    data = "%s:%s:%s" % (user, realm, password)
    if isinstance(data, text_type):
        data = data.encode('utf8')

    return "%s:%s:%s" % (user, realm, md5(data).hexdigest())


class UserCmdWdigestTestCase(SambaToolCmdTest):
    """Tests for samba-tool user subcommands extraction of the wdigest values
       Test results validated against Windows Server 2012 R2.
       NOTE: That as at 22-05-2017 the values Documented at
             3.1.1.8.11.3.1 WDIGEST_CREDENTIALS Construction
             are incorrect.
    """
    users = []
    samdb = None

    def setUp(self):
        super(UserCmdWdigestTestCase, self).setUp()
        self.lp = samba.tests.env_loadparm()
        self.samdb = self.getSamDB(
            "-H", "ldap://%s" % os.environ["DC_SERVER"],
            "-U%s%%%s" % (os.environ["DC_USERNAME"],
                          os.environ["DC_PASSWORD"]))
        self.dns_domain = self.samdb.domain_dns_name()
        res = self.samdb.search(
            base=self.samdb.get_config_basedn(),
            expression="ncName=%s" % self.samdb.get_default_basedn(),
            attrs=["nETBIOSName"])
        self.netbios_domain = str(res[0]["nETBIOSName"][0])
        self.runsubcmd("user",
                       "create",
                       USER_NAME,
                       USER_PASS,
                       "-H",
                       "ldap://%s" % os.environ["DC_SERVER"],
                       "-U%s%%%s" % (
                            os.environ["DC_USERNAME"],
                            os.environ["DC_PASSWORD"]))

    def tearDown(self):
        super(UserCmdWdigestTestCase, self).tearDown()
        self.runsubcmd("user", "delete", USER_NAME)

    def _testWDigest(self, attribute, expected, missing=False):

        (result, out, err) = self.runsubcmd("user",
                                            "getpassword",
                                            USER_NAME,
                                            "--attributes",
                                            attribute)
        self.assertCmdSuccess(result,
                              out,
                              err,
                              "Ensure getpassword runs")
        self.assertEqual(err, "", "getpassword")
        self.assertMatch(out,
                         "Got password OK",
                         "getpassword out[%s]" % out)

        if missing:
            self.assertTrue(attribute not in out)
        else:
            self.assertMatch(out.replace('\n ', ''),
                             "%s: %s" % (attribute, expected))

    def test_Wdigest_no_suffix(self):
        attribute = "virtualWDigest"
        self._testWDigest(attribute, None, True)

    def test_Wdigest_non_numeric_suffix(self):
        attribute = "virtualWDigestss"
        self._testWDigest(attribute, None, True)

    def test_Wdigest00(self):
        attribute = "virtualWDigest00"
        self._testWDigest(attribute, None, True)

    # Hash01  MD5(sAMAccountName,
    #            NETBIOSDomainName,
    #            password)
    #
    def test_Wdigest01(self):
        attribute = "virtualWDigest01"
        expected = calc_digest(USER_NAME,
                               self.netbios_domain,
                               USER_PASS)
        self._testWDigest(attribute, expected)

    # Hash02 MD5(LOWER(sAMAccountName),
    #            LOWER(NETBIOSDomainName),
    #            password)
    #
    def test_Wdigest02(self):
        attribute = "virtualWDigest02"
        expected = calc_digest(USER_NAME.lower(),
                               self.netbios_domain.lower(),
                               USER_PASS)
        self._testWDigest(attribute, expected)

    # Hash03 MD5(UPPER(sAMAccountName),
    #            UPPER(NETBIOSDomainName),
    #            password)
    #
    def test_Wdigest03(self):
        attribute = "virtualWDigest03"
        expected = calc_digest(USER_NAME.upper(),
                               self.netbios_domain.upper(),
                               USER_PASS)
        self._testWDigest(attribute, expected)

    # Hash04 MD5(sAMAccountName,
    #            UPPER(NETBIOSDomainName),
    #            password)
    #
    def test_Wdigest04(self):
        attribute = "virtualWDigest04"
        expected = calc_digest(USER_NAME,
                               self.netbios_domain.upper(),
                               USER_PASS)
        self._testWDigest(attribute, expected)

    # Hash05 MD5(sAMAccountName,
    #            LOWER(NETBIOSDomainName),
    #            password)
    #
    def test_Wdigest05(self):
        attribute = "virtualWDigest05"
        expected = calc_digest(USER_NAME,
                               self.netbios_domain.lower(),
                               USER_PASS)
        self._testWDigest(attribute, expected)

    # Hash06 MD5(UPPER(sAMAccountName),
    #            LOWER(NETBIOSDomainName),
    #            password)
    #
    def test_Wdigest06(self):
        attribute = "virtualWDigest06"
        expected = calc_digest(USER_NAME.upper(),
                               self.netbios_domain.lower(),
                               USER_PASS)
        self._testWDigest(attribute, expected)

    # Hash07 MD5(LOWER(sAMAccountName),
    #            UPPER(NETBIOSDomainName),
    #            password)
    #
    def test_Wdigest07(self):
        attribute = "virtualWDigest07"
        expected = calc_digest(USER_NAME.lower(),
                               self.netbios_domain.upper(),
                               USER_PASS)
        self._testWDigest(attribute, expected)

    # Hash08 MD5(sAMAccountName,
    #            DNSDomainName,
    #            password)
    #
    # Note: Samba lowercases the DNSDomainName at provision time,
    #       Windows preserves the case. This means that the WDigest08 values
    #       calculated byt Samba and Windows differ.
    #
    def test_Wdigest08(self):
        attribute = "virtualWDigest08"
        expected = calc_digest(USER_NAME,
                               self.dns_domain,
                               USER_PASS)
        self._testWDigest(attribute, expected)

    # Hash09 MD5(LOWER(sAMAccountName),
    #            LOWER(DNSDomainName),
    #            password)
    #
    def test_Wdigest09(self):
        attribute = "virtualWDigest09"
        expected = calc_digest(USER_NAME.lower(),
                               self.dns_domain.lower(),
                               USER_PASS)
        self._testWDigest(attribute, expected)

    # Hash10 MD5(UPPER(sAMAccountName),
    #            UPPER(DNSDomainName),
    #            password)
    #
    def test_Wdigest10(self):
        attribute = "virtualWDigest10"
        expected = calc_digest(USER_NAME.upper(),
                               self.dns_domain.upper(),
                               USER_PASS)
        self._testWDigest(attribute, expected)

    # Hash11 MD5(sAMAccountName,
    #            UPPER(DNSDomainName),
    #            password)
    #
    def test_Wdigest11(self):
        attribute = "virtualWDigest11"
        expected = calc_digest(USER_NAME,
                               self.dns_domain.upper(),
                               USER_PASS)
        self._testWDigest(attribute, expected)

    # Hash12 MD5(sAMAccountName,
    #            LOWER(DNSDomainName),
    #            password)
    #
    def test_Wdigest12(self):
        attribute = "virtualWDigest12"
        expected = calc_digest(USER_NAME,
                               self.dns_domain.lower(),
                               USER_PASS)
        self._testWDigest(attribute, expected)

    # Hash13 MD5(UPPER(sAMAccountName),
    #            LOWER(DNSDomainName),
    #            password)
    #
    def test_Wdigest13(self):
        attribute = "virtualWDigest13"
        expected = calc_digest(USER_NAME.upper(),
                               self.dns_domain.lower(),
                               USER_PASS)
        self._testWDigest(attribute, expected)

    # Hash14 MD5(LOWER(sAMAccountName),
    #            UPPER(DNSDomainName),
    #            password)
    #

    def test_Wdigest14(self):
        attribute = "virtualWDigest14"
        expected = calc_digest(USER_NAME.lower(),
                               self.dns_domain.upper(),
                               USER_PASS)
        self._testWDigest(attribute, expected)

    # Hash15 MD5(userPrincipalName,
    #            password)
    #
    def test_Wdigest15(self):
        attribute = "virtualWDigest15"
        name = "%s@%s" % (USER_NAME, self.dns_domain)
        expected = calc_digest(name,
                               "",
                               USER_PASS)
        self._testWDigest(attribute, expected)

    # Hash16 MD5(LOWER(userPrincipalName),
    #            password)
    #
    def test_Wdigest16(self):
        attribute = "virtualWDigest16"
        name = "%s@%s" % (USER_NAME.lower(), self.dns_domain.lower())
        expected = calc_digest(name,
                               "",
                               USER_PASS)
        self._testWDigest(attribute, expected)

    # Hash17 MD5(UPPER(userPrincipalName),
    #            password)
    #
    def test_Wdigest17(self):
        attribute = "virtualWDigest17"
        name = "%s@%s" % (USER_NAME.upper(), self.dns_domain.upper())
        expected = calc_digest(name,
                               "",
                               USER_PASS)
        self._testWDigest(attribute, expected)

    # Hash18 MD5(NETBIOSDomainName\sAMAccountName,
    #            password)
    #
    def test_Wdigest18(self):
        attribute = "virtualWDigest18"
        name = "%s\\%s" % (self.netbios_domain, USER_NAME)
        expected = calc_digest(name,
                               "",
                               USER_PASS)
        self._testWDigest(attribute, expected)

    # Hash19 MD5(LOWER(NETBIOSDomainName\sAMAccountName),
    #            password)
    #
    def test_Wdigest19(self):
        attribute = "virtualWDigest19"
        name = "%s\\%s" % (self.netbios_domain, USER_NAME)
        expected = calc_digest(name.lower(),
                               "",
                               USER_PASS)
        self._testWDigest(attribute, expected)

    # Hash20 MD5(UPPER(NETBIOSDomainName\sAMAccountName),
    #            password)
    #
    def test_Wdigest20(self):
        attribute = "virtualWDigest20"
        name = "%s\\%s" % (self.netbios_domain, USER_NAME)
        expected = calc_digest(name.upper(),
                               "",
                               USER_PASS)
        self._testWDigest(attribute, expected)

    # Hash21 MD5(sAMAccountName,
    #            "Digest",
    #            password)
    #
    def test_Wdigest21(self):
        attribute = "virtualWDigest21"
        expected = calc_digest(USER_NAME,
                               "Digest",
                               USER_PASS)
        self._testWDigest(attribute, expected)

    # Hash22 MD5(LOWER(sAMAccountName),
    #            "Digest",
    #            password)
    #
    def test_Wdigest22(self):
        attribute = "virtualWDigest22"
        expected = calc_digest(USER_NAME.lower(),
                               "Digest",
                               USER_PASS)
        self._testWDigest(attribute, expected)

    # Hash23 MD5(UPPER(sAMAccountName),
    #            "Digest",
    #            password)
    #
    def test_Wdigest23(self):
        attribute = "virtualWDigest23"
        expected = calc_digest(USER_NAME.upper(),
                               "Digest",
                               USER_PASS)
        self._testWDigest(attribute, expected)

    # Hash24  MD5(userPrincipalName),
    #             "Digest",
    #              password)
    #
    def test_Wdigest24(self):
        attribute = "virtualWDigest24"
        name = "%s@%s" % (USER_NAME, self.dns_domain)
        expected = calc_digest(name,
                               "Digest",
                               USER_PASS)
        self._testWDigest(attribute, expected)

    # Hash25 MD5(LOWER(userPrincipalName),
    #            "Digest",
    #            password)
    #
    def test_Wdigest25(self):
        attribute = "virtualWDigest25"
        name = "%s@%s" % (USER_NAME, self.dns_domain.lower())
        expected = calc_digest(name.lower(),
                               "Digest",
                               USER_PASS)
        self._testWDigest(attribute, expected)

    # Hash26 MD5(UPPER(userPrincipalName),
    #            "Digest",
    #             password)
    #
    def test_Wdigest26(self):
        attribute = "virtualWDigest26"
        name = "%s@%s" % (USER_NAME, self.dns_domain.lower())
        expected = calc_digest(name.upper(),
                               "Digest",
                               USER_PASS)
        self._testWDigest(attribute, expected)
    # Hash27 MD5(NETBIOSDomainName\sAMAccountName,
    #            "Digest",
    #            password)
    #

    def test_Wdigest27(self):
        attribute = "virtualWDigest27"
        name = "%s\\%s" % (self.netbios_domain, USER_NAME)
        expected = calc_digest(name,
                               "Digest",
                               USER_PASS)
        self._testWDigest(attribute, expected)

    # Hash28 MD5(LOWER(NETBIOSDomainName\sAMAccountName),
    #            "Digest",
    #            password)
    #
    def test_Wdigest28(self):
        attribute = "virtualWDigest28"
        name = "%s\\%s" % (self.netbios_domain.lower(), USER_NAME.lower())
        expected = calc_digest(name,
                               "Digest",
                               USER_PASS)
        self._testWDigest(attribute, expected)

    # Hash29 MD5(UPPER(NETBIOSDomainName\sAMAccountName),
    #            "Digest",
    #             password)
    #
    def test_Wdigest29(self):
        attribute = "virtualWDigest29"
        name = "%s\\%s" % (self.netbios_domain.upper(), USER_NAME.upper())
        expected = calc_digest(name,
                               "Digest",
                               USER_PASS)
        self._testWDigest(attribute, expected)

    def test_Wdigest30(self):
        attribute = "virtualWDigest30"
        self._testWDigest(attribute, None, True)

    # Check digest calculation against an known htdigest value
    def test_calc_digest(self):
        htdigest = "gary:fred:2204fcc247cb47ded249ef2fe0013255"
        digest = calc_digest("gary", "fred", "password")
        self.assertEqual(htdigest, digest)
