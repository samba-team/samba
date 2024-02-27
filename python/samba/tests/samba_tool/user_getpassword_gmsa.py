# Unix SMB/CIFS implementation.
#
# Blackbox tests for reading Group Managed Service Account passwords
#
# Copyright (C) Catalyst.Net Ltd. 2023
#
# Written by Rob van der Linde <rob@catalyst.net.nz>
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

import sys
import os

sys.path.insert(0, "bin/python")
os.environ["PYTHONUNBUFFERED"] = "1"

import datetime, shlex

from ldb import SCOPE_BASE

from samba.credentials import MUST_USE_KERBEROS
from samba.dcerpc import security, samr
from samba.dsdb import UF_WORKSTATION_TRUST_ACCOUNT
from samba.netcmd.domain.models import User
from samba.ndr import ndr_pack, ndr_unpack
from samba.nt_time import nt_time_from_datetime
from samba.tests import connect_samdb, connect_samdb_env, delete_force

from samba.tests import BlackboxTestCase

DC_SERVER = os.environ["SERVER"]
SERVER = os.environ["SERVER"]
SERVER_USERNAME = os.environ["USERNAME"]
SERVER_PASSWORD = os.environ["PASSWORD"]

HOST = f"ldap://{SERVER}"
CREDS = f"-U{SERVER_USERNAME}%{SERVER_PASSWORD}"


class GMSAPasswordTest(BlackboxTestCase):
    """Blackbox tests for GMSA getpassword and connecting as that user."""

    @classmethod
    def setUpClass(cls):
        cls.lp = cls.get_loadparm()
        cls.env_creds = cls.get_env_credentials(lp=cls.lp,
                                                env_username="USERNAME",
                                                env_password="PASSWORD",
                                                env_domain="DOMAIN",
                                                env_realm="REALM")
        cls.samdb = connect_samdb(HOST, lp=cls.lp, credentials=cls.env_creds)
        super().setUpClass()

    @classmethod
    def setUpTestData(cls):
        cls.username = "GMSA_Test_User$"
        cls.base_dn = f"CN=Managed Service Accounts,{cls.samdb.domain_dn()}"
        cls.user_dn = f"CN={cls.username},{cls.base_dn}"

        msg = cls.samdb.search(base="", scope=SCOPE_BASE, attrs=["tokenGroups"])[0]
        connecting_user_sid = str(ndr_unpack(security.dom_sid, msg["tokenGroups"][0]))

        domain_sid = security.dom_sid(cls.samdb.get_domain_sid())
        allow_sddl = f"O:SYD:(A;;RP;;;{connecting_user_sid})"
        allow_sd = ndr_pack(security.descriptor.from_sddl(allow_sddl, domain_sid))

        details = {
            "dn": str(cls.user_dn),
            "objectClass": "msDS-GroupManagedServiceAccount",
            "msDS-ManagedPasswordInterval": "1",
            "msDS-GroupMSAMembership": allow_sd,
            "sAMAccountName": cls.username,
            "userAccountControl": str(UF_WORKSTATION_TRUST_ACCOUNT),
        }

        cls.samdb.add(details)
        cls.addClassCleanup(delete_force, cls.samdb, cls.user_dn)

        cls.user = User.get(cls.samdb, account_name=cls.username)

    def getpassword(self, attrs):
        shattrs = shlex.quote(attrs)
        cmd = f"user getpassword --attributes={shattrs} {self.username}"

        ldif = self.check_output(cmd).decode()
        res = self.samdb.parse_ldif(ldif)
        _, user_message = next(res)

        # check each attr is returned
        for attr in attrs.split(","):
            self.assertIn(attr, user_message)

        return user_message

    def test_getpassword(self):
        self.getpassword("virtualClearTextUTF16,unicodePwd")
        self.getpassword("virtualClearTextUTF16")
        self.getpassword("unicodePwd")

    def test_utf16_password(self):
        user_msg = self.getpassword("virtualClearTextUTF16")
        password = user_msg["virtualClearTextUTF16"][0]

        creds = self.insta_creds(template=self.env_creds)
        creds.set_username(self.username)
        creds.set_utf16_password(password)
        db = connect_samdb(HOST, credentials=creds, lp=self.lp)

        msg = db.search(base="", scope=SCOPE_BASE, attrs=["tokenGroups"])[0]
        connecting_user_sid = str(ndr_unpack(security.dom_sid, msg["tokenGroups"][0]))

        self.assertEqual(self.user.object_sid, connecting_user_sid)

    def test_utf8_password(self):
        user_msg = self.getpassword("virtualClearTextUTF8")
        password = str(user_msg["virtualClearTextUTF8"][0])

        creds = self.insta_creds(template=self.env_creds)
        # Because the password has been converted to utf-8 via UTF16_MUNGED
        # the nthash is no longer valid. We need to use AES kerberos ciphers
        # for this to work.
        creds.set_kerberos_state(MUST_USE_KERBEROS)
        creds.set_username(self.username)
        creds.set_password(password)
        db = connect_samdb(HOST, credentials=creds, lp=self.lp)

        msg = db.search(base="", scope=SCOPE_BASE, attrs=["tokenGroups"])[0]
        connecting_user_sid = str(ndr_unpack(security.dom_sid, msg["tokenGroups"][0]))

        self.assertEqual(self.user.object_sid, connecting_user_sid)

    def test_unicode_pwd(self):
        user_msg = self.getpassword("unicodePwd")

        creds = self.insta_creds(template=self.env_creds)
        creds.set_username(self.username)
        nt_pass = samr.Password()
        nt_pass.hash = list(user_msg["unicodePwd"][0])
        creds.set_nt_hash(nt_pass)
        db = connect_samdb(HOST, credentials=creds, lp=self.lp)

        msg = db.search(base="", scope=SCOPE_BASE, attrs=["tokenGroups"])[0]
        connecting_user_sid = str(ndr_unpack(security.dom_sid, msg["tokenGroups"][0]))

        self.assertEqual(self.user.object_sid, connecting_user_sid)

    def test_querytime(self):
        user_msg = self.getpassword("virtualManagedPasswordQueryTime")
        querytime = int(user_msg["virtualManagedPasswordQueryTime"][0])

        # Just assert the number makes sense
        self.assertGreater(querytime, nt_time_from_datetime(datetime.datetime.now(tz=datetime.timezone.utc)))
        self.assertLess(querytime, nt_time_from_datetime(datetime.datetime.now(tz=datetime.timezone.utc) + datetime.timedelta(hours = 21)))

    def test_querytime_unixtime(self):
        user_msg = self.getpassword("virtualManagedPasswordQueryTime;format=UnixTime")
        querytime = int(user_msg["virtualManagedPasswordQueryTime;format=UnixTime"][0])

        # Just assert the number makes sense
        self.assertGreater(querytime, datetime.datetime.now(tz=datetime.timezone.utc).timestamp())
        self.assertLess(querytime, (datetime.datetime.now(tz=datetime.timezone.utc) + datetime.timedelta(hours = 21)).timestamp())

    @classmethod
    def _make_cmdline(cls, line):
        """Override to pass line as samba-tool subcommand instead.

        Automatically fills in HOST and CREDS as well.
        """
        if isinstance(line, list):
            cmd = ["samba-tool"] + line + ["-H", SERVER, CREDS]
        else:
            cmd = f"samba-tool {line} -H {HOST} {CREDS}"

        return super()._make_cmdline(cmd)


if __name__ == "__main__":
    import unittest
    unittest.main()
