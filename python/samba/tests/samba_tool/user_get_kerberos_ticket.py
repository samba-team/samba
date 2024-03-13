# Unix SMB/CIFS implementation.
#
# Blackbox tests for getting Kerberos tickets from Group Managed Service Account and other (local) passwords
#
# Copyright (C) Catalyst.Net Ltd. 2023
#
# Written by Rob van der Linde <rob@catalyst.net.nz>
#
# Copyright Andrew Bartlett <abartlet@samba.org> 2023
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
import sys

sys.path.insert(0, "bin/python")
os.environ["PYTHONUNBUFFERED"] = "1"

from ldb import SCOPE_BASE

from samba import credentials
from samba.credentials import MUST_USE_KERBEROS
from samba.dcerpc import security
from samba.domain.models import User
from samba.dsdb import UF_NORMAL_ACCOUNT, UF_WORKSTATION_TRUST_ACCOUNT
from samba.ndr import ndr_pack, ndr_unpack
from samba.tests import (BlackboxProcessError, BlackboxTestCase, connect_samdb,
                         delete_force)

# If not specified, this is None, meaning local sam.ldb
PW_READ_URL = os.environ.get("PW_READ_URL")

# We still need to connect to a remote server to check we got the ticket
SERVER = os.environ.get("SERVER")

PW_CHECK_URL = f"ldap://{SERVER}"

# For authentication to PW_READ_URL if required
SERVER_USERNAME = os.environ["USERNAME"]
SERVER_PASSWORD = os.environ["PASSWORD"]

CREDS = f"-U{SERVER_USERNAME}%{SERVER_PASSWORD}"


class GetKerberosTicketTest(BlackboxTestCase):
    """Blackbox tests for GMSA getpassword and connecting as that user."""

    @classmethod
    def setUpClass(cls):
        cls.lp = cls.get_loadparm()
        cls.env_creds = cls.get_env_credentials(lp=cls.lp,
                                                env_username="USERNAME",
                                                env_password="PASSWORD",
                                                env_domain="DOMAIN",
                                                env_realm="REALM")
        if PW_READ_URL is None:
            url = cls.lp.private_path("sam.ldb")
        else:
            url = PW_CHECK_URL
        cls.samdb = connect_samdb(url, lp=cls.lp, credentials=cls.env_creds)
        super().setUpClass()

    @classmethod
    def setUpTestData(cls):
        cls.gmsa_username = "GMSA_K5Test_User$"
        cls.username = "get-kerberos-ticket-test"
        cls.user_base_dn = f"CN=Users,{cls.samdb.domain_dn()}"
        cls.user_dn = f"CN={cls.username},{cls.user_base_dn}"
        cls.gmsa_base_dn = f"CN=Managed Service Accounts,{cls.samdb.domain_dn()}"
        cls.gmsa_user_dn = f"CN={cls.gmsa_username},{cls.gmsa_base_dn}"

        msg = cls.samdb.search(base="", scope=SCOPE_BASE, attrs=["tokenGroups"])[0]
        connecting_user_sid = str(ndr_unpack(security.dom_sid, msg["tokenGroups"][0]))

        domain_sid = security.dom_sid(cls.samdb.get_domain_sid())
        allow_sddl = f"O:SYD:(A;;RP;;;{connecting_user_sid})"
        allow_sd = ndr_pack(security.descriptor.from_sddl(allow_sddl, domain_sid))

        details = {
            "dn": str(cls.gmsa_user_dn),
            "objectClass": "msDS-GroupManagedServiceAccount",
            "msDS-ManagedPasswordInterval": "1",
            "msDS-GroupMSAMembership": allow_sd,
            "sAMAccountName": cls.gmsa_username,
            "userAccountControl": str(UF_WORKSTATION_TRUST_ACCOUNT),
        }

        cls.samdb.add(details)
        cls.addClassCleanup(delete_force, cls.samdb, cls.gmsa_user_dn)

        user_password = "P@ssw0rd"
        utf16pw = ('"' + user_password + '"').encode('utf-16-le')
        user_details = {
            "dn": str(cls.user_dn),
            "objectClass": "user",
            "sAMAccountName": cls.username,
            "userAccountControl": str(UF_NORMAL_ACCOUNT),
            "unicodePwd": utf16pw
        }

        cls.samdb.add(user_details)
        cls.addClassCleanup(delete_force, cls.samdb, cls.user_dn)

        cls.gmsa_user = User.get(cls.samdb, account_name=cls.gmsa_username)
        cls.user = User.get(cls.samdb, account_name=cls.username)

    def get_ticket(self, username, options=None):
        if options is None:
            options = ""
        ccache_path = f"{self.tempdir}/ccache"
        ccache_location = f"FILE:{ccache_path}"
        cmd = f"user get-kerberos-ticket --output-krb5-ccache={ccache_location} {username} {options}"

        try:
            self.check_output(cmd)
        except BlackboxProcessError as e:
            self.fail(e)
        self.addCleanup(os.unlink, ccache_path)
        return ccache_location

    def test_gmsa_ticket(self):
        # Get a ticket with the tool
        output_ccache = self.get_ticket(self.gmsa_username)
        creds = self.insta_creds(template=self.env_creds)
        creds.set_kerberos_state(MUST_USE_KERBEROS)
        creds.set_named_ccache(output_ccache, credentials.SPECIFIED, self.lp)
        db = connect_samdb(PW_CHECK_URL, credentials=creds, lp=self.lp)
        msg = db.search(base="", scope=SCOPE_BASE, attrs=["tokenGroups"])[0]
        connecting_user_sid = str(ndr_unpack(security.dom_sid, msg["tokenGroups"][0]))

        self.assertEqual(self.gmsa_user.object_sid, connecting_user_sid)

    def test_user_ticket(self):
        output_ccache = self.get_ticket(self.username)
        # Get a ticket with the tool
        creds = self.insta_creds(template=self.env_creds)
        creds.set_kerberos_state(MUST_USE_KERBEROS)

        # Currently this is based on reading the unicodePwd, but this should be expanded
        creds.set_named_ccache(output_ccache, credentials.SPECIFIED, self.lp)

        db = connect_samdb(PW_CHECK_URL, credentials=creds, lp=self.lp)

        msg = db.search(base="", scope=SCOPE_BASE, attrs=["tokenGroups"])[0]
        connecting_user_sid = str(ndr_unpack(security.dom_sid, msg["tokenGroups"][0]))

        self.assertEqual(self.user.object_sid, connecting_user_sid)

    def test_user_ticket_gpg(self):
        output_ccache = self.get_ticket(self.username, "--decrypt-samba-gpg")
        # Get a ticket with the tool
        creds = self.insta_creds(template=self.env_creds)
        creds.set_kerberos_state(MUST_USE_KERBEROS)
        creds.set_named_ccache(output_ccache, credentials.SPECIFIED, self.lp)
        db = connect_samdb(PW_CHECK_URL, credentials=creds, lp=self.lp)

        msg = db.search(base="", scope=SCOPE_BASE, attrs=["tokenGroups"])[0]
        connecting_user_sid = str(ndr_unpack(security.dom_sid, msg["tokenGroups"][0]))

        self.assertEqual(self.user.object_sid, connecting_user_sid)

    @classmethod
    def _make_cmdline(cls, line):
        """Override to pass line as samba-tool subcommand instead.

        Automatically fills in HOST and CREDS as well.
        """
        if isinstance(line, list):
            cmd = ["samba-tool"] + line
            if PW_READ_URL is not None:
                cmd += ["-H", PW_READ_URL, CREDS]
        else:
            cmd = f"samba-tool {line}"
            if PW_READ_URL is not None:
                cmd += "-H {PW_READ_URL} {CREDS}"

        return super()._make_cmdline(cmd)


if __name__ == "__main__":
    import unittest
    unittest.main()
