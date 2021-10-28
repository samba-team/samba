#!/usr/bin/env python3
# Unix SMB/CIFS implementation.
# Copyright (C) Stefan Metzmacher 2020
# Copyright (C) 2021 Catalyst.Net Ltd
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

from ldb import LdbError, ERR_OPERATIONS_ERROR, SCOPE_BASE, SCOPE_SUBTREE
from samba.dcerpc import security
from samba.ndr import ndr_unpack
from samba.samdb import SamDB
from samba import credentials

from samba.tests.krb5.kdc_base_test import KDCBaseTest

sys.path.insert(0, "bin/python")
os.environ["PYTHONUNBUFFERED"] = "1"

global_asn1_print = False
global_hexdump = False


class LdapTests(KDCBaseTest):
    """Test for LDAP authentication using Kerberos credentials stored in a
       credentials cache file.
    """

    def test_ldap(self):
        self._run_ldap_test("ldapusr")

    def test_ldap_no_pac(self):
        self._run_ldap_test("ldapusr_nopac", include_pac=False,
                            expect_anon=True, allow_error=True)

    def _run_ldap_test(self, user_name, include_pac=True,
                       expect_anon=False, allow_error=False):
        # Create a user account and a machine account, along with a Kerberos
        # credentials cache file where the service ticket authenticating the
        # user are stored.

        samdb = self.get_samdb()

        mach_name = samdb.host_dns_name()
        service = "ldap"

        # Create the user account.
        (user_credentials, _) = self.create_account(samdb, user_name)

        mach_credentials = self.get_dc_creds()

        # Talk to the KDC to obtain the service ticket, which gets placed into
        # the cache. The machine account name has to match the name in the
        # ticket, to ensure that the krbtgt ticket doesn't also need to be
        # stored.
        (creds, cachefile) = self.create_ccache_with_user(user_credentials,
                                                          mach_credentials,
                                                          service,
                                                          mach_name,
                                                          pac=include_pac)
        # Remove the cached credentials file.
        self.addCleanup(os.remove, cachefile.name)

        # Authenticate in-process to the machine account using the user's
        # cached credentials.

        # Retrieve the user account's SID.
        ldb_res = samdb.search(scope=SCOPE_SUBTREE,
                               expression="(sAMAccountName=%s)" % user_name,
                               attrs=["objectSid"])
        self.assertEqual(1, len(ldb_res))
        sid = ndr_unpack(security.dom_sid, ldb_res[0]["objectSid"][0])

        # Connect to the machine account and retrieve the user SID.
        try:
            ldb_as_user = SamDB(url="ldap://%s" % mach_name,
                                credentials=creds,
                                lp=self.get_lp())
        except LdbError as e:
            if not allow_error:
                self.fail()

            enum, estr = e.args
            self.assertEqual(ERR_OPERATIONS_ERROR, enum)
            self.assertIn('NT_STATUS_NO_IMPERSONATION_TOKEN', estr)
            return

        ldb_res = ldb_as_user.search('',
                                     scope=SCOPE_BASE,
                                     attrs=["tokenGroups"])
        self.assertEqual(1, len(ldb_res))

        token_groups = ldb_res[0]["tokenGroups"]
        token_sid = ndr_unpack(security.dom_sid, token_groups[0])

        if expect_anon:
            # Ensure we got an anonymous token.
            self.assertEqual(security.SID_NT_ANONYMOUS, str(token_sid))
            token_sid = ndr_unpack(security.dom_sid, token_groups[1])
            self.assertEqual(security.SID_NT_NETWORK, str(token_sid))
            if len(token_groups) >= 3:
                token_sid = ndr_unpack(security.dom_sid, token_groups[2])
                self.assertEqual(security.SID_NT_THIS_ORGANISATION,
                                 str(token_sid))
        else:
            # Ensure that they match.
            self.assertEqual(sid, token_sid)

    def test_ldap_anonymous(self):
        samdb = self.get_samdb()
        mach_name = samdb.host_dns_name()

        anon_creds = credentials.Credentials()
        anon_creds.set_anonymous()

        # Connect to the machine account and retrieve the user SID.
        ldb_as_user = SamDB(url="ldap://%s" % mach_name,
                            credentials=anon_creds,
                            lp=self.get_lp())
        ldb_res = ldb_as_user.search('',
                                     scope=SCOPE_BASE,
                                     attrs=["tokenGroups"])
        self.assertEqual(1, len(ldb_res))

        # Ensure we got an anonymous token.
        token_sid = ndr_unpack(security.dom_sid, ldb_res[0]["tokenGroups"][0])
        self.assertEqual(security.SID_NT_ANONYMOUS, str(token_sid))
        self.assertEqual(len(ldb_res[0]["tokenGroups"]), 1)


if __name__ == "__main__":
    global_asn1_print = False
    global_hexdump = False
    import unittest
    unittest.main()
