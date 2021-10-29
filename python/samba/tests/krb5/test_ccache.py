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

import ldb

from ldb import SCOPE_SUBTREE
from samba import NTSTATUSError, gensec
from samba.auth import AuthContext
from samba.dcerpc import security
from samba.ndr import ndr_unpack
from samba.ntstatus import NT_STATUS_NO_IMPERSONATION_TOKEN

from samba.tests.krb5.kdc_base_test import KDCBaseTest

sys.path.insert(0, "bin/python")
os.environ["PYTHONUNBUFFERED"] = "1"

global_asn1_print = False
global_hexdump = False


class CcacheTests(KDCBaseTest):
    """Test for authentication using Kerberos credentials stored in a
       credentials cache file.
    """

    def test_ccache(self):
        self._run_ccache_test()

    def test_ccache_rename(self):
        self._run_ccache_test(rename=True)

    def test_ccache_no_pac(self):
        self._run_ccache_test(include_pac=False,
                              expect_anon=True, allow_error=True)

    def _run_ccache_test(self, rename=False, include_pac=True,
                         expect_anon=False, allow_error=False):
        # Create a user account and a machine account, along with a Kerberos
        # credentials cache file where the service ticket authenticating the
        # user are stored.

        mach_name = "ccachemac"
        service = "host"

        samdb = self.get_samdb()

        # Create the user account.
        user_credentials = self.get_cached_creds(
            account_type=self.AccountType.USER,
            use_cache=False)
        user_name = user_credentials.get_username()

        # Create the machine account.
        (mach_credentials, _) = self.create_account(
            samdb,
            mach_name,
            account_type=self.AccountType.COMPUTER,
            spn="%s/%s" % (service,
                           mach_name))

        # Talk to the KDC to obtain the service ticket, which gets placed into
        # the cache. The machine account name has to match the name in the
        # ticket, to ensure that the krbtgt ticket doesn't also need to be
        # stored.
        (creds, cachefile) = self.create_ccache_with_user(user_credentials,
                                                          mach_credentials,
                                                          pac=include_pac)
        # Remove the cached credentials file.
        self.addCleanup(os.remove, cachefile.name)

        # Retrieve the user account's SID.
        ldb_res = samdb.search(scope=SCOPE_SUBTREE,
                               expression="(sAMAccountName=%s)" % user_name,
                               attrs=["objectSid"])
        self.assertEqual(1, len(ldb_res))
        sid = ndr_unpack(security.dom_sid, ldb_res[0]["objectSid"][0])

        if rename:
            # Rename the account.

            new_name = self.get_new_username()

            msg = ldb.Message(user_credentials.get_dn())
            msg['sAMAccountName'] = ldb.MessageElement(new_name,
                                                       ldb.FLAG_MOD_REPLACE,
                                                       'sAMAccountName')
            samdb.modify(msg)

        # Authenticate in-process to the machine account using the user's
        # cached credentials.

        lp = self.get_lp()
        lp.set('server role', 'active directory domain controller')

        settings = {}
        settings["lp_ctx"] = lp
        settings["target_hostname"] = mach_name

        gensec_client = gensec.Security.start_client(settings)
        gensec_client.set_credentials(creds)
        gensec_client.want_feature(gensec.FEATURE_SEAL)
        gensec_client.start_mech_by_sasl_name("GSSAPI")

        auth_context = AuthContext(lp_ctx=lp, ldb=samdb, methods=[])

        gensec_server = gensec.Security.start_server(settings, auth_context)
        gensec_server.set_credentials(mach_credentials)

        gensec_server.start_mech_by_sasl_name("GSSAPI")

        client_finished = False
        server_finished = False
        server_to_client = b''

        # Operate as both the client and the server to verify the user's
        # credentials.
        while not client_finished or not server_finished:
            if not client_finished:
                print("running client gensec_update")
                (client_finished, client_to_server) = gensec_client.update(
                    server_to_client)
            if not server_finished:
                print("running server gensec_update")
                (server_finished, server_to_client) = gensec_server.update(
                    client_to_server)

        # Ensure that the first SID contained within the obtained security
        # token is the SID of the user we created.

        # Retrieve the SIDs from the security token.
        try:
            session = gensec_server.session_info()
        except NTSTATUSError as e:
            if not allow_error:
                self.fail()

            enum, _ = e.args
            self.assertEqual(NT_STATUS_NO_IMPERSONATION_TOKEN, enum)
            return

        token = session.security_token
        token_sids = token.sids
        self.assertGreater(len(token_sids), 0)

        # Ensure that they match.
        self.assertEqual(sid, token_sids[0])


if __name__ == "__main__":
    global_asn1_print = False
    global_hexdump = False
    import unittest
    unittest.main()
