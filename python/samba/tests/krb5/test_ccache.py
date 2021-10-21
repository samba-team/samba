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

from ldb import SCOPE_SUBTREE
from samba import gensec
from samba.auth import AuthContext
from samba.dcerpc import security
from samba.ndr import ndr_unpack

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
        # Create a user account and a machine account, along with a Kerberos
        # credentials cache file where the service ticket authenticating the
        # user are stored.

        user_name = "ccacheusr"
        mach_name = "ccachemac"
        service = "host"

        samdb = self.get_samdb()

        # Create the user account.
        (user_credentials, _) = self.create_account(samdb, user_name)

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
                                                          mach_credentials)

        # Authenticate in-process to the machine account using the user's
        # cached credentials.

        lp = self.get_lp()

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

        # Retrieve the user account's SID.
        ldb_res = samdb.search(scope=SCOPE_SUBTREE,
                               expression="(sAMAccountName=%s)" % user_name,
                               attrs=["objectSid"])
        self.assertEqual(1, len(ldb_res))
        sid = ndr_unpack(security.dom_sid, ldb_res[0]["objectSid"][0])

        # Retrieve the SIDs from the security token.
        session = gensec_server.session_info()
        token = session.security_token
        token_sids = token.sids
        self.assertGreater(len(token_sids), 0)

        # Ensure that they match.
        self.assertEqual(sid, token_sids[0])

        # Remove the cached credentials file.
        os.remove(cachefile.name)


if __name__ == "__main__":
    global_asn1_print = False
    global_hexdump = False
    import unittest
    unittest.main()
