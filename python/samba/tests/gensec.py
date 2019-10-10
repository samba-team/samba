# Unix SMB/CIFS implementation.
# Copyright (C) Jelmer Vernooij <jelmer@samba.org> 2009
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

"""Tests for GENSEC.

Note that this just tests the bindings work. It does not intend to test
the functionality, that's already done in other tests.
"""

from samba.credentials import Credentials
from samba import gensec, auth
import samba.tests


class GensecTests(samba.tests.TestCase):

    def setUp(self):
        super(GensecTests, self).setUp()
        self.settings = {}
        self.settings["lp_ctx"] = self.lp_ctx = samba.tests.env_loadparm()
        self.settings["target_hostname"] = self.lp_ctx.get("netbios name")
        self.lp_ctx.set("spnego:simulate_w2k", "no")

        """This is just for the API tests"""
        self.gensec = gensec.Security.start_client(self.settings)

    def test_start_mech_by_unknown_name(self):
        self.assertRaises(RuntimeError, self.gensec.start_mech_by_name, "foo")

    def test_start_mech_by_name(self):
        self.gensec.start_mech_by_name("spnego")

    def test_info_uninitialized(self):
        self.assertRaises(RuntimeError, self.gensec.session_info)

    def _test_update(self, mech, client_mech=None, client_only_opt=None):
        """Test GENSEC by doing an exchange with ourselves using GSSAPI against a KDC"""

        """Start up a client and server GENSEC instance to test things with"""

        if client_only_opt:
            orig_client_opt = self.lp_ctx.get(client_only_opt)
            if not orig_client_opt:
                orig_client_opt = ''
            self.lp_ctx.set(client_only_opt, "yes")

        self.gensec_client = gensec.Security.start_client(self.settings)
        self.gensec_client.set_credentials(self.get_credentials())
        self.gensec_client.want_feature(gensec.FEATURE_SEAL)
        if client_mech is not None:
            self.gensec_client.start_mech_by_name(client_mech)
        else:
            self.gensec_client.start_mech_by_sasl_name(mech)

        if client_only_opt:
            self.lp_ctx.set(client_only_opt, "no")

        self.gensec_server = gensec.Security.start_server(settings=self.settings,
                                                          auth_context=auth.AuthContext(lp_ctx=self.lp_ctx))
        creds = Credentials()
        creds.guess(self.lp_ctx)
        creds.set_machine_account(self.lp_ctx)
        self.gensec_server.set_credentials(creds)

        self.gensec_server.want_feature(gensec.FEATURE_SEAL)
        self.gensec_server.start_mech_by_sasl_name(mech)

        client_finished = False
        server_finished = False
        server_to_client = b""
        client_to_server = b""

        """Run the actual call loop"""
        while True:
            if not client_finished:
                if client_only_opt:
                    self.lp_ctx.set(client_only_opt, "yes")
                print("running client gensec_update")
                try:
                    (client_finished, client_to_server) = self.gensec_client.update(server_to_client)
                except samba.NTSTATUSError as nt:
                    raise AssertionError(nt)
                if client_only_opt:
                    self.lp_ctx.set(client_only_opt, "no")
            if not server_finished:
                print("running server gensec_update")
                try:
                    (server_finished, server_to_client) = self.gensec_server.update(client_to_server)
                except samba.NTSTATUSError as nt:
                    raise AssertionError(nt)

            if client_finished and server_finished:
                break

        if client_only_opt:
            self.lp_ctx.set(client_only_opt, orig_client_opt)

        self.assertTrue(server_finished)
        self.assertTrue(client_finished)

        session_info = self.gensec_server.session_info()

        test_bytes = b"Hello Server"
        try:
            test_wrapped = self.gensec_client.wrap(test_bytes)
            test_unwrapped = self.gensec_server.unwrap(test_wrapped)
        except samba.NTSTATUSError as e:
            self.fail(str(e))

        self.assertEqual(test_bytes, test_unwrapped)
        test_bytes = b"Hello Client"
        test_wrapped = self.gensec_server.wrap(test_bytes)
        test_unwrapped = self.gensec_client.unwrap(test_wrapped)
        self.assertEqual(test_bytes, test_unwrapped)

        client_session_key = self.gensec_client.session_key()
        server_session_key = self.gensec_server.session_key()
        self.assertEqual(client_session_key, server_session_key)

    def test_update(self):
        self._test_update("GSSAPI")

    def test_update_spnego(self):
        self._test_update("GSS-SPNEGO")

    def test_update_spnego_downgrade(self):
        self._test_update("GSS-SPNEGO", "spnego", "gensec:gssapi_krb5")

    def test_update_no_optimistic_spnego(self):
        self._test_update("GSS-SPNEGO", "spnego", "spnego:client_no_optimistic")

    def test_update_w2k_spnego_client(self):
        self.lp_ctx.set("spnego:simulate_w2k", "yes")

        # Re-start the client with this set
        self.gensec = gensec.Security.start_client(self.settings)

        # Unset it for the server
        self.lp_ctx.set("spnego:simulate_w2k", "no")

        self._test_update("GSS-SPNEGO")

    def test_update_w2k_spnego_server(self):
        # Re-start the client with this set
        self.gensec = gensec.Security.start_client(self.settings)

        # Unset it for the server
        self.lp_ctx.set("spnego:simulate_w2k", "yes")

        self._test_update("GSS-SPNEGO")

    def test_update_w2k_spnego(self):
        self.lp_ctx.set("spnego:simulate_w2k", "no")

        # Re-start the client with this set
        self.gensec = gensec.Security.start_client(self.settings)

        self._test_update("GSS-SPNEGO")

    def test_update_gss_krb5_to_spnego(self):
        self._test_update("GSS-SPNEGO", "gssapi_krb5")

    def test_update_ntlmssp_to_spnego(self):
        self._test_update("GSS-SPNEGO", "ntlmssp")

    def test_max_update_size(self):
        """Test GENSEC by doing an exchange with ourselves using GSSAPI against a KDC"""

        """Start up a client and server GENSEC instance to test things with"""

        self.gensec_client = gensec.Security.start_client(self.settings)
        self.gensec_client.set_credentials(self.get_credentials())
        self.gensec_client.want_feature(gensec.FEATURE_SIGN)
        self.gensec_client.set_max_update_size(5)
        self.gensec_client.start_mech_by_name("spnego")

        self.gensec_server = gensec.Security.start_server(settings=self.settings,
                                                          auth_context=auth.AuthContext(lp_ctx=self.lp_ctx))
        creds = Credentials()
        creds.guess(self.lp_ctx)
        creds.set_machine_account(self.lp_ctx)
        self.gensec_server.set_credentials(creds)
        self.gensec_server.want_feature(gensec.FEATURE_SIGN)
        self.gensec_server.set_max_update_size(5)
        self.gensec_server.start_mech_by_name("spnego")

        client_finished = False
        server_finished = False
        server_to_client = b""

        """Run the actual call loop"""
        i = 0
        while not client_finished or not server_finished:
            i += 1
            if not client_finished:
                print("running client gensec_update: %d: %r" % (len(server_to_client), server_to_client))
                (client_finished, client_to_server) = self.gensec_client.update(server_to_client)
            if not server_finished:
                print("running server gensec_update: %d: %r" % (len(client_to_server), client_to_server))
                (server_finished, server_to_client) = self.gensec_server.update(client_to_server)

        """Here we expect a lot more than the typical 1 or 2 roundtrips"""
        self.assertTrue(i > 10)

        session_info = self.gensec_server.session_info()

        test_bytes = b"Hello Server"
        test_wrapped = self.gensec_client.wrap(test_bytes)
        test_unwrapped = self.gensec_server.unwrap(test_wrapped)
        self.assertEqual(test_bytes, test_unwrapped)
        test_bytes = b"Hello Client"
        test_wrapped = self.gensec_server.wrap(test_bytes)
        test_unwrapped = self.gensec_client.unwrap(test_wrapped)
        self.assertEqual(test_bytes, test_unwrapped)

        client_session_key = self.gensec_client.session_key()
        server_session_key = self.gensec_server.session_key()
        self.assertEqual(client_session_key, server_session_key)
