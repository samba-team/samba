# Unix SMB/CIFS implementation.
#
# Copyright (C) Samuel Cabrero <scabrero@suse.de> 2018
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
from subprocess import Popen, PIPE
from samba.tests.ntlm_auth_base import NTLMAuthTestCase
from samba.compat import get_string

class NTLMAuthHelpersTests(NTLMAuthTestCase):

    def setUp(self):
        super(NTLMAuthHelpersTests, self).setUp()
        self.username = os.environ["DC_USERNAME"]
        self.password = os.environ["DC_PASSWORD"]
        self.domain = os.environ["DOMAIN"]
        out = get_string(self.check_output("wbinfo -n %s" % self.username))
        self.group_sid = out.split(" ")[0]
        self.assertTrue(self.group_sid.startswith("S-1-5-21-"))
        self.bad_group_sid = self.group_sid[:-2]

    def test_specified_domain(self):
        """ ntlm_auth with specified domain """

        username = "foo"
        password = "secret"
        domain = "FOO"

        ret = self.run_helper(client_username=username,
                              client_password=password,
                              client_domain=domain,
                              server_username=username,
                              server_password=password,
                              server_domain=domain,
                              server_use_winbind=False)
        self.assertTrue(ret)

        username = "foo"
        password = "secret"
        domain = "fOo"

        ret = self.run_helper(client_username=username,
                              client_password=password,
                              client_domain=domain,
                              server_username=username,
                              server_password=password,
                              server_domain=domain,
                              server_use_winbind=False)
        self.assertTrue(ret)

    def test_against_winbind(self):
        """ ntlm_auth against winbindd """

        ret = self.run_helper(client_username=self.username,
                              client_password=self.password,
                              client_domain=self.domain,
                              server_use_winbind=True)
        self.assertTrue(ret)

    def test_ntlmssp_gss_spnego(self):
        """ ntlm_auth with NTLMSSP client and gss-spnego server """

        username = "foo"
        password = "secret"
        domain = "fOo"

        ret = self.run_helper(client_username=username,
                              client_password=password,
                              client_domain=domain,
                              server_username=username,
                              server_password=password,
                              server_domain=domain,
                              client_helper="ntlmssp-client-1",
                              server_helper="gss-spnego",
                              server_use_winbind=False)
        self.assertTrue(ret)

    def test_gss_spnego(self):
        """ ntlm_auth with NTLMSSP gss-spnego-client and gss-spnego server """

        username = "foo"
        password = "secret"
        domain = "fOo"

        ret = self.run_helper(client_username=username,
                              client_password=password,
                              client_domain=domain,
                              server_username=username,
                              server_password=password,
                              server_domain=domain,
                              client_helper="gss-spnego-client",
                              server_helper="gss-spnego",
                              server_use_winbind=False)
        self.assertTrue(ret)

    def test_gss_spnego_winbind(self):
        """ ntlm_auth with NTLMSSP gss-spnego-client and gss-spnego server
        against winbind """

        ret = self.run_helper(client_username=self.username,
                              client_password=self.password,
                              client_domain=self.domain,
                              client_helper="gss-spnego-client",
                              server_helper="gss-spnego",
                              server_use_winbind=True)
        self.assertTrue(ret)

    def test_ntlmssp_gss_spnego_cached_creds(self):
        """ ntlm_auth with NTLMSSP client and gss-spnego server against
        winbind with cached credentials """

        param = "--ccache-save=%s%s%s%%%s" % (self.domain,
                                              self.winbind_separator,
                                              self.username,
                                              self.password)
        cache_cmd = ["wbinfo",
                     param]
        self.check_exit_code(cache_cmd, 0)

        ret = self.run_helper(client_username=self.username,
                              client_password=self.password,
                              client_domain=self.domain,
                              client_use_cached_creds=True,
                              client_helper="ntlmssp-client-1",
                              server_helper="gss-spnego",
                              server_use_winbind=True)
        self.assertTrue(ret)

    def test_require_membership(self):
        """ ntlm_auth against winbindd with require-membership-of """

        ret = self.run_helper(client_username=self.username,
                              client_password=self.password,
                              client_domain=self.domain,
                              require_membership=self.group_sid,
                              server_use_winbind=True)
        self.assertTrue(ret)

        ret = self.run_helper(client_username=self.username,
                              client_password=self.password,
                              client_domain=self.domain,
                              require_membership=self.bad_group_sid,
                              server_use_winbind=True)
        self.assertFalse(ret)

    def test_require_membership_gss_spnego(self):
        """ ntlm_auth with NTLMSSP gss-spnego-client and gss-spnego server
        against winbind with require-membership-of """

        ret = self.run_helper(client_username=self.username,
                              client_password=self.password,
                              client_domain=self.domain,
                              require_membership=self.group_sid,
                              client_helper="gss-spnego-client",
                              server_helper="gss-spnego",
                              server_use_winbind=True)
        self.assertTrue(ret)

        ret = self.run_helper(client_username=self.username,
                              client_password=self.password,
                              client_domain=self.domain,
                              require_membership=self.bad_group_sid,
                              client_helper="gss-spnego-client",
                              server_helper="gss-spnego",
                              server_use_winbind=True)
        self.assertFalse(ret)

    def test_plaintext_with_membership(self):
        """ ntlm_auth plaintext authentication with require-membership-of """

        proc = Popen([self.ntlm_auth_path,
                      "--require-membership-of", self.group_sid,
                      "--helper-protocol", "squid-2.5-basic"],
                      stdout=PIPE, stdin=PIPE, stderr=PIPE)
        creds = "%s%s%s %s\n" % (self.domain, self.winbind_separator,
                                 self.username,
                                 self.password)
        (out, err) = proc.communicate(input=creds.encode('utf-8'))
        self.assertEqual(proc.returncode, 0)
        self.assertTrue(out.startswith(b"OK\n"))

        # Check membership failure
        proc = Popen([self.ntlm_auth_path,
                      "--require-membership-of", self.bad_group_sid,
                      "--helper-protocol", "squid-2.5-basic"],
                      stdout=PIPE, stdin=PIPE, stderr=PIPE)
        creds = "%s%s%s %s\n" % (self.domain,
                                 self.winbind_separator,
                                 self.username,
                                 self.password)
        (out, err) = proc.communicate(input=creds.encode('utf-8'))
        self.assertEqual(proc.returncode, 0)
        self.assertTrue(out.startswith(b"ERR\n"))

    def test_ntlm_server_1_with_fixed_password(self):
        """ ntlm_auth ntlm-server-1 with fixed password """

        ntlm_cmds = [
            "LANMAN-Challenge: 0123456789abcdef",
            "NT-Response: 25a98c1c31e81847466b29b2df4680f39958fb8c213a9cc6",
            "NT-Domain: TEST",
            "Username: testuser",
            "Request-User-Session-Key: Yes",
            ".\n" ]

        proc = Popen([self.ntlm_auth_path,
                      "--password", "SecREt01",
                      "--helper-protocol", "ntlm-server-1"],
                      stdout=PIPE, stdin=PIPE, stderr=PIPE)
        buf = "\n".join(ntlm_cmds)
        (out, err) = proc.communicate(input=buf.encode('utf-8'))
        self.assertEqual(proc.returncode, 0)

        lines = out.split(b"\n")

        self.assertEqual(len(lines), 4)
        self.assertEqual(lines[0], b"Authenticated: Yes")
        self.assertEqual(
            lines[1], b"User-Session-Key: 3F373EA8E4AF954F14FAA506F8EEBDC4")
        self.assertEqual(lines[2], b".")
        self.assertEqual(lines[3], b"")

        # Break the password with a leading A on the challenge
        ntlm_cmds[0] = "LANMAN-Challenge: A123456789abcdef"

        proc = Popen([self.ntlm_auth_path,
                      "--password", "SecREt01",
                      "--helper-protocol", "ntlm-server-1"],
                      stdout=PIPE, stdin=PIPE, stderr=PIPE)
        buf = "\n".join(ntlm_cmds)
        (out, err) = proc.communicate(input=buf.encode('utf-8'))
        self.assertEqual(proc.returncode, 0)

        lines = out.split(b"\n")
        self.assertEqual(len(lines), 5)
        self.assertEqual(lines[0], b"Authenticated: No")

    def test_ntlm_server_1_with_plaintext_winbind(self):
        """ ntlm_auth ntlm-server-1 with plaintext password against winbind """

        ntlm_cmds = [
            "Password: %s" % self.password,
            "NT-Domain: %s" % self.domain,
            "Username: %s" % self.username,
            "Request-User-Session-Key: Yes",
            ".\n" ]

        proc = Popen([self.ntlm_auth_path,
                      "--require-membership-of", self.group_sid,
                      "--helper-protocol", "ntlm-server-1"],
                      stdout=PIPE, stdin=PIPE, stderr=PIPE)
        buf = "\n".join(ntlm_cmds)
        (out, err) = proc.communicate(input=buf.encode('utf-8'))
        self.assertEqual(proc.returncode, 0)

        lines = out.split(b"\n")

        self.assertEqual(len(lines), 3)
        self.assertEqual(lines[0], b"Authenticated: Yes")
        self.assertEqual(lines[1], b".")
        self.assertEqual(lines[2], b"")

        # Check membership failure

        proc = Popen([self.ntlm_auth_path,
                      "--require-membership-of", self.bad_group_sid,
                      "--helper-protocol", "ntlm-server-1"],
                      stdout=PIPE, stdin=PIPE, stderr=PIPE)
        buf = "\n".join(ntlm_cmds)
        (out, err) = proc.communicate(input=buf.encode('utf-8'))
        self.assertEqual(proc.returncode, 0)

        lines = out.split(b"\n")

        self.assertEqual(len(lines), 3)
        self.assertEqual(lines[0], b"Authenticated: No")
        self.assertEqual(lines[1], b".")
        self.assertEqual(lines[2], b"")

    def test_ntlm_server_1_with_incorrect_password_winbind(self):
        """ ntlm_auth ntlm-server-1 with incorrect fixed password against
        winbind """

        ntlm_cmds = [
            "LANMAN-Challenge: 0123456789abcdef",
            "NT-Response: 25a98c1c31e81847466b29b2df4680f39958fb8c213a9cc6",
            "NT-Domain: %s" % self.domain,
            "Username: %s" % self.username,
            "Request-User-Session-Key: Yes",
            ".\n" ]

        proc = Popen([self.ntlm_auth_path,
                      "--helper-protocol", "ntlm-server-1"],
                      stdout=PIPE, stdin=PIPE, stderr=PIPE)
        buf = "\n".join(ntlm_cmds)
        (out, err) = proc.communicate(input=buf.encode('utf-8'))
        self.assertEqual(proc.returncode, 0)

        lines = out.split(b"\n")

        self.assertEqual(len(lines), 5)
        self.assertEqual(lines[0], b"Authenticated: No")

    def test_diagnostics(self):
        """ ntlm_auth diagnostics """
        cmd_line = [self.ntlm_auth_path,
                    "--username", self.username,
                    "--password", self.password,
                    "--domain", self.domain,
                    "--diagnostics"]
        self.check_exit_code(cmd_line, 0)
