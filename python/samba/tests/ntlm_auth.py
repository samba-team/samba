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

    def test_agaist_winbind(self):
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
