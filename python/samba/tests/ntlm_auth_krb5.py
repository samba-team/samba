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
import samba
from subprocess import Popen, PIPE
from samba.tests.ntlm_auth_base import NTLMAuthTestCase

class NTLMAuthKerberosTests(NTLMAuthTestCase):

    def setUp(self):
        super(NTLMAuthKerberosTests, self).setUp()
        self.old_ccache = os.path.join(os.environ["SELFTEST_PREFIX"],
                                       "ktest", "krb5_ccache-2")
        self.ccache = os.path.join(os.environ["SELFTEST_PREFIX"],
                                   "ktest", "krb5_ccache-3")

    def test_krb5_gss_spnego_client_gss_spnego_server(self):
        """ ntlm_auth with krb5 gss-spnego-client and gss-spnego server """

        os.environ["KRB5CCNAME"] = self.old_ccache
        ret = self.run_helper(client_username="foo",
                              client_password="secret",
                              client_domain="FOO",
                              target_hostname=os.environ["SERVER"],
                              target_service="host",
                              client_helper="gss-spnego-client",
                              server_helper="gss-spnego",
                              server_use_winbind=True)
        self.assertTrue(ret)

        os.environ["KRB5CCNAME"] = self.ccache
        ret = self.run_helper(client_username="foo",
                              client_password="secret",
                              client_domain="FOO",
                              target_hostname=os.environ["SERVER"],
                              target_service="host",
                              client_helper="gss-spnego-client",
                              server_helper="gss-spnego",
                              server_use_winbind=True)
        self.assertTrue(ret)

    def test_krb5_invalid_keytab(self):
        """ ntlm_auth with krb5 and an invalid keytab """

        dedicated_keytab = "FILE:%s.%s" % (
                self.old_ccache, "keytab-does-not-exists")
        proc = Popen([self.ntlm_auth_path,
                      "--helper-protocol", "gss-spnego",
                      "--option", "security=ads",
                      "--option", "kerberosmethod=dedicatedkeytab",
                      "--option", "dedicatedkeytabfile=%s" % dedicated_keytab],
                      stdout=PIPE, stdin=PIPE, stderr=PIPE)
        buf = "YR\n"
        (out, err) = proc.communicate(input=buf.encode('utf-8'))
        self.assertEqual(proc.returncode, 0)

        dedicated_keytab = "FILE:%s.%s" % (
                self.ccache, "keytab-does-not-exists")
        proc = Popen([self.ntlm_auth_path,
                      "--helper-protocol", "gss-spnego",
                      "--option", "security=ads",
                      "--option", "kerberosmethod=dedicatedkeytab",
                      "--option", "dedicatedkeytabfile=%s" % dedicated_keytab],
                      stdout=PIPE, stdin=PIPE, stderr=PIPE)
        buf = "YR\n"
        (out, err) = proc.communicate(input=buf.encode('utf-8'))
        self.assertEqual(proc.returncode, 0)
