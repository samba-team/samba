# Blackbox tests for "samba_dnsupdate" command
# Copyright (C) Kamen Mazdrashki <kamenim@samba.org> 2011
# Copyright (C) Andrew Bartlett <abartlet@samba.org> 2015
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

import samba.tests
from io import StringIO
from samba.common import get_string
from samba.netcmd.main import samba_tool
from samba.credentials import Credentials
from samba.auth import system_session
from samba.samdb import SamDB
import ldb
import shutil


class SambaDnsUpdateTests(samba.tests.BlackboxTestCase):
    """Blackbox test case for samba_dnsupdate."""

    def setUp(self):
        self.server_ip = samba.tests.env_get_var_value("DNS_SERVER_IP")
        super().setUp()
        try:
            out = self.check_output("samba_dnsupdate --verbose")
            self.assertTrue(b"Looking for DNS entry" in out, out)
        except samba.tests.BlackboxProcessError:
            pass

    def test_samba_dnsupdate_no_change(self):
        try:
            out = self.check_output("samba_dnsupdate --verbose")
        except samba.tests.BlackboxProcessError as e:
            self.fail("Error calling samba_dnsupdate: %s" % e)
        self.assertTrue(b"No DNS updates needed" in out, out)

    def test_samba_dnsupdate_set_ip(self):
        try:
            out = self.check_output("samba_dnsupdate --verbose --current-ip=10.0.0.1")
            self.assertTrue(b" DNS updates and" in out, out)
            self.assertTrue(b" DNS deletes needed" in out, out)
        except samba.tests.BlackboxProcessError:
            pass

        try:
            out = self.check_output("samba_dnsupdate --verbose --use-nsupdate --current-ip=10.0.0.1")
        except samba.tests.BlackboxProcessError as e:
            self.fail("Error calling samba_dnsupdate: %s" % e)

        self.assertTrue(b"No DNS updates needed" in out, out)
        try:
            rpc_out = self.check_output("samba_dnsupdate --verbose --use-samba-tool --rpc-server-ip=%s" % self.server_ip)
        except samba.tests.BlackboxProcessError as e:
            self.fail("Error calling samba_dnsupdate: %s" % e)

        self.assertTrue(b" DNS updates and" in rpc_out, rpc_out)
        self.assertTrue(b" DNS deletes needed" in rpc_out, rpc_out)
        out = self.check_output("samba_dnsupdate --verbose")
        self.assertTrue(b"No DNS updates needed" in out, out + rpc_out)

    def test_add_new_uncovered_site(self):
        site_name = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'

        # Clear out any existing site
        result = samba_tool('sites', 'remove', site_name,
                            outf=StringIO(),
                            errf=StringIO())

        result = samba_tool('sites', 'create', site_name,
                            outf=StringIO(),
                            errf=StringIO())

        if result is not None:
            self.fail("Error creating new site")

        self.lp = samba.tests.env_loadparm()
        self.creds = Credentials()
        self.creds.guess(self.lp)
        self.session = system_session()
        uc_fn = self.lp.private_path('dns_update_cache')
        tmp_uc = uc_fn + '_tmp'
        shutil.copyfile(uc_fn, tmp_uc)

        self.samdb = SamDB(session_info=self.session,
                           credentials=self.creds,
                           lp=self.lp)

        m = ldb.Message()
        m.dn = ldb.Dn(self.samdb, 'CN=DEFAULTIPSITELINK,CN=IP,'
                      'CN=Inter-Site Transports,CN=Sites,{0}'.format(
                          self.samdb.get_config_basedn()))
        m['siteList'] = ldb.MessageElement("CN={0},CN=Sites,{1}".format(
            site_name,
            self.samdb.get_config_basedn()),
            ldb.FLAG_MOD_ADD, "siteList")

        dns_c = "samba_dnsupdate --verbose --use-file={0}".format(tmp_uc)
        out = get_string(self.check_output(dns_c))
        self.assertNotIn(site_name.lower(), out)

        self.samdb.modify(m)

        shutil.copyfile(uc_fn, tmp_uc)
        out = get_string(self.check_output(dns_c))

        self.assertNotIn("No DNS updates needed", out)
        self.assertIn(site_name.lower(), out)

        result = samba_tool('sites', 'remove', site_name,
                            outf=StringIO(),
                            errf=StringIO())
        if result is not None:
            self.fail("Error deleting site")

    def test_samba_dnsupdate_samba_tool_all_names(self):
        """We ask it to update all names, which should all already
        exist and cause no errors."""
        try:
            out = self.check_output(["samba_dnsupdate",
                                     "--verbose",
                                     "--use-samba-tool",
                                     "--all-names"])
        except samba.tests.BlackboxProcessError as e:
            self.fail(f"samba_dnsupdate returned an error: {e}")
        self.assertIn(b"Record already exists", out)
        self.assertNotIn(b"ERROR", out)
