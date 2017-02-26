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

class SambaDnsUpdateTests(samba.tests.BlackboxTestCase):
    """Blackbox test case for samba_dnsupdate."""

    def setUp(self):
        self.server_ip = samba.tests.env_get_var_value("DNS_SERVER_IP")
        super(SambaDnsUpdateTests, self).setUp()
        try:
            out = self.check_output("samba_dnsupdate --verbose")
            self.assertTrue("Looking for DNS entry" in out, out)
        except samba.tests.BlackboxProcessError:
            pass

    def test_samba_dnsupate_no_change(self):
        out = self.check_output("samba_dnsupdate --verbose")
        self.assertTrue("No DNS updates needed" in out, out)

    def test_samba_dnsupate_set_ip(self):
        try:
            out = self.check_output("samba_dnsupdate --verbose --current-ip=10.0.0.1")
            self.assertTrue(" DNS updates and" in out, out)
            self.assertTrue(" DNS deletes needed" in out, out)
        except samba.tests.BlackboxProcessError:
            pass

        try:
            out = self.check_output("samba_dnsupdate --verbose --use-nsupdate --current-ip=10.0.0.1")
        except samba.tests.BlackboxProcessError as e:
            self.fail("Error calling samba_dnsupdate: %s" % e)

        self.assertTrue("No DNS updates needed" in out, out)
        try:
            rpc_out = self.check_output("samba_dnsupdate --verbose --use-samba-tool --rpc-server-ip=%s" % self.server_ip)
        except samba.tests.BlackboxProcessError as e:
            self.fail("Error calling samba_dnsupdate: %s" % e)

        self.assertTrue(" DNS updates and" in rpc_out, rpc_out)
        self.assertTrue(" DNS deletes needed" in rpc_out, rpc_out)
        out = self.check_output("samba_dnsupdate --verbose")
        self.assertTrue("No DNS updates needed" in out, out + rpc_out)
