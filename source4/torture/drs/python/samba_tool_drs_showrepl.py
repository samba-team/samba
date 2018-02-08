# Blackbox tests for "samba-tool drs" command
# Copyright (C) Kamen Mazdrashki <kamenim@samba.org> 2011
# Copyright (C) Andrew Bartlett <abartlet@samba.org> 2017
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

"""Blackbox tests for samba-tool drs showrepl."""
from __future__ import print_function
import samba.tests
import drs_base

class SambaToolDrsShowReplTests(drs_base.DrsBaseTestCase):
    """Blackbox test case for samba-tool drs."""

    def setUp(self):
        super(SambaToolDrsShowReplTests, self).setUp()

        self.dc1 = samba.tests.env_get_var_value("DC1")
        self.dc2 = samba.tests.env_get_var_value("DC2")

        creds = self.get_credentials()
        self.cmdline_creds = "-U%s/%s%%%s" % (creds.get_domain(),
                                              creds.get_username(),
                                              creds.get_password())

    def test_samba_tool_showrepl(self):
        """Tests 'samba-tool drs showrepl' command.
        """
        # Output should be like:
        #      <site-name>/<domain-name>
        #      DSA Options: <hex-options>
        #      DSA object GUID: <DSA-object-GUID>
        #      DSA invocationId: <DSA-invocationId>
        #      <Inbound-connections-list>
        #      <Outbound-connections-list>
        #      <KCC-objects>
        #      ...
        #   TODO: Perhaps we should check at least for
        #         DSA's objectGUDI and invocationId
        out = self.check_output("samba-tool drs showrepl "
                                "%s %s" % (self.dc1, self.cmdline_creds))

        self.assertTrue("DSA Options:" in out)
        self.assertTrue("DSA object GUID:" in out)
        self.assertTrue("DSA invocationId:" in out)
