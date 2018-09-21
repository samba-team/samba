# Unix SMB/CIFS implementation.
# Copyright (C) Andrew Bartlett <abartlet@samba.org> 2018
# Written by Joe Guo <joeg@catalyst.net.nz>
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
from samba.tests.samba_tool.base import SambaToolCmdTest


class DemoteCmdTestCase(SambaToolCmdTest):
    """Test for samba-tool domain demote subcommand"""

    def setUp(self):
        super(DemoteCmdTestCase, self).setUp()
        self.creds_string = "-U{0}%{1}".format(
            os.environ["DC_USERNAME"], os.environ["DC_PASSWORD"])

        self.dc_server = os.environ['DC_SERVER']
        self.dburl = "ldap://%s" % os.environ["DC_SERVER"]
        self.samdb = self.getSamDB("-H", self.dburl, self.creds_string)

    def test_demote_and_remove_dns(self):
        """
        Test domain demote command will also remove dns references
        """

        server = os.environ['SERVER']  # the server to demote
        zone = os.environ['REALM'].lower()

        # make sure zone exist
        result, out, err = self.runsubcmd(
            "dns", "zoneinfo", server, zone, self.creds_string)
        self.assertCmdSuccess(result, out, err)

        # add a A record for the server to demote
        result, out, err = self.runsubcmd(
            "dns", "add", self.dc_server, zone,
            server, "A", "192.168.0.193", self.creds_string)
        self.assertCmdSuccess(result, out, err)

        # make sure above A record exist
        result, out, err = self.runsubcmd(
            "dns", "query", self.dc_server, zone,
            server, 'A', self.creds_string)
        self.assertCmdSuccess(result, out, err)

        # the above A record points to this host
        dnshostname = '{0}.{1}'.format(server, zone)

        # add a SRV record points to above host
        srv_record = "{0} 65530 65530 65530".format(dnshostname)
        self.runsubcmd(
            "dns", "add", self.dc_server, zone, 'testrecord', "SRV",
            srv_record, self.creds_string)

        # make sure above SRV record exist
        result, out, err = self.runsubcmd(
            "dns", "query", self.dc_server, zone,
            "testrecord", 'SRV', self.creds_string)
        self.assertCmdSuccess(result, out, err)

        for type_ in ['CNAME', 'NS', 'PTR']:
            # create record
            self.runsubcmd(
                "dns", "add", self.dc_server, zone,
                'testrecord', type_, dnshostname,
                self.creds_string)
            self.assertCmdSuccess(result, out, err)

            # check exist
            result, out, err = self.runsubcmd(
                "dns", "query", self.dc_server, zone,
                "testrecord", 'SRV', self.creds_string)
            self.assertCmdSuccess(result, out, err)

        # now demote
        result, out, err = self.runsubcmd(
            "domain", "demote",
            "--server", self.dc_server,
            "--configfile", os.environ["CONFIGFILE"],
            "--workgroup", os.environ["DOMAIN"],
            self.creds_string)
        self.assertCmdSuccess(result, out, err)

        result, out, err = self.runsubcmd(
            "dns", "query", self.dc_server, zone,
            server, 'ALL', self.creds_string)
        self.assertCmdFail(result)

        result, out, err = self.runsubcmd(
            "dns", "query", self.dc_server, zone,
            "testrecord", 'ALL', self.creds_string)
        self.assertCmdFail(result)
