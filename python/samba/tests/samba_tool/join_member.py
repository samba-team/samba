# Unix SMB/CIFS implementation.
# Copyright (C) David Mulder <dmulder@samba.org> 2021
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
import re
from samba.tests.samba_tool.base import SambaToolCmdTest
from samba.param import LoadParm
from samba.netcmd.common import netcmd_dnsname

class JoinMemberCmdTestCase(SambaToolCmdTest):
    """Test for samba-tool domain join subcommand"""

    def test_join_member(self):
        """Run a domain member join, and check that dns is updated"""
        smb_conf = os.environ["SERVERCONFFILE"]
        zone = os.environ["REALM"].lower()
        lp = LoadParm()
        lp.load(smb_conf)
        dnsname = netcmd_dnsname(lp)
        # Fetch the existing dns A records
        (result, out, err) = self.runsubcmd("dns", "query",
                                    os.environ["DC_SERVER"],
                                    zone, dnsname, 'A',
                                    "-s", smb_conf,
                                    "-U%s%%%s" % (os.environ["DC_USERNAME"],
                                                  os.environ["DC_PASSWORD"]))
        self.assertCmdSuccess(result, out, err, 'Failed to find the record')

        existing_records = re.findall(r'A:\s+(\d+\.\d+\.\d+\.\d+)\s', out)

        # Remove the existing records
        for record in existing_records:
            (result, out, err) = self.runsubcmd("dns", "delete",
                                        os.environ["DC_SERVER"],
                                        zone, dnsname, 'A', record,
                                        "-s", smb_conf,
                                        "-U%s%%%s" % (os.environ["DC_USERNAME"],
                                                      os.environ["DC_PASSWORD"]))
            self.assertCmdSuccess(result, out, err, 'Failed to remove record')

        # Perform the s3 member join (net ads join)
        (result, out, err) = self.runsubcmd("domain", "join",
                                    os.environ["REALM"], "member",
                                    "-s", smb_conf,
                                    "-U%s%%%s" % (os.environ["DC_USERNAME"],
                                                  os.environ["DC_PASSWORD"]))
        self.assertCmdSuccess(result, out, err, 'Failed to join member')

        # Ensure the dns A record was created
        (result, out, err) = self.runsubcmd("dns", "query",
                                    os.environ["DC_SERVER"],
                                    zone, dnsname, 'A',
                                    "-s", smb_conf,
                                    "-U%s%%%s" % (os.environ["DC_USERNAME"],
                                                  os.environ["DC_PASSWORD"]))
        self.assertCmdSuccess(result, out, err,
                              'Failed to find dns host records for %s' % dnsname)
