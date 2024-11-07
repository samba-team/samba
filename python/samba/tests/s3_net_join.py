# Unix SMB/CIFS implementation.
#
# Copyright (C) David Mulder <dmulder@samba.org> 2020
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

"""
Confirm that net_s3.join_member works
"""

import samba.tests
import os
from samba.net_s3 import Net as s3_Net
from samba.credentials import DONT_USE_KERBEROS
from samba.samba3 import param as s3param
from samba import WERRORError


def rm(rmdir):
    for f in os.listdir(rmdir):
        if os.path.isdir(os.path.join(rmdir, f)):
            rm(os.path.join(rmdir, f))
            os.rmdir(os.path.join(rmdir, f))
        else:
            os.unlink(os.path.join(rmdir, f))

class NetS3JoinTests(samba.tests.TestCaseInTempDir):

    def setUp(self):
        super().setUp()
        self.realm = os.environ["REALM"]
        self.domain = os.environ["DOMAIN"]
        self.server = os.environ["SERVER"]
        self.lp = self.get_loadparm()

    def test_net_join(self):
        netbios_name = "S3NetJoinTest"
        machinepass  = "abcdefghij"
        creds = self.insta_creds(template=self.get_credentials())
        s3_lp = s3param.get_context()
        s3_lp.load(self.lp.configfile)

        s3_lp.set('realm', self.realm)
        s3_lp.set('workgroup', self.domain)
        s3_lp.set("private dir", self.tempdir)
        s3_lp.set("lock dir", self.tempdir)
        s3_lp.set("state directory", self.tempdir)
        s3_lp.set('server role', 'member server')
        net = s3_Net(creds, s3_lp, server=self.server)

        try:
            (domain_sid, domain_name) = net.join_member(netbios_name,
                                                        machinepass=machinepass)
        except WERRORError as e:
            self.fail('Join failed: %s' % e.args[1])
            raise

        try:
            ret = net.leave()
        except WERRORError as e:
            self.fail('Leave failed: %s' % e.args[1])
            raise
        self.assertTrue(ret, 'Leave failed!')
        rm(self.tempdir)
