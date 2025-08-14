#
# Unix SMB/CIFS implementation.
# Copyright Ralph Boehme <slow@samba.org> 2025
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

"""Tests for samba.dcerpc.dfs"""

import os
import logging
import samba
from samba.dcerpc import dfs
from samba.tests import RpcInterfaceTestCase
from samba.logger import get_samba_logger
from samba.credentials import Credentials
from samba.samba3 import libsmb_samba_internal as libsmb
import samba.tests.libsmb
from samba.samba3 import param as s3param

logger = get_samba_logger(name=__name__)

class DfsTests(samba.tests.libsmb.LibsmbTests):
    def setUp(self):
        super().setUp()
        self.dfs = dfs.netdfs('ncacn_np:%s[/pipe/netdfs]' % self.server, self.lp, self.creds)
        self.c = libsmb.Conn(self.server_ip, "msdfs-share", self.lp, self.creds)

    def tearDown(self):
        super().tearDown()

    def test_dfs_reparse_tag(self):
        self.dfs.Add('\\\\%s\\msdfs-share\\dfslink' % self.server, self.server, 'tmp', 'comment', 0)
        l = self.c.list('', info_level=libsmb.SMB2_FIND_ID_BOTH_DIRECTORY_INFO)
        files = {i['name']: i for i in l}
        self.assertEqual(files['dfslink']['reparse_tag'], libsmb.IO_REPARSE_TAG_DFS)
        self.dfs.Remove('\\\\%s\\msdfs-share\\dfslink' % self.server, self.server, 'tmp')
