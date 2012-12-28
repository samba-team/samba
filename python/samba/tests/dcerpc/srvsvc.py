# -*- coding: utf-8 -*-
#
# Unix SMB/CIFS implementation.
# Copyright © Dhananjay Sathe <dhanajaysathe@gmail.com> 2011
# Copyright © Jelmer Vernooij <jelmer@samba.org> 2011
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

"""Tests for samba.dcerpc.srvsvc."""

from samba.dcerpc import srvsvc
from samba.tests import RpcInterfaceTestCase


class SrvsvcTests(RpcInterfaceTestCase):

    def setUp(self):
        super(SrvsvcTests, self).setUp()
        self.conn = srvsvc.srvsvc("ncalrpc:", self.get_loadparm())
        self.server_unc = "\\\\."

    def getDummyShareObject(self):
        share = srvsvc.NetShareInfo2()

        share.name = u'test'
        share.comment = u'test share'
        share.type = srvsvc.STYPE_DISKTREE
        share.current_users = 0x00000000
        share.max_users = -1
        share.password = None
        share.path = u'C:\\tmp' # some random path
        share.permissions = 123434566
        return share

    def test_NetShareAdd(self):
        self.skip("Dangerous test")
        share = self.getDummyShareObject()
        self.conn.NetShareAdd(self.server_unc, 2, share, None)

    def test_NetShareSetInfo(self):
        self.skip("Dangerous test")
        share = self.getDummyShareObject()
        parm_error = 0x00000000
        self.conn.NetShareAdd(self.server_unc, 502, share, parm_error)
        name = share.name
        share.comment = "now sucessfully modified "
        parm_error = self.pipe.NetShareSetInfo(self.server_unc, name,
                502, share, parm_error)

    def test_NetShareDel(self):
        self.skip("Dangerous test")
        share = self.getDummyShareObject()
        parm_error = 0x00000000
        self.expectFailure("NetShareAdd doesn't work properly from Python",
            self.conn.NetShareAdd, self.server_unc, 502, share, parm_error)
        self.conn.NetShareDel(self.server_unc, share.name, 0)
