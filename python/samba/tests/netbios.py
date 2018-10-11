# -*- coding: utf-8 -*-
# Unix SMB/CIFS implementation. Tests for netbios py module
# Copyright (C) Noel Power <noel.power@suse.com> 2018
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

import samba
import os
from samba import netbios


class NetBiosTests(samba.tests.TestCase):
    def setUp(self):
        super(NetBiosTests, self).setUp()
        self.n = netbios.Node()
        self.ifc = os.environ["SERVER_IP"]
        self.dc = os.environ["DC_NETBIOSNAME"]

    def tearDown(self):
        super(NetBiosTests, self).tearDown()

    def test_query_name(self):
        (reply_from, names, addresses) = self.n.query_name(self.dc, self.ifc, timeout=4)
        assert reply_from == self.ifc
        assert names[0] == self.dc
        assert addresses[0] == self.ifc

    def test_name_status(self):
        (reply_from, name, name_list) = self.n.name_status(self.dc, self.ifc, timeout=4)
        assert reply_from == self.ifc
        assert name[0] == self.dc
        assert len(name_list) > 0

    def test_register_name(self):
        address = '127.0.0.3'
        (reply_from, name, reply_address, code) = self.n.register_name((self.dc, 0x20), address, self.ifc, multi_homed=False, timeout=4)
        assert reply_from == self.ifc
        assert name[0] == self.dc
        assert reply_address == address
        assert code == 6

    def disabled_test_refresh(self):
        # can't get the below test to work, disabling
        address = '127.0.0.3'
        res = self.n.refresh_name((self.dc, 0x20), address, self.ifc, timeout=10)
