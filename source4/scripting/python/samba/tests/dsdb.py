#!/usr/bin/python

# Unix SMB/CIFS implementation. Tests for dsdb 
# Copyright (C) Matthieu Patou <mat@matws.net> 2010
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

import samba.dsdb
from samba.credentials import Credentials
from samba import Ldb
from samba.auth import system_session
from testtools.testcase import TestCase
import os


class DsdbTests(TestCase):

    def _baseprovpath(self):
        return os.path.join(os.environ['SELFTEST_PREFIX'], "dc")

    def test_get_oid_from_attrid(self):
        lp = samba.param.LoadParm()
        lp.load(os.path.join(os.path.join(self._baseprovpath(), "etc"), "smb.conf"))
        creds = Credentials()
        creds.guess(lp)
        session = system_session()
        test_ldb = Ldb(os.path.join(self._baseprovpath(), "private", "sam.ldb"),
            session_info=session, credentials=creds,lp=lp)
        oid = samba.dsdb.dsdb_get_oid_from_attid(test_ldb, 591614)
        self.assertEquals(oid, "1.2.840.113556.1.4.1790")
