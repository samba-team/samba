# Unix SMB/CIFS implementation. Tests for ntacls manipulation
# Copyright (C) Matthieu Patou <mat@matws.net> 2009-2010
# Copyright (C) Andrew Bartlett 2012
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

"""Tests for samba.ntacls."""

import os

from samba.ntacls import setntacl, getntacl, XattrBackendError
from samba.param import LoadParm
from samba.dcerpc import security
from samba.tests import TestCaseInTempDir, SkipTest
from samba.auth_util import system_session_unix

NTACL_SDDL = "O:S-1-5-21-2212615479-2695158682-2101375467-512G:S-1-5-21-2212615479-2695158682-2101375467-513D:(A;OICI;0x001f01ff;;;S-1-5-21-2212615479-2695158682-2101375467-512)"
DOMAIN_SID = "S-1-5-21-2212615479-2695158682-2101375467"


class NtaclsTests(TestCaseInTempDir):

    def setUp(self):
        super(NtaclsTests, self).setUp()
        self.tempf = os.path.join(self.tempdir, "test")
        open(self.tempf, 'w').write("empty")
        self.session_info = system_session_unix()

    def tearDown(self):
        os.unlink(self.tempf)
        super(NtaclsTests, self).tearDown()

    def test_setntacl(self):
        lp = LoadParm()
        open(self.tempf, 'w').write("empty")
        lp.set("posix:eadb", os.path.join(self.tempdir, "eadbtest.tdb"))
        setntacl(lp, self.tempf, NTACL_SDDL, DOMAIN_SID, self.session_info)
        os.unlink(os.path.join(self.tempdir, "eadbtest.tdb"))

    def test_setntacl_getntacl(self):
        lp = LoadParm()
        open(self.tempf, 'w').write("empty")
        lp.set("posix:eadb", os.path.join(self.tempdir, "eadbtest.tdb"))
        setntacl(lp, self.tempf, NTACL_SDDL, DOMAIN_SID, self.session_info)
        facl = getntacl(lp, self.tempf, self.session_info)
        anysid = security.dom_sid(security.SID_NT_SELF)
        self.assertEqual(facl.as_sddl(anysid), NTACL_SDDL)
        os.unlink(os.path.join(self.tempdir, "eadbtest.tdb"))

    def test_setntacl_getntacl_param(self):
        lp = LoadParm()
        open(self.tempf, 'w').write("empty")
        setntacl(lp, self.tempf, NTACL_SDDL, DOMAIN_SID, self.session_info, "tdb",
                 os.path.join(self.tempdir, "eadbtest.tdb"))
        facl = getntacl(lp, self.tempf, self.session_info, "tdb", os.path.join(
            self.tempdir, "eadbtest.tdb"))
        domsid = security.dom_sid(security.SID_NT_SELF)
        self.assertEqual(facl.as_sddl(domsid), NTACL_SDDL)
        os.unlink(os.path.join(self.tempdir, "eadbtest.tdb"))

    def test_setntacl_invalidbackend(self):
        lp = LoadParm()
        open(self.tempf, 'w').write("empty")
        self.assertRaises(XattrBackendError, setntacl, lp, self.tempf,
                          NTACL_SDDL, DOMAIN_SID, self.session_info, "ttdb",
                          os.path.join(self.tempdir, "eadbtest.tdb"))

    def test_setntacl_forcenative(self):
        if os.getuid() == 0:
            raise SkipTest("Running test as root, test skipped")
        lp = LoadParm()
        open(self.tempf, 'w').write("empty")
        lp.set("posix:eadb", os.path.join(self.tempdir, "eadbtest.tdb"))
        self.assertRaises(Exception, setntacl, lp, self.tempf, NTACL_SDDL,
                          DOMAIN_SID, self.session_info, "native")
