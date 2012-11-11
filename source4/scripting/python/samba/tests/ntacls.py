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

from samba.ntacls import setntacl, getntacl, XattrBackendError
from samba.dcerpc import xattr, security
from samba.param import LoadParm
from samba.tests import TestCaseInTempDir, TestSkipped
import random
import os

class NtaclsTests(TestCaseInTempDir):

    def test_setntacl(self):
        lp = LoadParm()
        acl = "O:S-1-5-21-2212615479-2695158682-2101375467-512G:S-1-5-21-2212615479-2695158682-2101375467-513D:(A;OICI;0x001f01ff;;;S-1-5-21-2212615479-2695158682-2101375467-512)"
        open(self.tempf, 'w').write("empty")
        lp.set("posix:eadb",os.path.join(self.tempdir,"eadbtest.tdb"))
        setntacl(lp, self.tempf, acl, "S-1-5-21-2212615479-2695158682-2101375467")
        os.unlink(os.path.join(self.tempdir,"eadbtest.tdb"))

    def test_setntacl_getntacl(self):
        lp = LoadParm()
        acl = "O:S-1-5-21-2212615479-2695158682-2101375467-512G:S-1-5-21-2212615479-2695158682-2101375467-513D:(A;OICI;0x001f01ff;;;S-1-5-21-2212615479-2695158682-2101375467-512)"
        open(self.tempf, 'w').write("empty")
        lp.set("posix:eadb",os.path.join(self.tempdir,"eadbtest.tdb"))
        setntacl(lp,self.tempf,acl,"S-1-5-21-2212615479-2695158682-2101375467")
        facl = getntacl(lp,self.tempf)
        anysid = security.dom_sid(security.SID_NT_SELF)
        self.assertEquals(facl.as_sddl(anysid),acl)
        os.unlink(os.path.join(self.tempdir,"eadbtest.tdb"))

    def test_setntacl_getntacl_param(self):
        lp = LoadParm()
        acl = "O:S-1-5-21-2212615479-2695158682-2101375467-512G:S-1-5-21-2212615479-2695158682-2101375467-513D:(A;OICI;0x001f01ff;;;S-1-5-21-2212615479-2695158682-2101375467-512)"
        open(self.tempf, 'w').write("empty")
        setntacl(lp,self.tempf,acl,"S-1-5-21-2212615479-2695158682-2101375467","tdb",os.path.join(self.tempdir,"eadbtest.tdb"))
        facl=getntacl(lp,self.tempf,"tdb",os.path.join(self.tempdir,"eadbtest.tdb"))
        domsid=security.dom_sid(security.SID_NT_SELF)
        self.assertEquals(facl.as_sddl(domsid),acl)
        os.unlink(os.path.join(self.tempdir,"eadbtest.tdb"))

    def test_setntacl_invalidbackend(self):
        lp = LoadParm()
        acl = "O:S-1-5-21-2212615479-2695158682-2101375467-512G:S-1-5-21-2212615479-2695158682-2101375467-513D:(A;OICI;0x001f01ff;;;S-1-5-21-2212615479-2695158682-2101375467-512)"
        open(self.tempf, 'w').write("empty")
        self.assertRaises(XattrBackendError, setntacl, lp, self.tempf, acl, "S-1-5-21-2212615479-2695158682-2101375467","ttdb", os.path.join(self.tempdir,"eadbtest.tdb"))

    def test_setntacl_forcenative(self):
        if os.getuid() == 0:
            raise TestSkipped("Running test as root, test skipped")
        lp = LoadParm()
        acl = "O:S-1-5-21-2212615479-2695158682-2101375467-512G:S-1-5-21-2212615479-2695158682-2101375467-513D:(A;OICI;0x001f01ff;;;S-1-5-21-2212615479-2695158682-2101375467-512)"
        open(self.tempf, 'w').write("empty")
        lp.set("posix:eadb", os.path.join(self.tempdir,"eadbtest.tdb"))
        self.assertRaises(Exception, setntacl, lp, self.tempf ,acl,
            "S-1-5-21-2212615479-2695158682-2101375467","native")


    def setUp(self):
        super(NtaclsTests, self).setUp()
        self.tempf = os.path.join(self.tempdir, "test")
        open(self.tempf, 'w').write("empty")

    def tearDown(self):
        os.unlink(self.tempf)
        super(NtaclsTests, self).tearDown()
