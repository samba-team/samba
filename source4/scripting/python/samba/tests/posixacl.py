# Unix SMB/CIFS implementation. Tests for NT and posix ACL manipulation
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

"""Tests for the Samba3 NT -> posix ACL layer"""

from samba.ntacls import setntacl, getntacl, XattrBackendError
from samba.dcerpc import xattr, security, smb_acl
from samba.param import LoadParm
from samba.tests import TestCase, TestSkipped
from samba import provision
import random
import os
from samba.samba3 import smbd, passdb
from samba.samba3 import param as s3param

class PosixAclMappingTests(TestCase):

    def test_setntacl(self):
        random.seed()
        lp = LoadParm()
        path = os.environ['SELFTEST_PREFIX']
        acl = "O:S-1-5-21-2212615479-2695158682-2101375467-512G:S-1-5-21-2212615479-2695158682-2101375467-513D:(A;OICI;0x001f01ff;;;S-1-5-21-2212615479-2695158682-2101375467-512)"
        tempf = os.path.join(path,"pytests"+str(int(100000*random.random())))
        open(tempf, 'w').write("empty")
        setntacl(lp, tempf, acl, "S-1-5-21-2212615479-2695158682-2101375467", use_ntvfs=False)
        os.unlink(tempf)

    def test_setntacl_smbd_getntacl(self):
        random.seed()
        lp = LoadParm()
        path = None
        path = os.environ['SELFTEST_PREFIX']
        acl = "O:S-1-5-21-2212615479-2695158682-2101375467-512G:S-1-5-21-2212615479-2695158682-2101375467-513D:(A;OICI;0x001f01ff;;;S-1-5-21-2212615479-2695158682-2101375467-512)"
        tempf = os.path.join(path,"pytests"+str(int(100000*random.random())))
        open(tempf, 'w').write("empty")
        setntacl(lp,tempf,acl,"S-1-5-21-2212615479-2695158682-2101375467", use_ntvfs=True)
        facl = getntacl(lp,tempf)
        anysid = security.dom_sid(security.SID_NT_SELF)
        self.assertEquals(facl.as_sddl(anysid),acl)
        os.unlink(tempf)

    def test_setntacl_getntacl_smbd(self):
        random.seed()
        lp = LoadParm()
        path = None
        path = os.environ['SELFTEST_PREFIX']
        acl = "O:S-1-5-21-2212615479-2695158682-2101375467-512G:S-1-5-21-2212615479-2695158682-2101375467-513D:(A;OICI;0x001f01ff;;;S-1-5-21-2212615479-2695158682-2101375467-512)"
        tempf = os.path.join(path,"pytests"+str(int(100000*random.random())))
        open(tempf, 'w').write("empty")
        setntacl(lp,tempf,acl,"S-1-5-21-2212615479-2695158682-2101375467", use_ntvfs=False)
        facl = getntacl(lp,tempf, direct_db_access=True)
        anysid = security.dom_sid(security.SID_NT_SELF)
        self.assertEquals(facl.as_sddl(anysid),acl)
        os.unlink(tempf)

    def test_setntacl_smbd_getntacl_smbd(self):
        random.seed()
        lp = LoadParm()
        path = None
        path = os.environ['SELFTEST_PREFIX']
        acl = "O:S-1-5-21-2212615479-2695158682-2101375467-512G:S-1-5-21-2212615479-2695158682-2101375467-513D:(A;OICI;0x001f01ff;;;S-1-5-21-2212615479-2695158682-2101375467-512)"
        tempf = os.path.join(path,"pytests"+str(int(100000*random.random())))
        open(tempf, 'w').write("empty")
        setntacl(lp,tempf,acl,"S-1-5-21-2212615479-2695158682-2101375467", use_ntvfs=True)
        facl = getntacl(lp,tempf, direct_db_access=True)
        anysid = security.dom_sid(security.SID_NT_SELF)
        self.assertEquals(facl.as_sddl(anysid),acl)
        os.unlink(tempf)

    def test_setntacl_getposixacl(self):
        random.seed()
        lp = LoadParm()
        path = None
        path = os.environ['SELFTEST_PREFIX']
        acl = "O:S-1-5-21-2212615479-2695158682-2101375467-512G:S-1-5-21-2212615479-2695158682-2101375467-513D:(A;OICI;0x001f01ff;;;S-1-5-21-2212615479-2695158682-2101375467-512)"
        tempf = os.path.join(path,"pytests"+str(int(100000*random.random())))
        open(tempf, 'w').write("empty")
        setntacl(lp,tempf,acl,"S-1-5-21-2212615479-2695158682-2101375467", use_ntvfs=False)
        facl = getntacl(lp,tempf)
        anysid = security.dom_sid(security.SID_NT_SELF)
        self.assertEquals(facl.as_sddl(anysid),acl)
        posix_acl = smbd.get_sys_acl(tempf, smb_acl.SMB_ACL_TYPE_ACCESS)
        os.unlink(tempf)

    def test_setntacl_sysvol_check_getposixacl(self):
        random.seed()
        lp = LoadParm()
        s3conf = s3param.get_context()
        path = None
        path = os.environ['SELFTEST_PREFIX']
        acl = provision.SYSVOL_ACL
        tempf = os.path.join(path,"pytests"+str(int(100000*random.random())))
        open(tempf, 'w').write("empty")
        domsid = passdb.get_global_sam_sid()
        setntacl(lp,tempf,acl,str(domsid), use_ntvfs=False)
        facl = getntacl(lp,tempf)
        self.assertEquals(facl.as_sddl(domsid),acl)
        posix_acl = smbd.get_sys_acl(tempf, smb_acl.SMB_ACL_TYPE_ACCESS)

# check that it matches:
# user::rwx
# user:root:rwx
# group::rwx
# group:wheel:rwx
# group:3000000:r-x
# group:3000001:rwx
# group:3000002:r-x
# mask::rwx
# other::---

        os.unlink(tempf)

    def setUp(self):
        super(PosixAclMappingTests, self).setUp()
        s3conf = s3param.get_context()
        s3conf.load(self.get_loadparm().configfile)
