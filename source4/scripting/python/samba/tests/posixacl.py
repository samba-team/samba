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

from samba.ntacls import setntacl, getntacl
from samba.dcerpc import xattr, security, smb_acl, idmap
from samba.param import LoadParm
from samba.tests import TestCase
from samba import provision
import random
import os
from samba.samba3 import smbd, passdb
from samba.samba3 import param as s3param

# To print a posix ACL use:
#        for entry in posix_acl.acl:
#            print "a_type: %d" % entry.a_type
#            print "a_perm: %o" % entry.a_perm
#            print "uid: %d" % entry.uid
#            print "gid: %d" % entry.gid

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
        facl = getntacl(lp,tempf, direct_db_access=True)
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
        setntacl(lp,tempf,acl,"S-1-5-21-2212615479-2695158682-2101375467", use_ntvfs=True)
        facl = getntacl(lp,tempf, direct_db_access=False)
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
        setntacl(lp,tempf,acl,"S-1-5-21-2212615479-2695158682-2101375467", use_ntvfs=False)
        facl = getntacl(lp,tempf, direct_db_access=False)
        anysid = security.dom_sid(security.SID_NT_SELF)
        self.assertEquals(facl.as_sddl(anysid),acl)
        os.unlink(tempf)

    def test_setntacl_smbd_getntacl_smbd_gpo(self):
        random.seed()
        lp = LoadParm()
        path = None
        path = os.environ['SELFTEST_PREFIX']
        acl = "O:DAG:DUD:P(A;OICI;0x001f01ff;;;DA)(A;OICI;0x001f01ff;;;EA)(A;OICIIO;0x001f01ff;;;CO)(A;OICI;0x001f01ff;;;DA)(A;OICI;0x001f01ff;;;SY)(A;OICI;0x001200a9;;;AU)(A;OICI;0x001200a9;;;ED)S:AI(OU;CIIDSA;WP;f30e3bbe-9ff0-11d1-b603-0000f80367c1;bf967aa5-0de6-11d0-a285-00aa003049e2;WD)(OU;CIIDSA;WP;f30e3bbf-9ff0-11d1-b603-0000f80367c1;bf967aa5-0de6-11d0-a285-00aa003049e2;WD)"
        tempf = os.path.join(path,"pytests"+str(int(100000*random.random())))
        open(tempf, 'w').write("empty")
        setntacl(lp,tempf,acl,"S-1-5-21-2212615479-2695158682-2101375467", use_ntvfs=False)
        facl = getntacl(lp,tempf, direct_db_access=False)
        domsid = security.dom_sid("S-1-5-21-2212615479-2695158682-2101375467")
        self.assertEquals(facl.as_sddl(domsid),acl)
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

        LA_sid = security.dom_sid(str(domsid)+"-"+str(security.DOMAIN_RID_ADMINISTRATOR))
        BA_sid = security.dom_sid(security.SID_BUILTIN_ADMINISTRATORS)
        SO_sid = security.dom_sid(security.SID_BUILTIN_SERVER_OPERATORS)
        SY_sid = security.dom_sid(security.SID_NT_SYSTEM)
        AU_sid = security.dom_sid(security.SID_NT_AUTHENTICATED_USERS)

        s4_passdb = passdb.PDB(s3conf.get("passdb backend"))

        # These assertions correct for current plugin_s4_dc selftest
        # configuration.  When other environments have a broad range of
        # groups mapped via passdb, we can relax some of these checks
        (LA_uid,LA_type) = s4_passdb.sid_to_id(LA_sid)
        self.assertEquals(LA_type, idmap.ID_TYPE_UID)
        (BA_gid,BA_type) = s4_passdb.sid_to_id(BA_sid)
        self.assertEquals(BA_type, idmap.ID_TYPE_BOTH)
        (SO_gid,SO_type) = s4_passdb.sid_to_id(SO_sid)
        self.assertEquals(SO_type, idmap.ID_TYPE_BOTH)
        (SY_gid,SY_type) = s4_passdb.sid_to_id(SY_sid)
        self.assertEquals(SO_type, idmap.ID_TYPE_BOTH)
        (AU_gid,AU_type) = s4_passdb.sid_to_id(AU_sid)
        self.assertEquals(AU_type, idmap.ID_TYPE_BOTH)

        self.assertEquals(posix_acl.count, 9)

        self.assertEquals(posix_acl.acl[0].a_type, smb_acl.SMB_ACL_GROUP)
        self.assertEquals(posix_acl.acl[0].a_perm, 7)
        self.assertEquals(posix_acl.acl[0].info.gid, BA_gid)

        self.assertEquals(posix_acl.acl[1].a_type, smb_acl.SMB_ACL_USER)
        self.assertEquals(posix_acl.acl[1].a_perm, 6)
        self.assertEquals(posix_acl.acl[1].info.uid, LA_uid)

        self.assertEquals(posix_acl.acl[2].a_type, smb_acl.SMB_ACL_OTHER)
        self.assertEquals(posix_acl.acl[2].a_perm, 0)

        self.assertEquals(posix_acl.acl[3].a_type, smb_acl.SMB_ACL_USER_OBJ)
        self.assertEquals(posix_acl.acl[3].a_perm, 6)

        self.assertEquals(posix_acl.acl[4].a_type, smb_acl.SMB_ACL_GROUP_OBJ)
        self.assertEquals(posix_acl.acl[4].a_perm, 7)

        self.assertEquals(posix_acl.acl[5].a_type, smb_acl.SMB_ACL_GROUP)
        self.assertEquals(posix_acl.acl[5].a_perm, 5)
        self.assertEquals(posix_acl.acl[5].info.gid, SO_gid)

        self.assertEquals(posix_acl.acl[6].a_type, smb_acl.SMB_ACL_GROUP)
        self.assertEquals(posix_acl.acl[6].a_perm, 7)
        self.assertEquals(posix_acl.acl[6].info.gid, SY_gid)

        self.assertEquals(posix_acl.acl[7].a_type, smb_acl.SMB_ACL_GROUP)
        self.assertEquals(posix_acl.acl[7].a_perm, 5)
        self.assertEquals(posix_acl.acl[7].info.gid, AU_gid)

        self.assertEquals(posix_acl.acl[8].a_type, smb_acl.SMB_ACL_MASK)
        self.assertEquals(posix_acl.acl[8].a_perm, 7)


# check that it matches:
# user::rwx
# user:root:rwx (selftest user actually)
# group::rwx
# group:Local Admins:rwx
# group:3000000:r-x
# group:3000001:rwx
# group:3000002:r-x
# mask::rwx
# other::---

#
# This is in this order in the NDR smb_acl (not re-orderded for display)
# a_type: GROUP
# a_perm: 7
# uid: -1
# gid: 10
# a_type: USER
# a_perm: 6
# uid: 0 (selftest user actually)
# gid: -1
# a_type: OTHER
# a_perm: 0
# uid: -1
# gid: -1
# a_type: USER_OBJ
# a_perm: 6
# uid: -1
# gid: -1
# a_type: GROUP_OBJ
# a_perm: 7
# uid: -1
# gid: -1
# a_type: GROUP
# a_perm: 5
# uid: -1
# gid: 3000020
# a_type: GROUP
# a_perm: 7
# uid: -1
# gid: 3000000
# a_type: GROUP
# a_perm: 5
# uid: -1
# gid: 3000001
# a_type: MASK
# a_perm: 7
# uid: -1
# gid: -1

#

        os.unlink(tempf)

    def test_setntacl_policies_check_getposixacl(self):
        random.seed()
        lp = LoadParm()
        s3conf = s3param.get_context()
        path = None
        path = os.environ['SELFTEST_PREFIX']
        acl = provision.POLICIES_ACL
        tempf = os.path.join(path,"pytests"+str(int(100000*random.random())))
        open(tempf, 'w').write("empty")
        domsid = passdb.get_global_sam_sid()
        setntacl(lp,tempf,acl,str(domsid), use_ntvfs=False)
        facl = getntacl(lp,tempf)
        self.assertEquals(facl.as_sddl(domsid),acl)
        posix_acl = smbd.get_sys_acl(tempf, smb_acl.SMB_ACL_TYPE_ACCESS)

        LA_sid = security.dom_sid(str(domsid)+"-"+str(security.DOMAIN_RID_ADMINISTRATOR))
        BA_sid = security.dom_sid(security.SID_BUILTIN_ADMINISTRATORS)
        SO_sid = security.dom_sid(security.SID_BUILTIN_SERVER_OPERATORS)
        SY_sid = security.dom_sid(security.SID_NT_SYSTEM)
        AU_sid = security.dom_sid(security.SID_NT_AUTHENTICATED_USERS)
        PA_sid = security.dom_sid(str(domsid)+"-"+str(security.DOMAIN_RID_POLICY_ADMINS))

        s4_passdb = passdb.PDB(s3conf.get("passdb backend"))

        # These assertions correct for current plugin_s4_dc selftest
        # configuration.  When other environments have a broad range of
        # groups mapped via passdb, we can relax some of these checks
        (LA_uid,LA_type) = s4_passdb.sid_to_id(LA_sid)
        self.assertEquals(LA_type, idmap.ID_TYPE_UID)
        (BA_gid,BA_type) = s4_passdb.sid_to_id(BA_sid)
        self.assertEquals(BA_type, idmap.ID_TYPE_BOTH)
        (SO_gid,SO_type) = s4_passdb.sid_to_id(SO_sid)
        self.assertEquals(SO_type, idmap.ID_TYPE_BOTH)
        (SY_gid,SY_type) = s4_passdb.sid_to_id(SY_sid)
        self.assertEquals(SO_type, idmap.ID_TYPE_BOTH)
        (AU_gid,AU_type) = s4_passdb.sid_to_id(AU_sid)
        self.assertEquals(AU_type, idmap.ID_TYPE_BOTH)
        (PA_gid,PA_type) = s4_passdb.sid_to_id(PA_sid)
        self.assertEquals(PA_type, idmap.ID_TYPE_BOTH)

        self.assertEquals(posix_acl.count, 10)

        self.assertEquals(posix_acl.acl[0].a_type, smb_acl.SMB_ACL_GROUP)
        self.assertEquals(posix_acl.acl[0].a_perm, 7)
        self.assertEquals(posix_acl.acl[0].info.gid, BA_gid)

        self.assertEquals(posix_acl.acl[1].a_type, smb_acl.SMB_ACL_USER)
        self.assertEquals(posix_acl.acl[1].a_perm, 6)
        self.assertEquals(posix_acl.acl[1].info.uid, LA_uid)

        self.assertEquals(posix_acl.acl[2].a_type, smb_acl.SMB_ACL_OTHER)
        self.assertEquals(posix_acl.acl[2].a_perm, 0)

        self.assertEquals(posix_acl.acl[3].a_type, smb_acl.SMB_ACL_USER_OBJ)
        self.assertEquals(posix_acl.acl[3].a_perm, 6)

        self.assertEquals(posix_acl.acl[4].a_type, smb_acl.SMB_ACL_GROUP_OBJ)
        self.assertEquals(posix_acl.acl[4].a_perm, 7)

        self.assertEquals(posix_acl.acl[5].a_type, smb_acl.SMB_ACL_GROUP)
        self.assertEquals(posix_acl.acl[5].a_perm, 5)
        self.assertEquals(posix_acl.acl[5].info.gid, SO_gid)

        self.assertEquals(posix_acl.acl[6].a_type, smb_acl.SMB_ACL_GROUP)
        self.assertEquals(posix_acl.acl[6].a_perm, 7)
        self.assertEquals(posix_acl.acl[6].info.gid, SY_gid)

        self.assertEquals(posix_acl.acl[7].a_type, smb_acl.SMB_ACL_GROUP)
        self.assertEquals(posix_acl.acl[7].a_perm, 5)
        self.assertEquals(posix_acl.acl[7].info.gid, AU_gid)

        self.assertEquals(posix_acl.acl[8].a_type, smb_acl.SMB_ACL_GROUP)
        self.assertEquals(posix_acl.acl[8].a_perm, 7)
        self.assertEquals(posix_acl.acl[8].info.gid, PA_gid)

        self.assertEquals(posix_acl.acl[9].a_type, smb_acl.SMB_ACL_MASK)
        self.assertEquals(posix_acl.acl[9].a_perm, 7)


# check that it matches:
# user::rwx
# user:root:rwx (selftest user actually)
# group::rwx
# group:Local Admins:rwx
# group:3000000:r-x
# group:3000001:rwx
# group:3000002:r-x
# group:3000003:rwx
# mask::rwx
# other::---

#
# This is in this order in the NDR smb_acl (not re-orderded for display)
# a_type: GROUP
# a_perm: 7
# uid: -1
# gid: 10
# a_type: USER
# a_perm: 6
# uid: 0 (selftest user actually)
# gid: -1
# a_type: OTHER
# a_perm: 0
# uid: -1
# gid: -1
# a_type: USER_OBJ
# a_perm: 6
# uid: -1
# gid: -1
# a_type: GROUP_OBJ
# a_perm: 7
# uid: -1
# gid: -1
# a_type: GROUP
# a_perm: 5
# uid: -1
# gid: 3000020
# a_type: GROUP
# a_perm: 7
# uid: -1
# gid: 3000000
# a_type: GROUP
# a_perm: 5
# uid: -1
# gid: 3000001
# a_type: GROUP
# a_perm: 7
# uid: -1
# gid: 3000003
# a_type: MASK
# a_perm: 7
# uid: -1
# gid: -1

#

        os.unlink(tempf)

    def setUp(self):
        super(PosixAclMappingTests, self).setUp()
        s3conf = s3param.get_context()
        s3conf.load(self.get_loadparm().configfile)
