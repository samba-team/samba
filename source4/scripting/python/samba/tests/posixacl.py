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

from samba.ntacls import setntacl, getntacl, checkset_backend
from samba.dcerpc import xattr, security, smb_acl, idmap
from samba.param import LoadParm
from samba.tests import TestCaseInTempDir
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

class PosixAclMappingTests(TestCaseInTempDir):

    def test_setntacl(self):
        lp = LoadParm()
        acl = "O:S-1-5-21-2212615479-2695158682-2101375467-512G:S-1-5-21-2212615479-2695158682-2101375467-513D:(A;OICI;0x001f01ff;;;S-1-5-21-2212615479-2695158682-2101375467-512)"
        setntacl(lp, self.tempf, acl, "S-1-5-21-2212615479-2695158682-2101375467", use_ntvfs=False)

    def test_setntacl_smbd_getntacl(self):
        lp = LoadParm()
        acl = "O:S-1-5-21-2212615479-2695158682-2101375467-512G:S-1-5-21-2212615479-2695158682-2101375467-513D:(A;OICI;0x001f01ff;;;S-1-5-21-2212615479-2695158682-2101375467-512)"
        setntacl(lp,self.tempf,acl,"S-1-5-21-2212615479-2695158682-2101375467", use_ntvfs=True)
        facl = getntacl(lp,self.tempf, direct_db_access=True)
        anysid = security.dom_sid(security.SID_NT_SELF)
        self.assertEquals(facl.as_sddl(anysid),acl)

    def test_setntacl_smbd_setposixacl_getntacl(self):
        lp = LoadParm()
        acl = "O:S-1-5-21-2212615479-2695158682-2101375467-512G:S-1-5-21-2212615479-2695158682-2101375467-513D:(A;OICI;0x001f01ff;;;S-1-5-21-2212615479-2695158682-2101375467-512)"
        setntacl(lp,self.tempf,acl,"S-1-5-21-2212615479-2695158682-2101375467", use_ntvfs=True)

        # This will invalidate the ACL, as we have a hook!
        smbd.set_simple_acl(self.tempf, 0640)

        # However, this only asks the xattr
        try:
            facl = getntacl(lp, self.tempf, direct_db_access=True)
            self.assertTrue(False)
        except TypeError:
            pass

    def test_setntacl_invalidate_getntacl(self):
        lp = LoadParm()
        acl = "O:S-1-5-21-2212615479-2695158682-2101375467-512G:S-1-5-21-2212615479-2695158682-2101375467-513D:(A;OICI;0x001f01ff;;;S-1-5-21-2212615479-2695158682-2101375467-512)"
        setntacl(lp, self.tempf,acl,"S-1-5-21-2212615479-2695158682-2101375467", use_ntvfs=True)

        # This should invalidate the ACL, as we include the posix ACL in the hash
        (backend_obj, dbname) = checkset_backend(lp, None, None)
        backend_obj.wrap_setxattr(dbname,
                                  self.tempf, "system.fake_access_acl", "")

        #however, as this is direct DB access, we do not notice it
        facl = getntacl(lp, self.tempf, direct_db_access=True)
        anysid = security.dom_sid(security.SID_NT_SELF)
        self.assertEquals(acl, facl.as_sddl(anysid))

    def test_setntacl_invalidate_getntacl_smbd(self):
        lp = LoadParm()
        acl = "O:S-1-5-21-2212615479-2695158682-2101375467-512G:S-1-5-21-2212615479-2695158682-2101375467-513D:(A;OICI;0x001f01ff;;;S-1-5-21-2212615479-2695158682-2101375467-512)"
        setntacl(lp, self.tempf,acl,"S-1-5-21-2212615479-2695158682-2101375467", use_ntvfs=False)

        # This should invalidate the ACL, as we include the posix ACL in the hash
        (backend_obj, dbname) = checkset_backend(lp, None, None)
        backend_obj.wrap_setxattr(dbname,
                                  self.tempf, "system.fake_access_acl", "")

        #the hash would break, and we return an ACL based only on the mode, except we set the ACL using the 'ntvfs' mode that doesn't include a hash
        facl = getntacl(lp, self.tempf)
        anysid = security.dom_sid(security.SID_NT_SELF)
        self.assertEquals(acl, facl.as_sddl(anysid))

    def test_setntacl_smbd_invalidate_getntacl_smbd(self):
        lp = LoadParm()
        acl = "O:S-1-5-21-2212615479-2695158682-2101375467-512G:S-1-5-21-2212615479-2695158682-2101375467-513D:(A;OICI;0x001f01ff;;;S-1-5-21-2212615479-2695158682-2101375467-512)"
        simple_acl_from_posix = "O:S-1-5-21-2212615479-2695158682-2101375467-512G:S-1-5-21-2212615479-2695158682-2101375467-513D:(A;;0x001f01ff;;;S-1-5-21-2212615479-2695158682-2101375467-512)(A;;0x001200a9;;;S-1-5-21-2212615479-2695158682-2101375467-513)(A;;WO;;;WD)"
        os.chmod(self.tempf, 0750)
        setntacl(lp, self.tempf,acl,"S-1-5-21-2212615479-2695158682-2101375467", use_ntvfs=False)

        # This should invalidate the ACL, as we include the posix ACL in the hash
        (backend_obj, dbname) = checkset_backend(lp, None, None)
        backend_obj.wrap_setxattr(dbname,
                                  self.tempf, "system.fake_access_acl", "")

        #the hash will break, and we return an ACL based only on the mode
        facl = getntacl(lp, self.tempf, direct_db_access=False)
        anysid = security.dom_sid(security.SID_NT_SELF)
        self.assertEquals(simple_acl_from_posix, facl.as_sddl(anysid))

    def test_setntacl_getntacl_smbd(self):
        lp = LoadParm()
        acl = "O:S-1-5-21-2212615479-2695158682-2101375467-512G:S-1-5-21-2212615479-2695158682-2101375467-513D:(A;OICI;0x001f01ff;;;S-1-5-21-2212615479-2695158682-2101375467-512)"
        setntacl(lp, self.tempf,acl,"S-1-5-21-2212615479-2695158682-2101375467", use_ntvfs=True)
        facl = getntacl(lp, self.tempf, direct_db_access=False)
        anysid = security.dom_sid(security.SID_NT_SELF)
        self.assertEquals(facl.as_sddl(anysid),acl)

    def test_setntacl_smbd_getntacl_smbd(self):
        lp = LoadParm()
        acl = "O:S-1-5-21-2212615479-2695158682-2101375467-512G:S-1-5-21-2212615479-2695158682-2101375467-513D:(A;OICI;0x001f01ff;;;S-1-5-21-2212615479-2695158682-2101375467-512)"
        setntacl(lp, self.tempf,acl,"S-1-5-21-2212615479-2695158682-2101375467", use_ntvfs=False)
        facl = getntacl(lp, self.tempf, direct_db_access=False)
        anysid = security.dom_sid(security.SID_NT_SELF)
        self.assertEquals(facl.as_sddl(anysid),acl)

    def test_setntacl_smbd_setposixacl_getntacl_smbd(self):
        lp = LoadParm()
        acl = "O:S-1-5-21-2212615479-2695158682-2101375467-512G:S-1-5-21-2212615479-2695158682-2101375467-513D:(A;OICI;0x001f01ff;;;S-1-5-21-2212615479-2695158682-2101375467-512)"
        simple_acl_from_posix = "O:S-1-5-21-2212615479-2695158682-2101375467-512G:S-1-5-21-2212615479-2695158682-2101375467-513D:(A;;0x001f019f;;;S-1-5-21-2212615479-2695158682-2101375467-512)(A;;0x00120089;;;S-1-5-21-2212615479-2695158682-2101375467-513)(A;;WO;;;WD)"
        setntacl(lp, self.tempf,acl,"S-1-5-21-2212615479-2695158682-2101375467", use_ntvfs=False)
        # This invalidates the hash of the NT acl just set because there is a hook in the posix ACL set code
        smbd.set_simple_acl(self.tempf, 0640)
        facl = getntacl(lp, self.tempf, direct_db_access=False)
        anysid = security.dom_sid(security.SID_NT_SELF)
        self.assertEquals(simple_acl_from_posix, facl.as_sddl(anysid))

    def test_setntacl_smbd_setposixacl_group_getntacl_smbd(self):
        lp = LoadParm()
        acl = "O:S-1-5-21-2212615479-2695158682-2101375467-512G:S-1-5-21-2212615479-2695158682-2101375467-513D:(A;OICI;0x001f01ff;;;S-1-5-21-2212615479-2695158682-2101375467-512)"
        BA_sid = security.dom_sid(security.SID_BUILTIN_ADMINISTRATORS)
        simple_acl_from_posix = "O:S-1-5-21-2212615479-2695158682-2101375467-512G:S-1-5-21-2212615479-2695158682-2101375467-513D:(A;;0x001f019f;;;S-1-5-21-2212615479-2695158682-2101375467-512)(A;;0x00120089;;;BA)(A;;0x00120089;;;S-1-5-21-2212615479-2695158682-2101375467-513)(A;;WO;;;WD)"
        setntacl(lp,self.tempf,acl,"S-1-5-21-2212615479-2695158682-2101375467", use_ntvfs=False)
        # This invalidates the hash of the NT acl just set because there is a hook in the posix ACL set code
        s3conf = s3param.get_context()
        s4_passdb = passdb.PDB(s3conf.get("passdb backend"))
        (BA_gid,BA_type) = s4_passdb.sid_to_id(BA_sid)
        smbd.set_simple_acl(self.tempf, 0640, BA_gid)

        # This should re-calculate an ACL based on the posix details
        facl = getntacl(lp,self.tempf, direct_db_access=False)
        anysid = security.dom_sid(security.SID_NT_SELF)
        self.assertEquals(simple_acl_from_posix, facl.as_sddl(anysid))

    def test_setntacl_smbd_getntacl_smbd_gpo(self):
        lp = LoadParm()
        acl = "O:DAG:DUD:P(A;OICI;0x001f01ff;;;DA)(A;OICI;0x001f01ff;;;EA)(A;OICIIO;0x001f01ff;;;CO)(A;OICI;0x001f01ff;;;DA)(A;OICI;0x001f01ff;;;SY)(A;OICI;0x001200a9;;;AU)(A;OICI;0x001200a9;;;ED)S:AI(OU;CIIDSA;WP;f30e3bbe-9ff0-11d1-b603-0000f80367c1;bf967aa5-0de6-11d0-a285-00aa003049e2;WD)(OU;CIIDSA;WP;f30e3bbf-9ff0-11d1-b603-0000f80367c1;bf967aa5-0de6-11d0-a285-00aa003049e2;WD)"
        setntacl(lp, self.tempf,acl,"S-1-5-21-2212615479-2695158682-2101375467", use_ntvfs=False)
        facl = getntacl(lp, self.tempf, direct_db_access=False)
        domsid = security.dom_sid("S-1-5-21-2212615479-2695158682-2101375467")
        self.assertEquals(facl.as_sddl(domsid),acl)

    def test_setntacl_getposixacl(self):
        lp = LoadParm()
        acl = "O:S-1-5-21-2212615479-2695158682-2101375467-512G:S-1-5-21-2212615479-2695158682-2101375467-513D:(A;OICI;0x001f01ff;;;S-1-5-21-2212615479-2695158682-2101375467-512)"
        setntacl(lp, self.tempf,acl,"S-1-5-21-2212615479-2695158682-2101375467", use_ntvfs=False)
        facl = getntacl(lp, self.tempf)
        anysid = security.dom_sid(security.SID_NT_SELF)
        self.assertEquals(facl.as_sddl(anysid),acl)
        posix_acl = smbd.get_sys_acl(self.tempf, smb_acl.SMB_ACL_TYPE_ACCESS)

    def test_setposixacl_getposixacl(self):
        lp = LoadParm()
        smbd.set_simple_acl(self.tempf, 0640)
        posix_acl = smbd.get_sys_acl(self.tempf, smb_acl.SMB_ACL_TYPE_ACCESS)
        self.assertEquals(posix_acl.count, 4)

        self.assertEquals(posix_acl.acl[0].a_type, smb_acl.SMB_ACL_USER_OBJ)
        self.assertEquals(posix_acl.acl[0].a_perm, 6)

        self.assertEquals(posix_acl.acl[1].a_type, smb_acl.SMB_ACL_GROUP_OBJ)
        self.assertEquals(posix_acl.acl[1].a_perm, 4)

        self.assertEquals(posix_acl.acl[2].a_type, smb_acl.SMB_ACL_OTHER)
        self.assertEquals(posix_acl.acl[2].a_perm, 0)

        self.assertEquals(posix_acl.acl[3].a_type, smb_acl.SMB_ACL_MASK)
        self.assertEquals(posix_acl.acl[3].a_perm, 6)

    def test_setposixacl_getntacl(self):
        lp = LoadParm()
        acl = ""
        smbd.set_simple_acl(self.tempf, 0750)
        try:
            facl = getntacl(lp, self.tempf)
            self.assertTrue(False)
        except TypeError:
            # We don't expect the xattr to be filled in in this case
            pass

    def test_setposixacl_getntacl_smbd(self):
        lp = LoadParm()
        s3conf = s3param.get_context()
        s4_passdb = passdb.PDB(s3conf.get("passdb backend"))
        group_SID = s4_passdb.gid_to_sid(os.stat(self.tempf).st_gid)
        user_SID = s4_passdb.uid_to_sid(os.stat(self.tempf).st_uid)
        smbd.set_simple_acl(self.tempf, 0640)
        facl = getntacl(lp, self.tempf, direct_db_access=False)
        acl = "O:%sG:%sD:(A;;0x001f019f;;;%s)(A;;0x00120089;;;%s)(A;;WO;;;WD)" % (user_SID, group_SID, user_SID, group_SID)
        anysid = security.dom_sid(security.SID_NT_SELF)
        self.assertEquals(acl, facl.as_sddl(anysid))

    def test_setposixacl_dir_getntacl_smbd(self):
        lp = LoadParm()
        s3conf = s3param.get_context()
        s4_passdb = passdb.PDB(s3conf.get("passdb backend"))
        user_SID = s4_passdb.uid_to_sid(os.stat(self.tempdir).st_uid)
        smbd.set_simple_acl(self.tempdir, 0750)
        facl = getntacl(lp, self.tempdir, direct_db_access=False)
        acl = "O:%sG:BAD:(A;;0x001f01ff;;;%s)(A;;0x001200a9;;;BA)(A;;WO;;;WD)(A;OICIIO;0x001f01ff;;;CO)(A;OICIIO;0x001f01ff;;;CG)(A;OICIIO;0x001f01ff;;;WD)" % (user_SID, user_SID)

        anysid = security.dom_sid(security.SID_NT_SELF)
        self.assertEquals(acl, facl.as_sddl(anysid))

    def test_setposixacl_group_getntacl_smbd(self):
        lp = LoadParm()
        BA_sid = security.dom_sid(security.SID_BUILTIN_ADMINISTRATORS)
        s3conf = s3param.get_context()
        s4_passdb = passdb.PDB(s3conf.get("passdb backend"))
        (BA_gid,BA_type) = s4_passdb.sid_to_id(BA_sid)
        group_SID = s4_passdb.gid_to_sid(os.stat(self.tempf).st_gid)
        user_SID = s4_passdb.uid_to_sid(os.stat(self.tempf).st_uid)
        self.assertEquals(BA_type, idmap.ID_TYPE_BOTH)
        smbd.set_simple_acl(self.tempf, 0640, BA_gid)
        facl = getntacl(lp, self.tempf, direct_db_access=False)
        domsid = passdb.get_global_sam_sid()
        acl = "O:%sG:%sD:(A;;0x001f019f;;;%s)(A;;0x00120089;;;BA)(A;;0x00120089;;;%s)(A;;WO;;;WD)" % (user_SID, group_SID, user_SID, group_SID)
        anysid = security.dom_sid(security.SID_NT_SELF)
        self.assertEquals(acl, facl.as_sddl(anysid))

    def test_setposixacl_getposixacl(self):
        lp = LoadParm()
        smbd.set_simple_acl(self.tempf, 0640)
        posix_acl = smbd.get_sys_acl(self.tempf, smb_acl.SMB_ACL_TYPE_ACCESS)
        self.assertEquals(posix_acl.count, 4)

        self.assertEquals(posix_acl.acl[0].a_type, smb_acl.SMB_ACL_USER_OBJ)
        self.assertEquals(posix_acl.acl[0].a_perm, 6)

        self.assertEquals(posix_acl.acl[1].a_type, smb_acl.SMB_ACL_GROUP_OBJ)
        self.assertEquals(posix_acl.acl[1].a_perm, 4)

        self.assertEquals(posix_acl.acl[2].a_type, smb_acl.SMB_ACL_OTHER)
        self.assertEquals(posix_acl.acl[2].a_perm, 0)

        self.assertEquals(posix_acl.acl[3].a_type, smb_acl.SMB_ACL_MASK)
        self.assertEquals(posix_acl.acl[3].a_perm, 7)

    def test_setposixacl_dir_getposixacl(self):
        lp = LoadParm()
        smbd.set_simple_acl(self.tempdir, 0750)
        posix_acl = smbd.get_sys_acl(self.tempdir, smb_acl.SMB_ACL_TYPE_ACCESS)
        self.assertEquals(posix_acl.count, 4)

        self.assertEquals(posix_acl.acl[0].a_type, smb_acl.SMB_ACL_USER_OBJ)
        self.assertEquals(posix_acl.acl[0].a_perm, 7)

        self.assertEquals(posix_acl.acl[1].a_type, smb_acl.SMB_ACL_GROUP_OBJ)
        self.assertEquals(posix_acl.acl[1].a_perm, 5)

        self.assertEquals(posix_acl.acl[2].a_type, smb_acl.SMB_ACL_OTHER)
        self.assertEquals(posix_acl.acl[2].a_perm, 0)

        self.assertEquals(posix_acl.acl[3].a_type, smb_acl.SMB_ACL_MASK)
        self.assertEquals(posix_acl.acl[3].a_perm, 7)

    def test_setposixacl_group_getposixacl(self):
        lp = LoadParm()
        BA_sid = security.dom_sid(security.SID_BUILTIN_ADMINISTRATORS)
        s3conf = s3param.get_context()
        s4_passdb = passdb.PDB(s3conf.get("passdb backend"))
        (BA_gid,BA_type) = s4_passdb.sid_to_id(BA_sid)
        self.assertEquals(BA_type, idmap.ID_TYPE_BOTH)
        smbd.set_simple_acl(self.tempf, 0670, BA_gid)
        posix_acl = smbd.get_sys_acl(self.tempf, smb_acl.SMB_ACL_TYPE_ACCESS)

        self.assertEquals(posix_acl.count, 5)

        self.assertEquals(posix_acl.acl[0].a_type, smb_acl.SMB_ACL_USER_OBJ)
        self.assertEquals(posix_acl.acl[0].a_perm, 6)

        self.assertEquals(posix_acl.acl[1].a_type, smb_acl.SMB_ACL_GROUP_OBJ)
        self.assertEquals(posix_acl.acl[1].a_perm, 7)

        self.assertEquals(posix_acl.acl[2].a_type, smb_acl.SMB_ACL_OTHER)
        self.assertEquals(posix_acl.acl[2].a_perm, 0)

        self.assertEquals(posix_acl.acl[3].a_type, smb_acl.SMB_ACL_GROUP)
        self.assertEquals(posix_acl.acl[3].a_perm, 7)
        self.assertEquals(posix_acl.acl[3].info.gid, BA_gid)

        self.assertEquals(posix_acl.acl[4].a_type, smb_acl.SMB_ACL_MASK)
        self.assertEquals(posix_acl.acl[4].a_perm, 7)

    def test_setntacl_sysvol_check_getposixacl(self):
        lp = LoadParm()
        s3conf = s3param.get_context()
        acl = provision.SYSVOL_ACL
        domsid = passdb.get_global_sam_sid()
        setntacl(lp, self.tempf,acl,str(domsid), use_ntvfs=False)
        facl = getntacl(lp, self.tempf)
        self.assertEquals(facl.as_sddl(domsid),acl)
        posix_acl = smbd.get_sys_acl(self.tempf, smb_acl.SMB_ACL_TYPE_ACCESS)

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


    def test_setntacl_sysvol_dir_check_getposixacl(self):
        lp = LoadParm()
        s3conf = s3param.get_context()
        acl = provision.SYSVOL_ACL
        domsid = passdb.get_global_sam_sid()
        setntacl(lp, self.tempdir,acl,str(domsid), use_ntvfs=False)
        facl = getntacl(lp, self.tempdir)
        self.assertEquals(facl.as_sddl(domsid),acl)
        posix_acl = smbd.get_sys_acl(self.tempdir, smb_acl.SMB_ACL_TYPE_ACCESS)

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
        self.assertEquals(posix_acl.acl[1].a_perm, 7)
        self.assertEquals(posix_acl.acl[1].info.uid, LA_uid)

        self.assertEquals(posix_acl.acl[2].a_type, smb_acl.SMB_ACL_OTHER)
        self.assertEquals(posix_acl.acl[2].a_perm, 0)

        self.assertEquals(posix_acl.acl[3].a_type, smb_acl.SMB_ACL_USER_OBJ)
        self.assertEquals(posix_acl.acl[3].a_perm, 7)

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
# group:3000000:rwx
# group:3000001:r-x
# group:3000002:rwx
# group:3000003:r-x
# mask::rwx
# other::---


    def test_setntacl_policies_dir_check_getposixacl(self):
        lp = LoadParm()
        s3conf = s3param.get_context()
        acl = provision.POLICIES_ACL
        domsid = passdb.get_global_sam_sid()
        setntacl(lp, self.tempdir,acl,str(domsid), use_ntvfs=False)
        facl = getntacl(lp, self.tempdir)
        self.assertEquals(facl.as_sddl(domsid),acl)
        posix_acl = smbd.get_sys_acl(self.tempdir, smb_acl.SMB_ACL_TYPE_ACCESS)

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
        self.assertEquals(posix_acl.acl[1].a_perm, 7)
        self.assertEquals(posix_acl.acl[1].info.uid, LA_uid)

        self.assertEquals(posix_acl.acl[2].a_type, smb_acl.SMB_ACL_OTHER)
        self.assertEquals(posix_acl.acl[2].a_perm, 0)

        self.assertEquals(posix_acl.acl[3].a_type, smb_acl.SMB_ACL_USER_OBJ)
        self.assertEquals(posix_acl.acl[3].a_perm, 7)

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
# user:root:rwx  (selftest user actually)
# group::rwx
# group:3000000:rwx
# group:3000001:r-x
# group:3000002:rwx
# group:3000003:r-x
# group:3000004:rwx
# mask::rwx
# other::---



    def test_setntacl_policies_check_getposixacl(self):
        lp = LoadParm()
        s3conf = s3param.get_context()
        acl = provision.POLICIES_ACL

        domsid = passdb.get_global_sam_sid()
        setntacl(lp, self.tempf,acl,str(domsid), use_ntvfs=False)
        facl = getntacl(lp, self.tempf)
        self.assertEquals(facl.as_sddl(domsid),acl)
        posix_acl = smbd.get_sys_acl(self.tempf, smb_acl.SMB_ACL_TYPE_ACCESS)

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

    def setUp(self):
        super(PosixAclMappingTests, self).setUp()
        s3conf = s3param.get_context()
        s3conf.load(self.get_loadparm().configfile)
        self.tempf = os.path.join(self.tempdir, "test")
        open(self.tempf, 'w').write("empty")

    def tearDown(self):
        smbd.unlink(self.tempf)
        super(PosixAclMappingTests, self).tearDown()
