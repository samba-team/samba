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
from samba.dcerpc import security, smb_acl, idmap
from samba.tests.smbd_base import SmbdBaseTests
from samba import provision
import os
from samba.samba3 import smbd, passdb
from samba.samba3 import param as s3param
from samba import auth
from samba.samdb import SamDB
from samba.auth_util import system_session_unix

DOM_SID = "S-1-5-21-2212615479-2695158682-2101375467"
ACL = "O:S-1-5-21-2212615479-2695158682-2101375467-512G:S-1-5-21-2212615479-2695158682-2101375467-513D:(A;OICI;0x001f01ff;;;S-1-5-21-2212615479-2695158682-2101375467-512)"


class PosixAclMappingTests(SmbdBaseTests):

    def setUp(self):
        super(PosixAclMappingTests, self).setUp()
        s3conf = s3param.get_context()
        s3conf.load(self.get_loadparm().configfile)
        s3conf.set("xattr_tdb:file", os.path.join(self.tempdir, "xattr.tdb"))
        self.lp = s3conf
        self.tempf = os.path.join(self.tempdir, "test")
        open(self.tempf, 'w').write("empty")
        self.samdb = SamDB(lp=self.lp, session_info=auth.system_session())

    def tearDown(self):
        smbd.unlink(self.tempf, self.get_session_info())
        os.unlink(os.path.join(self.tempdir, "xattr.tdb"))
        super(PosixAclMappingTests, self).tearDown()

    def get_session_info(self, domsid=DOM_SID):
        """
        Get session_info for setntacl.
        """
        return system_session_unix()

    def print_posix_acl(self, posix_acl):
        aclstr = ""
        for entry in posix_acl.acl:
            aclstr += "a_type: %d\n" % entry.a_type +\
                      "a_perm: %o\n" % entry.a_perm
            if entry.a_type == smb_acl.SMB_ACL_USER:
                aclstr += "uid: %d\n" % entry.info.uid
            if entry.a_type == smb_acl.SMB_ACL_GROUP:
                aclstr += "gid: %d\n" % entry.info.gid
        return aclstr

    def test_setntacl(self):
        acl = ACL
        setntacl(self.lp, self.tempf, acl, DOM_SID,
                 self.get_session_info(), use_ntvfs=False)

    def test_setntacl_smbd_getntacl(self):
        acl = ACL
        setntacl(self.lp, self.tempf, acl, DOM_SID,
                 self.get_session_info(), use_ntvfs=True)
        facl = getntacl(self.lp, self.tempf, self.get_session_info(), direct_db_access=True)
        anysid = security.dom_sid(security.SID_NT_SELF)
        self.assertEqual(facl.as_sddl(anysid), acl)

    def test_setntacl_smbd_setposixacl_getntacl(self):
        acl = ACL
        setntacl(self.lp, self.tempf, acl, DOM_SID,
                 self.get_session_info(), use_ntvfs=True)

        # This will invalidate the ACL, as we have a hook!
        smbd.set_simple_acl(self.tempf, 0o640, self.get_session_info())

        # However, this only asks the xattr
        self.assertRaises(
            TypeError, getntacl, self.lp, self.tempf, self.get_session_info(), direct_db_access=True)

    def test_setntacl_invalidate_getntacl(self):
        acl = ACL
        setntacl(self.lp, self.tempf, acl, DOM_SID,
                 self.get_session_info(), use_ntvfs=True)

        # This should invalidate the ACL, as we include the posix ACL in the hash
        (backend_obj, dbname) = checkset_backend(self.lp, None, None)
        backend_obj.wrap_setxattr(dbname,
                                  self.tempf, "system.fake_access_acl", b"")

        # however, as this is direct DB access, we do not notice it
        facl = getntacl(self.lp, self.tempf, self.get_session_info(), direct_db_access=True)
        anysid = security.dom_sid(security.SID_NT_SELF)
        self.assertEqual(acl, facl.as_sddl(anysid))

    def test_setntacl_invalidate_getntacl_smbd(self):
        acl = ACL
        setntacl(self.lp, self.tempf, acl, DOM_SID,
                 self.get_session_info(), use_ntvfs=False)

        # This should invalidate the ACL, as we include the posix ACL in the hash
        (backend_obj, dbname) = checkset_backend(self.lp, None, None)
        backend_obj.wrap_setxattr(dbname,
                                  self.tempf, "system.fake_access_acl", b"")

        # the hash would break, and we return an ACL based only on the mode, except we set the ACL using the 'ntvfs' mode that doesn't include a hash
        facl = getntacl(self.lp, self.tempf, self.get_session_info())
        anysid = security.dom_sid(security.SID_NT_SELF)
        self.assertEqual(acl, facl.as_sddl(anysid))

    def test_setntacl_smbd_invalidate_getntacl_smbd(self):
        acl = ACL
        simple_acl_from_posix = "O:S-1-5-21-2212615479-2695158682-2101375467-512G:S-1-5-21-2212615479-2695158682-2101375467-513D:(A;;0x001f01ff;;;S-1-5-21-2212615479-2695158682-2101375467-512)(A;;0x001200a9;;;S-1-5-21-2212615479-2695158682-2101375467-513)(A;;;;;WD)"
        os.chmod(self.tempf, 0o750)
        setntacl(self.lp, self.tempf, acl, DOM_SID,
                 self.get_session_info(), use_ntvfs=False)

        # This should invalidate the ACL, as we include the posix ACL in the hash
        (backend_obj, dbname) = checkset_backend(self.lp, None, None)
        backend_obj.wrap_setxattr(dbname,
                                  self.tempf, "system.fake_access_acl", b"")

        # the hash will break, and we return an ACL based only on the mode
        facl = getntacl(self.lp, self.tempf, self.get_session_info(), direct_db_access=False)
        anysid = security.dom_sid(security.SID_NT_SELF)
        self.assertEqual(simple_acl_from_posix, facl.as_sddl(anysid))

    def test_setntacl_getntacl_smbd(self):
        acl = ACL
        setntacl(self.lp, self.tempf, acl, DOM_SID,
                 self.get_session_info(), use_ntvfs=True)
        facl = getntacl(self.lp, self.tempf, self.get_session_info(), direct_db_access=False)
        anysid = security.dom_sid(security.SID_NT_SELF)
        self.assertEqual(facl.as_sddl(anysid), acl)

    def test_setntacl_smbd_getntacl_smbd(self):
        acl = ACL
        setntacl(self.lp, self.tempf, acl, DOM_SID,
                 self.get_session_info(), use_ntvfs=False)
        facl = getntacl(self.lp, self.tempf, self.get_session_info(), direct_db_access=False)
        anysid = security.dom_sid(security.SID_NT_SELF)
        self.assertEqual(facl.as_sddl(anysid), acl)

    def test_setntacl_smbd_setposixacl_getntacl_smbd(self):
        acl = ACL
        simple_acl_from_posix = "O:S-1-5-21-2212615479-2695158682-2101375467-512G:S-1-5-21-2212615479-2695158682-2101375467-513D:(A;;0x001f019f;;;S-1-5-21-2212615479-2695158682-2101375467-512)(A;;0x00120089;;;S-1-5-21-2212615479-2695158682-2101375467-513)(A;;;;;WD)"
        setntacl(self.lp, self.tempf, acl, DOM_SID,
                 self.get_session_info(), use_ntvfs=False)
        # This invalidates the hash of the NT acl just set because there is a hook in the posix ACL set code
        smbd.set_simple_acl(self.tempf, 0o640, self.get_session_info())
        facl = getntacl(self.lp, self.tempf, self.get_session_info(), direct_db_access=False)
        anysid = security.dom_sid(security.SID_NT_SELF)
        self.assertEqual(simple_acl_from_posix, facl.as_sddl(anysid))

    def test_setntacl_smbd_setposixacl_group_getntacl_smbd(self):
        acl = ACL
        BA_sid = security.dom_sid(security.SID_BUILTIN_ADMINISTRATORS)
        simple_acl_from_posix = "O:S-1-5-21-2212615479-2695158682-2101375467-512G:S-1-5-21-2212615479-2695158682-2101375467-513D:(A;;0x001f019f;;;S-1-5-21-2212615479-2695158682-2101375467-512)(A;;0x00120089;;;BA)(A;;0x00120089;;;S-1-5-21-2212615479-2695158682-2101375467-513)(A;;;;;WD)"
        setntacl(self.lp, self.tempf, acl, DOM_SID,
                 self.get_session_info(), use_ntvfs=False)
        # This invalidates the hash of the NT acl just set because there is a hook in the posix ACL set code
        s4_passdb = passdb.PDB(self.lp.get("passdb backend"))
        (BA_gid, BA_type) = s4_passdb.sid_to_id(BA_sid)
        smbd.set_simple_acl(self.tempf, 0o640, self.get_session_info(), BA_gid)

        # This should re-calculate an ACL based on the posix details
        facl = getntacl(self.lp, self.tempf, self.get_session_info(), direct_db_access=False)
        anysid = security.dom_sid(security.SID_NT_SELF)
        self.assertEqual(simple_acl_from_posix, facl.as_sddl(anysid))

    def test_setntacl_smbd_getntacl_smbd_gpo(self):
        acl = "O:DAG:DUD:P(A;OICI;0x001f01ff;;;DA)(A;OICI;0x001f01ff;;;EA)(A;OICIIO;0x001f01ff;;;CO)(A;OICI;0x001f01ff;;;DA)(A;OICI;0x001f01ff;;;SY)(A;OICI;0x001200a9;;;AU)(A;OICI;0x001200a9;;;ED)S:AI(OU;CIIDSA;WP;f30e3bbe-9ff0-11d1-b603-0000f80367c1;bf967aa5-0de6-11d0-a285-00aa003049e2;WD)(OU;CIIDSA;WP;f30e3bbf-9ff0-11d1-b603-0000f80367c1;bf967aa5-0de6-11d0-a285-00aa003049e2;WD)"
        setntacl(self.lp, self.tempf, acl, DOM_SID,
                 self.get_session_info(), use_ntvfs=False)
        facl = getntacl(self.lp, self.tempf, self.get_session_info(), direct_db_access=False)
        domsid = security.dom_sid(DOM_SID)
        self.assertEqual(facl.as_sddl(domsid), acl)

    def test_setntacl_getposixacl(self):
        acl = ACL
        setntacl(self.lp, self.tempf, acl, DOM_SID,
                 self.get_session_info(), use_ntvfs=False)
        facl = getntacl(self.lp, self.tempf, self.get_session_info())
        anysid = security.dom_sid(security.SID_NT_SELF)
        self.assertEqual(facl.as_sddl(anysid), acl)
        posix_acl = smbd.get_sys_acl(self.tempf, smb_acl.SMB_ACL_TYPE_ACCESS, self.get_session_info())

    def test_setposixacl_getntacl(self):
        smbd.set_simple_acl(self.tempf, 0o750, self.get_session_info())
        # We don't expect the xattr to be filled in in this case
        self.assertRaises(TypeError, getntacl, self.lp, self.tempf, self.get_session_info())

    def test_setposixacl_getntacl_smbd(self):
        s4_passdb = passdb.PDB(self.lp.get("passdb backend"))
        group_SID = s4_passdb.gid_to_sid(os.stat(self.tempf).st_gid)
        user_SID = s4_passdb.uid_to_sid(os.stat(self.tempf).st_uid)
        smbd.set_simple_acl(self.tempf, 0o640, self.get_session_info())
        facl = getntacl(self.lp, self.tempf, self.get_session_info(), direct_db_access=False)
        acl = "O:%sG:%sD:(A;;0x001f019f;;;%s)(A;;0x00120089;;;%s)(A;;;;;WD)" % (user_SID, group_SID, user_SID, group_SID)
        anysid = security.dom_sid(security.SID_NT_SELF)
        self.assertEqual(acl, facl.as_sddl(anysid))

    def test_setposixacl_dir_getntacl_smbd(self):
        s4_passdb = passdb.PDB(self.lp.get("passdb backend"))
        user_SID = s4_passdb.uid_to_sid(os.stat(self.tempdir).st_uid)
        BA_sid = security.dom_sid(security.SID_BUILTIN_ADMINISTRATORS)
        s4_passdb = passdb.PDB(self.lp.get("passdb backend"))
        (BA_id, BA_type) = s4_passdb.sid_to_id(BA_sid)
        self.assertEqual(BA_type, idmap.ID_TYPE_BOTH)
        SO_sid = security.dom_sid(security.SID_BUILTIN_SERVER_OPERATORS)
        (SO_id, SO_type) = s4_passdb.sid_to_id(SO_sid)
        self.assertEqual(SO_type, idmap.ID_TYPE_BOTH)
        smbd.chown(self.tempdir, BA_id, SO_id, self.get_session_info())
        smbd.set_simple_acl(self.tempdir, 0o750, self.get_session_info())
        facl = getntacl(self.lp, self.tempdir, self.get_session_info(), direct_db_access=False)
        acl = "O:BAG:SOD:(A;;0x001f01ff;;;BA)(A;;0x001200a9;;;SO)(A;;;;;WD)(A;OICIIO;0x001f01ff;;;CO)(A;OICIIO;0x001200a9;;;CG)(A;OICIIO;0x001200a9;;;WD)"

        anysid = security.dom_sid(security.SID_NT_SELF)
        self.assertEqual(acl, facl.as_sddl(anysid))

    def test_setposixacl_group_getntacl_smbd(self):
        BA_sid = security.dom_sid(security.SID_BUILTIN_ADMINISTRATORS)
        s4_passdb = passdb.PDB(self.lp.get("passdb backend"))
        (BA_gid, BA_type) = s4_passdb.sid_to_id(BA_sid)
        group_SID = s4_passdb.gid_to_sid(os.stat(self.tempf).st_gid)
        user_SID = s4_passdb.uid_to_sid(os.stat(self.tempf).st_uid)
        self.assertEqual(BA_type, idmap.ID_TYPE_BOTH)
        smbd.set_simple_acl(self.tempf, 0o640, self.get_session_info(), BA_gid)
        facl = getntacl(self.lp, self.tempf, self.get_session_info(), direct_db_access=False)
        domsid = passdb.get_global_sam_sid()
        acl = "O:%sG:%sD:(A;;0x001f019f;;;%s)(A;;0x00120089;;;BA)(A;;0x00120089;;;%s)(A;;;;;WD)" % (user_SID, group_SID, user_SID, group_SID)
        anysid = security.dom_sid(security.SID_NT_SELF)
        self.assertEqual(acl, facl.as_sddl(anysid))

    def test_setposixacl_getposixacl(self):
        smbd.set_simple_acl(self.tempf, 0o640, self.get_session_info())
        posix_acl = smbd.get_sys_acl(self.tempf, smb_acl.SMB_ACL_TYPE_ACCESS, self.get_session_info())
        self.assertEqual(posix_acl.count, 4, self.print_posix_acl(posix_acl))

        self.assertEqual(posix_acl.acl[0].a_type, smb_acl.SMB_ACL_USER_OBJ)
        self.assertEqual(posix_acl.acl[0].a_perm, 6)

        self.assertEqual(posix_acl.acl[1].a_type, smb_acl.SMB_ACL_GROUP_OBJ)
        self.assertEqual(posix_acl.acl[1].a_perm, 4)

        self.assertEqual(posix_acl.acl[2].a_type, smb_acl.SMB_ACL_OTHER)
        self.assertEqual(posix_acl.acl[2].a_perm, 0)

        self.assertEqual(posix_acl.acl[3].a_type, smb_acl.SMB_ACL_MASK)
        self.assertEqual(posix_acl.acl[3].a_perm, 7)

    def test_setposixacl_dir_getposixacl(self):
        smbd.set_simple_acl(self.tempdir, 0o750, self.get_session_info())
        posix_acl = smbd.get_sys_acl(self.tempdir, smb_acl.SMB_ACL_TYPE_ACCESS, self.get_session_info())
        self.assertEqual(posix_acl.count, 4, self.print_posix_acl(posix_acl))

        self.assertEqual(posix_acl.acl[0].a_type, smb_acl.SMB_ACL_USER_OBJ)
        self.assertEqual(posix_acl.acl[0].a_perm, 7)

        self.assertEqual(posix_acl.acl[1].a_type, smb_acl.SMB_ACL_GROUP_OBJ)
        self.assertEqual(posix_acl.acl[1].a_perm, 5)

        self.assertEqual(posix_acl.acl[2].a_type, smb_acl.SMB_ACL_OTHER)
        self.assertEqual(posix_acl.acl[2].a_perm, 0)

        self.assertEqual(posix_acl.acl[3].a_type, smb_acl.SMB_ACL_MASK)
        self.assertEqual(posix_acl.acl[3].a_perm, 7)

    def test_setposixacl_group_getposixacl(self):
        BA_sid = security.dom_sid(security.SID_BUILTIN_ADMINISTRATORS)
        s4_passdb = passdb.PDB(self.lp.get("passdb backend"))
        (BA_gid, BA_type) = s4_passdb.sid_to_id(BA_sid)
        self.assertEqual(BA_type, idmap.ID_TYPE_BOTH)
        smbd.set_simple_acl(self.tempf, 0o670, self.get_session_info(), BA_gid)
        posix_acl = smbd.get_sys_acl(self.tempf, smb_acl.SMB_ACL_TYPE_ACCESS, self.get_session_info())

        self.assertEqual(posix_acl.count, 5, self.print_posix_acl(posix_acl))

        self.assertEqual(posix_acl.acl[0].a_type, smb_acl.SMB_ACL_USER_OBJ)
        self.assertEqual(posix_acl.acl[0].a_perm, 6)

        self.assertEqual(posix_acl.acl[1].a_type, smb_acl.SMB_ACL_GROUP_OBJ)
        self.assertEqual(posix_acl.acl[1].a_perm, 7)

        self.assertEqual(posix_acl.acl[2].a_type, smb_acl.SMB_ACL_OTHER)
        self.assertEqual(posix_acl.acl[2].a_perm, 0)

        self.assertEqual(posix_acl.acl[3].a_type, smb_acl.SMB_ACL_GROUP)
        self.assertEqual(posix_acl.acl[3].a_perm, 7)
        self.assertEqual(posix_acl.acl[3].info.gid, BA_gid)

        self.assertEqual(posix_acl.acl[4].a_type, smb_acl.SMB_ACL_MASK)
        self.assertEqual(posix_acl.acl[4].a_perm, 7)

    def test_setntacl_sysvol_check_getposixacl(self):
        acl = provision.SYSVOL_ACL
        domsid = passdb.get_global_sam_sid()
        session_info = self.get_session_info(domsid)
        setntacl(self.lp, self.tempf, acl, str(domsid),
                 session_info, use_ntvfs=False)
        facl = getntacl(self.lp, self.tempf, session_info)
        self.assertEqual(facl.as_sddl(domsid), acl)
        posix_acl = smbd.get_sys_acl(self.tempf, smb_acl.SMB_ACL_TYPE_ACCESS, session_info)

        nwrap_module_so_path = os.getenv('NSS_WRAPPER_MODULE_SO_PATH')
        nwrap_module_fn_prefix = os.getenv('NSS_WRAPPER_MODULE_FN_PREFIX')

        nwrap_winbind_active = (nwrap_module_so_path != "" and
                                nwrap_module_fn_prefix == "winbind")
        is_user_session = not session_info.security_token.is_system()

        LA_sid = security.dom_sid(str(domsid) + "-" + str(security.DOMAIN_RID_ADMINISTRATOR))
        BA_sid = security.dom_sid(security.SID_BUILTIN_ADMINISTRATORS)
        SO_sid = security.dom_sid(security.SID_BUILTIN_SERVER_OPERATORS)
        SY_sid = security.dom_sid(security.SID_NT_SYSTEM)
        AU_sid = security.dom_sid(security.SID_NT_AUTHENTICATED_USERS)

        s4_passdb = passdb.PDB(self.lp.get("passdb backend"))

        # These assertions correct for current ad_dc selftest
        # configuration.  When other environments have a broad range of
        # groups mapped via passdb, we can relax some of these checks
        (LA_uid, LA_type) = s4_passdb.sid_to_id(LA_sid)
        self.assertEqual(LA_type, idmap.ID_TYPE_UID)
        (BA_gid, BA_type) = s4_passdb.sid_to_id(BA_sid)
        self.assertEqual(BA_type, idmap.ID_TYPE_BOTH)
        (SO_gid, SO_type) = s4_passdb.sid_to_id(SO_sid)
        self.assertEqual(SO_type, idmap.ID_TYPE_BOTH)
        (SY_gid, SY_type) = s4_passdb.sid_to_id(SY_sid)
        self.assertEqual(SO_type, idmap.ID_TYPE_BOTH)
        (AU_gid, AU_type) = s4_passdb.sid_to_id(AU_sid)
        self.assertEqual(AU_type, idmap.ID_TYPE_BOTH)

        self.assertEqual(posix_acl.count, 13, self.print_posix_acl(posix_acl))

        self.assertEqual(posix_acl.acl[0].a_type, smb_acl.SMB_ACL_GROUP)
        self.assertEqual(posix_acl.acl[0].a_perm, 7)
        self.assertEqual(posix_acl.acl[0].info.gid, BA_gid)

        self.assertEqual(posix_acl.acl[1].a_type, smb_acl.SMB_ACL_USER)
        if nwrap_winbind_active or is_user_session:
            self.assertEqual(posix_acl.acl[1].a_perm, 7)
        else:
            self.assertEqual(posix_acl.acl[1].a_perm, 6)
        self.assertEqual(posix_acl.acl[1].info.uid, LA_uid)

        self.assertEqual(posix_acl.acl[2].a_type, smb_acl.SMB_ACL_OTHER)
        self.assertEqual(posix_acl.acl[2].a_perm, 0)

        self.assertEqual(posix_acl.acl[3].a_type, smb_acl.SMB_ACL_USER_OBJ)
        if nwrap_winbind_active or is_user_session:
            self.assertEqual(posix_acl.acl[3].a_perm, 7)
        else:
            self.assertEqual(posix_acl.acl[3].a_perm, 6)

        self.assertEqual(posix_acl.acl[4].a_type, smb_acl.SMB_ACL_USER)
        self.assertEqual(posix_acl.acl[4].a_perm, 7)
        self.assertEqual(posix_acl.acl[4].info.uid, BA_gid)

        self.assertEqual(posix_acl.acl[5].a_type, smb_acl.SMB_ACL_GROUP_OBJ)
        self.assertEqual(posix_acl.acl[5].a_perm, 7)

        self.assertEqual(posix_acl.acl[6].a_type, smb_acl.SMB_ACL_USER)
        self.assertEqual(posix_acl.acl[6].a_perm, 5)
        self.assertEqual(posix_acl.acl[6].info.uid, SO_gid)

        self.assertEqual(posix_acl.acl[7].a_type, smb_acl.SMB_ACL_GROUP)
        self.assertEqual(posix_acl.acl[7].a_perm, 5)
        self.assertEqual(posix_acl.acl[7].info.gid, SO_gid)

        self.assertEqual(posix_acl.acl[8].a_type, smb_acl.SMB_ACL_USER)
        self.assertEqual(posix_acl.acl[8].a_perm, 7)
        self.assertEqual(posix_acl.acl[8].info.uid, SY_gid)

        self.assertEqual(posix_acl.acl[9].a_type, smb_acl.SMB_ACL_GROUP)
        self.assertEqual(posix_acl.acl[9].a_perm, 7)
        self.assertEqual(posix_acl.acl[9].info.gid, SY_gid)

        self.assertEqual(posix_acl.acl[10].a_type, smb_acl.SMB_ACL_USER)
        self.assertEqual(posix_acl.acl[10].a_perm, 5)
        self.assertEqual(posix_acl.acl[10].info.uid, AU_gid)

        self.assertEqual(posix_acl.acl[11].a_type, smb_acl.SMB_ACL_GROUP)
        self.assertEqual(posix_acl.acl[11].a_perm, 5)
        self.assertEqual(posix_acl.acl[11].info.gid, AU_gid)

        self.assertEqual(posix_acl.acl[12].a_type, smb_acl.SMB_ACL_MASK)
        self.assertEqual(posix_acl.acl[12].a_perm, 7)

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

        # This is in this order in the NDR smb_acl(not re-orderded for display)
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

    def test_setntacl_sysvol_dir_check_getposixacl(self):
        acl = provision.SYSVOL_ACL
        domsid = passdb.get_global_sam_sid()
        session_info = self.get_session_info(domsid)
        setntacl(self.lp, self.tempdir, acl, str(domsid),
                 session_info, use_ntvfs=False)
        facl = getntacl(self.lp, self.tempdir, session_info)
        self.assertEqual(facl.as_sddl(domsid), acl)
        posix_acl = smbd.get_sys_acl(self.tempdir, smb_acl.SMB_ACL_TYPE_ACCESS, session_info)

        LA_sid = security.dom_sid(str(domsid) + "-" + str(security.DOMAIN_RID_ADMINISTRATOR))
        BA_sid = security.dom_sid(security.SID_BUILTIN_ADMINISTRATORS)
        SO_sid = security.dom_sid(security.SID_BUILTIN_SERVER_OPERATORS)
        SY_sid = security.dom_sid(security.SID_NT_SYSTEM)
        AU_sid = security.dom_sid(security.SID_NT_AUTHENTICATED_USERS)

        s4_passdb = passdb.PDB(self.lp.get("passdb backend"))

        # These assertions correct for current ad_dc selftest
        # configuration.  When other environments have a broad range of
        # groups mapped via passdb, we can relax some of these checks
        (LA_uid, LA_type) = s4_passdb.sid_to_id(LA_sid)
        self.assertEqual(LA_type, idmap.ID_TYPE_UID)
        (BA_gid, BA_type) = s4_passdb.sid_to_id(BA_sid)
        self.assertEqual(BA_type, idmap.ID_TYPE_BOTH)
        (SO_gid, SO_type) = s4_passdb.sid_to_id(SO_sid)
        self.assertEqual(SO_type, idmap.ID_TYPE_BOTH)
        (SY_gid, SY_type) = s4_passdb.sid_to_id(SY_sid)
        self.assertEqual(SO_type, idmap.ID_TYPE_BOTH)
        (AU_gid, AU_type) = s4_passdb.sid_to_id(AU_sid)
        self.assertEqual(AU_type, idmap.ID_TYPE_BOTH)

        self.assertEqual(posix_acl.count, 13, self.print_posix_acl(posix_acl))

        self.assertEqual(posix_acl.acl[0].a_type, smb_acl.SMB_ACL_GROUP)
        self.assertEqual(posix_acl.acl[0].a_perm, 7)
        self.assertEqual(posix_acl.acl[0].info.gid, BA_gid)

        self.assertEqual(posix_acl.acl[1].a_type, smb_acl.SMB_ACL_USER)
        self.assertEqual(posix_acl.acl[1].a_perm, 7)
        self.assertEqual(posix_acl.acl[1].info.uid, LA_uid)

        self.assertEqual(posix_acl.acl[2].a_type, smb_acl.SMB_ACL_OTHER)
        self.assertEqual(posix_acl.acl[2].a_perm, 0)

        self.assertEqual(posix_acl.acl[3].a_type, smb_acl.SMB_ACL_USER_OBJ)
        self.assertEqual(posix_acl.acl[3].a_perm, 7)

        self.assertEqual(posix_acl.acl[4].a_type, smb_acl.SMB_ACL_USER)
        self.assertEqual(posix_acl.acl[4].a_perm, 7)
        self.assertEqual(posix_acl.acl[4].info.uid, BA_gid)

        self.assertEqual(posix_acl.acl[5].a_type, smb_acl.SMB_ACL_GROUP_OBJ)
        self.assertEqual(posix_acl.acl[5].a_perm, 7)

        self.assertEqual(posix_acl.acl[6].a_type, smb_acl.SMB_ACL_USER)
        self.assertEqual(posix_acl.acl[6].a_perm, 5)
        self.assertEqual(posix_acl.acl[6].info.uid, SO_gid)

        self.assertEqual(posix_acl.acl[7].a_type, smb_acl.SMB_ACL_GROUP)
        self.assertEqual(posix_acl.acl[7].a_perm, 5)
        self.assertEqual(posix_acl.acl[7].info.gid, SO_gid)

        self.assertEqual(posix_acl.acl[8].a_type, smb_acl.SMB_ACL_USER)
        self.assertEqual(posix_acl.acl[8].a_perm, 7)
        self.assertEqual(posix_acl.acl[8].info.uid, SY_gid)

        self.assertEqual(posix_acl.acl[9].a_type, smb_acl.SMB_ACL_GROUP)
        self.assertEqual(posix_acl.acl[9].a_perm, 7)
        self.assertEqual(posix_acl.acl[9].info.gid, SY_gid)

        self.assertEqual(posix_acl.acl[10].a_type, smb_acl.SMB_ACL_USER)
        self.assertEqual(posix_acl.acl[10].a_perm, 5)
        self.assertEqual(posix_acl.acl[10].info.uid, AU_gid)

        self.assertEqual(posix_acl.acl[11].a_type, smb_acl.SMB_ACL_GROUP)
        self.assertEqual(posix_acl.acl[11].a_perm, 5)
        self.assertEqual(posix_acl.acl[11].info.gid, AU_gid)

        self.assertEqual(posix_acl.acl[12].a_type, smb_acl.SMB_ACL_MASK)
        self.assertEqual(posix_acl.acl[12].a_perm, 7)

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
        acl = provision.POLICIES_ACL
        domsid = passdb.get_global_sam_sid()
        session_info = self.get_session_info(domsid)
        setntacl(self.lp, self.tempdir, acl, str(domsid),
                 session_info, use_ntvfs=False)
        facl = getntacl(self.lp, self.tempdir, session_info)
        self.assertEqual(facl.as_sddl(domsid), acl)
        posix_acl = smbd.get_sys_acl(self.tempdir, smb_acl.SMB_ACL_TYPE_ACCESS, session_info)

        LA_sid = security.dom_sid(str(domsid) + "-" + str(security.DOMAIN_RID_ADMINISTRATOR))
        BA_sid = security.dom_sid(security.SID_BUILTIN_ADMINISTRATORS)
        SO_sid = security.dom_sid(security.SID_BUILTIN_SERVER_OPERATORS)
        SY_sid = security.dom_sid(security.SID_NT_SYSTEM)
        AU_sid = security.dom_sid(security.SID_NT_AUTHENTICATED_USERS)
        PA_sid = security.dom_sid(str(domsid) + "-" + str(security.DOMAIN_RID_POLICY_ADMINS))

        s4_passdb = passdb.PDB(self.lp.get("passdb backend"))

        # These assertions correct for current ad_dc selftest
        # configuration.  When other environments have a broad range of
        # groups mapped via passdb, we can relax some of these checks
        (LA_uid, LA_type) = s4_passdb.sid_to_id(LA_sid)
        self.assertEqual(LA_type, idmap.ID_TYPE_UID)
        (BA_gid, BA_type) = s4_passdb.sid_to_id(BA_sid)
        self.assertEqual(BA_type, idmap.ID_TYPE_BOTH)
        (SO_gid, SO_type) = s4_passdb.sid_to_id(SO_sid)
        self.assertEqual(SO_type, idmap.ID_TYPE_BOTH)
        (SY_gid, SY_type) = s4_passdb.sid_to_id(SY_sid)
        self.assertEqual(SO_type, idmap.ID_TYPE_BOTH)
        (AU_gid, AU_type) = s4_passdb.sid_to_id(AU_sid)
        self.assertEqual(AU_type, idmap.ID_TYPE_BOTH)
        (PA_gid, PA_type) = s4_passdb.sid_to_id(PA_sid)
        self.assertEqual(PA_type, idmap.ID_TYPE_BOTH)

        self.assertEqual(posix_acl.count, 15, self.print_posix_acl(posix_acl))

        self.assertEqual(posix_acl.acl[0].a_type, smb_acl.SMB_ACL_GROUP)
        self.assertEqual(posix_acl.acl[0].a_perm, 7)
        self.assertEqual(posix_acl.acl[0].info.gid, BA_gid)

        self.assertEqual(posix_acl.acl[1].a_type, smb_acl.SMB_ACL_USER)
        self.assertEqual(posix_acl.acl[1].a_perm, 7)
        self.assertEqual(posix_acl.acl[1].info.uid, LA_uid)

        self.assertEqual(posix_acl.acl[2].a_type, smb_acl.SMB_ACL_OTHER)
        self.assertEqual(posix_acl.acl[2].a_perm, 0)

        self.assertEqual(posix_acl.acl[3].a_type, smb_acl.SMB_ACL_USER_OBJ)
        self.assertEqual(posix_acl.acl[3].a_perm, 7)

        self.assertEqual(posix_acl.acl[4].a_type, smb_acl.SMB_ACL_USER)
        self.assertEqual(posix_acl.acl[4].a_perm, 7)
        self.assertEqual(posix_acl.acl[4].info.uid, BA_gid)

        self.assertEqual(posix_acl.acl[5].a_type, smb_acl.SMB_ACL_GROUP_OBJ)
        self.assertEqual(posix_acl.acl[5].a_perm, 7)

        self.assertEqual(posix_acl.acl[6].a_type, smb_acl.SMB_ACL_USER)
        self.assertEqual(posix_acl.acl[6].a_perm, 5)
        self.assertEqual(posix_acl.acl[6].info.uid, SO_gid)

        self.assertEqual(posix_acl.acl[7].a_type, smb_acl.SMB_ACL_GROUP)
        self.assertEqual(posix_acl.acl[7].a_perm, 5)
        self.assertEqual(posix_acl.acl[7].info.gid, SO_gid)

        self.assertEqual(posix_acl.acl[8].a_type, smb_acl.SMB_ACL_USER)
        self.assertEqual(posix_acl.acl[8].a_perm, 7)
        self.assertEqual(posix_acl.acl[8].info.uid, SY_gid)

        self.assertEqual(posix_acl.acl[9].a_type, smb_acl.SMB_ACL_GROUP)
        self.assertEqual(posix_acl.acl[9].a_perm, 7)
        self.assertEqual(posix_acl.acl[9].info.gid, SY_gid)

        self.assertEqual(posix_acl.acl[10].a_type, smb_acl.SMB_ACL_USER)
        self.assertEqual(posix_acl.acl[10].a_perm, 5)
        self.assertEqual(posix_acl.acl[10].info.uid, AU_gid)

        self.assertEqual(posix_acl.acl[11].a_type, smb_acl.SMB_ACL_GROUP)
        self.assertEqual(posix_acl.acl[11].a_perm, 5)
        self.assertEqual(posix_acl.acl[11].info.gid, AU_gid)

        self.assertEqual(posix_acl.acl[12].a_type, smb_acl.SMB_ACL_USER)
        self.assertEqual(posix_acl.acl[12].a_perm, 7)
        self.assertEqual(posix_acl.acl[12].info.uid, PA_gid)

        self.assertEqual(posix_acl.acl[13].a_type, smb_acl.SMB_ACL_GROUP)
        self.assertEqual(posix_acl.acl[13].a_perm, 7)
        self.assertEqual(posix_acl.acl[13].info.gid, PA_gid)

        self.assertEqual(posix_acl.acl[14].a_type, smb_acl.SMB_ACL_MASK)
        self.assertEqual(posix_acl.acl[14].a_perm, 7)

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
        acl = provision.POLICIES_ACL

        domsid = passdb.get_global_sam_sid()
        session_info = self.get_session_info(domsid)
        setntacl(self.lp, self.tempf, acl, str(domsid),
                 session_info, use_ntvfs=False)
        facl = getntacl(self.lp, self.tempf, session_info)
        self.assertEqual(facl.as_sddl(domsid), acl)
        posix_acl = smbd.get_sys_acl(self.tempf, smb_acl.SMB_ACL_TYPE_ACCESS, session_info)

        nwrap_module_so_path = os.getenv('NSS_WRAPPER_MODULE_SO_PATH')
        nwrap_module_fn_prefix = os.getenv('NSS_WRAPPER_MODULE_FN_PREFIX')

        nwrap_winbind_active = (nwrap_module_so_path != "" and
                                nwrap_module_fn_prefix == "winbind")
        is_user_session = not session_info.security_token.is_system()

        LA_sid = security.dom_sid(str(domsid) + "-" + str(security.DOMAIN_RID_ADMINISTRATOR))
        BA_sid = security.dom_sid(security.SID_BUILTIN_ADMINISTRATORS)
        SO_sid = security.dom_sid(security.SID_BUILTIN_SERVER_OPERATORS)
        SY_sid = security.dom_sid(security.SID_NT_SYSTEM)
        AU_sid = security.dom_sid(security.SID_NT_AUTHENTICATED_USERS)
        PA_sid = security.dom_sid(str(domsid) + "-" + str(security.DOMAIN_RID_POLICY_ADMINS))

        s4_passdb = passdb.PDB(self.lp.get("passdb backend"))

        # These assertions correct for current ad_dc selftest
        # configuration.  When other environments have a broad range of
        # groups mapped via passdb, we can relax some of these checks
        (LA_uid, LA_type) = s4_passdb.sid_to_id(LA_sid)
        self.assertEqual(LA_type, idmap.ID_TYPE_UID)
        (BA_gid, BA_type) = s4_passdb.sid_to_id(BA_sid)
        self.assertEqual(BA_type, idmap.ID_TYPE_BOTH)
        (SO_gid, SO_type) = s4_passdb.sid_to_id(SO_sid)
        self.assertEqual(SO_type, idmap.ID_TYPE_BOTH)
        (SY_gid, SY_type) = s4_passdb.sid_to_id(SY_sid)
        self.assertEqual(SO_type, idmap.ID_TYPE_BOTH)
        (AU_gid, AU_type) = s4_passdb.sid_to_id(AU_sid)
        self.assertEqual(AU_type, idmap.ID_TYPE_BOTH)
        (PA_gid, PA_type) = s4_passdb.sid_to_id(PA_sid)
        self.assertEqual(PA_type, idmap.ID_TYPE_BOTH)

        self.assertEqual(posix_acl.count, 15, self.print_posix_acl(posix_acl))

        self.assertEqual(posix_acl.acl[0].a_type, smb_acl.SMB_ACL_GROUP)
        self.assertEqual(posix_acl.acl[0].a_perm, 7)
        self.assertEqual(posix_acl.acl[0].info.gid, BA_gid)

        self.assertEqual(posix_acl.acl[1].a_type, smb_acl.SMB_ACL_USER)
        if nwrap_winbind_active or is_user_session:
            self.assertEqual(posix_acl.acl[1].a_perm, 7)
        else:
            self.assertEqual(posix_acl.acl[1].a_perm, 6)
        self.assertEqual(posix_acl.acl[1].info.uid, LA_uid)

        self.assertEqual(posix_acl.acl[2].a_type, smb_acl.SMB_ACL_OTHER)
        self.assertEqual(posix_acl.acl[2].a_perm, 0)

        self.assertEqual(posix_acl.acl[3].a_type, smb_acl.SMB_ACL_USER_OBJ)
        if nwrap_winbind_active or is_user_session:
            self.assertEqual(posix_acl.acl[3].a_perm, 7)
        else:
            self.assertEqual(posix_acl.acl[3].a_perm, 6)

        self.assertEqual(posix_acl.acl[4].a_type, smb_acl.SMB_ACL_USER)
        self.assertEqual(posix_acl.acl[4].a_perm, 7)
        self.assertEqual(posix_acl.acl[4].info.uid, BA_gid)

        self.assertEqual(posix_acl.acl[5].a_type, smb_acl.SMB_ACL_GROUP_OBJ)
        self.assertEqual(posix_acl.acl[5].a_perm, 7)

        self.assertEqual(posix_acl.acl[6].a_type, smb_acl.SMB_ACL_USER)
        self.assertEqual(posix_acl.acl[6].a_perm, 5)
        self.assertEqual(posix_acl.acl[6].info.uid, SO_gid)

        self.assertEqual(posix_acl.acl[7].a_type, smb_acl.SMB_ACL_GROUP)
        self.assertEqual(posix_acl.acl[7].a_perm, 5)
        self.assertEqual(posix_acl.acl[7].info.gid, SO_gid)

        self.assertEqual(posix_acl.acl[8].a_type, smb_acl.SMB_ACL_USER)
        self.assertEqual(posix_acl.acl[8].a_perm, 7)
        self.assertEqual(posix_acl.acl[8].info.uid, SY_gid)

        self.assertEqual(posix_acl.acl[9].a_type, smb_acl.SMB_ACL_GROUP)
        self.assertEqual(posix_acl.acl[9].a_perm, 7)
        self.assertEqual(posix_acl.acl[9].info.gid, SY_gid)

        self.assertEqual(posix_acl.acl[10].a_type, smb_acl.SMB_ACL_USER)
        self.assertEqual(posix_acl.acl[10].a_perm, 5)
        self.assertEqual(posix_acl.acl[10].info.uid, AU_gid)

        self.assertEqual(posix_acl.acl[11].a_type, smb_acl.SMB_ACL_GROUP)
        self.assertEqual(posix_acl.acl[11].a_perm, 5)
        self.assertEqual(posix_acl.acl[11].info.gid, AU_gid)

        self.assertEqual(posix_acl.acl[12].a_type, smb_acl.SMB_ACL_USER)
        self.assertEqual(posix_acl.acl[12].a_perm, 7)
        self.assertEqual(posix_acl.acl[12].info.uid, PA_gid)

        self.assertEqual(posix_acl.acl[13].a_type, smb_acl.SMB_ACL_GROUP)
        self.assertEqual(posix_acl.acl[13].a_perm, 7)
        self.assertEqual(posix_acl.acl[13].info.gid, PA_gid)

        self.assertEqual(posix_acl.acl[14].a_type, smb_acl.SMB_ACL_MASK)
        self.assertEqual(posix_acl.acl[14].a_perm, 7)

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

        # This is in this order in the NDR smb_acl(not re-orderded for display)
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


class SessionedPosixAclMappingTests(PosixAclMappingTests):
    """
    Run same test suite with session enabled.
    """

    def get_session_info(self, domsid=DOM_SID):
        """
        Get session_info for setntacl.
        """
        if str(domsid) != str(self.samdb.get_domain_sid()):
            # fake it with admin session as domsid is not in local db
            admin_session = auth.admin_session(self.lp, str(domsid))
            auth.session_info_fill_unix(admin_session,
                                        lp_ctx=self.lp,
                                        user_name="Administrator")
            return admin_session

        dn = '<SID={0}-{1}>'.format(domsid, security.DOMAIN_RID_ADMINISTRATOR)
        flags = (auth.AUTH_SESSION_INFO_DEFAULT_GROUPS |
                 auth.AUTH_SESSION_INFO_AUTHENTICATED |
                 auth.AUTH_SESSION_INFO_SIMPLE_PRIVILEGES)
        user_session = auth.user_session(self.samdb,
                                         lp_ctx=self.lp,
                                         dn=dn,
                                         session_info_flags=flags)
        auth.session_info_fill_unix(user_session,
                                    lp_ctx=self.lp,
                                    user_name="Administrator")
        return user_session


class UnixSessionedPosixAclMappingTests(PosixAclMappingTests):
    """
    Run same test suite with session enabled.
    """

    def get_session_info(self, domsid=DOM_SID):
        """
        Get session_info for setntacl.
        """
        if str(domsid) != str(self.samdb.get_domain_sid()):
            # fake it with admin session as domsid is not in local db
            admin_session = auth.admin_session(self.lp, str(domsid))
            auth.session_info_fill_unix(admin_session,
                                        lp_ctx=self.lp,
                                        user_name="Administrator")
            return admin_session

        dn = '<SID={0}-{1}>'.format(domsid, security.DOMAIN_RID_ADMINISTRATOR)
        flags = (auth.AUTH_SESSION_INFO_DEFAULT_GROUPS |
                 auth.AUTH_SESSION_INFO_AUTHENTICATED |
                 auth.AUTH_SESSION_INFO_SIMPLE_PRIVILEGES)

        session = auth.user_session(self.samdb, lp_ctx=self.lp, dn=dn,
                                    session_info_flags=flags)
        auth.session_info_fill_unix(session,
                                    lp_ctx=self.lp,
                                    user_name="Administrator")
        return session
