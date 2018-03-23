# Unix SMB/CIFS implementation.
# Copyright (C) Matthieu Patou <mat@matws.net> 2009-2010
#
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

from __future__ import print_function
"""NT Acls."""


import os
import samba.xattr_native, samba.xattr_tdb, samba.posix_eadb
from samba.dcerpc import security, xattr, idmap
from samba.ndr import ndr_pack, ndr_unpack
from samba.samba3 import smbd

class XattrBackendError(Exception):
    """A generic xattr backend error."""


def checkset_backend(lp, backend, eadbfile):
    '''return the path to the eadb, or None'''
    if backend is None:
        xattr_tdb = lp.get("xattr_tdb:file")
        if xattr_tdb is not None:
            return (samba.xattr_tdb, lp.get("xattr_tdb:file"))
        posix_eadb = lp.get("posix:eadb")
        if posix_eadb is not None:
            return (samba.posix_eadb, lp.get("posix:eadb"))
        return (None, None)
    elif backend == "native":
        return (None, None)
    elif backend == "eadb":
        if eadbfile is not None:
            return (samba.posix_eadb, eadbfile)
        else:
            return (samba.posix_eadb, os.path.abspath(os.path.join(lp.get("private dir"), "eadb.tdb")))
    elif backend == "tdb":
        if eadbfile is not None:
            return (samba.xattr_tdb, eadbfile)
        else:
            return (samba.xattr_tdb, os.path.abspath(os.path.join(lp.get("state dir"), "xattr.tdb")))
    else:
        raise XattrBackendError("Invalid xattr backend choice %s"%backend)

def getdosinfo(lp, file):
    try:
        attribute = samba.xattr_native.wrap_getxattr(file,
                                                     xattr.XATTR_DOSATTRIB_NAME_S3)
    except Exception:
        return

    return ndr_unpack(xattr.DOSATTRIB, attribute)

def getntacl(lp, file, backend=None, eadbfile=None, direct_db_access=True, service=None):
    if direct_db_access:
        (backend_obj, dbname) = checkset_backend(lp, backend, eadbfile)
        if dbname is not None:
            try:
                attribute = backend_obj.wrap_getxattr(dbname, file,
                                                      xattr.XATTR_NTACL_NAME)
            except Exception:
                # FIXME: Don't catch all exceptions, just those related to opening
                # xattrdb
                print("Fail to open %s" % dbname)
                attribute = samba.xattr_native.wrap_getxattr(file,
                                                             xattr.XATTR_NTACL_NAME)
        else:
            attribute = samba.xattr_native.wrap_getxattr(file,
                                                         xattr.XATTR_NTACL_NAME)
        ntacl = ndr_unpack(xattr.NTACL, attribute)
        if ntacl.version == 1:
            return ntacl.info
        elif ntacl.version == 2:
            return ntacl.info.sd
        elif ntacl.version == 3:
            return ntacl.info.sd
        elif ntacl.version == 4:
            return ntacl.info.sd
    else:
        return smbd.get_nt_acl(file, security.SECINFO_OWNER | security.SECINFO_GROUP | security.SECINFO_DACL | security.SECINFO_SACL, service=service)


def setntacl(lp, file, sddl, domsid, backend=None, eadbfile=None, use_ntvfs=True, skip_invalid_chown=False, passdb=None, service=None):
    assert(isinstance(domsid, str) or isinstance(domsid, security.dom_sid))
    if isinstance(domsid, str):
        sid = security.dom_sid(domsid)
    elif isinstance(domsid, security.dom_sid):
        sid = domsid
        domsid = str(sid)

    assert(isinstance(sddl, str) or isinstance(sddl, security.descriptor))
    if isinstance(sddl, str):
        sd = security.descriptor.from_sddl(sddl, sid)
    elif isinstance(sddl, security.descriptor):
        sd = sddl
        sddl = sd.as_sddl(sid)

    if not use_ntvfs and skip_invalid_chown:
        # Check if the owner can be resolved as a UID
        (owner_id, owner_type) = passdb.sid_to_id(sd.owner_sid)
        if ((owner_type != idmap.ID_TYPE_UID) and (owner_type != idmap.ID_TYPE_BOTH)):
            # Check if this particular owner SID was domain admins,
            # because we special-case this as mapping to
            # 'administrator' instead.
            if sd.owner_sid == security.dom_sid("%s-%d" % (domsid, security.DOMAIN_RID_ADMINS)):
                administrator = security.dom_sid("%s-%d" % (domsid, security.DOMAIN_RID_ADMINISTRATOR))
                (admin_id, admin_type) = passdb.sid_to_id(administrator)

                # Confirm we have a UID for administrator
                if ((admin_type == idmap.ID_TYPE_UID) or (admin_type == idmap.ID_TYPE_BOTH)):

                    # Set it, changing the owner to 'administrator' rather than domain admins
                    sd2 = sd
                    sd2.owner_sid = administrator

                    smbd.set_nt_acl(file, security.SECINFO_OWNER |security.SECINFO_GROUP | security.SECINFO_DACL | security.SECINFO_SACL, sd2, service=service)

                    # and then set an NTVFS ACL (which does not set the posix ACL) to pretend the owner really was set
                    use_ntvfs = True
                else:
                    raise XattrBackendError("Unable to find UID for domain administrator %s, got id %d of type %d" % (administrator, admin_id, admin_type))
            else:
                # For all other owning users, reset the owner to root
                # and then set the ACL without changing the owner
                #
                # This won't work in test environments, as it tries a real (rather than xattr-based fake) chown

                os.chown(file, 0, 0)
                smbd.set_nt_acl(file, security.SECINFO_GROUP | security.SECINFO_DACL | security.SECINFO_SACL, sd, service=service)

    if use_ntvfs:
        (backend_obj, dbname) = checkset_backend(lp, backend, eadbfile)
        ntacl = xattr.NTACL()
        ntacl.version = 1
        ntacl.info = sd
        if dbname is not None:
            try:
                backend_obj.wrap_setxattr(dbname,
                                          file, xattr.XATTR_NTACL_NAME, ndr_pack(ntacl))
            except Exception:
                # FIXME: Don't catch all exceptions, just those related to opening
                # xattrdb
                print("Fail to open %s" % dbname)
                samba.xattr_native.wrap_setxattr(file, xattr.XATTR_NTACL_NAME,
                                                 ndr_pack(ntacl))
        else:
            samba.xattr_native.wrap_setxattr(file, xattr.XATTR_NTACL_NAME,
                                             ndr_pack(ntacl))
    else:
        smbd.set_nt_acl(file, security.SECINFO_OWNER | security.SECINFO_GROUP | security.SECINFO_DACL | security.SECINFO_SACL, sd, service=service)


def ldapmask2filemask(ldm):
    """Takes the access mask of a DS ACE and transform them in a File ACE mask.
    """
    RIGHT_DS_CREATE_CHILD     = 0x00000001
    RIGHT_DS_DELETE_CHILD     = 0x00000002
    RIGHT_DS_LIST_CONTENTS    = 0x00000004
    ACTRL_DS_SELF             = 0x00000008
    RIGHT_DS_READ_PROPERTY    = 0x00000010
    RIGHT_DS_WRITE_PROPERTY   = 0x00000020
    RIGHT_DS_DELETE_TREE      = 0x00000040
    RIGHT_DS_LIST_OBJECT      = 0x00000080
    RIGHT_DS_CONTROL_ACCESS   = 0x00000100
    FILE_READ_DATA            = 0x0001
    FILE_LIST_DIRECTORY       = 0x0001
    FILE_WRITE_DATA           = 0x0002
    FILE_ADD_FILE             = 0x0002
    FILE_APPEND_DATA          = 0x0004
    FILE_ADD_SUBDIRECTORY     = 0x0004
    FILE_CREATE_PIPE_INSTANCE = 0x0004
    FILE_READ_EA              = 0x0008
    FILE_WRITE_EA             = 0x0010
    FILE_EXECUTE              = 0x0020
    FILE_TRAVERSE             = 0x0020
    FILE_DELETE_CHILD         = 0x0040
    FILE_READ_ATTRIBUTES      = 0x0080
    FILE_WRITE_ATTRIBUTES     = 0x0100
    DELETE                    = 0x00010000
    READ_CONTROL              = 0x00020000
    WRITE_DAC                 = 0x00040000
    WRITE_OWNER               = 0x00080000
    SYNCHRONIZE               = 0x00100000
    STANDARD_RIGHTS_ALL       = 0x001F0000

    filemask = ldm & STANDARD_RIGHTS_ALL

    if (ldm & RIGHT_DS_READ_PROPERTY) and (ldm & RIGHT_DS_LIST_CONTENTS):
        filemask = filemask | (SYNCHRONIZE | FILE_LIST_DIRECTORY |
                                FILE_READ_ATTRIBUTES | FILE_READ_EA |
                                FILE_READ_DATA | FILE_EXECUTE)

    if ldm & RIGHT_DS_WRITE_PROPERTY:
        filemask = filemask | (SYNCHRONIZE | FILE_WRITE_DATA |
                                FILE_APPEND_DATA | FILE_WRITE_EA |
                                FILE_WRITE_ATTRIBUTES | FILE_ADD_FILE |
                                FILE_ADD_SUBDIRECTORY)

    if ldm & RIGHT_DS_CREATE_CHILD:
        filemask = filemask | (FILE_ADD_SUBDIRECTORY | FILE_ADD_FILE)

    if ldm & RIGHT_DS_DELETE_CHILD:
        filemask = filemask | FILE_DELETE_CHILD

    return filemask


def dsacl2fsacl(dssddl, sid, as_sddl=True):
    """

    This function takes an the SDDL representation of a DS
    ACL and return the SDDL representation of this ACL adapted
    for files. It's used for Policy object provision
    """
    ref = security.descriptor.from_sddl(dssddl, sid)
    fdescr = security.descriptor()
    fdescr.owner_sid = ref.owner_sid
    fdescr.group_sid = ref.group_sid
    fdescr.type = ref.type
    fdescr.revision = ref.revision
    aces = ref.dacl.aces
    for i in range(0, len(aces)):
        ace = aces[i]
        if not ace.type & security.SEC_ACE_TYPE_ACCESS_ALLOWED_OBJECT and str(ace.trustee) != security.SID_BUILTIN_PREW2K:
       #    if fdescr.type & security.SEC_DESC_DACL_AUTO_INHERITED:
            ace.flags = ace.flags | security.SEC_ACE_FLAG_OBJECT_INHERIT | security.SEC_ACE_FLAG_CONTAINER_INHERIT
            if str(ace.trustee) == security.SID_CREATOR_OWNER:
                # For Creator/Owner the IO flag is set as this ACE has only a sense for child objects
                ace.flags = ace.flags | security.SEC_ACE_FLAG_INHERIT_ONLY
            ace.access_mask =  ldapmask2filemask(ace.access_mask)
            fdescr.dacl_add(ace)

    if not as_sddl:
        return fdescr

    return fdescr.as_sddl(sid)
