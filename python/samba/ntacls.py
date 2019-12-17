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
import tarfile
import tempfile
import shutil

import samba.xattr_native
import samba.xattr_tdb
import samba.posix_eadb
from samba.samba3 import param as s3param
from samba.dcerpc import security, xattr, idmap
from samba.ndr import ndr_pack, ndr_unpack
from samba.samba3 import smbd
from samba.samba3 import libsmb_samba_internal as libsmb
from samba.logger import get_samba_logger
from samba import NTSTATUSError
from samba.auth_util import system_session_unix

# don't include volumes
SMB_FILE_ATTRIBUTE_FLAGS = libsmb.FILE_ATTRIBUTE_SYSTEM | \
                           libsmb.FILE_ATTRIBUTE_DIRECTORY | \
                           libsmb.FILE_ATTRIBUTE_ARCHIVE | \
                           libsmb.FILE_ATTRIBUTE_HIDDEN


SECURITY_SECINFO_FLAGS = security.SECINFO_OWNER | \
                         security.SECINFO_GROUP | \
                         security.SECINFO_DACL  | \
                         security.SECINFO_SACL


# SEC_FLAG_SYSTEM_SECURITY is required otherwise get Access Denied
SECURITY_SEC_FLAGS = security.SEC_FLAG_SYSTEM_SECURITY | \
                     security.SEC_STD_READ_CONTROL


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
            state_dir = lp.get("state directory")
            db_path = os.path.abspath(os.path.join(state_dir, "xattr.tdb"))
            return (samba.xattr_tdb, db_path)
    else:
        raise XattrBackendError("Invalid xattr backend choice %s" % backend)


def getdosinfo(lp, file):
    try:
        attribute = samba.xattr_native.wrap_getxattr(file,
                                                     xattr.XATTR_DOSATTRIB_NAME_S3)
    except Exception:
        return

    return ndr_unpack(xattr.DOSATTRIB, attribute)


def getntacl(lp,
             file,
             session_info,
             backend=None,
             eadbfile=None,
             direct_db_access=True,
             service=None):
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
        return smbd.get_nt_acl(file,
                               SECURITY_SECINFO_FLAGS,
                               session_info,
                               service=service)


def setntacl(lp, file, sddl, domsid, session_info,
             backend=None, eadbfile=None,
             use_ntvfs=True, skip_invalid_chown=False,
             passdb=None, service=None):
    """
    A wrapper for smbd set_nt_acl api.

    Args:
        lp (LoadParam): load param from conf
        file (str): a path to file or dir
        sddl (str): ntacl sddl string
        service (str): name of share service, e.g.: sysvol
        session_info (auth_session_info): session info for authentication

    Note:
        Get `session_info` with `samba.auth.user_session`, do not use the
        `admin_session` api.

    Returns:
        None
    """

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

                    smbd.set_nt_acl(
                        file, SECURITY_SECINFO_FLAGS, sd2,
                        session_info,
                        service=service)

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
                smbd.set_nt_acl(
                    file,
                    security.SECINFO_GROUP |
                    security.SECINFO_DACL |
                    security.SECINFO_SACL,
                    sd,
                    session_info,
                    service=service)

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
        smbd.set_nt_acl(
            file, SECURITY_SECINFO_FLAGS, sd,
            service=service, session_info=session_info)


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
            ace.access_mask = ldapmask2filemask(ace.access_mask)
            fdescr.dacl_add(ace)

    if not as_sddl:
        return fdescr

    return fdescr.as_sddl(sid)


class SMBHelper:
    """
    A wrapper class for SMB connection

    smb_path: path with separator "\\" other than "/"
    """

    def __init__(self, smb_conn, dom_sid):
        self.smb_conn = smb_conn
        self.dom_sid = dom_sid

    def get_acl(self, smb_path, as_sddl=False):
        assert '/' not in smb_path

        ntacl_sd = self.smb_conn.get_acl(
            smb_path, SECURITY_SECINFO_FLAGS, SECURITY_SEC_FLAGS)

        return ntacl_sd.as_sddl(self.dom_sid) if as_sddl else ntacl_sd

    def list(self, smb_path=''):
        """
        List file and dir base names in smb_path without recursive.
        """
        assert '/' not in smb_path
        return self.smb_conn.list(smb_path, attribs=SMB_FILE_ATTRIBUTE_FLAGS)

    def is_dir(self, attrib):
        """
        Check whether the attrib value is a directory.

        attrib is from list method.
        """
        return bool(attrib & libsmb.FILE_ATTRIBUTE_DIRECTORY)

    def join(self, root, name):
        """
        Join path with '\\'
        """
        return root + '\\' + name if root else name

    def loadfile(self, smb_path):
        assert '/' not in smb_path
        return self.smb_conn.loadfile(smb_path)

    def create_tree(self, tree, smb_path=''):
        """
        Create files as defined in tree
        """
        for name, content in tree.items():
            fullname = self.join(smb_path, name)
            if isinstance(content, dict):  # a dir
                if not self.smb_conn.chkpath(fullname):
                    self.smb_conn.mkdir(fullname)
                self.create_tree(content, smb_path=fullname)
            else:  # a file
                self.smb_conn.savefile(fullname, content)

    def get_tree(self, smb_path=''):
        """
        Get the tree structure via smb conn

        self.smb_conn.list example:

        [
          {
            'attrib': 16,
            'mtime': 1528848309,
            'name': 'dir1',
            'short_name': 'dir1',
            'size': 0L
          }, {
            'attrib': 32,
            'mtime': 1528848309,
            'name': 'file0.txt',
            'short_name': 'file0.txt',
            'size': 10L
          }
        ]
        """
        tree = {}
        for item in self.list(smb_path):
            name = item['name']
            fullname = self.join(smb_path, name)
            if self.is_dir(item['attrib']):
                tree[name] = self.get_tree(smb_path=fullname)
            else:
                tree[name] = self.loadfile(fullname)
        return tree

    def get_ntacls(self, smb_path=''):
        """
        Get ntacl for each file and dir via smb conn
        """
        ntacls = {}
        for item in self.list(smb_path):
            name = item['name']
            fullname = self.join(smb_path, name)
            if self.is_dir(item['attrib']):
                ntacls.update(self.get_ntacls(smb_path=fullname))
            else:
                ntacl_sd = self.get_acl(fullname)
                ntacls[fullname] = ntacl_sd.as_sddl(self.dom_sid)
        return ntacls

    def delete_tree(self):
        for item in self.list():
            name = item['name']
            if self.is_dir(item['attrib']):
                self.smb_conn.deltree(name)
            else:
                self.smb_conn.unlink(name)


class NtaclsHelper:

    def __init__(self, service, smb_conf_path, dom_sid):
        self.service = service
        self.dom_sid = dom_sid

        # this is important to help smbd find services.
        self.lp = s3param.get_context()
        self.lp.load(smb_conf_path)

        self.use_ntvfs = "smb" in self.lp.get("server services")

    def getntacl(self, path, session_info, as_sddl=False, direct_db_access=None):
        if direct_db_access is None:
            direct_db_access = self.use_ntvfs

        ntacl_sd = getntacl(
            self.lp, path, session_info,
            direct_db_access=direct_db_access,
            service=self.service)

        return ntacl_sd.as_sddl(self.dom_sid) if as_sddl else ntacl_sd

    def setntacl(self, path, ntacl_sd, session_info):
        # ntacl_sd can be obj or str
        return setntacl(self.lp, path, ntacl_sd, self.dom_sid, session_info,
                        use_ntvfs=self.use_ntvfs)


def _create_ntacl_file(dst, ntacl_sddl_str):
    with open(dst + '.NTACL', 'w') as f:
        f.write(ntacl_sddl_str)


def _read_ntacl_file(src):
    ntacl_file = src + '.NTACL'

    if not os.path.exists(ntacl_file):
        return None

    with open(ntacl_file, 'r') as f:
        return f.read()


def backup_online(smb_conn, dest_tarfile_path, dom_sid):
    """
    Backup all files and dirs with ntacl for the serive behind smb_conn.

    1. Create a temp dir as container dir
    2. Backup all files with dir structure into container dir
    3. Generate file.NTACL files for each file and dir in contianer dir
    4. Create a tar file from container dir(without top level folder)
    5. Delete contianer dir
    """

    logger = get_samba_logger()

    if isinstance(dom_sid, str):
        dom_sid = security.dom_sid(dom_sid)

    smb_helper = SMBHelper(smb_conn, dom_sid)

    remotedir = ''  # root dir

    localdir = tempfile.mkdtemp()

    r_dirs = [remotedir]
    l_dirs = [localdir]

    while r_dirs:
        r_dir = r_dirs.pop()
        l_dir = l_dirs.pop()

        for e in smb_helper.list(smb_path=r_dir):
            r_name = smb_helper.join(r_dir, e['name'])
            l_name = os.path.join(l_dir, e['name'])

            if smb_helper.is_dir(e['attrib']):
                r_dirs.append(r_name)
                l_dirs.append(l_name)
                os.mkdir(l_name)
            else:
                data = smb_helper.loadfile(r_name)
                with open(l_name, 'wb') as f:
                    f.write(data)

            # get ntacl for this entry and save alongside
            try:
                ntacl_sddl_str = smb_helper.get_acl(r_name, as_sddl=True)
                _create_ntacl_file(l_name, ntacl_sddl_str)
            except NTSTATUSError as e:
                logger.error('Failed to get the ntacl for %s: %s' % \
                             (r_name, e.args[1]))
                logger.warning('The permissions for %s may not be' % r_name +
                               ' restored correctly')

    with tarfile.open(name=dest_tarfile_path, mode='w:gz') as tar:
        for name in os.listdir(localdir):
            path = os.path.join(localdir, name)
            tar.add(path, arcname=name)

    shutil.rmtree(localdir)


def backup_offline(src_service_path, dest_tarfile_path, samdb_conn, smb_conf_path):
    """
    Backup files and ntacls to a tarfile for a service
    """
    service = src_service_path.rstrip('/').rsplit('/', 1)[-1]
    tempdir = tempfile.mkdtemp()
    session_info = system_session_unix()

    dom_sid_str = samdb_conn.get_domain_sid()
    dom_sid = security.dom_sid(dom_sid_str)

    ntacls_helper = NtaclsHelper(service, smb_conf_path, dom_sid)

    for dirpath, dirnames, filenames in os.walk(src_service_path):
        # each dir only cares about its direct children
        rel_dirpath = os.path.relpath(dirpath, start=src_service_path)
        dst_dirpath = os.path.join(tempdir, rel_dirpath)

        # create sub dirs and NTACL file
        for dirname in dirnames:
            src = os.path.join(dirpath, dirname)
            dst = os.path.join(dst_dirpath, dirname)
            # mkdir with metadata
            smbd.mkdir(dst, session_info, service)
            ntacl_sddl_str = ntacls_helper.getntacl(src, session_info, as_sddl=True)
            _create_ntacl_file(dst, ntacl_sddl_str)

        # create files and NTACL file, then copy data
        for filename in filenames:
            src = os.path.join(dirpath, filename)
            dst = os.path.join(dst_dirpath, filename)
            # create an empty file with metadata
            smbd.create_file(dst, session_info, service)
            ntacl_sddl_str = ntacls_helper.getntacl(src, session_info, as_sddl=True)
            _create_ntacl_file(dst, ntacl_sddl_str)

            # now put data in
            with open(src, 'rb') as src_file:
                data = src_file.read()
                with open(dst, 'wb') as dst_file:
                    dst_file.write(data)

    # add all files in tempdir to tarfile without a top folder
    with tarfile.open(name=dest_tarfile_path, mode='w:gz') as tar:
        for name in os.listdir(tempdir):
            path = os.path.join(tempdir, name)
            tar.add(path, arcname=name)

    shutil.rmtree(tempdir)


def backup_restore(src_tarfile_path, dst_service_path, samdb_conn, smb_conf_path):
    """
    Restore files and ntacls from a tarfile to a service
    """
    logger = get_samba_logger()
    service = dst_service_path.rstrip('/').rsplit('/', 1)[-1]
    tempdir = tempfile.mkdtemp()  # src files

    dom_sid_str = samdb_conn.get_domain_sid()
    dom_sid = security.dom_sid(dom_sid_str)

    ntacls_helper = NtaclsHelper(service, smb_conf_path, dom_sid)
    session_info = system_session_unix()

    with tarfile.open(src_tarfile_path) as f:
        f.extractall(path=tempdir)
        # e.g.: /tmp/tmpRNystY/{dir1,dir1.NTACL,...file1,file1.NTACL}

    for dirpath, dirnames, filenames in os.walk(tempdir):
        rel_dirpath = os.path.relpath(dirpath, start=tempdir)
        dst_dirpath = os.path.normpath(
            os.path.join(dst_service_path, rel_dirpath))

        for dirname in dirnames:
            if not dirname.endswith('.NTACL'):
                src = os.path.join(dirpath, dirname)
                dst = os.path.join(dst_dirpath, dirname)
                if not os.path.isdir(dst):
                    # dst must be absolute path for smbd API
                    smbd.mkdir(dst, session_info, service)

                ntacl_sddl_str = _read_ntacl_file(src)
                if ntacl_sddl_str:
                    ntacls_helper.setntacl(dst, ntacl_sddl_str, session_info)
                else:
                    logger.warning(
                        'Failed to restore ntacl for directory %s.' % dst
                        + ' Please check the permissions are correct')

        for filename in filenames:
            if not filename.endswith('.NTACL'):
                src = os.path.join(dirpath, filename)
                dst = os.path.join(dst_dirpath, filename)
                if not os.path.isfile(dst):
                    # dst must be absolute path for smbd API
                    smbd.create_file(dst, session_info, service)

                ntacl_sddl_str = _read_ntacl_file(src)
                if ntacl_sddl_str:
                    ntacls_helper.setntacl(dst, ntacl_sddl_str, session_info)
                else:
                    logger.warning('Failed to restore ntacl for file %s.' % dst
                                 + ' Please check the permissions are correct')

                # now put data in
                with open(src, 'rb') as src_file:
                    data = src_file.read()
                    with open(dst, 'wb') as dst_file:
                        dst_file.write(data)

    shutil.rmtree(tempdir)
