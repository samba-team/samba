# Utility code for dealing with POSIX extended attributes
#
# Copyright (C) Jelmer Vernooij <jelmer@samba.org> 2012
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

from samba.dcerpc import xattr
import os
import samba.xattr_native
import shutil


def copyattrs(frompath, topath):
    """Copy ACL related attributes from a path to another path."""
    for attr_name in (xattr.XATTR_NTACL_NAME, "system.posix_acl_access"):
        # Get the xattr attributes if any
        try:
            attribute = samba.xattr_native.wrap_getxattr(frompath,
                                                         xattr.XATTR_NTACL_NAME)
            samba.xattr_native.wrap_setxattr(topath,
                                             xattr.XATTR_NTACL_NAME,
                                             attribute)
        except Exception:
            pass
            # FIXME:Catch a specific exception


def copytree_with_xattrs(src, dst):
    """Recursively copy a directory tree using shutil.copy2(), preserving xattrs.

    The destination directory must not already exist.
    If exception(s) occur, an Error is raised with a list of reasons.
    """
    names = os.listdir(src)

    os.makedirs(dst)
    for name in names:
        srcname = os.path.join(src, name)
        dstname = os.path.join(dst, name)
        if os.path.islink(srcname):
            linkto = os.readlink(srcname)
            os.symlink(linkto, dstname)
        elif os.path.isdir(srcname):
            copytree_with_xattrs(srcname, dstname)
        else:
            # Will raise a SpecialFileError for unsupported file types
            shutil.copy2(srcname, dstname)
    shutil.copystat(src, dst)
    copyattrs(src, dst)
