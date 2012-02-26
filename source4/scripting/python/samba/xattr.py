#!/usr/bin/env python
# vim: expandtab
#
# Utility code for dealing with POSIX extended attributes
#
# Copyright (C) Matthieu Patou <mat@matws.net> 2009 - 2010
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


def copytree_with_xattrs(source, target):
    """Copy a tree but preserve extended attributes.

    :param source: Source tree path
    :param target: Target path
    """
    shutil.copytree(source, target)
    copyxattrs(target, source)


def copyxattrs(dir, refdir):
    """Copy extended attributes from a reference dir to a destination dir

    Both dir are supposed to hold the same files
    :param dir: Destination dir
    :param refdir: Reference directory"""

    for root, dirs, files in os.walk(dir, topdown=True):
        for name in files:
            subdir = root[len(dir):]
            ref = os.path.join(refdir, subdir, name)
            statsinfo = os.stat(ref)
            tgt = os.path.join(root, name)
            try:
                os.chown(tgt, statsinfo.st_uid, statsinfo.st_gid)
                # Get the xattr attributes if any
                try:
                    attribute = samba.xattr_native.wrap_getxattr(ref,
                                                 xattr.XATTR_NTACL_NAME)
                    samba.xattr_native.wrap_setxattr(tgt,
                                                 xattr.XATTR_NTACL_NAME,
                                                 attribute)
                except Exception:
                    pass
                    # FIXME:Catch a specific exception
                attribute = samba.xattr_native.wrap_getxattr(ref,
                                                 "system.posix_acl_access")
                samba.xattr_native.wrap_setxattr(tgt,
                                                 "system.posix_acl_access",
                                                  attribute)
            except Exception:
                # FIXME: Catch a specific exception
                continue
        for name in dirs:
            subdir = root[len(dir):]
            ref = os.path.join(refdir, subdir, name)
            statsinfo = os.stat(ref)
            tgt = os.path.join(root, name)
            try:
                os.chown(os.path.join(root, name), statsinfo.st_uid,
                          statsinfo.st_gid)
                try:
                    attribute = samba.xattr_native.wrap_getxattr(ref,
                                                 xattr.XATTR_NTACL_NAME)
                    samba.xattr_native.wrap_setxattr(tgt,
                                                 xattr.XATTR_NTACL_NAME,
                                                 attribute)
                except Exception:
                    pass # FIXME: Catch a specific exception
                attribute = samba.xattr_native.wrap_getxattr(ref,
                                                 "system.posix_acl_access")
                samba.xattr_native.wrap_setxattr(tgt,
                                                 "system.posix_acl_access",
                                                  attribute)

            except Exception:
                continue
