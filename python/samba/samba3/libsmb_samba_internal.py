# Copyright (C) Volker Lendecke <vl@samba.org> 2020
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

from samba.samba3.libsmb_samba_cwrapper import *
from samba.dcerpc import security

class Conn(LibsmbCConn):
    def deltree(self, path):
        if self.chkpath(path):
            for entry in self.list(path):
                self.deltree(path + "\\" + entry['name'])
            self.rmdir(path)
        else:
            self.unlink(path)

    SECINFO_DEFAULT_FLAGS = \
        security.SECINFO_OWNER | \
        security.SECINFO_GROUP | \
        security.SECINFO_DACL | \
        security.SECINFO_PROTECTED_DACL | \
        security.SECINFO_UNPROTECTED_DACL | \
        security.SECINFO_SACL | \
        security.SECINFO_PROTECTED_SACL | \
        security.SECINFO_UNPROTECTED_SACL

    def get_acl(self,
                filename,
                sinfo = SECINFO_DEFAULT_FLAGS,
                access_mask = security.SEC_FLAG_MAXIMUM_ALLOWED):
        """Get security descriptor for file."""
        fnum = self.create(
            Name=filename,
            DesiredAccess=access_mask,
            ShareAccess=(FILE_SHARE_READ|FILE_SHARE_WRITE))
        try:
            sd = self.get_sd(fnum, sinfo)
        finally:
            self.close(fnum)
        return sd

    def set_acl(self,
                filename,
                sd,
                sinfo = SECINFO_DEFAULT_FLAGS):
        """Set security descriptor for file."""
        fnum = self.create(
            Name=filename,
            DesiredAccess=security.SEC_FLAG_MAXIMUM_ALLOWED,
            ShareAccess=(FILE_SHARE_READ|FILE_SHARE_WRITE))
        try:
            self.set_sd(fnum, sd, sinfo)
        finally:
            self.close(fnum)
