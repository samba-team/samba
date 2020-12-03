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
        security.SECINFO_SACL

    def required_access_for_get_secinfo(self, secinfo):
        access = 0

        #
        # This is based on MS-FSA
        # 2.1.5.13 Server Requests a Query of Security Information
        #
        # Note that MS-SMB2 3.3.5.20.3 Handling SMB2_0_INFO_SECURITY
        # doesn't specify any extra checks
        #

        if secinfo & security.SECINFO_OWNER:
            access |= security.SEC_STD_READ_CONTROL
        if secinfo & security.SECINFO_GROUP:
            access |= security.SEC_STD_READ_CONTROL
        if secinfo & security.SECINFO_DACL:
            access |= security.SEC_STD_READ_CONTROL
        if secinfo & security.SECINFO_SACL:
            access |= security.SEC_FLAG_SYSTEM_SECURITY

        if secinfo & security.SECINFO_LABEL:
            access |= security.SEC_STD_READ_CONTROL

        return access

    def required_access_for_set_secinfo(self, secinfo):
        access = 0

        #
        # This is based on MS-FSA
        # 2.1.5.16 Server Requests Setting of Security Information
        # and additional constraints from
        # MS-SMB2 3.3.5.21.3 Handling SMB2_0_INFO_SECURITY
        #

        if secinfo & security.SECINFO_OWNER:
            access |= security.SEC_STD_WRITE_OWNER
        if secinfo & security.SECINFO_GROUP:
            access |= security.SEC_STD_WRITE_OWNER
        if secinfo & security.SECINFO_DACL:
            access |= security.SEC_STD_WRITE_DAC
        if secinfo & security.SECINFO_SACL:
            access |= security.SEC_FLAG_SYSTEM_SECURITY

        if secinfo & security.SECINFO_LABEL:
            access |= security.SEC_STD_WRITE_OWNER

        if secinfo & security.SECINFO_ATTRIBUTE:
            access |= security.SEC_STD_WRITE_DAC

        if secinfo & security.SECINFO_SCOPE:
            access |= security.SEC_FLAG_SYSTEM_SECURITY

        if secinfo & security.SECINFO_BACKUP:
            access |= security.SEC_STD_WRITE_OWNER
            access |= security.SEC_STD_WRITE_DAC
            access |= security.SEC_FLAG_SYSTEM_SECURITY

        return access

    def get_acl(self,
                filename,
                sinfo=None,
                access_mask=None):
        """Get security descriptor for file."""
        if sinfo is None:
            sinfo = self.SECINFO_DEFAULT_FLAGS
        if access_mask is None:
            access_mask = self.required_access_for_get_secinfo(sinfo)
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
                sinfo=None,
                access_mask=None):
        """Set security descriptor for file."""
        if sinfo is None:
            sinfo = self.SECINFO_DEFAULT_FLAGS
        if access_mask is None:
            access_mask = self.required_access_for_set_secinfo(sinfo)
        fnum = self.create(
            Name=filename,
            DesiredAccess=access_mask,
            ShareAccess=(FILE_SHARE_READ|FILE_SHARE_WRITE))
        try:
            self.set_sd(fnum, sd, sinfo)
        finally:
            self.close(fnum)
