# Unix SMB/CIFS implementation.
#
# User model.
#
# Copyright (C) Catalyst.Net Ltd. 2023
#
# Written by Rob van der Linde <rob@catalyst.net.nz>
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

from ldb import Dn

from samba.dcerpc.security import dom_sid
from samba.dsdb import DS_GUID_USERS_CONTAINER

from .exceptions import NotFound
from .fields import DnField, EnumField, IntegerField, NtTimeField, StringField
from .fields import KeyCredentialLinkDnField
from .group import Group
from .org import OrganizationalPerson
from .types import AccountType, UserAccountControl


class User(OrganizationalPerson):
    account_name = StringField("sAMAccountName")
    account_type = EnumField("sAMAccountType", AccountType)
    assigned_policy = DnField("msDS-AssignedAuthNPolicy")
    assigned_silo = DnField("msDS-AssignedAuthNPolicySilo")
    bad_password_time = NtTimeField("badPasswordTime", readonly=True)
    bad_pwd_count = IntegerField("badPwdCount", readonly=True)
    code_page = IntegerField("codePage")
    display_name = StringField("displayName")
    key_credential_link = KeyCredentialLinkDnField("msDS-KeyCredentialLink",
                                                   many=True)
    last_logoff = NtTimeField("lastLogoff", readonly=True)
    last_logon = NtTimeField("lastLogon", readonly=True)
    logon_count = IntegerField("logonCount", readonly=True)
    primary_group_id = IntegerField("primaryGroupID")
    pwd_last_set = NtTimeField("pwdLastSet", readonly=True)
    user_account_control = EnumField("userAccountControl", UserAccountControl)
    user_principal_name = StringField("userPrincipalName")

    def __str__(self):
        """Return sAMAccountName rather than cn for User model."""
        return self.account_name

    def get_primary_group(self, samdb) -> Group:
        """Returns the primary Group object for this User."""
        group_sid = f"{samdb.domain_sid}-{self.primary_group_id}"
        return Group.get(samdb, object_sid=group_sid)

    @staticmethod
    def get_base_dn(samdb):
        """Return the base DN for the User model.

        :param samdb: SamDB connection
        :return: Dn to use for new objects
        """
        return samdb.get_wellknown_dn(samdb.get_default_basedn(),
                                      DS_GUID_USERS_CONTAINER)

    @classmethod
    def get_search_dn(cls, samdb):
        """Return Dn used for searching so Computers will also be found.

        :param samdb: SamDB connection
        :return: Dn to use for searching
        """
        return samdb.get_root_basedn()

    @staticmethod
    def get_object_class():
        return "user"

    @classmethod
    def find(cls, samdb, name):
        """Helper function to find a user by Dn, objectSid, or sAMAccountName.

        If the Dn or Sid can't be parsed, use sAMAccountName instead.
        """
        try:
            query = {"dn": Dn(samdb, name)}
        except ValueError:
            try:
                query = {"object_sid": dom_sid(name)}
            except ValueError:
                query = {"account_name": name}

        return cls.get(samdb, **query)

    @classmethod
    def get_sid_for_principal(cls, samdb, principal) -> str:
        """Return object_sid for the provided principal.

        If principal is already an object sid then return without fetching,
        this is different to `User.find` which must fetch the User.
        """
        try:
            return str(dom_sid(principal))
        except ValueError:
            user = cls.find(samdb, principal)
            if user:
                return user.object_sid
            else:
                raise NotFound(f"Principal {principal} not found.")
