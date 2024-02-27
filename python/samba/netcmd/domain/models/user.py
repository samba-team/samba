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

from samba.dsdb import DS_GUID_USERS_CONTAINER

from .fields import DnField, EnumField, IntegerField, NtTimeField, StringField
from .person import OrganizationalPerson
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

    @staticmethod
    def get_base_dn(ldb):
        """Return the base DN for the User model.

        :param ldb: Ldb connection
        :return: Dn to use for new objects
        """
        return ldb.get_wellknown_dn(ldb.get_default_basedn(),
                                    DS_GUID_USERS_CONTAINER)

    @classmethod
    def get_search_dn(cls, ldb):
        """Return Dn used for searching so Computers will also be found.

        :param ldb: Ldb connection
        :return: Dn to use for searching
        """
        return ldb.get_root_basedn()

    @staticmethod
    def get_object_class():
        return "user"

    @classmethod
    def find(cls, ldb, name):
        """Helper function to find a user first by Dn then sAMAccountName.

        If the Dn can't be parsed, use sAMAccountName instead.
        """
        try:
            query = {"dn": Dn(ldb, name)}
        except ValueError:
            query = {"account_name": name}

        return cls.get(ldb, **query)
