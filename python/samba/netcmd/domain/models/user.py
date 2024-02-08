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

from ldb import FLAG_MOD_ADD, Dn

from samba.dcerpc import security
from samba.dsdb import (DS_GUID_MANAGED_SERVICE_ACCOUNTS_CONTAINER,
                        DS_GUID_USERS_CONTAINER)
from samba.ndr import ndr_unpack

from .fields import (BinaryField, DnField, EnumField, IntegerField, SDDLField,
                     SIDField, StringField, NtTimeField)
from .model import Model
from .types import AccountType, SupportedEncryptionTypes, UserAccountControl


class User(Model):
    username = StringField("sAMAccountName")
    account_type = EnumField("sAMAccountType", AccountType)
    assigned_policy = DnField("msDS-AssignedAuthNPolicy")
    assigned_silo = DnField("msDS-AssignedAuthNPolicySilo")
    object_sid = SIDField("objectSid")
    bad_password_time = NtTimeField("badPasswordTime", readonly=True)
    bad_pwd_count = IntegerField("badPwdCount", readonly=True)
    code_page = IntegerField("codePage")
    country_code = IntegerField("countryCode")
    display_name = StringField("displayName")
    given_name = StringField("givenName")
    sn = StringField("sn")
    last_logoff = NtTimeField("lastLogoff", readonly=True)
    last_logon = NtTimeField("lastLogon", readonly=True)
    logon_count = IntegerField("logonCount", readonly=True)
    primary_group_id = IntegerField("primaryGroupID")
    pwd_last_set = NtTimeField("pwdLastSet", readonly=True)
    user_account_control = EnumField("userAccountControl", UserAccountControl)
    user_principal_name = StringField("userPrincipalName")

    def __str__(self):
        """Return username rather than cn for User model."""
        return self.username

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
        """Helper function to find a user first by Dn then username.

        If the Dn can't be parsed, use sAMAccountName instead.
        """
        try:
            query = {"dn": Dn(ldb, name)}
        except ValueError:
            query = {"username": name}

        return cls.get(ldb, **query)


class GroupManagedServiceAccount(User):
    """A GroupManagedServiceAccount is a type of User with additional fields."""
    managed_password_interval = IntegerField("msDS-ManagedPasswordInterval")
    dns_host_name = StringField("dNSHostName")
    group_msa_membership = SDDLField("msDS-GroupMSAMembership")
    managed_password_id = BinaryField("msDS-ManagedPasswordId",
                                      readonly=True, hidden=True)
    managed_password_previous_id = BinaryField("msDS-ManagedPasswordPreviousId",
                                               readonly=True, hidden=True)
    supported_encryption_types = EnumField("msDS-SupportedEncryptionTypes",
                                           SupportedEncryptionTypes)

    @staticmethod
    def get_base_dn(ldb):
        """Return base Dn for Managed Service Accounts.

        :param ldb: Ldb connection
        :return: Dn to use for searching
        """
        return ldb.get_wellknown_dn(ldb.get_default_basedn(),
                                    DS_GUID_MANAGED_SERVICE_ACCOUNTS_CONTAINER)

    @staticmethod
    def get_object_class():
        return "msDS-GroupManagedServiceAccount"

    def trustees(self, ldb):
        """Returns list of trustees from the msDS-GroupMSAMembership SDDL.

        :return: list of User objects
        """
        users = []
        field = self.fields["group_msa_membership"]
        sddl = self.group_msa_membership
        message = field.to_db_value(ldb, sddl, FLAG_MOD_ADD)
        desc = ndr_unpack(security.descriptor, message[0])

        for ace in desc.dacl.aces:
            users.append(User.get(ldb, object_sid=ace.trustee))

        return users

    @classmethod
    def find(cls, ldb, name):
        """Helper function to find a service account first by Dn then username.

        If the Dn can't be parsed use sAMAccountName, automatically add the $.
        """
        try:
            query = {"dn": Dn(ldb, name)}
        except ValueError:
            if name.endswith("$"):
                query = {"username": name}
            else:
                query = {"username": name + "$"}

        return cls.get(ldb, **query)

    @staticmethod
    def group_sddl(group):
        return f"O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;{group.object_sid})"
