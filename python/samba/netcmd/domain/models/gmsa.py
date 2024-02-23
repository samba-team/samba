# Unix SMB/CIFS implementation.
#
# GroupManagedServiceAccount model.
#
# Copyright (C) Catalyst.Net Ltd. 2024
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

from samba.dcerpc import security
from samba.dsdb import DS_GUID_MANAGED_SERVICE_ACCOUNTS_CONTAINER

from .computer import Computer
from .constants import GROUP_MSA_MEMBERSHIP_DEFAULT
from .exceptions import FieldError
from .fields import BinaryField, EnumField, IntegerField, SDDLField, StringField
from .types import SupportedEncryptionTypes


class GroupManagedServiceAccount(Computer):
    """A GroupManagedServiceAccount is a type of Computer which is also a User."""
    managed_password_interval = IntegerField("msDS-ManagedPasswordInterval")
    dns_host_name = StringField("dNSHostName")
    group_msa_membership = SDDLField("msDS-GroupMSAMembership",
                                     default=GROUP_MSA_MEMBERSHIP_DEFAULT)
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

    @property
    def trustees(self):
        """Returns list of trustees from the msDS-GroupMSAMembership field.

        :return: list of SID strings
        """
        allowed = []

        # Make sure to exclude DENY aces.
        for ace in self.group_msa_membership.dacl.aces:
            if ((ace.access_mask & security.SEC_ADS_READ_PROP)
                    and ace.type == security.SEC_ACE_TYPE_ACCESS_ALLOWED):
                allowed.append(str(ace.trustee))
            else:
                raise FieldError(
                    "Cannot be represented as a simple list (try viewing as SDDL)",
                    field=GroupManagedServiceAccount.group_msa_membership)

        return allowed
