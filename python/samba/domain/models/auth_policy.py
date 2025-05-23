# Unix SMB/CIFS implementation.
#
# Authentication policy model.
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

from enum import IntEnum
from ldb import Dn

from .fields import (BooleanField, EnumField, IntegerField, SDDLField,
                     StringField)
from .model import Model

# Ticket-Granting-Ticket lifetimes.
MIN_TGT_LIFETIME = 45
MAX_TGT_LIFETIME = 2147483647


class StrongNTLMPolicy(IntEnum):
    DISABLED = 0
    OPTIONAL = 1
    REQUIRED = 2

    @classmethod
    def get_choices(cls):
        return sorted([choice.capitalize() for choice in cls._member_names_])

    @classmethod
    def choices_str(cls):
        return ", ".join(cls.get_choices())


class AuthenticationPolicy(Model):
    description = StringField("description")
    enforced = BooleanField("msDS-AuthNPolicyEnforced")
    strong_ntlm_policy = EnumField("msDS-StrongNTLMPolicy", StrongNTLMPolicy)
    user_allow_ntlm_network_auth = BooleanField(
        "msDS-UserAllowedNTLMNetworkAuthentication")
    user_tgt_lifetime = IntegerField("msDS-UserTGTLifetime")
    service_allow_ntlm_network_auth = BooleanField(
        "msDS-ServiceAllowedNTLMNetworkAuthentication")
    service_tgt_lifetime = IntegerField("msDS-ServiceTGTLifetime")
    computer_tgt_lifetime = IntegerField("msDS-ComputerTGTLifetime")
    user_allowed_to_authenticate_from = SDDLField(
        "msDS-UserAllowedToAuthenticateFrom", allow_device_in_sddl=False)
    user_allowed_to_authenticate_to = SDDLField(
        "msDS-UserAllowedToAuthenticateTo")
    service_allowed_to_authenticate_from = SDDLField(
        "msDS-ServiceAllowedToAuthenticateFrom", allow_device_in_sddl=False)
    service_allowed_to_authenticate_to = SDDLField(
        "msDS-ServiceAllowedToAuthenticateTo")
    computer_allowed_to_authenticate_to = SDDLField(
        "msDS-ComputerAllowedToAuthenticateTo")

    @staticmethod
    def get_base_dn(samdb):
        """Return the base DN for the AuthenticationPolicy model.

        :param samdb: SamDB connection
        :return: Dn object of container
        """
        base_dn = samdb.get_config_basedn()
        base_dn.add_child(
            "CN=AuthN Policies,CN=AuthN Policy Configuration,CN=Services")
        return base_dn

    @staticmethod
    def get_object_class():
        return "msDS-AuthNPolicy"

    @staticmethod
    def find(samdb, name):
        """Helper function to return auth policy or raise NotFound.

        :param samdb: SamDB connection
        :param name: Either DN or name of Authentication Policy
        :raises: NotFound if not found
        :raises: ValueError if name is not set
        """
        if not name:
            raise ValueError("Attribute 'name' is required.")

        try:
            # It's possible name is already a Dn.
            dn = name if isinstance(name, Dn) else Dn(samdb, name)
            policy = AuthenticationPolicy.get(samdb, dn=dn)
        except ValueError:
            policy = AuthenticationPolicy.get(samdb, cn=name)

        if policy is None:
            raise LookupError(f"Authentication policy {name} not found.")

        return policy
