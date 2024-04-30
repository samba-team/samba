# Unix SMB/CIFS implementation.
#
# Authentication silo model.
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

from ldb import FLAG_MOD_ADD, FLAG_MOD_DELETE, LdbError, Message, MessageElement

from samba.sd_utils import escaped_claim_id

from .exceptions import GrantMemberError, RevokeMemberError
from .fields import DnField, BooleanField, StringField
from .model import Model


class AuthenticationSilo(Model):
    description = StringField("description")
    enforced = BooleanField("msDS-AuthNPolicySiloEnforced")
    user_authentication_policy = DnField("msDS-UserAuthNPolicy")
    service_authentication_policy = DnField("msDS-ServiceAuthNPolicy")
    computer_authentication_policy = DnField("msDS-ComputerAuthNPolicy")
    members = DnField("msDS-AuthNPolicySiloMembers", many=True)

    @staticmethod
    def get_base_dn(samdb):
        """Return the base DN for the AuthenticationSilo model.

        :param samdb: SamDB connection
        :return: Dn object of container
        """
        base_dn = samdb.get_config_basedn()
        base_dn.add_child(
            "CN=AuthN Silos,CN=AuthN Policy Configuration,CN=Services")
        return base_dn

    @staticmethod
    def get_object_class():
        return "msDS-AuthNPolicySilo"

    def grant(self, samdb, member):
        """Grant a member access to the Authentication Silo.

        Rather than saving the silo object and writing the entire member
        list out again, just add one member only.

        :param samdb: SamDB connection
        :param member: Member to grant access to silo
        """
        # Create a message with only an add member operation.
        message = Message(dn=self.dn)
        message.add(MessageElement(str(member.dn), FLAG_MOD_ADD,
                                   "msDS-AuthNPolicySiloMembers"))

        # Update authentication silo.
        try:
            samdb.modify(message)
        except LdbError as e:
            raise GrantMemberError(f"Failed to grant access to silo member: {e}")

        # If the modify operation was successful refresh members field.
        self.refresh(samdb, fields=["members"])

    def revoke(self, samdb, member):
        """Revoke a member from the Authentication Silo.

        Rather than saving the silo object and writing the entire member
        list out again, just remove one member only.

        :param samdb: SamDB connection
        :param member: Member to revoke from silo
        """
        # Create a message with only a remove member operation.
        message = Message(dn=self.dn)
        message.add(MessageElement(str(member.dn), FLAG_MOD_DELETE,
                                   "msDS-AuthNPolicySiloMembers"))

        # Update authentication silo.
        try:
            samdb.modify(message)
        except LdbError as e:
            raise RevokeMemberError(f"Failed to revoke silo member: {e}")

        # If the modify operation was successful refresh members field.
        self.refresh(samdb, fields=["members"])

    def get_authentication_sddl(self):
        return ('O:SYG:SYD:(XA;OICI;CR;;;WD;(@USER.ad://ext/'
                f'AuthenticationSilo == "{escaped_claim_id(self.name)}"))')
