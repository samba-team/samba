# Unix SMB/CIFS implementation.
#
# Computer model.
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

from samba.dsdb import DS_GUID_COMPUTERS_CONTAINER

from .user import User


class Computer(User):
    """A Computer is a type of User."""

    def __init__(self, **kwargs):
        """Computer constructor automatically adds "$" to account_name.

        The various ways a Computer can be constructed:

        >>> Computer(name="pc")
        >>> Computer(account_name="pc$")
        >>> Computer(cn="pc")
        >>> Computer(account_name="pc$", name="pc")

        In each case the constructor does its best to ensure the
        account name ends with a "$" and the name doesn't.

        Also applies to GroupManagedServiceAccount subclass."""
        name = kwargs.get("name", kwargs.pop("cn", None))
        account_name = kwargs.get("account_name")

        # First make sure the account_name always has a "$".
        if account_name and not account_name.endswith("$"):
            account_name += "$"

        # The name is present but not account name.
        # If the name already has a "$" don't add two.
        if name and not account_name:
            if name.endswith("$"):
                account_name = name
            else:
                account_name = name + "$"

        # The account name is present but not the name.
        # Use the account name, stripping the "$" character.
        elif account_name and not name:
            name = account_name.rstrip("$")

        kwargs["name"] = name
        kwargs["account_name"] = account_name
        super().__init__(**kwargs)

    @staticmethod
    def get_base_dn(samdb):
        """Return base Dn for Computers.

        :param samdb: SamDB connection
        :return: Dn to use for searching
        """
        return samdb.get_wellknown_dn(samdb.get_default_basedn(),
                                      DS_GUID_COMPUTERS_CONTAINER)

    @staticmethod
    def get_object_class():
        return "computer"

    @classmethod
    def find(cls, samdb, name):
        """Helper function to find a computer, first by Dn then sAMAccountName.

        If the Dn can't be parsed use sAMAccountName, automatically add the $.
        """
        try:
            query = {"dn": Dn(samdb, name)}
        except ValueError:
            if name.endswith("$"):
                query = {"account_name": name}
            else:
                query = {"account_name": name + "$"}

        return cls.get(samdb, **query)
