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

        Also applies to GroupManagedServiceAccount subclass.
        """
        name = kwargs.get("name", kwargs.get("cn"))
        account_name = kwargs.get("account_name")

        # If account_name is missing, use name or cn and add a "$".
        # If account_name is present but lacking "$", add it automatically.
        if name and not account_name:
            kwargs["account_name"] = name + "$"
        elif account_name and not account_name.endswith("$"):
            kwargs["account_name"] = account_name + "$"

        super().__init__(**kwargs)

    @staticmethod
    def get_base_dn(ldb):
        """Return base Dn for Computers.

        :param ldb: Ldb connection
        :return: Dn to use for searching
        """
        return ldb.get_wellknown_dn(ldb.get_default_basedn(),
                                    DS_GUID_COMPUTERS_CONTAINER)

    @staticmethod
    def get_object_class():
        return "computer"

    @classmethod
    def find(cls, ldb, name):
        """Helper function to find a computer, first by Dn then sAMAccountName.

        If the Dn can't be parsed use sAMAccountName, automatically add the $.
        """
        try:
            query = {"dn": Dn(ldb, name)}
        except ValueError:
            if name.endswith("$"):
                query = {"account_name": name}
            else:
                query = {"account_name": name + "$"}

        return cls.get(ldb, **query)
