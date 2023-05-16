# Unix SMB/CIFS implementation.
#
# claim management - base class and common code
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

import json

from ldb import SCOPE_ONELEVEL
from samba.auth import system_session
from samba.netcmd import Command
from samba.netcmd.encoders import JSONEncoder
from samba.samdb import SamDB


class ClaimCommand(Command):
    """Base class for all claim commands."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.ldb = None

    def ldb_connect(self, ldap_url, sambaopts, credopts):
        """Helper to connect to Ldb database using command line opts."""
        lp = sambaopts.get_loadparm()
        creds = credopts.get_credentials(lp)
        return SamDB(ldap_url, credentials=creds,
                     session_info=system_session(lp), lp=lp)

    def print_json(self, data):
        """Print json on the screen using consistent formatting and sorting.

        A custom JSONEncoder class is used to help with serializing unknown
        objects such as Dn for example.
        """
        json.dump(data, self.outf, cls=JSONEncoder, indent=2, sort_keys=True)
        self.outf.write("\n")

    def get_attribute_from_schema(self, name):
        """Find DN by name in attribute schema.

        :raises LookupError: if not found.
        """
        if not name:
            raise ValueError("Attribute name is required.")
        return self.get_object_from_schema(name, "attributeSchema")

    def get_class_from_schema(self, name):
        """Find DN by name in class schema.

        :raises LookupError: if not found.
        """
        if not name:
            raise ValueError("Class name is required.")
        return self.get_object_from_schema(name, "classSchema")

    def get_object_from_schema(self, name, object_class):
        """Gets a single item from the schema by name and object class.

        :raises LookupError: if not found.
        """
        schema_dn = self.ldb.get_schema_basedn()

        res = self.ldb.search(base=schema_dn,
                              scope=SCOPE_ONELEVEL,
                              expression=(f"(&(objectClass={object_class})"
                                          f"(lDAPDisplayName={name}))"))

        if len(res) != 1:
            raise LookupError(f"Could not locate {name} in {object_class}.")

        return res[0]
