# Unix SMB/CIFS implementation.
#
# authentication silos - base class and common code
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

from samba.netcmd import Command, CommandError
from samba.netcmd.encoders import JSONEncoder
from samba.netcmd.domain.models import AuthenticationPolicy


class SiloCommand(Command):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.ldb = None

    def print_json(self, data):
        """Print json on the screen using consistent formatting and sorting.

        A custom JSONEncoder class is used to help with serializing unknown
        objects such as Dn for example.
        """
        json.dump(data, self.outf, cls=JSONEncoder, indent=2, sort_keys=True)
        self.outf.write("\n")

    def get_policy(self, name):
        """Helper function to return auth policy or raise CommandError.

        :raises CommandError: if the policy was not found.
        """
        policy = AuthenticationPolicy.get(self.ldb, cn=name)
        if policy is None:
            raise CommandError(f"Authentication policy {name} not found.")
        return policy
