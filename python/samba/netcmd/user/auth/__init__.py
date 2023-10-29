# Unix SMB/CIFS implementation.
#
# manage assigned authentication policies and silos on a user
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

from samba.netcmd import SuperCommand

from .policy import cmd_user_auth_policy
from .silo import cmd_user_auth_silo


class cmd_user_auth(SuperCommand):
    """Manage authentication policies and silos on a user."""

    subcommands = {
        "policy": cmd_user_auth_policy(),
        "silo": cmd_user_auth_silo(),
    }
