# Unix SMB/CIFS implementation.
#
# authentication silos - authentication silo management
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

from .member import cmd_domain_auth_silo_member
from .silo import (
    cmd_domain_auth_silo_create,
    cmd_domain_auth_silo_delete,
    cmd_domain_auth_silo_list,
    cmd_domain_auth_silo_modify,
    cmd_domain_auth_silo_view,
)


class cmd_domain_auth_silo(SuperCommand):
    """Manage authentication silos on the domain."""

    subcommands = {
        "list": cmd_domain_auth_silo_list(),
        "view": cmd_domain_auth_silo_view(),
        "create": cmd_domain_auth_silo_create(),
        "modify": cmd_domain_auth_silo_modify(),
        "delete": cmd_domain_auth_silo_delete(),
        "member": cmd_domain_auth_silo_member(),
    }
