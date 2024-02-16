# Unix SMB/CIFS implementation.
#
# Service account management.
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

from samba.netcmd import SuperCommand

from .group_msa_membership import cmd_service_account_group_msa_membership
from .service_account import (cmd_service_account_create,
                              cmd_service_account_delete,
                              cmd_service_account_list,
                              cmd_service_account_modify,
                              cmd_service_account_view)


class cmd_service_account(SuperCommand):
    """Service Account and Group Managed Service Account management."""

    subcommands = {
        "create": cmd_service_account_create(),
        "delete": cmd_service_account_delete(),
        "list": cmd_service_account_list(),
        "view": cmd_service_account_view(),
        "modify": cmd_service_account_modify(),
        "group-msa-membership": cmd_service_account_group_msa_membership(),
    }
