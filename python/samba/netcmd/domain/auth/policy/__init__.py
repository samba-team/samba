# Unix SMB/CIFS implementation.
#
# authentication silos - authentication policy management
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

from .computer_allowed_to_authenticate_to import (
    cmd_domain_auth_policy_computer_allowed_to_authenticate_to,
)
from .service_allowed_to_authenticate_from import (
    cmd_domain_auth_policy_service_allowed_to_authenticate_from,
)
from .service_allowed_to_authenticate_to import (
    cmd_domain_auth_policy_service_allowed_to_authenticate_to,
)
from .user_allowed_to_authenticate_from import (
    cmd_domain_auth_policy_user_allowed_to_authenticate_from,
)
from .user_allowed_to_authenticate_to import (
    cmd_domain_auth_policy_user_allowed_to_authenticate_to,
)
from .policy import (
    cmd_domain_auth_policy_create,
    cmd_domain_auth_policy_delete,
    cmd_domain_auth_policy_list,
    cmd_domain_auth_policy_modify,
    cmd_domain_auth_policy_view,
)


class cmd_domain_auth_policy(SuperCommand):
    """Manage authentication policies on the domain."""

    subcommands = {
        "list": cmd_domain_auth_policy_list(),
        "view": cmd_domain_auth_policy_view(),
        "create": cmd_domain_auth_policy_create(),
        "modify": cmd_domain_auth_policy_modify(),
        "delete": cmd_domain_auth_policy_delete(),
        "computer-allowed-to-authenticate-to":
            cmd_domain_auth_policy_computer_allowed_to_authenticate_to(),
        "service-allowed-to-authenticate-from":
            cmd_domain_auth_policy_service_allowed_to_authenticate_from(),
        "service-allowed-to-authenticate-to":
            cmd_domain_auth_policy_service_allowed_to_authenticate_to(),
        "user-allowed-to-authenticate-from":
            cmd_domain_auth_policy_user_allowed_to_authenticate_from(),
        "user-allowed-to-authenticate-to":
            cmd_domain_auth_policy_user_allowed_to_authenticate_to(),
    }
