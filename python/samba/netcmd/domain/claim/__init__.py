# Unix SMB/CIFS implementation.
#
# claim management
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

from .claim_type import cmd_domain_claim_claim_type
from .value_type import cmd_domain_claim_value_type


class cmd_domain_claim(SuperCommand):
    """Manage claims on the domain."""

    subcommands = {
        "claim-type": cmd_domain_claim_claim_type(),
        "value-type": cmd_domain_claim_value_type(),
    }
