# Unix SMB/CIFS implementation.
#
# Enums and flag types for models.
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

from enum import IntFlag

from samba.dsdb import (ATYPE_SECURITY_GLOBAL_GROUP,
                        ATYPE_SECURITY_LOCAL_GROUP,
                        ATYPE_NORMAL_ACCOUNT,
                        ATYPE_DISTRIBUTION_GLOBAL_GROUP,
                        ATYPE_DISTRIBUTION_LOCAL_GROUP,
                        ATYPE_WORKSTATION_TRUST,
                        ATYPE_INTERDOMAIN_TRUST)


class AccountType(IntFlag):
    SECURITY_GLOBAL_GROUP = ATYPE_SECURITY_GLOBAL_GROUP
    SECURITY_LOCAL_GROUP = ATYPE_SECURITY_LOCAL_GROUP
    NORMAL_ACCOUNT = ATYPE_NORMAL_ACCOUNT
    DISTRIBUTION_GLOBAL_GROUP = ATYPE_DISTRIBUTION_GLOBAL_GROUP
    DISTRIBUTION_LOCAL_GROUP = ATYPE_DISTRIBUTION_LOCAL_GROUP
    WORKSTATION_TRUST = ATYPE_WORKSTATION_TRUST
    INTERDOMAIN_TRUST = ATYPE_INTERDOMAIN_TRUST
