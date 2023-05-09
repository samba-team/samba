# domain management
#
# Copyright Matthias Dieter Wallnoefer 2009
# Copyright Andrew Kroeger 2009
# Copyright Jelmer Vernooij 2007-2012
# Copyright Giampaolo Lauria 2011
# Copyright Matthieu Patou <mat@matws.net> 2011
# Copyright Andrew Bartlett 2008-2015
# Copyright Stefan Metzmacher 2012
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

from samba import is_ad_dc_built
from samba.netcmd import SuperCommand

from .backup import cmd_domain_backup
from .claim import cmd_domain_claim
from .classicupgrade import cmd_domain_classicupgrade
from .common import (common_join_options, common_ntvfs_options,
                     common_provision_join_options)
from .dcpromo import cmd_domain_dcpromo
from .demote import cmd_domain_demote
from .functional_prep import cmd_domain_functional_prep
from .info import cmd_domain_info
from .join import cmd_domain_join
from .keytab import cmd_domain_export_keytab
from .leave import cmd_domain_leave
from .level import cmd_domain_level
from .passwordsettings import cmd_domain_passwordsettings
from .provision import cmd_domain_provision
from .samba3upgrade import cmd_domain_samba3upgrade
from .schemaupgrade import cmd_domain_schema_upgrade
from .tombstones import cmd_domain_tombstones
from .trust import cmd_domain_trust


class cmd_domain(SuperCommand):
    """Domain management."""

    subcommands = {}
    if cmd_domain_export_keytab is not None:
        subcommands["exportkeytab"] = cmd_domain_export_keytab()
    subcommands["info"] = cmd_domain_info()
    subcommands["join"] = cmd_domain_join()
    subcommands["leave"] = cmd_domain_leave()
    subcommands["claim"] = cmd_domain_claim()
    if is_ad_dc_built():
        subcommands["demote"] = cmd_domain_demote()
        subcommands["provision"] = cmd_domain_provision()
        subcommands["dcpromo"] = cmd_domain_dcpromo()
        subcommands["level"] = cmd_domain_level()
        subcommands["passwordsettings"] = cmd_domain_passwordsettings()
        subcommands["classicupgrade"] = cmd_domain_classicupgrade()
        subcommands["samba3upgrade"] = cmd_domain_samba3upgrade()
        subcommands["trust"] = cmd_domain_trust()
        subcommands["tombstones"] = cmd_domain_tombstones()
        subcommands["schemaupgrade"] = cmd_domain_schema_upgrade()
        subcommands["functionalprep"] = cmd_domain_functional_prep()
        subcommands["backup"] = cmd_domain_backup()
