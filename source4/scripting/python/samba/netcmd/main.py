# Unix SMB/CIFS implementation.
# Copyright (C) Jelmer Vernooij <jelmer@samba.org> 2011
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

"""The main samba-tool command implementation."""

from samba import getopt as options

from samba.netcmd import SuperCommand
from samba.netcmd.dbcheck import cmd_dbcheck
from samba.netcmd.delegation import cmd_delegation
from samba.netcmd.dns import cmd_dns
from samba.netcmd.domain import cmd_domain
from samba.netcmd.drs import cmd_drs
from samba.netcmd.dsacl import cmd_dsacl
from samba.netcmd.fsmo import cmd_fsmo
from samba.netcmd.gpo import cmd_gpo
from samba.netcmd.group import cmd_group
from samba.netcmd.ldapcmp import cmd_ldapcmp
from samba.netcmd.ntacl import cmd_ntacl
from samba.netcmd.rodc import cmd_rodc
from samba.netcmd.sites import cmd_sites
from samba.netcmd.spn import cmd_spn
from samba.netcmd.testparm import cmd_testparm
from samba.netcmd.time import cmd_time
from samba.netcmd.user import cmd_user
from samba.netcmd.vampire import cmd_vampire
from samba.netcmd.processes import cmd_processes


class cmd_sambatool(SuperCommand):
    """Main samba administration tool."""

    takes_optiongroups = {
        "versionopts": options.VersionOptions,
        }

    subcommands = {}
    subcommands["dbcheck"] =  cmd_dbcheck()
    subcommands["delegation"] = cmd_delegation()
    subcommands["dns"] = cmd_dns()
    subcommands["domain"] = cmd_domain()
    subcommands["drs"] = cmd_drs()
    subcommands["dsacl"] = cmd_dsacl()
    subcommands["fsmo"] = cmd_fsmo()
    subcommands["gpo"] = cmd_gpo()
    subcommands["group"] = cmd_group()
    subcommands["ldapcmp"] = cmd_ldapcmp()
    subcommands["ntacl"] = cmd_ntacl()
    subcommands["rodc"] = cmd_rodc()
    subcommands["sites"] = cmd_sites()
    subcommands["spn"] = cmd_spn()
    subcommands["testparm"] =  cmd_testparm()
    subcommands["time"] = cmd_time()
    subcommands["user"] = cmd_user()
    subcommands["vampire"] = cmd_vampire()
    subcommands["processes"] = cmd_processes()
