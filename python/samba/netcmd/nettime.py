# time
#
# Copyright Jelmer Vernooij 2010 <jelmer@samba.org>
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

import samba.getopt as options
from . import common
from samba.net import Net

from samba.netcmd import (
    Command,
)


class cmd_time(Command):
    """Retrieve the time on a server.

This command returns the date and time of the Active Directory server specified on the command.  The server name specified may be the local server or a remote server.  If the servername is not specified, the command returns the time and date of the local AD server.

Example1:
samba-tool time samdom.example.com

Example1 returns the date and time of the server samdom.example.com.

Example2:
samba-tool time

Example2 return the date and time of the local server.
"""
    synopsis = "%prog [server-name] [options]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "credopts": options.CredentialsOptions,
        "versionopts": options.VersionOptions,
    }

    takes_args = ["server_name?"]

    def run(self, server_name=None, credopts=None, sambaopts=None,
            versionopts=None):
        lp = sambaopts.get_loadparm()
        creds = credopts.get_credentials(lp, fallback_machine=True)
        net = Net(creds, lp, server=credopts.ipaddress)
        if server_name is None:
            server_name = common.netcmd_dnsname(lp)
        self.outf.write(net.time(server_name) + "\n")
