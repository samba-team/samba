# domain management - domain keytab
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

import samba.getopt as options
from samba import enable_net_export_keytab
from samba.net import Net
from samba.netcmd import Command, Option

try:
    enable_net_export_keytab()
except ImportError:
    cmd_domain_export_keytab = None
else:
    class cmd_domain_export_keytab(Command):
        """Dump Kerberos keys of the domain into a keytab."""

        synopsis = "%prog <keytab> [options]"

        takes_optiongroups = {
            "sambaopts": options.SambaOptions,
            "credopts": options.CredentialsOptions,
            "versionopts": options.VersionOptions,
        }

        takes_options = [
            Option("--principal", help="extract only this principal", type=str),
        ]

        takes_args = ["keytab"]

        def run(self, keytab, credopts=None, sambaopts=None, versionopts=None, principal=None):
            lp = sambaopts.get_loadparm()
            net = Net(None, lp)
            net.export_keytab(keytab=keytab, principal=principal)
