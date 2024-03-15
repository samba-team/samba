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
from samba import enable_net_export_keytab, NTSTATUSError
from samba.net import Net
from samba.netcmd import Command, CommandError, Option

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
            "hostopts": options.HostOptions,
            "versionopts": options.VersionOptions,
        }

        takes_options = [
            Option("--principal", help="extract only this principal", type=str),
            Option("--keep-stale-entries", help="keep stale keys in keytab (useful for collecting keys for Wireshark)", action="store_true"),
            Option("--only-current-keys",
                   help="This avoids exporting old and older keys (useful for keytabs used by kinit)",
                   action="store_true"),
        ]

        takes_args = ["keytab"]

        def run(self,
                keytab,
                credopts=None,
                sambaopts=None,
                versionopts=None,
                hostopts=None,
                principal=None,
                keep_stale_entries=None,
                only_current_keys=None):
            lp = sambaopts.get_loadparm()
            net = Net(None, lp)
            samdb = self.ldb_connect(hostopts, sambaopts, credopts)
            try:
                net.export_keytab(samdb=samdb,
                                  keytab=keytab,
                                  principal=principal,
                                  keep_stale_entries=keep_stale_entries,
                                  only_current_keys=only_current_keys)
            except NTSTATUSError as error:
                raise CommandError(f"Failed to export domain keys into keytab {keytab}: {error.args[1]}")
