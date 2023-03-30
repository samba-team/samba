# domain management - domain info
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
from samba.netcmd import Command, CommandError
from samba.netcmd.common import netcmd_get_domain_infos_via_cldap


class cmd_domain_info(Command):
    """Print basic info about a domain and the DC passed as parameter."""

    synopsis = "%prog <ip_address> [options]"

    takes_options = [
    ]

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "credopts": options.CredentialsOptions,
        "versionopts": options.VersionOptions,
    }

    takes_args = ["address"]

    def run(self, address, credopts=None, sambaopts=None, versionopts=None):
        lp = sambaopts.get_loadparm()
        try:
            res = netcmd_get_domain_infos_via_cldap(lp, None, address)
        except RuntimeError:
            raise CommandError("Invalid IP address '" + address + "'!")
        self.outf.write("Forest           : %s\n" % res.forest)
        self.outf.write("Domain           : %s\n" % res.dns_domain)
        self.outf.write("Netbios domain   : %s\n" % res.domain_name)
        self.outf.write("DC name          : %s\n" % res.pdc_dns_name)
        self.outf.write("DC netbios name  : %s\n" % res.pdc_name)
        self.outf.write("Server site      : %s\n" % res.server_site)
        self.outf.write("Client site      : %s\n" % res.client_site)
