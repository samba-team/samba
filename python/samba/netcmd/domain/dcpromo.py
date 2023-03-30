# domain management - domain dcpromo
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

import samba
import samba.getopt as options
from samba.join import join_DC, join_RODC
from samba.net import Net
from samba.netcmd import Command, CommandError

from .common import (common_join_options, common_ntvfs_options,
                     common_provision_join_options)


class cmd_domain_dcpromo(Command):
    """Promote an existing domain member or NT4 PDC to an AD DC."""

    synopsis = "%prog <dnsdomain> [DC|RODC] [options]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "versionopts": options.VersionOptions,
        "credopts": options.CredentialsOptions,
    }

    takes_options = []
    takes_options.extend(common_join_options)

    takes_options.extend(common_provision_join_options)

    if samba.is_ntvfs_fileserver_built():
        takes_options.extend(common_ntvfs_options)

    takes_args = ["domain", "role?"]

    def run(self, domain, role=None, sambaopts=None, credopts=None,
            versionopts=None, server=None, site=None, targetdir=None,
            domain_critical_only=False, machinepass=None,
            use_ntvfs=False, dns_backend=None,
            quiet=False, verbose=False, plaintext_secrets=False,
            backend_store=None, backend_store_size=None):
        lp = sambaopts.get_loadparm()
        creds = credopts.get_credentials(lp)
        net = Net(creds, lp, server=credopts.ipaddress)

        logger = self.get_logger(verbose=verbose, quiet=quiet)

        netbios_name = lp.get("netbios name")

        if role is not None:
            role = role.upper()

        if role == "DC":
            join_DC(logger=logger, server=server, creds=creds, lp=lp, domain=domain,
                    site=site, netbios_name=netbios_name, targetdir=targetdir,
                    domain_critical_only=domain_critical_only,
                    machinepass=machinepass, use_ntvfs=use_ntvfs,
                    dns_backend=dns_backend,
                    promote_existing=True, plaintext_secrets=plaintext_secrets,
                    backend_store=backend_store,
                    backend_store_size=backend_store_size)
        elif role == "RODC":
            join_RODC(logger=logger, server=server, creds=creds, lp=lp, domain=domain,
                      site=site, netbios_name=netbios_name, targetdir=targetdir,
                      domain_critical_only=domain_critical_only,
                      machinepass=machinepass, use_ntvfs=use_ntvfs, dns_backend=dns_backend,
                      promote_existing=True, plaintext_secrets=plaintext_secrets,
                      backend_store=backend_store,
                      backend_store_size=backend_store_size)
        else:
            raise CommandError("Invalid role '%s' (possible values: DC, RODC)" % role)
