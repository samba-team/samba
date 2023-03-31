# domain management - domain join
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

import os
import tempfile

import samba
import samba.getopt as options
from samba import is_ad_dc_built
from samba.dcerpc import nbt
from samba.join import join_DC, join_RODC
from samba.net import LIBNET_JOIN_AUTOMATIC, Net
from samba.net_s3 import Net as s3_Net
from samba.netcmd import Command, CommandError, Option
from samba.param import default_path
from samba.samba3 import param as s3param

from .common import common_join_options, common_provision_join_options


class cmd_domain_join(Command):
    """Join domain as either member or backup domain controller."""

    synopsis = "%prog <dnsdomain> [DC|RODC|MEMBER] [options]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "versionopts": options.VersionOptions,
        "credopts": options.CredentialsOptions,
    }

    ntvfs_options = [
        Option(
            "--use-ntvfs", help="Use NTVFS for the fileserver (default = no)",
            action="store_true")
    ]

    selftest_options = [
        Option("--experimental-s4-member", action="store_true",
               help="Perform member joins using the s4 Net join_member. "
                    "Don't choose this unless you know what you're doing")
    ]

    takes_options = [
        Option("--no-dns-updates", action="store_true",
               help="Disable DNS updates")
    ]
    takes_options.extend(common_join_options)
    takes_options.extend(common_provision_join_options)

    if samba.is_ntvfs_fileserver_built():
        takes_options.extend(ntvfs_options)

    if samba.is_selftest_enabled():
        takes_options.extend(selftest_options)

    takes_args = ["domain", "role?"]

    def run(self, domain, role=None, sambaopts=None, credopts=None,
            versionopts=None, server=None, site=None, targetdir=None,
            domain_critical_only=False, machinepass=None,
            use_ntvfs=False, experimental_s4_member=False, dns_backend=None,
            quiet=False, verbose=False, no_dns_updates=False,
            plaintext_secrets=False,
            backend_store=None, backend_store_size=None):
        lp = sambaopts.get_loadparm()
        creds = credopts.get_credentials(lp)
        net = Net(creds, lp, server=credopts.ipaddress)

        logger = self.get_logger(verbose=verbose, quiet=quiet)

        netbios_name = lp.get("netbios name")

        if role is not None:
            role = role.upper()

        if role is None or role == "MEMBER":
            if experimental_s4_member:
                (join_password, sid, domain_name) = net.join_member(
                    domain, netbios_name, LIBNET_JOIN_AUTOMATIC,
                    machinepass=machinepass)
            else:
                lp.set('realm', domain)
                if lp.get('workgroup') == 'WORKGROUP':
                    lp.set('workgroup', net.finddc(domain=domain,
                        flags=(nbt.NBT_SERVER_LDAP |
                               nbt.NBT_SERVER_DS)).domain_name)
                lp.set('server role', 'member server')
                smb_conf = lp.configfile if lp.configfile else default_path()
                with tempfile.NamedTemporaryFile(delete=False,
                        dir=os.path.dirname(smb_conf)) as f:
                    lp.dump(False, f.name)
                    if os.path.exists(smb_conf):
                        mode = os.stat(smb_conf).st_mode
                        os.chmod(f.name, mode)
                    os.rename(f.name, smb_conf)
                s3_lp = s3param.get_context()
                s3_lp.load(smb_conf)
                s3_net = s3_Net(creds, s3_lp, server=server)
                (sid, domain_name) = s3_net.join_member(netbios_name,
                                                        machinepass=machinepass,
                                                        debug=verbose,
                                                        noDnsUpdates=no_dns_updates)

            self.errf.write("Joined domain %s (%s)\n" % (domain_name, sid))
        elif role == "DC" and is_ad_dc_built():
            join_DC(logger=logger, server=server, creds=creds, lp=lp, domain=domain,
                    site=site, netbios_name=netbios_name, targetdir=targetdir,
                    domain_critical_only=domain_critical_only,
                    machinepass=machinepass, use_ntvfs=use_ntvfs,
                    dns_backend=dns_backend,
                    plaintext_secrets=plaintext_secrets,
                    backend_store=backend_store,
                    backend_store_size=backend_store_size)
        elif role == "RODC" and is_ad_dc_built():
            join_RODC(logger=logger, server=server, creds=creds, lp=lp, domain=domain,
                      site=site, netbios_name=netbios_name, targetdir=targetdir,
                      domain_critical_only=domain_critical_only,
                      machinepass=machinepass, use_ntvfs=use_ntvfs,
                      dns_backend=dns_backend,
                      plaintext_secrets=plaintext_secrets,
                      backend_store=backend_store,
                      backend_store_size=backend_store_size)
        else:
            raise CommandError("Invalid role '%s' (possible values: MEMBER, DC, RODC)" % role)
