#!/usr/bin/env python
#
# joins
# 
# Copyright Jelmer Vernooij 2010
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

from samba.net import Net, LIBNET_JOIN_AUTOMATIC
from samba.netcmd import Command, CommandError
from samba.dcerpc.netr import SEC_CHAN_WKSTA, SEC_CHAN_BDC


class cmd_join(Command):
    """Joins domain as either member or backup domain controller [server connection needed]"""

    synopsis = "%prog join <domain> [BDC | MEMBER] [options]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "versionopts": options.VersionOptions,
        "credopts": options.CredentialsOptions,
    }

    takes_args = ["domain", "role?"]

    def run(self, domain, role=None, sambaopts=None, credopts=None,
            versionopts=None):
        lp = sambaopts.get_loadparm()
        creds = credopts.get_credentials(lp)
        net = Net(creds, lp)
        
        if role is None:
            secure_channel_type = SEC_CHAN_WKSTA
        elif role == "BDC":
            secure_channel_type = SEC_CHAN_BDC
        elif role == "MEMBER":
            secure_channel_type = SEC_CHAN_WKSTA
        else:
            raise CommandError("Invalid role %s (possible values: MEMBER, BDC)" % role)

        (join_password, sid, domain_name) = net.join(domain,
            lp.get("netbios name"), SEC_CHAN_WKSTA, LIBNET_JOIN_AUTOMATIC)

        self.outf.write("Joined domain %s (%s)\n" % (domain_name, sid))
