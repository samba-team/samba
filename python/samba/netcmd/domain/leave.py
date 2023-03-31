# domain management - domain leave
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
from samba.net_s3 import Net as s3_Net
from samba.netcmd import Command, Option
from samba.param import default_path
from samba.samba3 import param as s3param


class cmd_domain_leave(Command):
    """Cause a domain member to leave the joined domain."""

    synopsis = "%prog [options]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "versionopts": options.VersionOptions,
        "credopts": options.CredentialsOptions,
    }

    takes_options = [
        Option("--keep-account", action="store_true",
               help="Disable the machine account instead of deleting it.")
    ]

    takes_args = []

    def run(self, sambaopts=None, credopts=None, versionopts=None,
            keep_account=False):
        lp = sambaopts.get_loadparm()
        creds = credopts.get_credentials(lp)

        s3_lp = s3param.get_context()
        smb_conf = lp.configfile if lp.configfile else default_path()
        s3_lp.load(smb_conf)
        s3_net = s3_Net(creds, s3_lp)
        s3_net.leave(keep_account)
