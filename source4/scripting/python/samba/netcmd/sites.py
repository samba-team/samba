# sites management
#
# Copyright Matthieu Patou <mat@matws.net> 2011
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
from samba import sites
from samba.samdb import SamDB
import samba.getopt as options
from samba.auth import system_session
from samba.netcmd import (
    Command,
    CommandError,
    SuperCommand
    )


class cmd_sites_create(Command):
    """Create a new site."""

    synopsis = "%prog <site> [options]"

    takes_args = ["sitename"]

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "versionopts": options.VersionOptions,
        "credopts": options.CredentialsOptions,
    }

    def run(self, sitename, sambaopts=None, credopts=None, versionopts=None):
        lp = sambaopts.get_loadparm()
        creds = credopts.get_credentials(lp, fallback_machine=True)
        url =  lp.private_path("sam.ldb")

        if not os.path.exists(url):
            raise CommandError("secret database not found at %s " % url)
        samdb = SamDB(url=url, session_info=system_session(),
                      credentials=creds, lp=lp)

        samdb.transaction_start()
        try:
            ok = sites.create_site(samdb, samdb.get_config_basedn(), sitename)
            samdb.transaction_commit()
        except sites.SiteAlreadyExistsException, e:
            samdb.transaction_cancel()
            raise CommandError("Error while creating site %s, error: %s" % (sitename, str(e)))

        self.outf.write("Site %s created !\n" % sitename)

class cmd_sites_delete(Command):
    """Delete an existing site."""

    synopsis = "%prog <site> [options]"

    takes_args = ["sitename"]

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "versionopts": options.VersionOptions,
        "credopts": options.CredentialsOptions,
    }

    def run(self, sitename, sambaopts=None, credopts=None, versionopts=None):
        lp = sambaopts.get_loadparm()
        creds = credopts.get_credentials(lp, fallback_machine=True)
        url =  lp.private_path("sam.ldb")

        if not os.path.exists(url):
            raise CommandError("secret database not found at %s " % url)
        samdb = SamDB(url=url, session_info=system_session(),
            credentials=creds, lp=lp)

        samdb.transaction_start()
        try:
            ok = sites.delete_site(samdb, samdb.get_config_basedn(), sitename)
            samdb.transaction_commit()
        except sites.SiteException, e:
            samdb.transaction_cancel()
            raise CommandError(
                "Error while removing site %s, error: %s" % (sitename, str(e)))

        self.outf.write("Site %s removed!\n" % sitename)



class cmd_sites(SuperCommand):
    """Sites management."""

    subcommands = {}
    subcommands["create"] = cmd_sites_create()
    subcommands["remove"] = cmd_sites_delete()
