# domain management - domain tombstones
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

import time

import ldb
import samba.getopt as options
from samba.auth import system_session
from samba.netcmd import Command, CommandError, Option, SuperCommand
from samba.samdb import SamDB


class cmd_domain_tombstones_expunge(Command):
    """Expunge tombstones from the database.

This command expunges tombstones from the database."""
    synopsis = "%prog NC [NC [...]] [options]"

    takes_options = [
        Option("-H", "--URL", help="LDB URL for database or target server", type=str,
               metavar="URL", dest="H"),
        Option("--current-time",
               help="The current time to evaluate the tombstone lifetime from, expressed as YYYY-MM-DD",
               type=str),
        Option("--tombstone-lifetime", help="Number of days a tombstone should be preserved for", type=int),
    ]

    takes_args = ["nc*"]

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "credopts": options.CredentialsOptions,
        "versionopts": options.VersionOptions,
    }

    def run(self, *ncs, **kwargs):
        sambaopts = kwargs.get("sambaopts")
        credopts = kwargs.get("credopts")
        H = kwargs.get("H")
        current_time_string = kwargs.get("current_time")
        tombstone_lifetime = kwargs.get("tombstone_lifetime")
        lp = sambaopts.get_loadparm()
        creds = credopts.get_credentials(lp)
        samdb = SamDB(url=H, session_info=system_session(),
                      credentials=creds, lp=lp)

        if current_time_string is None and tombstone_lifetime is None:
            print("Note: without --current-time or --tombstone-lifetime "
                  "only tombstones already scheduled for deletion will "
                  "be deleted.", file=self.outf)
            print("To remove all tombstones, use --tombstone-lifetime=0.",
                  file=self.outf)

        if current_time_string is not None:
            current_time_obj = time.strptime(current_time_string, "%Y-%m-%d")
            current_time = int(time.mktime(current_time_obj))

        else:
            current_time = int(time.time())

        if len(ncs) == 0:
            res = samdb.search(expression="", base="", scope=ldb.SCOPE_BASE,
                               attrs=["namingContexts"])

            ncs = []
            for nc in res[0]["namingContexts"]:
                ncs.append(str(nc))
        else:
            ncs = list(ncs)

        started_transaction = False
        try:
            samdb.transaction_start()
            started_transaction = True
            (removed_objects,
             removed_links) = samdb.garbage_collect_tombstones(ncs,
                                                               current_time=current_time,
                                                               tombstone_lifetime=tombstone_lifetime)

        except Exception as err:
            if started_transaction:
                samdb.transaction_cancel()
            raise CommandError("Failed to expunge / garbage collect tombstones", err)

        samdb.transaction_commit()

        self.outf.write("Removed %d objects and %d links successfully\n"
                        % (removed_objects, removed_links))


class cmd_domain_tombstones(SuperCommand):
    """Domain tombstone and recycled object management."""

    subcommands = {}
    subcommands["expunge"] = cmd_domain_tombstones_expunge()
