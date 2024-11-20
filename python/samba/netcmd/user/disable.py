# user management
#
# disable user
#
# Copyright Jelmer Vernooij 2010 <jelmer@samba.org>
# Copyright Theresa Halloran 2011 <theresahalloran@gmail.com>
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
from samba import ldb
from samba.auth import system_session
from samba.netcmd import Command, CommandError, Option
from samba.samdb import SamDB


class cmd_user_disable(Command):
    """Disable a user."""

    synopsis = "%prog (<username>|--filter <filter>) [options]"

    takes_options = [
        Option("-H", "--URL", help="LDB URL for database or target server", type=str,
               metavar="URL", dest="H"),
        Option("--filter",
               help="LDAP filter to select user",
               type=str,
               dest="search_filter"),
    ]

    takes_args = ["username?"]

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "credopts": options.CredentialsOptions,
        "versionopts": options.VersionOptions,
    }

    def run(self, username=None, sambaopts=None, credopts=None,
            versionopts=None, search_filter=None, H=None):
        if username is None and search_filter is None:
            raise CommandError("Either the username or '--filter' must be specified!")

        if search_filter is None:
            search_filter = "(&(objectClass=user)(sAMAccountName=%s))" % (
                ldb.binary_encode(username))

        lp = sambaopts.get_loadparm()
        creds = credopts.get_credentials(lp, fallback_machine=True)

        samdb = SamDB(url=H, session_info=system_session(),
                      credentials=creds, lp=lp)
        try:
            samdb.disable_account(search_filter)
        except Exception as msg:
            raise CommandError("Failed to disable user '%s': %s" % (
                username or search_filter, msg))
