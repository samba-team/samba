# user management
#
# user unlock command
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
from samba.samdb import SamDB, SamDBError


class cmd_user_unlock(Command):
    """Unlock a user account.

    This command unlocks a user account in the Active Directory domain. The
    username specified on the command is the sAMAccountName. The username may
    also be specified using the --filter option.

    The command may be run from the root userid or another authorized userid.
    The -H or --URL= option can be used to execute the command against a remote
    server.

    Example:
    samba-tool user unlock user1 -H ldap://samba.samdom.example.com \\
        --username=Administrator --password=Passw0rd

    The example shows how to unlock a user account in the domain against a
    remote LDAP server. The -H parameter is used to specify the remote target
    server. The --username= and --password= options are used to pass the
    username and password of a user that exists on the remote server and is
    authorized to issue the command on that server.
"""

    synopsis = "%prog (<username>|--filter <filter>) [options]"

    takes_options = [
        Option("-H",
               "--URL",
               help="LDB URL for database or target server",
               type=str,
               metavar="URL",
               dest="H"),
        Option("--filter",
               help="LDAP Filter to set password on",
               type=str),
    ]

    takes_args = ["username?"]

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "credopts": options.CredentialsOptions,
        "versionopts": options.VersionOptions,
    }

    def run(self,
            username=None,
            sambaopts=None,
            credopts=None,
            versionopts=None,
            filter=None,
            H=None):
        if username is None and filter is None:
            raise CommandError("Either the username or '--filter' must be "
                               "specified!")

        if filter is None:
            filter = ("(&(objectClass=user)(sAMAccountName=%s))" % (
                ldb.binary_encode(username)))

        lp = sambaopts.get_loadparm()
        creds = credopts.get_credentials(lp, fallback_machine=True)

        samdb = SamDB(url=H,
                      session_info=system_session(),
                      credentials=creds,
                      lp=lp)
        try:
            samdb.unlock_account(filter)
        except (SamDBError, ldb.LdbError) as msg:
            raise CommandError("Failed to unlock user '%s': %s" % (
                               username or filter, msg))
