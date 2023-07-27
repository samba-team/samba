# user management
#
# set user expiry
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


class cmd_user_setexpiry(Command):
    """Set the expiration of a user account.

The user can either be specified by their sAMAccountName or using the --filter option.

When a user account expires, it becomes disabled and the user is unable to logon.  The administrator may issue the samba-tool user enable command to enable the account for logon.  The permissions and memberships associated with the account are retained when the account is enabled.

The command may be run from the root userid or another authorized userid.  The -H or --URL= option can be used to execute the command on a remote server.

Example1:
samba-tool user setexpiry User1 --days=20 --URL=ldap://samba.samdom.example.com --username=administrator --password=passw1rd

Example1 shows how to set the expiration of an account in a remote LDAP server.  The --URL parameter is used to specify the remote target server.  The --username= and --password= options are used to pass the username and password of a user that exists on the remote server and is authorized to update that server.

Example2:
sudo samba-tool user setexpiry User2 --noexpiry

Example2 shows how to set the account expiration of user User2 so it will never expire.  The user in this example resides on the  local server.   sudo is used so a user may run the command as root.

Example3:
samba-tool user setexpiry --days=20 --filter=samaccountname=User3

Example3 shows how to set the account expiration date to end of day 20 days from the current day.  The username or sAMAccountName is specified using the --filter= parameter and the username in this example is User3.

Example4:
samba-tool user setexpiry --noexpiry User4
Example4 shows how to set the account expiration so that it will never expire.  The username and sAMAccountName in this example is User4.

"""
    synopsis = "%prog (<username>|--filter <filter>) [options]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "versionopts": options.VersionOptions,
        "credopts": options.CredentialsOptions,
    }

    takes_options = [
        Option("-H", "--URL", help="LDB URL for database or target server", type=str,
               metavar="URL", dest="H"),
        Option("--filter", help="LDAP Filter to set password on", type=str),
        Option("--days", help="Days to expiry", type=int, default=0),
        Option("--noexpiry", help="Password does never expire", action="store_true", default=False),
    ]

    takes_args = ["username?"]

    def run(self, username=None, sambaopts=None, credopts=None,
            versionopts=None, H=None, filter=None, days=None, noexpiry=None):
        if username is None and filter is None:
            raise CommandError("Either the username or '--filter' must be specified!")

        if filter is None:
            filter = "(&(objectClass=user)(sAMAccountName=%s))" % (ldb.binary_encode(username))

        lp = sambaopts.get_loadparm()
        creds = credopts.get_credentials(lp)

        samdb = SamDB(url=H, session_info=system_session(),
                      credentials=creds, lp=lp)

        try:
            samdb.setexpiry(filter, days * 24 * 3600, no_expiry_req=noexpiry)
        except Exception as msg:
            # FIXME: Catch more specific exception
            raise CommandError("Failed to set expiry for user '%s': %s" % (
                username or filter, msg))
        if noexpiry:
            self.outf.write("Expiry for user '%s' disabled.\n" % (
                username or filter))
        else:
            self.outf.write("Expiry for user '%s' set to %u days.\n" % (
                username or filter, days))
