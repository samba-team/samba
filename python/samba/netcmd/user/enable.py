# user management
#
# enable user
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


class cmd_user_enable(Command):
    """Enable a user.

This command enables a user account for logon to an Active Directory domain.  The username specified on the command is the sAMAccountName.  The username may also be specified using the --filter option.

There are many reasons why an account may become disabled.  These include:
- If a user exceeds the account policy for logon attempts
- If an administrator disables the account
- If the account expires

The samba-tool user enable command allows an administrator to enable an account which has become disabled.

Additionally, the enable function allows an administrator to have a set of created user accounts defined and setup with default permissions that can be easily enabled for use.

The command may be run from the root userid or another authorized userid.  The -H or --URL= option can be used to execute the command against a remote server.

Example1:
samba-tool user enable Testuser1 --URL=ldap://samba.samdom.example.com --username=administrator --password=passw1rd

Example1 shows how to enable a user in the domain against a remote LDAP server.  The --URL parameter is used to specify the remote target server.  The --username= and --password= options are used to pass the username and password of a user that exists on the remote server and is authorized to update that server.

Example2:
su samba-tool user enable Testuser2

Example2 shows how to enable user Testuser2 for use in the domain on the local server. sudo is used so a user may run the command as root.

Example3:
samba-tool user enable --filter=samaccountname=Testuser3

Example3 shows how to enable a user in the domain against a local LDAP server.  It uses the --filter=samaccountname to specify the username.

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
    ]

    takes_args = ["username?"]

    def run(self, username=None, sambaopts=None, credopts=None,
            versionopts=None, filter=None, H=None):
        if username is None and filter is None:
            raise CommandError("Either the username or '--filter' must be specified!")

        if filter is None:
            filter = "(&(objectClass=user)(sAMAccountName=%s))" % (ldb.binary_encode(username))

        lp = sambaopts.get_loadparm()
        creds = credopts.get_credentials(lp, fallback_machine=True)

        samdb = SamDB(url=H, session_info=system_session(),
                      credentials=creds, lp=lp)
        try:
            samdb.enable_account(filter)
        except Exception as msg:
            raise CommandError("Failed to enable user '%s': %s" % (username or filter, msg))
        self.outf.write("Enabled user '%s'\n" % (username or filter))
