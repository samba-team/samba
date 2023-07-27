# user management
#
# delete user
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


class cmd_user_delete(Command):
    """Delete a user.

This command deletes a user account from the Active Directory domain.  The username specified on the command is the sAMAccountName.

Once the account is deleted, all permissions and memberships associated with that account are deleted.  If a new user account is added with the same name as a previously deleted account name, the new user does not have the previous permissions.  The new account user will be assigned a new security identifier (SID) and permissions and memberships will have to be added.

The command may be run from the root userid or another authorized userid.  The -H or --URL= option can be used to execute the command against a remote server.

Example1:
samba-tool user delete User1 -H ldap://samba.samdom.example.com --username=administrator --password=passw1rd

Example1 shows how to delete a user in the domain against a remote LDAP server.  The -H parameter is used to specify the remote target server.  The --username= and --password= options are used to pass the username and password of a user that exists on the remote server and is authorized to issue the command on that server.

Example2:
sudo samba-tool user delete User2

Example2 shows how to delete a user in the domain against the local server.   sudo is used so a user may run the command as root.

"""
    synopsis = "%prog <username> [options]"

    takes_options = [
        Option("-H", "--URL", help="LDB URL for database or target server", type=str,
               metavar="URL", dest="H"),
    ]

    takes_args = ["username"]
    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "credopts": options.CredentialsOptions,
        "versionopts": options.VersionOptions,
    }

    def run(self, username, credopts=None, sambaopts=None, versionopts=None,
            H=None):
        lp = sambaopts.get_loadparm()
        creds = credopts.get_credentials(lp, fallback_machine=True)

        samdb = SamDB(url=H, session_info=system_session(),
                      credentials=creds, lp=lp)

        filter = ("(&(sAMAccountName=%s)(sAMAccountType=805306368))" %
                  ldb.binary_encode(username))

        try:
            res = samdb.search(base=samdb.domain_dn(),
                               scope=ldb.SCOPE_SUBTREE,
                               expression=filter,
                               attrs=["dn"])
            user_dn = res[0].dn
        except IndexError:
            raise CommandError('Unable to find user "%s"' % (username))

        try:
            samdb.delete(user_dn)
        except Exception as e:
            raise CommandError('Failed to remove user "%s"' % username, e)
        self.outf.write("Deleted user %s\n" % username)
