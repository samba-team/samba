# user management
#
# user password
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

from getpass import getpass

import samba.getopt as options
from samba.net import Net
from samba.netcmd import Command, CommandError, Option


class cmd_user_password(Command):
    """Change password for a user account (the one provided in authentication).
"""

    synopsis = "%prog [options]"

    takes_options = [
        Option("--newpassword", help="New password", type=str),
    ]

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "credopts": options.CredentialsOptions,
        "versionopts": options.VersionOptions,
    }

    def run(self, credopts=None, sambaopts=None, versionopts=None,
            newpassword=None):

        lp = sambaopts.get_loadparm()
        creds = credopts.get_credentials(lp)

        # get old password now, to get the password prompts in the right order
        old_password = creds.get_password()

        net = Net(creds, lp, server=credopts.ipaddress)

        password = newpassword
        while True:
            if password is not None and password != '':
                break
            password = getpass("New Password: ")
            passwordverify = getpass("Retype Password: ")
            if not password == passwordverify:
                password = None
                self.outf.write("Sorry, passwords do not match.\n")

        try:
            if not isinstance(password, str):
                password = password.decode('utf8')
            net.change_password(password)
        except Exception as msg:
            # FIXME: catch more specific exception
            raise CommandError("Failed to change password : %s" % msg)
        self.outf.write("Changed password OK\n")
