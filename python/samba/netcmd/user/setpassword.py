# user management
#
# user setpassword command
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
from samba import dsdb, generate_random_password, gensec, ldb
from samba.auth import system_session
from samba.netcmd import Command, CommandError, Option
from samba.samdb import SamDB


class cmd_user_setpassword(Command):
    """Set or reset the password of a user account.

This command sets or resets the logon password for a user account.  The username specified on the command is the sAMAccountName.  The username may also be specified using the --filter option.

If the password is not specified on the command through the --newpassword parameter, the user is prompted for the password to be entered through the command line.

It is good security practice for the administrator to use the --must-change-at-next-login option which requires that when the user logs on to the account for the first time following the password change, he/she must change the password.

The command may be run from the root userid or another authorized userid.  The -H or --URL= option can be used to execute the command against a remote server.

Example1:
samba-tool user setpassword TestUser1 --newpassword=passw0rd --URL=ldap://samba.samdom.example.com -Uadministrator%passw1rd

Example1 shows how to set the password of user TestUser1 on a remote LDAP server.  The --URL parameter is used to specify the remote target server.  The -U option is used to pass the username and password of a user that exists on the remote server and is authorized to update the server.

Example2:
sudo samba-tool user setpassword TestUser2 --newpassword=passw0rd --must-change-at-next-login

Example2 shows how an administrator would reset the TestUser2 user's password to passw0rd.  The user is running under the root userid using the sudo command.  In this example the user TestUser2 must change their password the next time they logon to the account.

Example3:
samba-tool user setpassword --filter=samaccountname=TestUser3 --newpassword=passw0rd

Example3 shows how an administrator would reset TestUser3 user's password to passw0rd using the --filter= option to specify the username.

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
        Option("--newpassword", help="Set password", type=str),
        Option("--must-change-at-next-login",
               help="Force password to be changed on next login",
               action="store_true"),
        Option("--random-password",
               help="Generate random password",
               action="store_true"),
        Option("--smartcard-required",
               help="Require a smartcard for interactive logons",
               action="store_true"),
        Option("--clear-smartcard-required",
               help="Don't require a smartcard for interactive logons",
               action="store_true"),
    ]

    takes_args = ["username?"]

    def run(self, username=None, filter=None, credopts=None, sambaopts=None,
            versionopts=None, H=None, newpassword=None,
            must_change_at_next_login=False, random_password=False,
            smartcard_required=False, clear_smartcard_required=False):
        if filter is None and username is None:
            raise CommandError("Either the username or '--filter' must be specified!")

        password = newpassword

        if smartcard_required:
            if password is not None and password != '':
                raise CommandError('It is not allowed to specify '
                                   '--newpassword '
                                   'together with --smartcard-required.')
            if must_change_at_next_login:
                raise CommandError('It is not allowed to specify '
                                   '--must-change-at-next-login '
                                   'together with --smartcard-required.')
            if clear_smartcard_required:
                raise CommandError('It is not allowed to specify '
                                   '--clear-smartcard-required '
                                   'together with --smartcard-required.')

        if random_password and not smartcard_required:
            password = generate_random_password(128, 255)

        while True:
            if smartcard_required:
                break
            if password is not None and password != '':
                break
            password = getpass("New Password: ")
            passwordverify = getpass("Retype Password: ")
            if not password == passwordverify:
                password = None
                self.outf.write("Sorry, passwords do not match.\n")

        if filter is None:
            filter = "(&(objectClass=user)(sAMAccountName=%s))" % (ldb.binary_encode(username))

        lp = sambaopts.get_loadparm()
        creds = credopts.get_credentials(lp)

        creds.set_gensec_features(creds.get_gensec_features() | gensec.FEATURE_SEAL)

        samdb = SamDB(url=H, session_info=system_session(),
                      credentials=creds, lp=lp)

        if smartcard_required:
            command = ""
            try:
                command = "Failed to set UF_SMARTCARD_REQUIRED for user '%s'" % (username or filter)
                flags = dsdb.UF_SMARTCARD_REQUIRED
                samdb.toggle_userAccountFlags(filter, flags, on=True)
                command = "Failed to enable account for user '%s'" % (username or filter)
                samdb.enable_account(filter)
            except Exception as msg:
                # FIXME: catch more specific exception
                raise CommandError("%s: %s" % (command, msg))
            self.outf.write("Added UF_SMARTCARD_REQUIRED OK\n")
        else:
            command = ""
            try:
                if clear_smartcard_required:
                    command = "Failed to remove UF_SMARTCARD_REQUIRED for user '%s'" % (username or filter)
                    flags = dsdb.UF_SMARTCARD_REQUIRED
                    samdb.toggle_userAccountFlags(filter, flags, on=False)
                command = "Failed to set password for user '%s'" % (username or filter)
                samdb.setpassword(filter, password,
                                  force_change_at_next_login=must_change_at_next_login,
                                  username=username)
            except Exception as msg:
                # FIXME: catch more specific exception
                raise CommandError("%s: %s" % (command, msg))
            self.outf.write("Changed password OK\n")
