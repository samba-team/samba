#!/usr/bin/env python
#
# user management
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
import sys
from samba.auth import system_session
from samba.samdb import SamDB


from samba.net import Net

from samba.netcmd import (
    Command,
    CommandError,
    SuperCommand,
    Option,
    )

class cmd_user_add(Command):
    """Create a new user."""
    synopsis = "%prog user add <name> [<password>]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "credopts": options.CredentialsOptions,
        "versionopts": options.VersionOptions,
        }

    takes_args = ["name", "password?"]

    def run(self, name, password=None, credopts=None, sambaopts=None, versionopts=None):
        lp = sambaopts.get_loadparm()
        creds = credopts.get_credentials(lp )
        net = Net(creds, lp, server=credopts.ipaddress)
        net.create_user(name)
        if password is not None:
            net.set_password(name, creds.get_domain(), password, creds)


class cmd_user_delete(Command):
    """Delete a user."""
    synopsis = "%prog user delete <name>"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "credopts": options.CredentialsOptions,
        "versionopts": options.VersionOptions,
        }

    takes_args = ["name"]

    def run(self, name, credopts=None, sambaopts=None, versionopts=None):
        lp = sambaopts.get_loadparm()
        creds = credopts.get_credentials(lp, fallback_machine=True)
        net = Net(creds, lp, server=credopts.ipaddress)
        try:
            net.delete_user(name)
        except RuntimeError, msg:
            raise CommandError("Failed to delete user %s: %s" % (name, msg))

class cmd_user_enable(Command):
    """Enables a user"""

    synopsis = "%prog user enable <username> [options]"


    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "versionopts": options.VersionOptions,
        "credopts": options.CredentialsOptions,
    }

    takes_options = [
        Option("-H", help="LDB URL for database or target server", type=str),
        Option("--filter", help="LDAP Filter to set password on", type=str),
        ]

    takes_args = ["username?"]

    def run(self, username=None, sambaopts=None, credopts=None,
            versionopts=None, filter=None, H=None):
        if username is None and filter is None:
            raise CommandError("Either the username or '--filter' must be specified!")

        if filter is None:
            filter = "(&(objectClass=user)(sAMAccountName=%s))" % (username)

        lp = sambaopts.get_loadparm()
        creds = credopts.get_credentials(lp, fallback_machine=True)

        samdb = SamDB(url=H, session_info=system_session(),
            credentials=creds, lp=lp)
        samdb.enable_account(filter)



class cmd_user(SuperCommand):
    """User management [server connection needed]"""

    subcommands = {}
    subcommands["add"] = cmd_user_add()
    subcommands["delete"] = cmd_user_delete()
    subcommands["enable"] = cmd_user_enable()

