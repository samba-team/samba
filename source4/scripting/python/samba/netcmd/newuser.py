#!/usr/bin/python
#
# Adds a new user to a Samba4 server
# Copyright Jelmer Vernooij 2008
#
# Based on the original in EJS:
# Copyright Andrew Tridgell 2005
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

import samba.getopt as options
from samba.netcmd import Command, CommandError, Option

from getpass import getpass
from samba.auth import system_session
from samba.samdb import SamDB

class cmd_newuser(Command):
    """Create a new user."""

    synopsis = "newuser [options] <username> [<password>]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "versionopts": options.VersionOptions,
        "credopts": options.CredentialsOptions,
    }

    takes_options = [
        Option("-H", help="LDB URL for database or target server", type=str),
        Option("--unixname", help="Unix Username", type=str),
        Option("--must-change-at-next-login",
            help="Force password to be changed on next login",
            action="store_true"),
    ]

    takes_args = ["username", "password?"]

    def run(self, username, password=None, credopts=None, sambaopts=None,
            versionopts=None, H=None, unixname=None,
            must_change_at_next_login=None):
        if password is None:
            password = getpass("New Password: ")

        if unixname is None:
            unixname = username

        lp = sambaopts.get_loadparm()
        creds = credopts.get_credentials(lp)

        if H is not None:
            url = H
        else:
            url = lp.get("sam database")

        samdb = SamDB(url=url, session_info=system_session(), credentials=creds,
            lp=lp)
        samdb.newuser(username, unixname, password,
            force_password_change_at_next_login_req=must_change_at_next_login)
