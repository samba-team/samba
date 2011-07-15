#!/usr/bin/env python
#
# user management
#
# Copyright Jelmer Vernooij 2010 <jelmer@samba.org>
# Copyright Theresa Halloran 2011 <theresahalloran@gmail.com>
# Copyright Giampaolo Lauria 2011 <lauria2@yahoo.com>
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
from getpass import getpass
from samba.auth import system_session
from samba.samdb import SamDB
from samba import gensec
from samba.net import Net

from samba.netcmd import (
    Command,
    CommandError,
    SuperCommand,
    Option,
    )



class cmd_user_add(Command):
    """Create a new user."""
    synopsis = "%prog user add <username> [<password>] [options]"

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
    synopsis = "%prog user delete <username> [options]"

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
        try:
            samdb.enable_account(filter)
        except Exception, msg:
            raise CommandError("Failed to enable user %s: %s" % (username or filter, msg))
        print("Enabled user %s" % (username or filter))



class cmd_user_setexpiry(Command):
    """Sets the expiration of a user account"""

    synopsis = "%prog user setexpiry (<username>|--filter <filter>) [options]"

    takes_options = [
        Option("-H", help="LDB URL for database or target server", type=str),
        Option("--filter", help="LDAP Filter to set password on", type=str),
        Option("--days", help="Days to expiry", type=int),
        Option("--noexpiry", help="Password does never expire", action="store_true"),
    ]

    takes_args = ["username?"]
    def run(self, username=None, sambaopts=None, credopts=None,
            versionopts=None, H=None, filter=None, days=None, noexpiry=None):
        if username is None and filter is None:
            raise CommandError("Either the username or '--filter' must be specified!")

        if filter is None:
            filter = "(&(objectClass=user)(sAMAccountName=%s))" % (username)

        lp = sambaopts.get_loadparm()
        creds = credopts.get_credentials(lp)

        if days is None:
            days = 0

        samdb = SamDB(url=H, session_info=system_session(),
            credentials=creds, lp=lp)

        try:
            samdb.setexpiry(filter, days*24*3600, no_expiry_req=noexpiry)
        except Exception, msg:
            raise CommandError("Failed to set expiry for user %s: %s" % (username or filter, msg))
        print("Set expiry for user %s to %u days" % (username or filter, days))


class cmd_user_setpassword(Command):
    """(Re)sets the password of a user account"""

    synopsis = "%prog user setpassword (<username>|--filter <filter>) [options]"

    takes_options = [
        Option("-H", help="LDB URL for database or target server", type=str),
        Option("--filter", help="LDAP Filter to set password on", type=str),
        Option("--newpassword", help="Set password", type=str),
        Option("--must-change-at-next-login",
            help="Force password to be changed on next login",
            action="store_true"),
        ]

    takes_args = ["username?"]

    def run(self, username=None, filter=None, credopts=None, sambaopts=None,
            versionopts=None, H=None, newpassword=None,
            must_change_at_next_login=None):
        if filter is None and username is None:
            raise CommandError("Either the username or '--filter' must be specified!")

        password = newpassword
        if password is None:
            password = getpass("New Password: ")

        if filter is None:
            filter = "(&(objectClass=user)(sAMAccountName=%s))" % (username)

        lp = sambaopts.get_loadparm()
        creds = credopts.get_credentials(lp)

        creds.set_gensec_features(creds.get_gensec_features() | gensec.FEATURE_SEAL)

        samdb = SamDB(url=H, session_info=system_session(),
                      credentials=creds, lp=lp)

        try:
            samdb.setpassword(filter, password,
                              force_change_at_next_login=must_change_at_next_login,
                              username=username)
        except Exception, e:
            raise CommandError('Failed to set password for user "%s"' % username, e)
        print "Changed password OK"


class cmd_user(SuperCommand):
    """User management [server connection needed]"""

    subcommands = {}
    subcommands["add"] = cmd_user_add()
    subcommands["delete"] = cmd_user_delete()
    subcommands["enable"] = cmd_user_enable()
    subcommands["setexpiry"] = cmd_user_setexpiry()
    subcommands["setpassword"] = cmd_user_setpassword()
