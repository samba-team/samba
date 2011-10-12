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
import sys, ldb
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
    """Creates a new user"""

    synopsis = "%prog user add <username> [<password>] [options]"

    takes_options = [
        Option("-H", "--URL", help="LDB URL for database or target server", type=str,
                metavar="URL", dest="H"),
        Option("--must-change-at-next-login",
                help="Force password to be changed on next login",
                action="store_true"),
        Option("--use-username-as-cn",
                help="Force use of username as user's CN",
                action="store_true"),
        Option("--userou",
                help="Alternative location (without domainDN counterpart) to default CN=Users in which new user object will be created",
                type=str),
        Option("--surname", help="User's surname", type=str),
        Option("--given-name", help="User's given name", type=str),
        Option("--initials", help="User's initials", type=str),
        Option("--profile-path", help="User's profile path", type=str),
        Option("--script-path", help="User's logon script path", type=str),
        Option("--home-drive", help="User's home drive letter", type=str),
        Option("--home-directory", help="User's home directory path", type=str),
        Option("--job-title", help="User's job title", type=str),
        Option("--department", help="User's department", type=str),
        Option("--company", help="User's company", type=str),
        Option("--description", help="User's description", type=str),
        Option("--mail-address", help="User's email address", type=str),
        Option("--internet-address", help="User's home page", type=str),
        Option("--telephone-number", help="User's phone number", type=str),
        Option("--physical-delivery-office", help="User's office location", type=str),
    ]

    takes_args = ["username", "password?"]

    def run(self, username, password=None, credopts=None, sambaopts=None,
            versionopts=None, H=None, must_change_at_next_login=None,
            use_username_as_cn=None, userou=None, surname=None, given_name=None, initials=None,
            profile_path=None, script_path=None, home_drive=None, home_directory=None,
            job_title=None, department=None, company=None, description=None,
            mail_address=None, internet_address=None, telephone_number=None, physical_delivery_office=None):

        while 1:
            if password is not None and password is not '':
                break
            password = getpass("New Password: ")

        lp = sambaopts.get_loadparm()
        creds = credopts.get_credentials(lp)

        try:
            samdb = SamDB(url=H, session_info=system_session(),
                          credentials=creds, lp=lp)
            samdb.newuser(username, password,
                          force_password_change_at_next_login_req=must_change_at_next_login,
                          useusernameascn=use_username_as_cn, userou=userou, surname=surname, givenname=given_name, initials=initials,
                          profilepath=profile_path, homedrive=home_drive, scriptpath=script_path, homedirectory=home_directory,
                          jobtitle=job_title, department=department, company=company, description=description,
                          mailaddress=mail_address, internetaddress=internet_address,
                          telephonenumber=telephone_number, physicaldeliveryoffice=physical_delivery_office)
        except Exception, e:
            raise CommandError("Failed to add user '%s': " % username, e)

        self.outf.write("User '%s' created successfully\n" % username)


class cmd_user_delete(Command):
    """Delete a user"""

    synopsis = "%prog user delete <username> [options]"

    takes_options = [
        Option("-H", "--URL", help="LDB URL for database or target server", type=str,
               metavar="URL", dest="H"),
    ]

    takes_args = ["username"]

    def run(self, username, credopts=None, sambaopts=None, versionopts=None, H=None):

        lp = sambaopts.get_loadparm()
        creds = credopts.get_credentials(lp, fallback_machine=True)

        try:
            samdb = SamDB(url=H, session_info=system_session(),
                          credentials=creds, lp=lp)
            samdb.deleteuser(username)
        except Exception, e:
            raise CommandError('Failed to remove user "%s"' % username, e)
        self.outf.write("Deleted user %s\n" % username)


class cmd_user_enable(Command):
    """Enables a user"""

    synopsis = "%prog user enable (<username>|--filter <filter>) [options]"

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
        except Exception, msg:
            raise CommandError("Failed to enable user '%s': %s" % (username or filter, msg))
        self.outf.write("Enabled user '%s'\n" % (username or filter))


class cmd_user_setexpiry(Command):
    """Sets the expiration of a user account"""

    synopsis = "%prog user setexpiry (<username>|--filter <filter>) [options]"

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
            samdb.setexpiry(filter, days*24*3600, no_expiry_req=noexpiry)
        except Exception, msg:
            # FIXME: Catch more specific exception
            raise CommandError("Failed to set expiry for user '%s': %s" % (
                username or filter, msg))
        self.outf.write("Set expiry for user '%s' to %u days\n" % (
            username or filter, days))


class cmd_user_password(Command):
    """Change password for a user account (the one provided in authentication)"""

    synopsis = "%prog user password [options]"

    takes_options = [
        Option("--newpassword", help="New password", type=str),
        ]

    def run(self, credopts=None, sambaopts=None, versionopts=None,
                newpassword=None):

        lp = sambaopts.get_loadparm()
        creds = credopts.get_credentials(lp)

        # get old password now, to get the password prompts in the right order
        old_password = creds.get_password()

        net = Net(creds, lp, server=credopts.ipaddress)

        password = newpassword
        while 1:
            if password is not None and password is not '':
                break
            password = getpass("New Password: ")

        try:
            net.change_password(password)
        except Exception, msg:
            # FIXME: catch more specific exception
            raise CommandError("Failed to change password : %s" % msg)
        self.outf.write("Changed password OK\n")


class cmd_user_setpassword(Command):
    """(Re)sets the password of a user account"""

    synopsis = "%prog user setpassword (<username>|--filter <filter>) [options]"

    takes_options = [
        Option("-H", "--URL", help="LDB URL for database or target server", type=str,
               metavar="URL", dest="H"),
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
        while 1:
            if password is not None and password is not '':
                break
            password = getpass("New Password: ")

        if filter is None:
            filter = "(&(objectClass=user)(sAMAccountName=%s))" % (ldb.binary_encode(username))

        lp = sambaopts.get_loadparm()
        creds = credopts.get_credentials(lp)

        creds.set_gensec_features(creds.get_gensec_features() | gensec.FEATURE_SEAL)

        samdb = SamDB(url=H, session_info=system_session(),
                      credentials=creds, lp=lp)

        try:
            samdb.setpassword(filter, password,
                              force_change_at_next_login=must_change_at_next_login,
                              username=username)
        except Exception, msg:
            # FIXME: catch more specific exception
            raise CommandError("Failed to set password for user '%s': %s" % (username or filter, msg))
        self.outf.write("Changed password OK\n")



class cmd_user(SuperCommand):
    """User management"""

    subcommands = {}
    subcommands["add"] = cmd_user_add()
    subcommands["delete"] = cmd_user_delete()
    subcommands["enable"] = cmd_user_enable()
    subcommands["setexpiry"] = cmd_user_setexpiry()
    subcommands["password"] = cmd_user_password()
    subcommands["setpassword"] = cmd_user_setpassword()
