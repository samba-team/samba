# user management
#
# disable user
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
from samba.dcerpc import security
from samba.ndr import ndr_unpack


class cmd_user_disable(Command):
    """Disable a user."""

    synopsis = "%prog (<username>|--filter <filter>) [options]"

    takes_options = [
        Option("-H", "--URL", help="LDB URL for database or target server", type=str,
               metavar="URL", dest="H"),
        Option("--filter",
               help="LDAP filter to select user",
               type=str,
               dest="search_filter"),
        Option("--remove-supplemental-groups",
               help="Remove user's supplemental groups",
               action="store_true"),
    ]

    takes_args = ["username?"]

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "credopts": options.CredentialsOptions,
        "versionopts": options.VersionOptions,
    }

    def run(self, username=None, sambaopts=None, credopts=None,
            versionopts=None, search_filter=None, H=None,
            remove_supplemental_groups=False):
        if username is None and search_filter is None:
            raise CommandError("Either the username or '--filter' must be specified!")

        if search_filter is None:
            search_filter = "(&(objectClass=user)(sAMAccountName=%s))" % (
                ldb.binary_encode(username))

        lp = sambaopts.get_loadparm()
        creds = credopts.get_credentials(lp, fallback_machine=True)

        samdb = SamDB(url=H, session_info=system_session(),
                      credentials=creds, lp=lp)

        samdb.transaction_start()
        try:
            res = samdb.search(base=samdb.domain_dn(),
                               expression=search_filter,
                               scope=ldb.SCOPE_SUBTREE,
                               controls=["extended_dn:1:1"],
                               attrs=["objectSid", "memberOf"])
            user_groups = res[0].get("memberOf")
            if user_groups is None:
                user_groups = []
            user_binary_sid = res[0].get("objectSid", idx=0)
            user_sid = ndr_unpack(security.dom_sid, user_binary_sid)
        except IndexError:
            samdb.transaction_cancel()
            raise CommandError("Unable to find user '%s'" % (
                               username or search_filter))
        except Exception as msg:
            samdb.transaction_cancel()
            raise CommandError("Failed to find user '%s': '%s'" % (
                               username or search_filter, msg))
        if len(res) > 1:
            samdb.transaction_cancel()
            raise CommandError("Found more than one user '%s'" % (
                               username or search_filter))

        if remove_supplemental_groups:
            for user_group in user_groups:
                try:
                    samdb.add_remove_group_members(str(user_group),
                                                   [str(user_sid)],
                                                   add_members_operation=False)
                except Exception as msg:
                    samdb.transaction_cancel()
                    raise CommandError("Failed to remove user from group "
                                       "'%s': %s" % (user_group, msg))

        try:
            samdb.disable_account(search_filter)
        except Exception as msg:
            samdb.transaction_cancel()
            raise CommandError("Failed to disable user '%s': %s" % (
                username or search_filter, msg))
        samdb.transaction_commit()
