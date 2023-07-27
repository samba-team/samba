# user management
#
# user sensitive command
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
from samba import dsdb, ldb
from samba.auth import system_session
from samba.netcmd import Command, CommandError, Option
from samba.samdb import SamDB


class cmd_user_sensitive(Command):
    """Set/unset or show UF_NOT_DELEGATED for an account."""

    synopsis = "%prog <accountname> [(show|on|off)] [options]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "credopts": options.CredentialsOptions,
        "versionopts": options.VersionOptions,
    }

    takes_options = [
        Option("-H", "--URL", help="LDB URL for database or target server", type=str,
               metavar="URL", dest="H"),
    ]

    takes_args = ["accountname", "cmd"]

    def run(self, accountname, cmd, H=None, credopts=None, sambaopts=None,
            versionopts=None):

        if cmd not in ("show", "on", "off"):
            raise CommandError("invalid argument: '%s' (choose from 'show', 'on', 'off')" % cmd)

        lp = sambaopts.get_loadparm()
        creds = credopts.get_credentials(lp, fallback_machine=True)
        sam = SamDB(url=H, session_info=system_session(),
                    credentials=creds, lp=lp)

        search_filter = "sAMAccountName=%s" % ldb.binary_encode(accountname)
        flag = dsdb.UF_NOT_DELEGATED;

        if cmd == "show":
            res = sam.search(scope=ldb.SCOPE_SUBTREE, expression=search_filter,
                             attrs=["userAccountControl"])
            if len(res) == 0:
                raise Exception("Unable to find account where '%s'" % search_filter)

            uac = int(res[0].get("userAccountControl")[0])

            self.outf.write("Account-DN: %s\n" % str(res[0].dn))
            self.outf.write("UF_NOT_DELEGATED: %s\n" % bool(uac & flag))

            return

        if cmd == "on":
            on = True
        elif cmd == "off":
            on = False

        try:
            sam.toggle_userAccountFlags(search_filter, flag, flags_str="Not-Delegated",
                                        on=on, strict=True)
        except Exception as err:
            raise CommandError(err)
