# user management
#
# list users
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
from samba.netcmd import Command, Option
from samba.samdb import SamDB


class cmd_user_list(Command):
    """List all users."""

    synopsis = "%prog [options]"

    takes_options = [
        Option("-H", "--URL", help="LDB URL for database or target server", type=str,
               metavar="URL", dest="H"),
        Option("--hide-expired",
               help="Do not list expired user accounts",
               default=False,
               action='store_true'),
        Option("--hide-disabled",
               default=False,
               action='store_true',
               help="Do not list disabled user accounts"),
        Option("-b", "--base-dn",
               help="Specify base DN to use",
               type=str),
        Option("--full-dn", dest="full_dn",
               default=False,
               action='store_true',
               help="Display DN instead of the sAMAccountName.")
    ]

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "credopts": options.CredentialsOptions,
        "versionopts": options.VersionOptions,
    }

    def run(self,
            sambaopts=None,
            credopts=None,
            versionopts=None,
            H=None,
            hide_expired=False,
            hide_disabled=False,
            base_dn=None,
            full_dn=False):
        lp = sambaopts.get_loadparm()
        creds = credopts.get_credentials(lp, fallback_machine=True)

        samdb = SamDB(url=H, session_info=system_session(),
                      credentials=creds, lp=lp)

        search_dn = samdb.domain_dn()
        if base_dn:
            search_dn = samdb.normalize_dn_in_domain(base_dn)

        filter_expires = ""
        if hide_expired is True:
            current_nttime = samdb.get_nttime()
            filter_expires = "(|(accountExpires=0)(accountExpires>=%u))" % (
                current_nttime)

        filter_disabled = ""
        if hide_disabled is True:
            filter_disabled = "(!(userAccountControl:%s:=%u))" % (
                ldb.OID_COMPARATOR_AND, dsdb.UF_ACCOUNTDISABLE)

        filter = "(&(objectClass=user)(userAccountControl:%s:=%u)%s%s)" % (
            ldb.OID_COMPARATOR_AND,
            dsdb.UF_NORMAL_ACCOUNT,
            filter_disabled,
            filter_expires)

        res = samdb.search(search_dn,
                           scope=ldb.SCOPE_SUBTREE,
                           expression=filter,
                           attrs=["samaccountname"])
        if (len(res) == 0):
            return

        for msg in res:
            if full_dn:
                self.outf.write("%s\n" % msg.get("dn"))
                continue

            self.outf.write("%s\n" % msg.get("samaccountname", idx=0))
