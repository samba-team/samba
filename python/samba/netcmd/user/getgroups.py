# user management
#
# user getgroups command
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
from samba.dcerpc import security
from samba.ndr import ndr_unpack
from samba.netcmd import Command, CommandError, Option
from samba.samdb import SamDB


class cmd_user_getgroups(Command):
    """Get the direct group memberships of a user account.

The username specified on the command is the sAMAccountName."""
    synopsis = "%prog <username> [options]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "versionopts": options.VersionOptions,
        "credopts": options.CredentialsOptions,
    }

    takes_options = [
        Option("-H", "--URL", help="LDB URL for database or target server",
               type=str, metavar="URL", dest="H"),
        Option("--full-dn", dest="full_dn",
               default=False,
               action='store_true',
               help="Display DN instead of the sAMAccountName."),
        ]

    takes_args = ["username"]

    def run(self,
            username,
            credopts=None,
            sambaopts=None,
            versionopts=None,
            H=None,
            full_dn=False):

        lp = sambaopts.get_loadparm()
        creds = credopts.get_credentials(lp)

        samdb = SamDB(url=H, session_info=system_session(),
                      credentials=creds, lp=lp)

        filter = ("(&(sAMAccountName=%s)(objectClass=user))" %
                  ldb.binary_encode(username))
        try:
            res = samdb.search(base=samdb.domain_dn(),
                               expression=filter,
                               scope=ldb.SCOPE_SUBTREE,
                               attrs=["objectSid",
                                      "memberOf",
                                      "primaryGroupID"])
            user_sid_binary = res[0].get('objectSid', idx=0)
            user_sid = ndr_unpack(security.dom_sid, user_sid_binary)
            (user_dom_sid, user_rid) = user_sid.split()
            user_sid_dn = "<SID=%s>" % user_sid
            user_pgid = int(res[0].get('primaryGroupID', idx=0))
            user_groups = res[0].get('memberOf')
            if user_groups is None:
                user_groups = []
        except IndexError:
            raise CommandError("Unable to find user '%s'" % (username))

        primarygroup_sid_dn = "<SID=%s-%u>" % (user_dom_sid, user_pgid)

        filter = "(objectClass=group)"
        try:
            res = samdb.search(base=primarygroup_sid_dn,
                               expression=filter,
                               scope=ldb.SCOPE_BASE,
                               attrs=['sAMAccountName'])
            primary_group_dn = str(res[0].dn)
            primary_group_name = res[0].get('sAMAccountName')
        except IndexError:
            raise CommandError("Unable to find primary group '%s'" % (primarygroup_sid_dn))

        if full_dn:
            self.outf.write("%s\n" % primary_group_dn)
            for group_dn in user_groups:
                self.outf.write("%s\n" % group_dn)
            return

        group_names = []
        for gdn in user_groups:
            try:
                res = samdb.search(base=gdn,
                                   expression=filter,
                                   scope=ldb.SCOPE_BASE,
                                   attrs=['sAMAccountName'])
                group_names.extend(res[0].get('sAMAccountName'))
            except IndexError:
                raise CommandError("Unable to find group '%s'" % (gdn))

        self.outf.write("%s\n" % primary_group_name)
        for group_name in group_names:
            self.outf.write("%s\n" % group_name)
