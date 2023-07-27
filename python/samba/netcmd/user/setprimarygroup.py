# user management
#
# user setprimarygroup command
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


class cmd_user_setprimarygroup(Command):
    """Set the primary group a user account.

This command sets the primary group a user account. The username specified on
the command is the sAMAccountName. The primarygroupname is the sAMAccountName
of the new primary group. The user must be a member of the group.

The command may be run from the root userid or another authorized userid. The
-H or --URL= option can be used to execute the command against a remote server.

Example1:
samba-tool user setprimarygroup TestUser1 newPrimaryGroup --URL=ldap://samba.samdom.example.com -Uadministrator%passw1rd

Example1 shows how to set the primary group for TestUser1 on a remote LDAP
server. The --URL parameter is used to specify the remote target server.  The
-U option is used to pass the username and password of a user that exists on
the remote server and is authorized to update the server.
"""
    synopsis = "%prog <username> <primarygroupname> [options]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "versionopts": options.VersionOptions,
        "credopts": options.CredentialsOptions,
    }

    takes_options = [
        Option("-H", "--URL", help="LDB URL for database or target server", type=str,
               metavar="URL", dest="H"),
        ]

    takes_args = ["username", "primarygroupname"]

    def run(self, username, primarygroupname, credopts=None, sambaopts=None,
            versionopts=None, H=None):

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
                               controls=["extended_dn:1:1"],
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

        user_group_sids = []
        for user_group in user_groups:
            user_group_dn = ldb.Dn(samdb, str(user_group))
            user_group_binary_sid = user_group_dn.get_extended_component("SID")
            user_group_sid = ndr_unpack(security.dom_sid, user_group_binary_sid)
            user_group_sids.append(user_group_sid)

        filter = ("(&(sAMAccountName=%s)(objectClass=group))" %
                  ldb.binary_encode(primarygroupname))
        try:
            res = samdb.search(base=samdb.domain_dn(),
                               expression=filter,
                               scope=ldb.SCOPE_SUBTREE,
                               attrs=["objectSid"])
            group_sid_binary = res[0].get('objectSid', idx=0)
        except IndexError:
            raise CommandError("Unable to find group '%s'" % (primarygroupname))

        primarygroup_sid = ndr_unpack(security.dom_sid, group_sid_binary)
        (primarygroup_dom_sid, primarygroup_rid) = primarygroup_sid.split()

        if user_dom_sid != primarygroup_dom_sid:
            raise CommandError("Group '%s' does not belong to the user's "
                               "domain" % primarygroupname)

        if primarygroup_rid != user_pgid and primarygroup_sid not in user_group_sids:
            raise CommandError("User '%s' is not member of group '%s'" %
                               (username, primarygroupname))

        setprimarygroup_ldif = """
dn: %s
changetype: modify
delete: primaryGroupID
primaryGroupID: %u
add: primaryGroupID
primaryGroupID: %u
""" % (user_sid_dn, user_pgid, primarygroup_rid)

        try:
            samdb.modify_ldif(setprimarygroup_ldif)
        except Exception as msg:
            raise CommandError("Failed to set primary group '%s' "
                               "for user '%s': %s" %
                               (primarygroupname, username, msg))
        self.outf.write("Changed primary group to '%s'\n" % primarygroupname)
