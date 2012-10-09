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
from samba.netcmd import Command, SuperCommand, CommandError, Option
import ldb
from samba.ndr import ndr_unpack
from samba.dcerpc import security

from getpass import getpass
from samba.auth import system_session
from samba.samdb import SamDB
from samba.dsdb import (
    GTYPE_SECURITY_DOMAIN_LOCAL_GROUP,
    GTYPE_SECURITY_GLOBAL_GROUP,
    GTYPE_SECURITY_UNIVERSAL_GROUP,
    GTYPE_DISTRIBUTION_DOMAIN_LOCAL_GROUP,
    GTYPE_DISTRIBUTION_GLOBAL_GROUP,
    GTYPE_DISTRIBUTION_UNIVERSAL_GROUP,
)

security_group = dict({"Domain": GTYPE_SECURITY_DOMAIN_LOCAL_GROUP, "Global": GTYPE_SECURITY_GLOBAL_GROUP, "Universal": GTYPE_SECURITY_UNIVERSAL_GROUP})
distribution_group = dict({"Domain": GTYPE_DISTRIBUTION_DOMAIN_LOCAL_GROUP, "Global": GTYPE_DISTRIBUTION_GLOBAL_GROUP, "Universal": GTYPE_DISTRIBUTION_UNIVERSAL_GROUP})


class cmd_group_add(Command):
    """Creates a new AD group.

This command creates a new Active Directory group.  The groupname specified on the command is a unique sAMAccountName.

An Active Directory group may contain user and computer accounts as well as other groups.  An administrator creates a group and adds members to that group so they can be managed as a single entity.  This helps to simplify security and system administration.

Groups may also be used to establish email distribution lists, using --group-type=Distribution.

Groups are located in domains in organizational units (OUs).  The group's scope is a characteristic of the group that designates the extent to which the group is applied within the domain tree or forest.

The group location (OU), type (security or distribution) and scope may all be specified on the samba-tool command when the group is created.

The command may be run from the root userid or another authorized userid.  The
-H or --URL= option can be used to execute the command on a remote server.

Example1:
samba-tool group add Group1 -H ldap://samba.samdom.example.com --description='Simple group'

Example1 adds a new group with the name Group1 added to the Users container on a remote LDAP server.  The -U parameter is used to pass the userid and password of a user that exists on the remote server and is authorized to issue the command on that server.  It defaults to the security type and global scope.

Example2:
sudo samba-tool group add Group2 --group-type=Distribution

Example2 adds a new distribution group to the local server.  The command is run under root using the sudo command.
"""

    synopsis = "%prog <groupname> [options]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "versionopts": options.VersionOptions,
        "credopts": options.CredentialsOptions,
    }

    takes_options = [
        Option("-H", "--URL", help="LDB URL for database or target server", type=str,
               metavar="URL", dest="H"),
        Option("--groupou",
           help="Alternative location (without domainDN counterpart) to default CN=Users in which new user object will be created",
           type=str),
        Option("--group-scope", type="choice", choices=["Domain", "Global", "Universal"],
            help="Group scope (Domain | Global | Universal)"),
        Option("--group-type", type="choice", choices=["Security", "Distribution"],
            help="Group type (Security | Distribution)"),
        Option("--description", help="Group's description", type=str),
        Option("--mail-address", help="Group's email address", type=str),
        Option("--notes", help="Groups's notes", type=str),
    ]

    takes_args = ["groupname"]

    def run(self, groupname, credopts=None, sambaopts=None,
            versionopts=None, H=None, groupou=None, group_scope=None,
            group_type=None, description=None, mail_address=None, notes=None):

        if (group_type or "Security") == "Security":
            gtype = security_group.get(group_scope, GTYPE_SECURITY_GLOBAL_GROUP)
        else:
            gtype = distribution_group.get(group_scope, GTYPE_DISTRIBUTION_GLOBAL_GROUP)

        lp = sambaopts.get_loadparm()
        creds = credopts.get_credentials(lp, fallback_machine=True)

        try:
            samdb = SamDB(url=H, session_info=system_session(),
                          credentials=creds, lp=lp)
            samdb.newgroup(groupname, groupou=groupou, grouptype = gtype,
                          description=description, mailaddress=mail_address, notes=notes)
        except Exception, e:
            # FIXME: catch more specific exception
            raise CommandError('Failed to create group "%s"' % groupname, e)
        self.outf.write("Added group %s\n" % groupname)


class cmd_group_delete(Command):
    """Deletes an AD group.

The command deletes an existing AD group from the Active Directory domain.  The groupname specified on the command is the sAMAccountName.

Deleting a group is a permanent operation.  When a group is deleted, all permissions and rights that users in the group had inherited from the group account are deleted as well.

The command may be run from the root userid or another authorized userid.  The -H or --URL option can be used to execute the command on a remote server.

Example1:
samba-tool group delete Group1 -H ldap://samba.samdom.example.com -Uadministrator%passw0rd

Example1 shows how to delete an AD group from a remote LDAP server.  The -U parameter is used to pass the userid and password of a user that exists on the remote server and is authorized to issue the command on that server.

Example2:
sudo samba-tool group delete Group2

Example2 deletes group Group2 from the local server.  The command is run under root using the sudo command.
"""

    synopsis = "%prog <groupname> [options]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "versionopts": options.VersionOptions,
        "credopts": options.CredentialsOptions,
    }

    takes_options = [
        Option("-H", "--URL", help="LDB URL for database or target server", type=str,
               metavar="URL", dest="H"),
    ]

    takes_args = ["groupname"]

    def run(self, groupname, credopts=None, sambaopts=None, versionopts=None, H=None):

        lp = sambaopts.get_loadparm()
        creds = credopts.get_credentials(lp, fallback_machine=True)

        try:
            samdb = SamDB(url=H, session_info=system_session(),
                          credentials=creds, lp=lp)
            samdb.deletegroup(groupname)
        except Exception, e:
            # FIXME: catch more specific exception
            raise CommandError('Failed to remove group "%s"' % groupname, e)
        self.outf.write("Deleted group %s\n" % groupname)


class cmd_group_add_members(Command):
    """Add members to an AD group.

This command adds one or more members to an existing Active Directory group.  The command accepts one or more group member names seperated by commas.  A group member may be a user or computer account or another Active Directory group.

When a member is added to a group the member may inherit permissions and rights from the group.  Likewise, when permission or rights of a group are changed, the changes may reflect in the members through inheritance.

Example1:
samba-tool group addmembers supergroup Group1,Group2,User1 -H ldap://samba.samdom.example.com -Uadministrator%passw0rd

Example1 shows how to add two groups, Group1 and Group2 and one user account, User1, to the existing AD group named supergroup.  The command will be run on a remote server specified with the -H.  The -U parameter is used to pass the userid and password of a user authorized to issue the command on the remote server.

Example2:
sudo samba-tool group addmembers supergroup User2

Example2 shows how to add a single user account, User2, to the supergroup AD group.  It uses the sudo command to run as root when issuing the command.
"""

    synopsis = "%prog <groupname> <listofmembers> [options]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "versionopts": options.VersionOptions,
        "credopts": options.CredentialsOptions,
    }

    takes_options = [
        Option("-H", "--URL", help="LDB URL for database or target server", type=str,
               metavar="URL", dest="H"),
    ]

    takes_args = ["groupname", "listofmembers"]

    def run(self, groupname, listofmembers, credopts=None, sambaopts=None,
            versionopts=None, H=None):

        lp = sambaopts.get_loadparm()
        creds = credopts.get_credentials(lp, fallback_machine=True)

        try:
            samdb = SamDB(url=H, session_info=system_session(),
                          credentials=creds, lp=lp)
            groupmembers = listofmembers.split(',')
            samdb.add_remove_group_members(groupname, groupmembers,
                    add_members_operation=True)
        except Exception, e:
            # FIXME: catch more specific exception
            raise CommandError('Failed to add members "%s" to group "%s"' % (
                listofmembers, groupname), e)
        self.outf.write("Added members to group %s\n" % groupname)


class cmd_group_remove_members(Command):
    """Remove members from an AD group.

This command removes one or more members from an existing Active Directory group.  The command accepts one or more group member names seperated by commas.  A group member may be a user or computer account or another Active Directory group that is a member of the group specified on the command.

When a member is removed from a group, inherited permissions and rights will no longer apply to the member.

Example1:
samba-tool group removemembers supergroup Group1 -H ldap://samba.samdom.example.com -Uadministrator%passw0rd

Example1 shows how to remove Group1 from supergroup.  The command will run on the remote server specified on the -H parameter.  The -U parameter is used to pass the userid and password of a user authorized to issue the command on the remote server.

Example2:
sudo samba-tool group removemembers supergroup User1

Example2 shows how to remove a single user account, User2, from the supergroup AD group.  It uses the sudo command to run as root when issuing the command.
"""

    synopsis = "%prog <groupname> <listofmembers> [options]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "versionopts": options.VersionOptions,
        "credopts": options.CredentialsOptions,
    }

    takes_options = [
        Option("-H", "--URL", help="LDB URL for database or target server", type=str,
               metavar="URL", dest="H"),
    ]

    takes_args = ["groupname", "listofmembers"]

    def run(self, groupname, listofmembers, credopts=None, sambaopts=None,
            versionopts=None, H=None):

        lp = sambaopts.get_loadparm()
        creds = credopts.get_credentials(lp, fallback_machine=True)

        try:
            samdb = SamDB(url=H, session_info=system_session(),
                          credentials=creds, lp=lp)
            samdb.add_remove_group_members(groupname, listofmembers.split(","),
                    add_members_operation=False)
        except Exception, e:
            # FIXME: Catch more specific exception
            raise CommandError('Failed to remove members "%s" from group "%s"' % (listofmembers, groupname), e)
        self.outf.write("Removed members from group %s\n" % groupname)


class cmd_group_list(Command):
    """List all groups."""

    synopsis = "%prog [options]"

    takes_options = [
        Option("-H", "--URL", help="LDB URL for database or target server", type=str,
               metavar="URL", dest="H"),
        ]

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "credopts": options.CredentialsOptions,
        "versionopts": options.VersionOptions,
        }

    def run(self, sambaopts=None, credopts=None, versionopts=None, H=None):
        lp = sambaopts.get_loadparm()
        creds = credopts.get_credentials(lp, fallback_machine=True)

        samdb = SamDB(url=H, session_info=system_session(),
            credentials=creds, lp=lp)

        domain_dn = samdb.domain_dn()
        res = samdb.search(domain_dn, scope=ldb.SCOPE_SUBTREE,
                    expression=("(objectClass=group)"),
                    attrs=["samaccountname"])
        if (len(res) == 0):
            return

        for msg in res:
            self.outf.write("%s\n" % msg.get("samaccountname", idx=0))


class cmd_group_list_members(Command):
    """List all members of an AD group.

This command lists members from an existing Active Directory group. The command accepts one group name.

Example1:
samba-tool group listmembers \"Domain Users\" -H ldap://samba.samdom.example.com -Uadministrator%passw0rd
"""

    synopsis = "%prog <groupname> [options]"

    takes_options = [
        Option("-H", "--URL", help="LDB URL for database or target server", type=str,
               metavar="URL", dest="H"),
        ]

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "credopts": options.CredentialsOptions,
        "versionopts": options.VersionOptions,
        }

    takes_args = ["groupname"]

    def run(self, groupname, credopts=None, sambaopts=None, versionopts=None, H=None):
        lp = sambaopts.get_loadparm()
        creds = credopts.get_credentials(lp, fallback_machine=True)

        try:
            samdb = SamDB(url=H, session_info=system_session(),
                          credentials=creds, lp=lp)

            search_filter = "(&(objectClass=group)(samaccountname=%s))" % groupname
            res = samdb.search(samdb.domain_dn(), scope=ldb.SCOPE_SUBTREE,
                               expression=(search_filter),
                               attrs=["objectSid"])

            if (len(res) != 1):
                return

            group_dn = res[0].get('dn', idx=0)
            object_sid = res[0].get('objectSid', idx=0)

            object_sid = ndr_unpack(security.dom_sid, object_sid)
            (group_dom_sid, rid) = object_sid.split()

            search_filter = "(|(primaryGroupID=%s)(memberOf=%s))" % (rid, group_dn)
            res = samdb.search(samdb.domain_dn(), scope=ldb.SCOPE_SUBTREE,
                               expression=(search_filter),
                               attrs=["samAccountName", "cn"])

            if (len(res) == 0):
                return

            for msg in res:
                member_name = msg.get("samAccountName", idx=0)
                if member_name is None:
                    member_name = msg.get("cn", idx=0)
                self.outf.write("%s\n" % member_name)

        except Exception, e:
            raise CommandError('Failed to list members of "%s" group ' % groupname, e)


class cmd_group(SuperCommand):
    """Group management."""

    subcommands = {}
    subcommands["add"] = cmd_group_add()
    subcommands["delete"] = cmd_group_delete()
    subcommands["addmembers"] = cmd_group_add_members()
    subcommands["removemembers"] = cmd_group_remove_members()
    subcommands["list"] = cmd_group_list()
    subcommands["listmembers"] = cmd_group_list_members()
