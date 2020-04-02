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

from samba.auth import system_session
from samba.samdb import SamDB
from samba.dsdb import (
    ATYPE_SECURITY_GLOBAL_GROUP,
    GTYPE_SECURITY_BUILTIN_LOCAL_GROUP,
    GTYPE_SECURITY_DOMAIN_LOCAL_GROUP,
    GTYPE_SECURITY_GLOBAL_GROUP,
    GTYPE_SECURITY_UNIVERSAL_GROUP,
    GTYPE_DISTRIBUTION_DOMAIN_LOCAL_GROUP,
    GTYPE_DISTRIBUTION_GLOBAL_GROUP,
    GTYPE_DISTRIBUTION_UNIVERSAL_GROUP,
)
from collections import defaultdict
from subprocess import check_call, CalledProcessError
from samba.compat import get_bytes
import os
import tempfile
from . import common

security_group = dict({"Builtin": GTYPE_SECURITY_BUILTIN_LOCAL_GROUP,
                       "Domain": GTYPE_SECURITY_DOMAIN_LOCAL_GROUP,
                       "Global": GTYPE_SECURITY_GLOBAL_GROUP,
                       "Universal": GTYPE_SECURITY_UNIVERSAL_GROUP})
distribution_group = dict({"Domain": GTYPE_DISTRIBUTION_DOMAIN_LOCAL_GROUP,
                           "Global": GTYPE_DISTRIBUTION_GLOBAL_GROUP,
                           "Universal": GTYPE_DISTRIBUTION_UNIVERSAL_GROUP})


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

Example3:
samba-tool group add Group3 --nis-domain=samdom --gid-number=12345

Example3 adds a new RFC2307 enabled group for NIS domain samdom and GID 12345 (both options are required to enable this feature).
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
        Option("--gid-number", help="Group's Unix/RFC2307 GID number", type=int),
        Option("--nis-domain", help="SFU30 NIS Domain", type=str),
    ]

    takes_args = ["groupname"]

    def run(self, groupname, credopts=None, sambaopts=None,
            versionopts=None, H=None, groupou=None, group_scope=None,
            group_type=None, description=None, mail_address=None, notes=None, gid_number=None, nis_domain=None):

        if (group_type or "Security") == "Security":
            gtype = security_group.get(group_scope, GTYPE_SECURITY_GLOBAL_GROUP)
        else:
            gtype = distribution_group.get(group_scope, GTYPE_DISTRIBUTION_GLOBAL_GROUP)

        if (gid_number is None and nis_domain is not None) or (gid_number is not None and nis_domain is None):
            raise CommandError('Both --gid-number and --nis-domain have to be set for a RFC2307-enabled group. Operation cancelled.')

        lp = sambaopts.get_loadparm()
        creds = credopts.get_credentials(lp, fallback_machine=True)

        try:
            samdb = SamDB(url=H, session_info=system_session(),
                          credentials=creds, lp=lp)
            samdb.newgroup(groupname, groupou=groupou, grouptype=gtype,
                           description=description, mailaddress=mail_address, notes=notes,
                           gidnumber=gid_number, nisdomain=nis_domain)
        except Exception as e:
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
        samdb = SamDB(url=H, session_info=system_session(),
                      credentials=creds, lp=lp)

        filter = ("(&(sAMAccountName=%s)(objectClass=group))" %
                  ldb.binary_encode(groupname))

        try:
            res = samdb.search(base=samdb.domain_dn(),
                               scope=ldb.SCOPE_SUBTREE,
                               expression=filter,
                               attrs=["dn"])
            group_dn = res[0].dn
        except IndexError:
            raise CommandError('Unable to find group "%s"' % (groupname))

        try:
            samdb.delete(group_dn)
        except Exception as e:
            # FIXME: catch more specific exception
            raise CommandError('Failed to remove group "%s"' % groupname, e)
        self.outf.write("Deleted group %s\n" % groupname)


class cmd_group_add_members(Command):
    """Add members to an AD group.

This command adds one or more members to an existing Active Directory group. The command accepts one or more group member names separated by commas.  A group member may be a user or computer account or another Active Directory group.

When a member is added to a group the member may inherit permissions and rights from the group.  Likewise, when permission or rights of a group are changed, the changes may reflect in the members through inheritance.

The member names specified on the command must be the sAMaccountName.

Example1:
samba-tool group addmembers supergroup Group1,Group2,User1 -H ldap://samba.samdom.example.com -Uadministrator%passw0rd

Example1 shows how to add two groups, Group1 and Group2 and one user account, User1, to the existing AD group named supergroup.  The command will be run on a remote server specified with the -H.  The -U parameter is used to pass the userid and password of a user authorized to issue the command on the remote server.

Example2:
sudo samba-tool group addmembers supergroup User2

Example2 shows how to add a single user account, User2, to the supergroup AD group.  It uses the sudo command to run as root when issuing the command.
"""

    synopsis = "%prog <groupname> (<listofmembers>]|--member-dn=<member-dn>) [options]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "versionopts": options.VersionOptions,
        "credopts": options.CredentialsOptions,
    }

    takes_options = [
        Option("-H", "--URL", help="LDB URL for database or target server", type=str,
               metavar="URL", dest="H"),
        Option("--member-dn",
               help=("DN of the new group member to be added.\n"
                     "The --object-types option will be ignored."),
               type=str,
               action="append"),
        Option("--object-types",
               help=("Comma separated list of object types.\n"
                     "The types are used to filter the search for the "
                     "specified members.\n"
                     "Valid values are: user, group, computer, serviceaccount, "
                     "contact and all.\n"
                     "Default: user,group,computer"),
               default="user,group,computer",
               type=str),
        Option("--member-base-dn",
               help=("Base DN for group member search.\n"
                     "Default is the domain DN."),
               type=str),
    ]

    takes_args = ["groupname", "listofmembers?"]

    def run(self,
            groupname,
            listofmembers=None,
            credopts=None,
            sambaopts=None,
            versionopts=None,
            H=None,
            member_base_dn=None,
            member_dn=None,
            object_types="user,group,computer"):

        lp = sambaopts.get_loadparm()
        creds = credopts.get_credentials(lp, fallback_machine=True)

        if member_dn is None and listofmembers is None:
            self.usage()
            raise CommandError(
                'Either listofmembers or --member-dn must be specified.')

        try:
            samdb = SamDB(url=H, session_info=system_session(),
                          credentials=creds, lp=lp)
            groupmembers = []
            if member_dn is not None:
                groupmembers += member_dn
            if listofmembers is not None:
                groupmembers += listofmembers.split(',')
            group_member_types = object_types.split(',')

            if member_base_dn is not None:
                member_base_dn = samdb.normalize_dn_in_domain(member_base_dn)

            samdb.add_remove_group_members(groupname, groupmembers,
                                           add_members_operation=True,
                                           member_types=group_member_types,
                                           member_base_dn=member_base_dn)
        except Exception as e:
            # FIXME: catch more specific exception
            raise CommandError('Failed to add members %r to group "%s" - %s' % (
                groupmembers, groupname, e))
        self.outf.write("Added members to group %s\n" % groupname)


class cmd_group_remove_members(Command):
    """Remove members from an AD group.

This command removes one or more members from an existing Active Directory group.  The command accepts one or more group member names separated by commas.  A group member may be a user or computer account or another Active Directory group that is a member of the group specified on the command.

When a member is removed from a group, inherited permissions and rights will no longer apply to the member.

Example1:
samba-tool group removemembers supergroup Group1 -H ldap://samba.samdom.example.com -Uadministrator%passw0rd

Example1 shows how to remove Group1 from supergroup.  The command will run on the remote server specified on the -H parameter.  The -U parameter is used to pass the userid and password of a user authorized to issue the command on the remote server.

Example2:
sudo samba-tool group removemembers supergroup User1

Example2 shows how to remove a single user account, User2, from the supergroup AD group.  It uses the sudo command to run as root when issuing the command.
"""

    synopsis = "%prog <groupname> (<listofmembers>]|--member-dn=<member-dn>) [options]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "versionopts": options.VersionOptions,
        "credopts": options.CredentialsOptions,
    }

    takes_options = [
        Option("-H", "--URL", help="LDB URL for database or target server", type=str,
               metavar="URL", dest="H"),
        Option("--member-dn",
               help=("DN of the group member to be removed.\n"
                     "The --object-types option will be ignored."),
               type=str,
               action="append"),
        Option("--object-types",
               help=("Comma separated list of object types.\n"
                     "The types are used to filter the search for the "
                     "specified members.\n"
                     "Valid values are: user, group, computer, serviceaccount, "
                     "contact and all.\n"
                     "Default: user,group,computer"),
               default="user,group,computer",
               type=str),
        Option("--member-base-dn",
               help=("Base DN for group member search.\n"
                     "Default is the domain DN."),
               type=str),
    ]

    takes_args = ["groupname", "listofmembers?"]

    def run(self,
            groupname,
            listofmembers=None,
            credopts=None,
            sambaopts=None,
            versionopts=None,
            H=None,
            member_base_dn=None,
            member_dn=None,
            object_types="user,group,computer"):

        lp = sambaopts.get_loadparm()
        creds = credopts.get_credentials(lp, fallback_machine=True)

        if member_dn is None and listofmembers is None:
            self.usage()
            raise CommandError(
                'Either listofmembers or --member-dn must be specified.')

        try:
            samdb = SamDB(url=H, session_info=system_session(),
                          credentials=creds, lp=lp)
            groupmembers = []
            if member_dn is not None:
                groupmembers += member_dn
            if listofmembers is not None:
                groupmembers += listofmembers.split(',')
            group_member_types = object_types.split(',')

            if member_base_dn is not None:
                member_base_dn = samdb.normalize_dn_in_domain(member_base_dn)

            samdb.add_remove_group_members(groupname,
                                           groupmembers,
                                           add_members_operation=False,
                                           member_types=group_member_types,
                                           member_base_dn=member_base_dn)
        except Exception as e:
            # FIXME: Catch more specific exception
            raise CommandError('Failed to remove members %r from group "%s"' % (listofmembers, groupname), e)
        self.outf.write("Removed members from group %s\n" % groupname)


class cmd_group_list(Command):
    """List all groups."""

    synopsis = "%prog [options]"

    takes_options = [
        Option("-H", "--URL", help="LDB URL for database or target server", type=str,
               metavar="URL", dest="H"),
        Option("-v", "--verbose",
               help="Verbose output, showing group type and group scope.",
               action="store_true"),
        Option("-b", "--base-dn",
               help="Specify base DN to use.",
               type=str),
        Option("--full-dn", dest="full_dn",
               default=False,
               action='store_true',
               help="Display DN instead of the sAMAccountName."),
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
            verbose=False,
            base_dn=None,
            full_dn=False):
        lp = sambaopts.get_loadparm()
        creds = credopts.get_credentials(lp, fallback_machine=True)

        samdb = SamDB(url=H, session_info=system_session(),
                      credentials=creds, lp=lp)
        attrs=["samaccountname"]

        if verbose:
            attrs += ["grouptype", "member"]
        domain_dn = samdb.domain_dn()
        if base_dn:
            domain_dn = samdb.normalize_dn_in_domain(base_dn)
        res = samdb.search(domain_dn, scope=ldb.SCOPE_SUBTREE,
                           expression=("(objectClass=group)"),
                           attrs=attrs)
        if (len(res) == 0):
            return

        if verbose:
            self.outf.write("Group Name                                  Group Type      Group Scope  Members\n")
            self.outf.write("--------------------------------------------------------------------------------\n")

            for msg in res:
                self.outf.write("%-44s" % msg.get("samaccountname", idx=0))
                hgtype = hex(int("%s" % msg["grouptype"]) & 0x00000000FFFFFFFF)
                if (hgtype == hex(int(security_group.get("Builtin")))):
                    self.outf.write("Security         Builtin  ")
                elif (hgtype == hex(int(security_group.get("Domain")))):
                    self.outf.write("Security         Domain   ")
                elif (hgtype == hex(int(security_group.get("Global")))):
                    self.outf.write("Security         Global   ")
                elif (hgtype == hex(int(security_group.get("Universal")))):
                    self.outf.write("Security         Universal")
                elif (hgtype == hex(int(distribution_group.get("Global")))):
                    self.outf.write("Distribution     Global   ")
                elif (hgtype == hex(int(distribution_group.get("Domain")))):
                    self.outf.write("Distribution     Domain   ")
                elif (hgtype == hex(int(distribution_group.get("Universal")))):
                    self.outf.write("Distribution     Universal")
                else:
                    self.outf.write("                          ")
                num_members = len(msg.get("member", default=[]))
                self.outf.write("    %6u\n" % num_members)
        else:
            for msg in res:
                if full_dn:
                    self.outf.write("%s\n" % msg.get("dn"))
                    continue

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

    takes_args = ["groupname"]

    def run(self,
            groupname,
            credopts=None,
            sambaopts=None,
            versionopts=None,
            H=None,
            full_dn=False):
        lp = sambaopts.get_loadparm()
        creds = credopts.get_credentials(lp, fallback_machine=True)

        try:
            samdb = SamDB(url=H, session_info=system_session(),
                          credentials=creds, lp=lp)

            search_filter = ("(&(objectClass=group)(sAMAccountName=%s))" %
                             ldb.binary_encode(groupname))
            try:
                res = samdb.search(samdb.domain_dn(), scope=ldb.SCOPE_SUBTREE,
                                   expression=(search_filter),
                                   attrs=["objectSid"])
                group_sid_binary = res[0].get('objectSid', idx=0)
            except IndexError:
                raise CommandError('Unable to find group "%s"' % (groupname))

            group_sid = ndr_unpack(security.dom_sid, group_sid_binary)
            (group_dom_sid, rid) = group_sid.split()
            group_sid_dn = "<SID=%s>" % (group_sid)

            search_filter = ("(|(primaryGroupID=%s)(memberOf=%s))" %
                             (rid, group_sid_dn))
            res = samdb.search(samdb.domain_dn(), scope=ldb.SCOPE_SUBTREE,
                               expression=(search_filter),
                               attrs=["samAccountName", "cn"])

            if (len(res) == 0):
                return

            for msg in res:
                if full_dn:
                    self.outf.write("%s\n" % msg.get("dn"))
                    continue

                member_name = msg.get("samAccountName", idx=0)
                if member_name is None:
                    member_name = msg.get("cn", idx=0)
                self.outf.write("%s\n" % member_name)

        except Exception as e:
            raise CommandError('Failed to list members of "%s" group - %s' %
                               (groupname, e))


class cmd_group_move(Command):
    """Move a group to an organizational unit/container.

    This command moves a group object into the specified organizational unit
    or container.
    The groupname specified on the command is the sAMAccountName.
    The name of the organizational unit or container can be specified as a
    full DN or without the domainDN component.

    The command may be run from the root userid or another authorized userid.

    The -H or --URL= option can be used to execute the command against a remote
    server.

    Example1:
    samba-tool group move Group1 'OU=OrgUnit,DC=samdom.DC=example,DC=com' \\
        -H ldap://samba.samdom.example.com -U administrator

    Example1 shows how to move a group Group1 into the 'OrgUnit' organizational
    unit on a remote LDAP server.

    The -H parameter is used to specify the remote target server.

    Example2:
    samba-tool group move Group1 CN=Users

    Example2 shows how to move a group Group1 back into the CN=Users container
    on the local server.
    """

    synopsis = "%prog <groupname> <new_parent_dn> [options]"

    takes_options = [
        Option("-H", "--URL", help="LDB URL for database or target server",
               type=str, metavar="URL", dest="H"),
    ]

    takes_args = ["groupname", "new_parent_dn"]
    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "credopts": options.CredentialsOptions,
        "versionopts": options.VersionOptions,
    }

    def run(self, groupname, new_parent_dn, credopts=None, sambaopts=None,
            versionopts=None, H=None):
        lp = sambaopts.get_loadparm()
        creds = credopts.get_credentials(lp, fallback_machine=True)
        samdb = SamDB(url=H, session_info=system_session(),
                      credentials=creds, lp=lp)
        domain_dn = ldb.Dn(samdb, samdb.domain_dn())

        filter = ("(&(sAMAccountName=%s)(objectClass=group))" %
                  ldb.binary_encode(groupname))
        try:
            res = samdb.search(base=domain_dn,
                               expression=filter,
                               scope=ldb.SCOPE_SUBTREE)
            group_dn = res[0].dn
        except IndexError:
            raise CommandError('Unable to find group "%s"' % (groupname))

        try:
            full_new_parent_dn = samdb.normalize_dn_in_domain(new_parent_dn)
        except Exception as e:
            raise CommandError('Invalid new_parent_dn "%s": %s' %
                               (new_parent_dn, e.message))

        full_new_group_dn = ldb.Dn(samdb, str(group_dn))
        full_new_group_dn.remove_base_components(len(group_dn) - 1)
        full_new_group_dn.add_base(full_new_parent_dn)

        try:
            samdb.rename(group_dn, full_new_group_dn)
        except Exception as e:
            raise CommandError('Failed to move group "%s"' % groupname, e)
        self.outf.write('Moved group "%s" into "%s"\n' %
                        (groupname, full_new_parent_dn))


class cmd_group_show(Command):
    """Display a group AD object.

This command displays a group object and it's attributes in the Active
Directory domain.
The group name specified on the command is the sAMAccountName of the group.

The command may be run from the root userid or another authorized userid.

The -H or --URL= option can be used to execute the command against a remote
server.

Example1:
samba-tool group show Group1 -H ldap://samba.samdom.example.com \\
    -U administrator --password=passw1rd

Example1 shows how to display a group's attributes in the domain against a
remote LDAP server.

The -H parameter is used to specify the remote target server.

Example2:
samba-tool group show Group2

Example2 shows how to display a group's attributes in the domain against a local
LDAP server.

Example3:
samba-tool group show Group3 --attributes=member,objectGUID

Example3 shows how to display a groups objectGUID and member attributes.
"""
    synopsis = "%prog <group name> [options]"

    takes_options = [
        Option("-H", "--URL", help="LDB URL for database or target server",
               type=str, metavar="URL", dest="H"),
        Option("--attributes",
               help=("Comma separated list of attributes, "
                     "which will be printed."),
               type=str, dest="group_attrs"),
    ]

    takes_args = ["groupname"]
    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "credopts": options.CredentialsOptions,
        "versionopts": options.VersionOptions,
    }

    def run(self, groupname, credopts=None, sambaopts=None, versionopts=None,
            H=None, group_attrs=None):

        lp = sambaopts.get_loadparm()
        creds = credopts.get_credentials(lp, fallback_machine=True)
        samdb = SamDB(url=H, session_info=system_session(),
                      credentials=creds, lp=lp)

        attrs = None
        if group_attrs:
            attrs = group_attrs.split(",")

        filter = ("(&(objectCategory=group)(sAMAccountName=%s))" %
                   ldb.binary_encode(groupname))

        domaindn = samdb.domain_dn()

        try:
            res = samdb.search(base=domaindn, expression=filter,
                               scope=ldb.SCOPE_SUBTREE, attrs=attrs)
            user_dn = res[0].dn
        except IndexError:
            raise CommandError('Unable to find group "%s"' % (groupname))

        for msg in res:
            group_ldif = common.get_ldif_for_editor(samdb, msg)
            self.outf.write(group_ldif)


class cmd_group_stats(Command):
    """Summary statistics about group memberships."""

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

    def num_in_range(self, range_min, range_max, group_freqs):
        total_count = 0
        for members, count in group_freqs.items():
            if range_min <= members and members <= range_max:
                total_count += count

        return total_count

    def run(self, sambaopts=None, credopts=None, versionopts=None, H=None):
        lp = sambaopts.get_loadparm()
        creds = credopts.get_credentials(lp, fallback_machine=True)

        samdb = SamDB(url=H, session_info=system_session(),
                      credentials=creds, lp=lp)

        domain_dn = samdb.domain_dn()
        res = samdb.search(domain_dn, scope=ldb.SCOPE_SUBTREE,
                           expression=("(objectClass=group)"),
                           attrs=["samaccountname", "member"])

        # first count up how many members each group has
        group_assignments = {}
        total_memberships = 0

        for msg in res:
            name = str(msg.get("samaccountname"))
            num_members = len(msg.get("member", default=[]))
            group_assignments[name] = num_members
            total_memberships += num_members

        num_groups = res.count
        self.outf.write("Group membership statistics*\n")
        self.outf.write("-------------------------------------------------\n")
        self.outf.write("Total groups: {0}\n".format(num_groups))
        self.outf.write("Total memberships: {0}\n".format(total_memberships))
        average = total_memberships / float(num_groups)
        self.outf.write("Average members per group: %.2f\n" % average)

        # find the max and median memberships (note that some default groups
        # always have zero members, so displaying the min is not very helpful)
        group_names = list(group_assignments.keys())
        group_members = list(group_assignments.values())
        idx = group_members.index(max(group_members))
        max_members = group_members[idx]
        self.outf.write("Max members: {0} ({1})\n".format(max_members,
                                                          group_names[idx]))
        group_members.sort()
        midpoint = num_groups // 2
        median = group_members[midpoint]
        if num_groups % 2 == 0:
            median = (median + group_members[midpoint - 1]) / 2
        self.outf.write("Median members per group: {0}\n\n".format(median))

        # convert this to the frequency of group membership, i.e. how many
        # groups have 5 members, how many have 6 members, etc
        group_freqs = defaultdict(int)
        for group, num_members in group_assignments.items():
            group_freqs[num_members] += 1

        # now squash this down even further, so that we just display the number
        # of groups that fall into one of the following membership bands
        bands = [(0, 1), (2, 4), (5, 9), (10, 14), (15, 19), (20, 24),
                 (25, 29), (30, 39), (40, 49), (50, 59), (60, 69), (70, 79),
                 (80, 89), (90, 99), (100, 149), (150, 199), (200, 249),
                 (250, 299), (300, 399), (400, 499), (500, 999), (1000, 1999),
                 (2000, 2999), (3000, 3999), (4000, 4999), (5000, 9999),
                 (10000, max_members)]

        self.outf.write("Members        Number of Groups\n")
        self.outf.write("-------------------------------------------------\n")

        for band in bands:
            band_start = band[0]
            band_end = band[1]
            if band_start > max_members:
                break

            num_groups = self.num_in_range(band_start, band_end, group_freqs)

            if num_groups != 0:
                band_str = "{0}-{1}".format(band_start, band_end)
                self.outf.write("%13s  %u\n" % (band_str, num_groups))

        self.outf.write("\n* Note this does not include nested group memberships\n")


class cmd_group_edit(Command):
    """Modify Group AD object.

    This command will allow editing of a group account in the Active Directory
    domain. You will then be able to add or change attributes and their values.

    The groupname specified on the command is the sAMAccountName.

    The command may be run from the root userid or another authorized userid.

    The -H or --URL= option can be used to execute the command against a remote
    server.

    Example1:
    samba-tool group edit Group1 -H ldap://samba.samdom.example.com \\
        -U administrator --password=passw1rd

    Example1 shows how to edit a groups attributes in the domain against a
    remote LDAP server.

    The -H parameter is used to specify the remote target server.

    Example2:
    samba-tool group edit Group2

    Example2 shows how to edit a groups attributes in the domain against a local
    server.

    Example3:
    samba-tool group edit Group3 --editor=nano

    Example3 shows how to edit a groups attributes in the domain against a local
    server using the 'nano' editor.
    """
    synopsis = "%prog <groupname> [options]"

    takes_options = [
        Option("-H", "--URL", help="LDB URL for database or target server",
               type=str, metavar="URL", dest="H"),
        Option("--editor", help="Editor to use instead of the system default,"
               " or 'vi' if no system default is set.", type=str),
    ]

    takes_args = ["groupname"]
    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "credopts": options.CredentialsOptions,
        "versionopts": options.VersionOptions,
    }

    def run(self, groupname, credopts=None, sambaopts=None, versionopts=None,
            H=None, editor=None):
        lp = sambaopts.get_loadparm()
        creds = credopts.get_credentials(lp, fallback_machine=True)
        samdb = SamDB(url=H, session_info=system_session(),
                      credentials=creds, lp=lp)

        filter = ("(&(sAMAccountName=%s)(objectClass=group))" %
                  ldb.binary_encode(groupname))

        domaindn = samdb.domain_dn()

        try:
            res = samdb.search(base=domaindn,
                               expression=filter,
                               scope=ldb.SCOPE_SUBTREE)
            group_dn = res[0].dn
        except IndexError:
            raise CommandError('Unable to find group "%s"' % (groupname))

        if len(res) != 1:
            raise CommandError('Invalid number of results: for "%s": %d' %
                               ((groupname), len(res)))

        msg = res[0]
        result_ldif = common.get_ldif_for_editor(samdb, msg)

        if editor is None:
            editor = os.environ.get('EDITOR')
            if editor is None:
                editor = 'vi'

        with tempfile.NamedTemporaryFile(suffix=".tmp") as t_file:
            t_file.write(get_bytes(result_ldif))
            t_file.flush()
            try:
                check_call([editor, t_file.name])
            except CalledProcessError as e:
                raise CalledProcessError("ERROR: ", e)
            with open(t_file.name) as edited_file:
                edited_message = edited_file.read()

        msgs_edited = samdb.parse_ldif(edited_message)
        msg_edited = next(msgs_edited)[1]

        res_msg_diff = samdb.msg_diff(msg, msg_edited)
        if len(res_msg_diff) == 0:
            self.outf.write("Nothing to do\n")
            return

        try:
            samdb.modify(res_msg_diff)
        except Exception as e:
            raise CommandError("Failed to modify group '%s': " % groupname, e)

        self.outf.write("Modified group '%s' successfully\n" % groupname)


class cmd_group_add_unix_attrs(Command):
    """Add RFC2307 attributes to a group.

This command adds Unix attributes to a group account in the Active
Directory domain.
The groupname specified on the command is the sAMaccountName.

Unix (RFC2307) attributes will be added to the group account.

Add 'idmap_ldb:use rfc2307 = Yes' to smb.conf to use these attributes for
UID/GID mapping.

The command may be run from the root userid or another authorized userid.
The -H or --URL= option can be used to execute the command against a
remote server.

Example1:
samba-tool group addunixattrs Group1 10000

Example1 shows how to add RFC2307 attributes to a domain enabled group
account.

The groups Unix ID will be set to '10000', provided this ID isn't already
in use.

"""
    synopsis = "%prog <groupname> <gidnumber> [options]"

    takes_options = [
        Option("-H", "--URL", help="LDB URL for database or target server",
               type=str, metavar="URL", dest="H"),
    ]

    takes_args = ["groupname", "gidnumber"]

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "credopts": options.CredentialsOptions,
        "versionopts": options.VersionOptions,
        }

    def run(self, groupname, gidnumber, credopts=None, sambaopts=None,
            versionopts=None, H=None):

        lp = sambaopts.get_loadparm()
        creds = credopts.get_credentials(lp)

        samdb = SamDB(url=H, session_info=system_session(),
                      credentials=creds, lp=lp)

        domaindn = samdb.domain_dn()

        # Check group exists and doesn't have a gidNumber
        filter = "(samaccountname={})".format(ldb.binary_encode(groupname))
        res = samdb.search(domaindn,
                           scope=ldb.SCOPE_SUBTREE,
                           expression=filter)
        if (len(res) == 0):
            raise CommandError("Unable to find group '{}'".format(groupname))

        group_dn = res[0].dn

        if "gidNumber" in res[0]:
            raise CommandError("Group {} is a Unix group.".format(groupname))

        # Check if supplied gidnumber isn't already being used
        filter = "(&(objectClass=group)(gidNumber={}))".format(gidnumber)
        res = samdb.search(domaindn,
                           scope=ldb.SCOPE_SUBTREE,
                           expression=filter)
        if (len(res) != 0):
            raise CommandError('gidNumber {} already used.'.format(gidnumber))

        if not lp.get("idmap_ldb:use rfc2307"):
            self.outf.write("You are setting a Unix/RFC2307 GID. "
                            "You may want to set 'idmap_ldb:use rfc2307 = Yes'"
                            " in smb.conf to use the attributes for "
                            "XID/SID-mapping.\n")

        group_mod = """
dn: {0}
changetype: modify
add: gidNumber
gidNumber: {1}
""".format(group_dn, gidnumber)

        try:
            samdb.modify_ldif(group_mod)
        except ldb.LdbError as e:
            raise CommandError("Failed to modify group '{0}': {1}"
                               .format(groupname, e))

        self.outf.write("Modified Group '{}' successfully\n".format(groupname))


class cmd_group(SuperCommand):
    """Group management."""

    subcommands = {}
    subcommands["add"] = cmd_group_add()
    subcommands["delete"] = cmd_group_delete()
    subcommands["edit"] = cmd_group_edit()
    subcommands["addmembers"] = cmd_group_add_members()
    subcommands["removemembers"] = cmd_group_remove_members()
    subcommands["list"] = cmd_group_list()
    subcommands["listmembers"] = cmd_group_list_members()
    subcommands["move"] = cmd_group_move()
    subcommands["show"] = cmd_group_show()
    subcommands["stats"] = cmd_group_stats()
    subcommands["addunixattrs"] = cmd_group_add_unix_attrs()
