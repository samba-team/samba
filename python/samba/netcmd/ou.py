# implement samba-tool ou commands
#
# Copyright Bjoern Baumbach 2018-2019 <bb@samba.org>
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
import ldb

from samba.auth import system_session
from samba.netcmd import (
    Command,
    CommandError,
    Option,
    SuperCommand,
)
from samba.samdb import SamDB
from samba import dsdb
from operator import attrgetter


class cmd_rename(Command):
    """Rename an organizational unit.

    The name of the organizational units can be specified as a full DN
    or without the domainDN component.

    Examples:
    samba-tool ou rename 'OU=OrgUnit,DC=samdom,DC=example,DC=com' \\
        'OU=NewNameOfOrgUnit,DC=samdom,DC=example,DC=com'
    samba-tool ou rename 'OU=OrgUnit' 'OU=NewNameOfOrgUnit'

    The examples show how an administrator would rename an ou 'OrgUnit'
    to 'NewNameOfOrgUnit'. The new DN would be
    'OU=NewNameOfOrgUnit,DC=samdom,DC=example,DC=com'
    """

    synopsis = "%prog <old_ou_dn> <new_ou_dn> [options]"

    takes_options = [
        Option("-H", "--URL", help="LDB URL for database or target server",
               type=str, metavar="URL", dest="H"),
    ]

    takes_args = ["old_ou_dn", "new_ou_dn"]
    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "credopts": options.CredentialsOptions,
        "versionopts": options.VersionOptions,
    }

    def run(self, old_ou_dn, new_ou_dn, credopts=None, sambaopts=None,
            versionopts=None, H=None):
        lp = sambaopts.get_loadparm()
        creds = credopts.get_credentials(lp, fallback_machine=True)
        samdb = SamDB(url=H, session_info=system_session(),
                      credentials=creds, lp=lp)
        domain_dn = ldb.Dn(samdb, samdb.domain_dn())

        try:
            full_old_ou_dn = samdb.normalize_dn_in_domain(old_ou_dn)
        except Exception as e:
            raise CommandError('Invalid old_ou_dn "%s": %s' %
                               (old_ou_dn, e))
        try:
            full_new_ou_dn = samdb.normalize_dn_in_domain(new_ou_dn)
        except Exception as e:
            raise CommandError('Invalid new_ou_dn "%s": %s' %
                               (new_ou_dn, e))

        try:
            res = samdb.search(base=full_old_ou_dn,
                               expression="(objectclass=organizationalUnit)",
                               scope=ldb.SCOPE_BASE, attrs=[])
            if len(res) == 0:
                self.outf.write('Unable to find ou "%s"\n' % old_ou_dn)
                return

            samdb.rename(full_old_ou_dn, full_new_ou_dn)
        except Exception as e:
            raise CommandError('Failed to rename ou "%s"' % full_old_ou_dn, e)
        self.outf.write('Renamed ou "%s" to "%s"\n' % (full_old_ou_dn,
                                                       full_new_ou_dn))


class cmd_move(Command):
    """Move an organizational unit.

    The name of the organizational units can be specified as a full DN
    or without the domainDN component.

    Examples:
    samba-tool ou move 'OU=OrgUnit,DC=samdom,DC=example,DC=com' \\
        'OU=NewParentOfOrgUnit,DC=samdom,DC=example,DC=com'
    samba-tool ou rename 'OU=OrgUnit' 'OU=NewParentOfOrgUnit'

    The examples show how an administrator would move an ou 'OrgUnit'
    into the ou 'NewParentOfOrgUnit'. The ou 'OrgUnit' would become
    a child of the 'NewParentOfOrgUnit' ou. The new DN would be
    'OU=OrgUnit,OU=NewParentOfOrgUnit,DC=samdom,DC=example,DC=com'
    """

    synopsis = "%prog <old_ou_dn> <new_parent_dn> [options]"

    takes_options = [
        Option("-H", "--URL", help="LDB URL for database or target server",
               type=str, metavar="URL", dest="H"),
    ]

    takes_args = ["old_ou_dn", "new_parent_dn"]
    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "credopts": options.CredentialsOptions,
        "versionopts": options.VersionOptions,
    }

    def run(self, old_ou_dn, new_parent_dn, credopts=None, sambaopts=None,
            versionopts=None, H=None):
        lp = sambaopts.get_loadparm()
        creds = credopts.get_credentials(lp, fallback_machine=True)
        samdb = SamDB(url=H, session_info=system_session(),
                      credentials=creds, lp=lp)

        domain_dn = ldb.Dn(samdb, samdb.domain_dn())
        try:
            full_old_ou_dn = samdb.normalize_dn_in_domain(old_ou_dn)
        except Exception as e:
            raise CommandError('Invalid old_ou_dn "%s": %s' %
                               (old_ou_dn, e))
        try:
            full_new_parent_dn = samdb.normalize_dn_in_domain(new_parent_dn)
        except Exception as e:
            raise CommandError('Invalid new_parent_dn "%s": %s' %
                               (new_parent_dn, e))

        full_new_ou_dn = ldb.Dn(samdb, str(full_old_ou_dn))
        full_new_ou_dn.remove_base_components(len(full_old_ou_dn) - 1)
        full_new_ou_dn.add_base(full_new_parent_dn)

        try:
            res = samdb.search(base=full_old_ou_dn,
                               expression="(objectclass=organizationalUnit)",
                               scope=ldb.SCOPE_BASE, attrs=[])
            if len(res) == 0:
                self.outf.write('Unable to find ou "%s"\n' % full_old_ou_dn)
                return
            samdb.rename(full_old_ou_dn, full_new_ou_dn)
        except Exception as e:
            raise CommandError('Failed to move ou "%s"' % full_old_ou_dn, e)
        self.outf.write('Moved ou "%s" into "%s"\n' %
                        (full_old_ou_dn, full_new_parent_dn))


class cmd_create(Command):
    """Create an organizational unit.

    The name of the new ou can be specified as a full DN or without the
    domainDN component.

    Examples:
    samba-tool ou create 'OU=OrgUnit'
    samba-tool ou create 'OU=SubOU,OU=OrgUnit,DC=samdom,DC=example,DC=com'

    The examples show how an administrator would create a new ou 'OrgUnit'
    and a new ou 'SubOU' as a child of the ou 'OrgUnit'.
    """

    synopsis = "%prog <ou_dn> [options]"

    takes_options = [
        Option("-H", "--URL", help="LDB URL for database or target server",
               type=str, metavar="URL", dest="H"),
        Option("--description", help="OU's description",
               type=str, dest="description"),
    ]

    takes_args = ["ou_dn"]
    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "credopts": options.CredentialsOptions,
        "versionopts": options.VersionOptions,
    }

    def run(self, ou_dn, credopts=None, sambaopts=None, versionopts=None,
            H=None, description=None):
        lp = sambaopts.get_loadparm()
        creds = credopts.get_credentials(lp, fallback_machine=True)
        samdb = SamDB(url=H, session_info=system_session(),
                      credentials=creds, lp=lp)

        try:
            full_ou_dn = samdb.normalize_dn_in_domain(ou_dn)
        except Exception as e:
            raise CommandError('Invalid ou_dn "%s": %s' % (ou_dn, e))

        try:
            samdb.create_ou(full_ou_dn, description=description)
        except Exception as e:
            raise CommandError('Failed to create ou "%s"' % full_ou_dn, e)

        self.outf.write('Created ou "%s"\n' % full_ou_dn)


class cmd_listobjects(Command):
    """List all objects in an organizational unit.

    The name of the organizational unit can be specified as a full DN
    or without the domainDN component.

    Examples:
    samba-tool ou listobjects 'OU=OrgUnit,DC=samdom,DC=example,DC=com'
    samba-tool ou listobjects 'OU=OrgUnit'

    The examples show how an administrator would list all child objects
    of the ou 'OrgUnit'.
    """
    synopsis = "%prog <ou_dn> [options]"

    takes_options = [
        Option("-H", "--URL", help="LDB URL for database or target server",
               type=str, metavar="URL", dest="H"),
        Option("--full-dn", dest="full_dn", default=False, action='store_true',
               help="Display DNs including the base DN."),
        Option("-r", "--recursive", dest="recursive", default=False,
               action='store_true', help="List objects recursively."),
    ]

    takes_args = ["ou_dn"]
    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "credopts": options.CredentialsOptions,
        "versionopts": options.VersionOptions,
    }

    def run(self, ou_dn, credopts=None, sambaopts=None, versionopts=None,
            H=None, full_dn=False, recursive=False):
        lp = sambaopts.get_loadparm()
        creds = credopts.get_credentials(lp, fallback_machine=True)
        samdb = SamDB(url=H, session_info=system_session(),
                      credentials=creds, lp=lp)
        domain_dn = ldb.Dn(samdb, samdb.domain_dn())

        try:
            full_ou_dn = samdb.normalize_dn_in_domain(ou_dn)
        except Exception as e:
            raise CommandError('Invalid ou_dn "%s": %s' % (ou_dn, e))

        minchilds = 0
        scope = ldb.SCOPE_ONELEVEL
        if recursive:
            minchilds = 1
            scope = ldb.SCOPE_SUBTREE

        try:
            childs = samdb.search(base=full_ou_dn,
                                  expression="(objectclass=*)",
                                  scope=scope, attrs=[])
            if len(childs) <= minchilds:
                self.outf.write('ou "%s" is empty\n' % ou_dn)
                return

            for child in sorted(childs, key=attrgetter('dn')):
                if child.dn == full_ou_dn:
                    continue
                if not full_dn:
                    child.dn.remove_base_components(len(domain_dn))
                self.outf.write("%s\n" % child.dn)

        except Exception as e:
            raise CommandError('Failed to list contents of ou "%s"' %
                               full_ou_dn, e)


class cmd_list(Command):
    """List all organizational units.

    Example:
    samba-tool ou listobjects

    The example shows how an administrator would list all organizational
    units.
    """

    synopsis = "%prog [options]"

    takes_options = [
        Option("-H", "--URL", help="LDB URL for database or target server",
               type=str, metavar="URL", dest="H"),
        Option("-b", "--base-dn",
               help="Specify base DN to use.",
               type=str),
        Option("--full-dn", dest="full_dn", default=False, action='store_true',
               help="Display DNs including the base DN."),
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
            base_dn=None,
            full_dn=False):
        lp = sambaopts.get_loadparm()
        creds = credopts.get_credentials(lp, fallback_machine=True)
        samdb = SamDB(url=H, session_info=system_session(),
                      credentials=creds, lp=lp)

        search_dn = ldb.Dn(samdb, samdb.domain_dn())
        if base_dn:
            search_dn = samdb.normalize_dn_in_domain(base_dn)

        res = samdb.search(search_dn,
                           scope=ldb.SCOPE_SUBTREE,
                           expression="(objectClass=organizationalUnit)",
                           attrs=[])
        if (len(res) == 0):
            return

        for msg in sorted(res, key=attrgetter('dn')):
            if not full_dn:
                domain_dn = ldb.Dn(samdb, samdb.domain_dn())
                msg.dn.remove_base_components(len(domain_dn))
            self.outf.write("%s\n" % str(msg.dn))


class cmd_delete(Command):
    """Delete an organizational unit.

    The name of the organizational unit can be specified as a full DN
    or without the domainDN component.

    Examples:
    samba-tool ou delete 'OU=OrgUnit,DC=samdom,DC=example,DC=com'
    samba-tool ou delete 'OU=OrgUnit'

    The examples show how an administrator would delete the ou 'OrgUnit'.
    """

    synopsis = "%prog <ou_dn> [options]"

    takes_options = [
        Option("-H", "--URL", help="LDB URL for database or target server",
               type=str, metavar="URL", dest="H"),
        Option("--force-subtree-delete", dest="force_subtree_delete",
               default=False, action='store_true',
               help="Delete organizational unit and all children reclusively"),
    ]

    takes_args = ["ou_dn"]
    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "credopts": options.CredentialsOptions,
        "versionopts": options.VersionOptions,
    }

    def run(self, ou_dn, credopts=None, sambaopts=None, versionopts=None,
            H=None, force_subtree_delete=False):
        lp = sambaopts.get_loadparm()
        creds = credopts.get_credentials(lp, fallback_machine=True)
        samdb = SamDB(url=H, session_info=system_session(),
                      credentials=creds, lp=lp)
        domain_dn = ldb.Dn(samdb, samdb.domain_dn())

        try:
            full_ou_dn = samdb.normalize_dn_in_domain(ou_dn)
        except Exception as e:
            raise CommandError('Invalid ou_dn "%s": %s' % (ou_dn, e))

        controls = []
        if force_subtree_delete:
            controls = ["tree_delete:1"]

        try:
            res = samdb.search(base=full_ou_dn,
                               expression="(objectclass=organizationalUnit)",
                               scope=ldb.SCOPE_BASE, attrs=[])
            if len(res) == 0:
                self.outf.write('Unable to find ou "%s"\n' % ou_dn)
                return
            samdb.delete(full_ou_dn, controls)
        except Exception as e:
            raise CommandError('Failed to delete ou "%s"' % full_ou_dn, e)

        self.outf.write('Deleted ou "%s"\n' % full_ou_dn)


class cmd_ou(SuperCommand):
    """Organizational Units (OU) management."""

    subcommands = {}
    subcommands["create"] = cmd_create()
    subcommands["delete"] = cmd_delete()
    subcommands["move"] = cmd_move()
    subcommands["rename"] = cmd_rename()
    subcommands["list"] = cmd_list()
    subcommands["listobjects"] = cmd_listobjects()
