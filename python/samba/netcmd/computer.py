# machine account (computer) management
#
# Copyright Bjoern Baumbch <bb@sernet.de> 2018
#
# based on user management
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
import ldb
from samba.auth import system_session
from samba.samdb import SamDB
from samba import (
    credentials,
    dsdb,
    Ldb,
    )

from samba.netcmd import (
    Command,
    CommandError,
    SuperCommand,
    Option,
    )

class cmd_computer_create(Command):
    """Create a new computer.

This command creates a new computer account in the Active Directory domain.
The computername specified on the command is the sAMaccountName without the
trailing $ (dollar sign).

User accounts may represent physical entities, such as workstations. Computer
accounts are also referred to as security principals and are assigned a
security identifier (SID).

Example1:
samba-tool computer create Computer1 -H ldap://samba.samdom.example.com \
    -Uadministrator%passw1rd

Example1 shows how to create a new computer in the domain against a remote LDAP
server. The -H parameter is used to specify the remote target server. The -U
option is used to pass the userid and password authorized to issue the command
remotely.

Example2:
sudo samba-tool computer create Computer2

Example2 shows how to create a new computer in the domain against the local
server. sudo is used so a user may run the command as root.

Example3:
samba-tool computer create Computer3 --computerou='OU=OrgUnit'

Example3 shows how to create a new computer in the OrgUnit organizational unit.

"""
    synopsis = "%prog <computername> [options]"

    takes_options = [
        Option("-H", "--URL", help="LDB URL for database or target server",
               type=str, metavar="URL", dest="H"),
        Option("--computerou",
                help=("DN of alternative location (with or without domainDN "
                      "counterpart) to default CN=Users in which new computer "
                      "object will be created. E. g. 'OU=<OU name>'"),
                type=str),
        Option("--description", help="Computers's description", type=str),
        Option("--prepare-oldjoin",
               help="Prepare enabled machine account for oldjoin mechanism",
               action="store_true"),
    ]

    takes_args = ["computername"]

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "credopts": options.CredentialsOptions,
        "versionopts": options.VersionOptions,
        }

    def run(self, computername, credopts=None, sambaopts=None, versionopts=None,
            H=None, computerou=None, description=None, prepare_oldjoin=False):

        lp = sambaopts.get_loadparm()
        creds = credopts.get_credentials(lp)

        try:
            samdb = SamDB(url=H, session_info=system_session(),
                          credentials=creds, lp=lp)
            samdb.newcomputer(computername, computerou=computerou,
                              description=description,
                              prepare_oldjoin=prepare_oldjoin)
        except Exception, e:
            raise CommandError("Failed to create computer '%s': " %
                               computername, e)

        self.outf.write("Computer '%s' created successfully\n" % computername)

class cmd_computer_delete(Command):
    """Delete a computer.

This command deletes a computer account from the Active Directory domain. The
computername specified on the command is the sAMAccountName without the
trailing $ (dollar sign).

Once the account is deleted, all permissions and memberships associated with
that account are deleted. If a new computer account is added with the same name
as a previously deleted account name, the new computer does not have the
previous permissions. The new account computer will be assigned a new security
identifier (SID) and permissions and memberships will have to be added.

The command may be run from the root userid or another authorized
userid. The -H or --URL= option can be used to execute the command against
a remote server.

Example1:
samba-tool computer delete Computer1 -H ldap://samba.samdom.example.com \
    -Uadministrator%passw1rd

Example1 shows how to delete a computer in the domain against a remote LDAP
server. The -H parameter is used to specify the remote target server. The
--computername= and --password= options are used to pass the computername and
password of a computer that exists on the remote server and is authorized to
issue the command on that server.

Example2:
sudo samba-tool computer delete Computer2

Example2 shows how to delete a computer in the domain against the local server.
sudo is used so a computer may run the command as root.

"""
    synopsis = "%prog <computername> [options]"

    takes_options = [
        Option("-H", "--URL", help="LDB URL for database or target server",
               type=str, metavar="URL", dest="H"),
    ]

    takes_args = ["computername"]
    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "credopts": options.CredentialsOptions,
        "versionopts": options.VersionOptions,
        }

    def run(self, computername, credopts=None, sambaopts=None,
            versionopts=None, H=None):
        lp = sambaopts.get_loadparm()
        creds = credopts.get_credentials(lp, fallback_machine=True)

        samdb = SamDB(url=H, session_info=system_session(),
                      credentials=creds, lp=lp)

        samaccountname = computername
        if not computername.endswith('$'):
            samaccountname = "%s$" % computername

        filter = ("(&(sAMAccountName=%s)(sAMAccountType=%u))" %
                  (samaccountname, dsdb.ATYPE_WORKSTATION_TRUST))
        try:
            res = samdb.search(base=samdb.domain_dn(),
                               scope=ldb.SCOPE_SUBTREE,
                               expression=filter,
                               attrs=["userAccountControl"])
            computer_dn = res[0].dn
            computer_ac = int(res[0]["userAccountControl"][0])
        except IndexError:
            raise CommandError('Unable to find computer "%s"' % computername)

        computer_is_workstation = (
            computer_ac & dsdb.UF_WORKSTATION_TRUST_ACCOUNT)
        if computer_is_workstation == False:
            raise CommandError('Failed to remove computer "%s": '
                               'Computer is not a workstation - removal denied'
                               % computername)
        try:
            samdb.delete(computer_dn)
        except Exception, e:
            raise CommandError('Failed to remove computer "%s"' %
                               samaccountname, e)
        self.outf.write("Deleted computer %s\n" % computername)


class cmd_computer_list(Command):
    """List all computers."""

    synopsis = "%prog [options]"

    takes_options = [
        Option("-H", "--URL", help="LDB URL for database or target server",
               type=str, metavar="URL", dest="H"),
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

        filter = "(sAMAccountType=%u)" % (dsdb.ATYPE_WORKSTATION_TRUST)

        domain_dn = samdb.domain_dn()
        res = samdb.search(domain_dn, scope=ldb.SCOPE_SUBTREE,
                           expression=filter,
                           attrs=["samaccountname"])
        if (len(res) == 0):
            return

        for msg in res:
            self.outf.write("%s\n" % msg.get("samaccountname", idx=0))

class cmd_computer_show(Command):
    """Display a computer AD object.

This command displays a computer account and it's attributes in the Active
Directory domain.
The computername specified on the command is the sAMAccountName.

The command may be run from the root userid or another authorized
userid.

The -H or --URL= option can be used to execute the command against a remote
server.

Example1:
samba-tool computer show Computer1 -H ldap://samba.samdom.example.com \
    -U administrator

Example1 shows how display a computers attributes in the domain against a
remote LDAP server.

The -H parameter is used to specify the remote target server.

Example2:
samba-tool computer show Computer2

Example2 shows how to display a computers attributes in the domain against a
local LDAP server.

Example3:
samba-tool computer show Computer2 --attributes=objectSid,operatingSystem

Example3 shows how to display a computers objectSid and operatingSystem
attribute.
"""
    synopsis = "%prog <computername> [options]"

    takes_options = [
        Option("-H", "--URL", help="LDB URL for database or target server",
               type=str, metavar="URL", dest="H"),
        Option("--attributes",
               help=("Comma separated list of attributes, "
                     "which will be printed."),
               type=str, dest="computer_attrs"),
    ]

    takes_args = ["computername"]
    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "credopts": options.CredentialsOptions,
        "versionopts": options.VersionOptions,
        }

    def run(self, computername, credopts=None, sambaopts=None, versionopts=None,
            H=None, computer_attrs=None):

        lp = sambaopts.get_loadparm()
        creds = credopts.get_credentials(lp, fallback_machine=True)
        samdb = SamDB(url=H, session_info=system_session(),
                      credentials=creds, lp=lp)

        attrs = None
        if computer_attrs:
            attrs = computer_attrs.split(",")

        samaccountname = computername
        if not computername.endswith('$'):
            samaccountname = "%s$" % computername

        filter = ("(&(sAMAccountType=%d)(sAMAccountName=%s))" %
                  (dsdb.ATYPE_WORKSTATION_TRUST,
                   ldb.binary_encode(samaccountname)))

        domaindn = samdb.domain_dn()

        try:
            res = samdb.search(base=domaindn, expression=filter,
                               scope=ldb.SCOPE_SUBTREE, attrs=attrs)
            computer_dn = res[0].dn
        except IndexError:
            raise CommandError('Unable to find computer "%s"' %
                               samaccountname)

        for msg in res:
            computer_ldif = samdb.write_ldif(msg, ldb.CHANGETYPE_NONE)
            self.outf.write(computer_ldif)

class cmd_computer_move(Command):
    """Move a computer to an organizational unit/container."""

    synopsis = "%prog computername <new_ou_dn> [options]"

    takes_options = [
        Option("-H", "--URL", help="LDB URL for database or target server",
               type=str, metavar="URL", dest="H"),
    ]

    takes_args = [ "computername", "new_ou_dn" ]
    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "credopts": options.CredentialsOptions,
        "versionopts": options.VersionOptions,
        }

    def run(self, computername, new_ou_dn, credopts=None, sambaopts=None,
            versionopts=None, H=None):
        lp = sambaopts.get_loadparm()
        creds = credopts.get_credentials(lp, fallback_machine=True)
        samdb = SamDB(url=H, session_info=system_session(),
                      credentials=creds, lp=lp)
        domain_dn = ldb.Dn(samdb, samdb.domain_dn())

        samaccountname = computername
        if not computername.endswith('$'):
            samaccountname = "%s$" % computername

        filter = ("(&(sAMAccountName=%s)(sAMAccountType=%u))" %
                  (samaccountname, dsdb.ATYPE_WORKSTATION_TRUST))
        try:
            res = samdb.search(base=domain_dn,
                               expression=filter,
                               scope=ldb.SCOPE_SUBTREE)
            computer_dn = res[0].dn
        except IndexError:
            raise CommandError('Unable to find computer "%s"' % (computername))

        full_new_ou_dn = ldb.Dn(samdb, new_ou_dn)
        if not full_new_ou_dn.is_child_of(domain_dn):
            full_new_ou_dn.add_base(domain_dn)
        new_computer_dn = ldb.Dn(samdb, str(computer_dn))
        new_computer_dn.remove_base_components(len(computer_dn)-1)
        new_computer_dn.add_base(full_new_ou_dn)
        try:
            samdb.rename(computer_dn, new_computer_dn)
        except Exception, e:
            raise CommandError('Failed to move computer "%s"' % computername, e)
        self.outf.write('Moved computer "%s" to "%s"\n' %
                        (computername, new_ou_dn))


class cmd_computer(SuperCommand):
    """Computer management."""

    subcommands = {}
    subcommands["create"] = cmd_computer_create()
    subcommands["delete"] = cmd_computer_delete()
    subcommands["list"] = cmd_computer_list()
    subcommands["show"] = cmd_computer_show()
    subcommands["move"] = cmd_computer_move()
