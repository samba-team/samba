# user management
#
# user move command
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


class cmd_user_move(Command):
    """Move a user to an organizational unit/container.

    This command moves a user account into the specified organizational unit
    or container.
    The username specified on the command is the sAMAccountName.
    The name of the organizational unit or container can be specified as a
    full DN or without the domainDN component.

    The command may be run from the root userid or another authorized userid.

    The -H or --URL= option can be used to execute the command against a remote
    server.

    Example1:
    samba-tool user move User1 'OU=OrgUnit,DC=samdom,DC=example,DC=com' \\
        -H ldap://samba.samdom.example.com -U administrator

    Example1 shows how to move a user User1 into the 'OrgUnit' organizational
    unit on a remote LDAP server.

    The -H parameter is used to specify the remote target server.

    Example2:
    samba-tool user move User1 CN=Users

    Example2 shows how to move a user User1 back into the CN=Users container
    on the local server.
    """

    synopsis = "%prog <username> <new_parent_dn> [options]"

    takes_options = [
        Option("-H", "--URL", help="LDB URL for database or target server",
               type=str, metavar="URL", dest="H"),
    ]

    takes_args = ["username", "new_parent_dn"]
    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "credopts": options.CredentialsOptions,
        "versionopts": options.VersionOptions,
    }

    def run(self, username, new_parent_dn, credopts=None, sambaopts=None,
            versionopts=None, H=None):
        lp = sambaopts.get_loadparm()
        creds = credopts.get_credentials(lp, fallback_machine=True)
        samdb = SamDB(url=H, session_info=system_session(),
                      credentials=creds, lp=lp)
        domain_dn = ldb.Dn(samdb, samdb.domain_dn())

        filter = ("(&(sAMAccountType=%d)(sAMAccountName=%s))" %
                  (dsdb.ATYPE_NORMAL_ACCOUNT, ldb.binary_encode(username)))
        try:
            res = samdb.search(base=domain_dn,
                               expression=filter,
                               scope=ldb.SCOPE_SUBTREE)
            user_dn = res[0].dn
        except IndexError:
            raise CommandError('Unable to find user "%s"' % (username))

        try:
            full_new_parent_dn = samdb.normalize_dn_in_domain(new_parent_dn)
        except Exception as e:
            raise CommandError('Invalid new_parent_dn "%s": %s' %
                               (new_parent_dn, e))

        full_new_user_dn = ldb.Dn(samdb, str(user_dn))
        full_new_user_dn.remove_base_components(len(user_dn) - 1)
        full_new_user_dn.add_base(full_new_parent_dn)

        try:
            samdb.rename(user_dn, full_new_user_dn)
        except Exception as e:
            raise CommandError('Failed to move user "%s"' % username, e)
        self.outf.write('Moved user "%s" into "%s"\n' %
                        (username, full_new_parent_dn))
