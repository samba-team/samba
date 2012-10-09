# rodc related commands
#
# Copyright Andrew Tridgell 2010
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

from samba.netcmd import Command, CommandError, Option, SuperCommand
import samba.getopt as options
from samba.samdb import SamDB
from samba.auth import system_session
import ldb
from samba.dcerpc import misc, drsuapi
from samba.drs_utils import drs_Replicate


class cmd_rodc_preload(Command):
    """Preload one account for an RODC."""

    synopsis = "%prog (<SID>|<DN>|<accountname>) [options]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "versionopts": options.VersionOptions,
        "credopts": options.CredentialsOptions,
    }

    takes_options = [
        Option("--server", help="DC to use", type=str),
        ]

    takes_args = ["account"]

    def get_dn(self, samdb, account):
        '''work out what DN they meant'''

        # we accept the account in SID, accountname or DN form
        if account[0:2] == 'S-':
            res = samdb.search(base="<SID=%s>" % account,
                               expression="objectclass=user",
                               scope=ldb.SCOPE_BASE, attrs=[])
        elif account.find('=') >= 0:
            res = samdb.search(base=account,
                               expression="objectclass=user",
                               scope=ldb.SCOPE_BASE, attrs=[])
        else:
            res = samdb.search(expression="(&(samAccountName=%s)(objectclass=user))" % ldb.binary_encode(account),
                               scope=ldb.SCOPE_SUBTREE, attrs=[])
        if len(res) != 1:
            raise Exception("Failed to find account '%s'" % account)
        return str(res[0]["dn"])


    def run(self, account, sambaopts=None,
            credopts=None, versionopts=None, server=None):

        if server is None:
            raise Exception("You must supply a server")

        lp = sambaopts.get_loadparm()

        creds = credopts.get_credentials(lp, fallback_machine=True)

        # connect to the remote and local SAMs
        samdb = SamDB(url="ldap://%s" % server,
                      session_info=system_session(),
                      credentials=creds, lp=lp)

        local_samdb = SamDB(url=None, session_info=system_session(),
                            credentials=creds, lp=lp)

        # work out the source and destination GUIDs
        dc_ntds_dn = samdb.get_dsServiceName()
        res = samdb.search(base=dc_ntds_dn, scope=ldb.SCOPE_BASE, attrs=["invocationId"])
        source_dsa_invocation_id = misc.GUID(local_samdb.schema_format_value("objectGUID", res[0]["invocationId"][0]))

        dn = self.get_dn(samdb, account)
        self.outf.write("Replicating DN %s\n" % dn)

        destination_dsa_guid = misc.GUID(local_samdb.get_ntds_GUID())

        local_samdb.transaction_start()
        repl = drs_Replicate("ncacn_ip_tcp:%s[seal,print]" % server, lp, creds, local_samdb)
        try:
            repl.replicate(dn, source_dsa_invocation_id, destination_dsa_guid,
                           exop=drsuapi.DRSUAPI_EXOP_REPL_SECRET, rodc=True)
        except Exception, e:
            raise CommandError("Error replicating DN %s" % dn, e)
        local_samdb.transaction_commit()



class cmd_rodc(SuperCommand):
    """Read-Only Domain Controller (RODC) management."""

    subcommands = {}
    subcommands["preload"] = cmd_rodc_preload()
