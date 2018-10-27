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
import sys


class RODCException(Exception):
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return "%s: %s" % (self.__class__.__name__, self.value)


class NamingError(RODCException):
    pass


class ReplicationError(RODCException):
    pass


class cmd_rodc_preload(Command):
    """Preload accounts for an RODC.  Multiple accounts may be requested."""

    synopsis = "%prog (<SID>|<DN>|<accountname>)+ ... [options]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "versionopts": options.VersionOptions,
        "credopts": options.CredentialsOptions,
    }

    takes_options = [
        Option("--server", help="DC to use", type=str),
        Option("--file", help="Read account list from a file, or - for stdin (one per line)", type=str),
        Option("--ignore-errors", help="When preloading multiple accounts, skip any failing accounts", action="store_true"),
    ]

    takes_args = ["account*"]

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
            raise NamingError("Failed to find account '%s'" % account)
        return str(res[0]["dn"])

    def run(self, *accounts, **kwargs):
        sambaopts = kwargs.get("sambaopts")
        credopts = kwargs.get("credopts")
        server = kwargs.get("server")
        accounts_file = kwargs.get("file")
        ignore_errors = kwargs.get("ignore_errors")

        if server is None:
            raise Exception("You must supply a server")

        if accounts_file is not None:
            accounts = []
            if accounts_file == "-":
                for line in sys.stdin:
                    accounts.append(line.strip())
            else:
                for line in open(accounts_file, 'r'):
                    accounts.append(line.strip())

        lp = sambaopts.get_loadparm()

        creds = credopts.get_credentials(lp, fallback_machine=True)

        # connect to the remote and local SAMs
        samdb = SamDB(url="ldap://%s" % server,
                      session_info=system_session(),
                      credentials=creds, lp=lp)

        local_samdb = SamDB(url=None, session_info=system_session(),
                            credentials=creds, lp=lp)

        destination_dsa_guid = misc.GUID(local_samdb.get_ntds_GUID())

        binding_options = "seal"
        if lp.log_level() >= 9:
            binding_options += ",print"
        repl = drs_Replicate("ncacn_ip_tcp:%s[%s]" % (server, binding_options),
                             lp, creds,
                             local_samdb, destination_dsa_guid)

        errors = []
        for account in accounts:
            # work out the source and destination GUIDs
            dc_ntds_dn = samdb.get_dsServiceName()
            res = samdb.search(base=dc_ntds_dn, scope=ldb.SCOPE_BASE, attrs=["invocationId"])
            source_dsa_invocation_id = misc.GUID(local_samdb.schema_format_value("objectGUID", res[0]["invocationId"][0]))

            try:
                dn = self.get_dn(samdb, account)
            except RODCException as e:
                if not ignore_errors:
                    raise CommandError(str(e))
                errors.append(e)
                continue

            self.outf.write("Replicating DN %s\n" % dn)

            local_samdb.transaction_start()
            try:
                repl.replicate(dn, source_dsa_invocation_id, destination_dsa_guid,
                               exop=drsuapi.DRSUAPI_EXOP_REPL_SECRET, rodc=True)
            except Exception as e:
                local_samdb.transaction_cancel()
                if not ignore_errors:
                    raise CommandError("Error replicating DN %s" % dn)
                errors.append(ReplicationError("Error replicating DN %s" % dn))
                continue

            local_samdb.transaction_commit()

        if len(errors) > 0:
            self.message("\nPreload encountered problematic users:")
            for error in errors:
                self.message("    %s" % error)


class cmd_rodc(SuperCommand):
    """Read-Only Domain Controller (RODC) management."""

    subcommands = {}
    subcommands["preload"] = cmd_rodc_preload()
