# Changes a FSMO role owner
#
# Copyright Nadezhda Ivanova 2009
# Copyright Jelmer Vernooij 2009
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
from ldb import LdbError

from samba.auth import system_session
from samba.netcmd import (
    Command,
    CommandError,
    SuperCommand,
    Option,
    )
from samba.samdb import SamDB

def transfer_role(outf, role, samdb):
    m = ldb.Message()
    m.dn = ldb.Dn(samdb, "")
    if role == "rid":
        m["becomeRidMaster"]= ldb.MessageElement(
            "1", ldb.FLAG_MOD_REPLACE,
            "becomeRidMaster")
    elif role == "pdc":
        domain_dn = samdb.domain_dn()
        res = samdb.search(domain_dn,
                           scope=ldb.SCOPE_BASE, attrs=["objectSid"])
        assert len(res) == 1
        sid = res[0]["objectSid"][0]
        m["becomePdc"]= ldb.MessageElement(
            sid, ldb.FLAG_MOD_REPLACE,
            "becomePdc")
    elif role == "naming":
        m["becomeDomainMaster"]= ldb.MessageElement(
            "1", ldb.FLAG_MOD_REPLACE,
            "becomeDomainMaster")
        samdb.modify(m)
    elif role == "infrastructure":
        m["becomeInfrastructureMaster"]= ldb.MessageElement(
            "1", ldb.FLAG_MOD_REPLACE,
            "becomeInfrastructureMaster")
    elif role == "schema":
        m["becomeSchemaMaster"]= ldb.MessageElement(
            "1", ldb.FLAG_MOD_REPLACE,
            "becomeSchemaMaster")
    else:
        raise CommandError("Invalid FSMO role.")
    try:
        samdb.modify(m)
    except LdbError, (num, msg):
        raise CommandError("Failed to initiate transfer of '%s' role: %s" % (role, msg))
    outf.write("FSMO transfer of '%s' role successful\n" % role)


class cmd_fsmo_seize(Command):
    """Seize the role."""

    synopsis = "%prog [options]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "credopts": options.CredentialsOptions,
        "versionopts": options.VersionOptions,
        }

    takes_options = [
        Option("-H", "--URL", help="LDB URL for database or target server", type=str,
               metavar="URL", dest="H"),
        Option("--force", help="Force seizing of the role without attempting to transfer first.", action="store_true"),
        Option("--role", type="choice", choices=["rid", "pdc", "infrastructure","schema","naming","all"],
               help="""The FSMO role to seize or transfer.\n
rid=RidAllocationMasterRole\n
schema=SchemaMasterRole\n
pdc=PdcEmulationMasterRole\n
naming=DomainNamingMasterRole\n
infrastructure=InfrastructureMasterRole\n
all=all of the above"""),
        ]

    takes_args = []

    def seize_role(self, role, samdb, force):
        res = samdb.search("",
                           scope=ldb.SCOPE_BASE, attrs=["dsServiceName"])
        assert len(res) == 1
        serviceName = res[0]["dsServiceName"][0]
        domain_dn = samdb.domain_dn()
        self.infrastructure_dn = "CN=Infrastructure," + domain_dn
        self.naming_dn = "CN=Partitions,%s" % samdb.get_config_basedn()
        self.schema_dn = str(samdb.get_schema_basedn())
        self.rid_dn = "CN=RID Manager$,CN=System," + domain_dn

        m = ldb.Message()
        if role == "rid":
            m.dn = ldb.Dn(samdb, self.rid_dn)
        elif role == "pdc":
            m.dn = ldb.Dn(samdb, domain_dn)
        elif role == "naming":
            m.dn = ldb.Dn(samdb, self.naming_dn)
        elif role == "infrastructure":
            m.dn = ldb.Dn(samdb, self.infrastructure_dn)
        elif role == "schema":
            m.dn = ldb.Dn(samdb, self.schema_dn)
        else:
            raise CommandError("Invalid FSMO role.")
        #first try to transfer to avoid problem if the owner is still active
        if force is None:
            self.message("Attempting transfer...")
            try:
                transfer_role(self.outf, role, samdb)
            except CommandError:
            #transfer failed, use the big axe...
                self.message("Transfer unsuccessful, seizing...")
                m["fSMORoleOwner"]= ldb.MessageElement(
                    serviceName, ldb.FLAG_MOD_REPLACE,
                    "fSMORoleOwner")
        else:
            self.message("Will not attempt transfer, seizing...")
            m["fSMORoleOwner"]= ldb.MessageElement(
                serviceName, ldb.FLAG_MOD_REPLACE,
                "fSMORoleOwner")
        try:
            samdb.modify(m)
        except LdbError, (num, msg):
            raise CommandError("Failed to initiate role seize of '%s' role: %s" % (role, msg))
        self.outf.write("FSMO transfer of '%s' role successful\n" % role)

    def run(self, force=None, H=None, role=None,
            credopts=None, sambaopts=None, versionopts=None):

        lp = sambaopts.get_loadparm()
        creds = credopts.get_credentials(lp, fallback_machine=True)

        samdb = SamDB(url=H, session_info=system_session(),
                      credentials=creds, lp=lp)

        if role == "all":
            self.seize_role("rid", samdb, force)
            self.seize_role("pdc", samdb, force)
            self.seize_role("naming", samdb, force)
            self.seize_role("infrastructure", samdb, force)
            self.seize_role("schema", samdb, force)
        else:
            self.seize_role(role, samdb, force)


class cmd_fsmo_show(Command):
    """Show the roles."""

    synopsis = "%prog [options]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "credopts": options.CredentialsOptions,
        "versionopts": options.VersionOptions,
        }

    takes_options = [
        Option("-H", "--URL", help="LDB URL for database or target server", type=str,
               metavar="URL", dest="H"),
        ]

    takes_args = []

    def run(self, H=None, credopts=None, sambaopts=None, versionopts=None):
        lp = sambaopts.get_loadparm()
        creds = credopts.get_credentials(lp, fallback_machine=True)

        samdb = SamDB(url=H, session_info=system_session(),
            credentials=creds, lp=lp)

        domain_dn = samdb.domain_dn()
        self.infrastructure_dn = "CN=Infrastructure," + domain_dn
        self.naming_dn = "CN=Partitions,%s" % samdb.get_config_basedn()
        self.schema_dn = samdb.get_schema_basedn()
        self.rid_dn = "CN=RID Manager$,CN=System," + domain_dn

        res = samdb.search(self.infrastructure_dn,
                           scope=ldb.SCOPE_BASE, attrs=["fSMORoleOwner"])
        assert len(res) == 1
        self.infrastructureMaster = res[0]["fSMORoleOwner"][0]

        res = samdb.search(domain_dn,
                           scope=ldb.SCOPE_BASE, attrs=["fSMORoleOwner"])
        assert len(res) == 1
        self.pdcEmulator = res[0]["fSMORoleOwner"][0]

        res = samdb.search(self.naming_dn,
                           scope=ldb.SCOPE_BASE, attrs=["fSMORoleOwner"])
        assert len(res) == 1
        self.namingMaster = res[0]["fSMORoleOwner"][0]

        res = samdb.search(self.schema_dn,
                           scope=ldb.SCOPE_BASE, attrs=["fSMORoleOwner"])
        assert len(res) == 1
        self.schemaMaster = res[0]["fSMORoleOwner"][0]

        res = samdb.search(self.rid_dn,
                           scope=ldb.SCOPE_BASE, attrs=["fSMORoleOwner"])
        assert len(res) == 1
        self.ridMaster = res[0]["fSMORoleOwner"][0]

        self.message("InfrastructureMasterRole owner: " + self.infrastructureMaster)
        self.message("RidAllocationMasterRole owner: " + self.ridMaster)
        self.message("PdcEmulationMasterRole owner: " + self.pdcEmulator)
        self.message("DomainNamingMasterRole owner: " + self.namingMaster)
        self.message("SchemaMasterRole owner: " + self.schemaMaster)


class cmd_fsmo_transfer(Command):
    """Transfer the role."""

    synopsis = "%prog [options]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "credopts": options.CredentialsOptions,
        "versionopts": options.VersionOptions,
        }

    takes_options = [
        Option("-H", "--URL", help="LDB URL for database or target server", type=str,
               metavar="URL", dest="H"),
        Option("--role", type="choice", choices=["rid", "pdc", "infrastructure","schema","naming","all"],
               help="""The FSMO role to seize or transfer.\n
rid=RidAllocationMasterRole\n
schema=SchemaMasterRole\n
pdc=PdcEmulationMasterRole\n
naming=DomainNamingMasterRole\n
infrastructure=InfrastructureMasterRole\n
all=all of the above"""),
        ]

    takes_args = []

    def run(self, force=None, H=None, role=None,
            credopts=None, sambaopts=None, versionopts=None):

        lp = sambaopts.get_loadparm()
        creds = credopts.get_credentials(lp, fallback_machine=True)

        samdb = SamDB(url=H, session_info=system_session(),
                      credentials=creds, lp=lp)

        if role == "all":
            transfer_role(self.outf, "rid", samdb)
            transfer_role(self.outf, "pdc", samdb)
            transfer_role(self.outf, "naming", samdb)
            transfer_role(self.outf, "infrastructure", samdb)
            transfer_role(self.outf, "schema", samdb)
        else:
            transfer_role(self.outf, role, samdb)


class cmd_fsmo(SuperCommand):
    """Flexible Single Master Operations (FSMO) roles management."""

    subcommands = {}
    subcommands["seize"] = cmd_fsmo_seize()
    subcommands["show"] = cmd_fsmo_show()
    subcommands["transfer"] = cmd_fsmo_transfer()
