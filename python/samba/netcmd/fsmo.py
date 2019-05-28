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

import samba
import samba.getopt as options
import ldb
from ldb import LdbError
from samba.dcerpc import drsuapi, misc
from samba.auth import system_session
import samba.drs_utils
from samba.netcmd import (
    Command,
    CommandError,
    SuperCommand,
    Option,
)
from samba.samdb import SamDB


def get_fsmo_roleowner(samdb, roledn, role):
    """Gets the owner of an FSMO role

    :param roledn: The DN of the FSMO role
    :param role: The FSMO role
    """
    try:
        res = samdb.search(roledn,
                           scope=ldb.SCOPE_BASE, attrs=["fSMORoleOwner"])
    except LdbError as e7:
        (num, msg) = e7.args
        if num == ldb.ERR_NO_SUCH_OBJECT:
            raise CommandError("The '%s' role is not present in this domain" % role)
        raise

    if 'fSMORoleOwner' in res[0]:
        master_owner = (ldb.Dn(samdb, res[0]["fSMORoleOwner"][0].decode('utf8')))
    else:
        master_owner = None

    return master_owner


def transfer_dns_role(outf, sambaopts, credopts, role, samdb):
    """Transfer dns FSMO role. """

    if role == "domaindns":
        domain_dn = samdb.domain_dn()
        role_object = "CN=Infrastructure,DC=DomainDnsZones," + domain_dn
    elif role == "forestdns":
        forest_dn = samba.dn_from_dns_name(samdb.forest_dns_name())
        role_object = "CN=Infrastructure,DC=ForestDnsZones," + forest_dn

    new_host_dns_name = samdb.host_dns_name()

    res = samdb.search(role_object,
                       attrs=["fSMORoleOwner"],
                       scope=ldb.SCOPE_BASE,
                       controls=["extended_dn:1:1"])

    if 'fSMORoleOwner' in res[0]:
        try:
            master_guid = str(misc.GUID(ldb.Dn(samdb,
                                               res[0]['fSMORoleOwner'][0].decode('utf8'))
                                        .get_extended_component('GUID')))
            master_owner = str(ldb.Dn(samdb, res[0]['fSMORoleOwner'][0].decode('utf8')))
        except LdbError as e3:
            (num, msg) = e3.args
            raise CommandError("No GUID found in naming master DN %s : %s \n" %
                               (res[0]['fSMORoleOwner'][0], msg))
    else:
        outf.write("* The '%s' role does not have an FSMO roleowner\n" % role)
        return False

    if role == "domaindns":
        master_dns_name = '%s._msdcs.%s' % (master_guid,
                                            samdb.domain_dns_name())
        new_dns_name = '%s._msdcs.%s' % (samdb.get_ntds_GUID(),
                                         samdb.domain_dns_name())
    elif role == "forestdns":
        master_dns_name = '%s._msdcs.%s' % (master_guid,
                                            samdb.forest_dns_name())
        new_dns_name = '%s._msdcs.%s' % (samdb.get_ntds_GUID(),
                                         samdb.forest_dns_name())

    new_owner = samdb.get_dsServiceName()

    if master_dns_name != new_dns_name:
        lp = sambaopts.get_loadparm()
        creds = credopts.get_credentials(lp, fallback_machine=True)
        samdb = SamDB(url="ldap://%s" % (master_dns_name),
                      session_info=system_session(),
                      credentials=creds, lp=lp)

        m = ldb.Message()
        m.dn = ldb.Dn(samdb, role_object)
        m["fSMORoleOwner_Del"] = ldb.MessageElement(master_owner,
                                                    ldb.FLAG_MOD_DELETE,
                                                    "fSMORoleOwner")
        m["fSMORoleOwner_Add"] = ldb.MessageElement(new_owner,
                                                    ldb.FLAG_MOD_ADD,
                                                    "fSMORoleOwner")
        try:
            samdb.modify(m)
        except LdbError as e5:
            (num, msg) = e5.args
            raise CommandError("Failed to add role '%s': %s" % (role, msg))

        try:
            connection = samba.drs_utils.drsuapi_connect(new_host_dns_name,
                                                         lp, creds)
        except samba.drs_utils.drsException as e:
            raise CommandError("Drsuapi Connect failed", e)

        try:
            drsuapi_connection = connection[0]
            drsuapi_handle = connection[1]
            req_options = drsuapi.DRSUAPI_DRS_WRIT_REP
            NC = role_object[18:]
            samba.drs_utils.sendDsReplicaSync(drsuapi_connection,
                                              drsuapi_handle,
                                              master_guid,
                                              NC, req_options)
        except samba.drs_utils.drsException as estr:
            raise CommandError("Replication failed", estr)

        outf.write("FSMO transfer of '%s' role successful\n" % role)
        return True
    else:
        outf.write("This DC already has the '%s' FSMO role\n" % role)
        return False


def transfer_role(outf, role, samdb):
    """Transfer standard FSMO role. """

    domain_dn = samdb.domain_dn()
    rid_dn = "CN=RID Manager$,CN=System," + domain_dn
    naming_dn = "CN=Partitions,%s" % samdb.get_config_basedn()
    infrastructure_dn = "CN=Infrastructure," + domain_dn
    schema_dn = str(samdb.get_schema_basedn())
    new_owner = ldb.Dn(samdb, samdb.get_dsServiceName())
    m = ldb.Message()
    m.dn = ldb.Dn(samdb, "")
    if role == "rid":
        master_owner = get_fsmo_roleowner(samdb, rid_dn, role)
        m["becomeRidMaster"] = ldb.MessageElement(
            "1", ldb.FLAG_MOD_REPLACE,
            "becomeRidMaster")
    elif role == "pdc":
        master_owner = get_fsmo_roleowner(samdb, domain_dn, role)

        res = samdb.search(domain_dn,
                           scope=ldb.SCOPE_BASE, attrs=["objectSid"])
        assert len(res) == 1
        sid = res[0]["objectSid"][0]
        m["becomePdc"] = ldb.MessageElement(
            sid, ldb.FLAG_MOD_REPLACE,
            "becomePdc")
    elif role == "naming":
        master_owner = get_fsmo_roleowner(samdb, naming_dn, role)
        m["becomeDomainMaster"] = ldb.MessageElement(
            "1", ldb.FLAG_MOD_REPLACE,
            "becomeDomainMaster")
    elif role == "infrastructure":
        master_owner = get_fsmo_roleowner(samdb, infrastructure_dn, role)
        m["becomeInfrastructureMaster"] = ldb.MessageElement(
            "1", ldb.FLAG_MOD_REPLACE,
            "becomeInfrastructureMaster")
    elif role == "schema":
        master_owner = get_fsmo_roleowner(samdb, schema_dn, role)
        m["becomeSchemaMaster"] = ldb.MessageElement(
            "1", ldb.FLAG_MOD_REPLACE,
            "becomeSchemaMaster")
    else:
        raise CommandError("Invalid FSMO role.")

    if master_owner is None:
        outf.write("Cannot transfer, no DC assigned to the %s role.  Try 'seize' instead\n" % role)
        return False

    if master_owner != new_owner:
        try:
            samdb.modify(m)
        except LdbError as e6:
            (num, msg) = e6.args
            raise CommandError("Transfer of '%s' role failed: %s" %
                               (role, msg))

        outf.write("FSMO transfer of '%s' role successful\n" % role)
        return True
    else:
        outf.write("This DC already has the '%s' FSMO role\n" % role)
        return False


class cmd_fsmo_seize(Command):
    """Seize the role."""

    synopsis = "%prog [options]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "credopts": options.CredentialsOptions,
        "versionopts": options.VersionOptions,
    }

    takes_options = [
        Option("-H", "--URL", help="LDB URL for database or target server",
               type=str, metavar="URL", dest="H"),
        Option("--force",
               help="Force seizing of role without attempting to transfer.",
               action="store_true"),
        Option("--role", type="choice", choices=["rid", "pdc", "infrastructure",
                                                 "schema", "naming", "domaindns", "forestdns", "all"],
               help="""The FSMO role to seize or transfer.\n
rid=RidAllocationMasterRole\n
schema=SchemaMasterRole\n
pdc=PdcEmulationMasterRole\n
naming=DomainNamingMasterRole\n
infrastructure=InfrastructureMasterRole\n
domaindns=DomainDnsZonesMasterRole\n
forestdns=ForestDnsZonesMasterRole\n
all=all of the above\n
You must provide an Admin user and password."""),
    ]

    takes_args = []

    def seize_role(self, role, samdb, force):
        """Seize standard fsmo role. """

        serviceName = samdb.get_dsServiceName()
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
        # first try to transfer to avoid problem if the owner is still active
        seize = False
        master_owner = get_fsmo_roleowner(samdb, m.dn, role)
        # if there is a different owner
        if master_owner is not None:
            # if there is a different owner
            if master_owner != serviceName:
                # if --force isn't given, attempt transfer
                if force is None:
                    self.message("Attempting transfer...")
                    try:
                        transfer_role(self.outf, role, samdb)
                    except:
                        # transfer failed, use the big axe...
                        seize = True
                        self.message("Transfer unsuccessful, seizing...")
                    else:
                        self.message("Transfer successful, not seizing role")
                        return True
            else:
                self.outf.write("This DC already has the '%s' FSMO role\n" %
                                role)
                return False
        else:
            seize = True

        if force is not None or seize:
            self.message("Seizing %s FSMO role..." % role)
            m["fSMORoleOwner"] = ldb.MessageElement(
                serviceName, ldb.FLAG_MOD_REPLACE,
                "fSMORoleOwner")

            samdb.transaction_start()
            try:
                samdb.modify(m)
                if role == "rid":
                    # We may need to allocate the initial RID Set
                    samdb.create_own_rid_set()

            except LdbError as e1:
                (num, msg) = e1.args
                if role == "rid" and num == ldb.ERR_ENTRY_ALREADY_EXISTS:

                    # Try again without the RID Set allocation
                    # (normal).  We have to manage the transaction as
                    # we do not have nested transactions and creating
                    # a RID set touches multiple objects. :-(
                    samdb.transaction_cancel()
                    samdb.transaction_start()
                    try:
                        samdb.modify(m)
                    except LdbError as e:
                        (num, msg) = e.args
                        samdb.transaction_cancel()
                        raise CommandError("Failed to seize '%s' role: %s" %
                                           (role, msg))

                else:
                    samdb.transaction_cancel()
                    raise CommandError("Failed to seize '%s' role: %s" %
                                       (role, msg))
            samdb.transaction_commit()
            self.outf.write("FSMO seize of '%s' role successful\n" % role)

            return True

    def seize_dns_role(self, role, samdb, credopts, sambaopts,
                       versionopts, force):
        """Seize DNS FSMO role. """

        serviceName = samdb.get_dsServiceName()
        domain_dn = samdb.domain_dn()
        forest_dn = samba.dn_from_dns_name(samdb.forest_dns_name())
        self.domaindns_dn = "CN=Infrastructure,DC=DomainDnsZones," + domain_dn
        self.forestdns_dn = "CN=Infrastructure,DC=ForestDnsZones," + forest_dn

        m = ldb.Message()
        if role == "domaindns":
            m.dn = ldb.Dn(samdb, self.domaindns_dn)
        elif role == "forestdns":
            m.dn = ldb.Dn(samdb, self.forestdns_dn)
        else:
            raise CommandError("Invalid FSMO role.")
        # first try to transfer to avoid problem if the owner is still active
        seize = False
        master_owner = get_fsmo_roleowner(samdb, m.dn, role)
        if master_owner is not None:
            # if there is a different owner
            if master_owner != serviceName:
                # if --force isn't given, attempt transfer
                if force is None:
                    self.message("Attempting transfer...")
                    try:
                        transfer_dns_role(self.outf, sambaopts, credopts, role,
                                          samdb)
                    except:
                        # transfer failed, use the big axe...
                        seize = True
                        self.message("Transfer unsuccessful, seizing...")
                    else:
                        self.message("Transfer successful, not seizing role\n")
                        return True
            else:
                self.outf.write("This DC already has the '%s' FSMO role\n" %
                                role)
                return False
        else:
            seize = True

        if force is not None or seize:
            self.message("Seizing %s FSMO role..." % role)
            m["fSMORoleOwner"] = ldb.MessageElement(
                serviceName, ldb.FLAG_MOD_REPLACE,
                "fSMORoleOwner")
            try:
                samdb.modify(m)
            except LdbError as e2:
                (num, msg) = e2.args
                raise CommandError("Failed to seize '%s' role: %s" %
                                   (role, msg))
            self.outf.write("FSMO seize of '%s' role successful\n" % role)
            return True

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
            self.seize_dns_role("domaindns", samdb, credopts, sambaopts,
                                versionopts, force)
            self.seize_dns_role("forestdns", samdb, credopts, sambaopts,
                                versionopts, force)
        else:
            if role == "domaindns" or role == "forestdns":
                self.seize_dns_role(role, samdb, credopts, sambaopts,
                                    versionopts, force)
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
        Option("-H", "--URL", help="LDB URL for database or target server",
               type=str, metavar="URL", dest="H"),
    ]

    takes_args = []

    def run(self, H=None, credopts=None, sambaopts=None, versionopts=None):
        lp = sambaopts.get_loadparm()
        creds = credopts.get_credentials(lp, fallback_machine=True)

        samdb = SamDB(url=H, session_info=system_session(),
                      credentials=creds, lp=lp)

        domain_dn = samdb.domain_dn()
        forest_dn = samba.dn_from_dns_name(samdb.forest_dns_name())
        infrastructure_dn = "CN=Infrastructure," + domain_dn
        naming_dn = "CN=Partitions,%s" % samdb.get_config_basedn()
        schema_dn = samdb.get_schema_basedn()
        rid_dn = "CN=RID Manager$,CN=System," + domain_dn
        domaindns_dn = "CN=Infrastructure,DC=DomainDnsZones," + domain_dn
        forestdns_dn = "CN=Infrastructure,DC=ForestDnsZones," + forest_dn

        masters = [(schema_dn, "schema", "SchemaMasterRole"),
                   (infrastructure_dn, "infrastructure", "InfrastructureMasterRole"),
                   (rid_dn, "rid", "RidAllocationMasterRole"),
                   (domain_dn, "pdc", "PdcEmulationMasterRole"),
                   (naming_dn, "naming", "DomainNamingMasterRole"),
                   (domaindns_dn, "domaindns", "DomainDnsZonesMasterRole"),
                   (forestdns_dn, "forestdns", "ForestDnsZonesMasterRole"),
                   ]

        for master in masters:
            (dn, short_name, long_name) = master
            try:
                master = get_fsmo_roleowner(samdb, dn, short_name)
                if master is not None:
                    self.message("%s owner: %s" % (long_name, str(master)))
                else:
                    self.message("%s has no current owner" % (long_name))
            except CommandError as e:
                self.message("%s: * %s" % (long_name, e.message))


class cmd_fsmo_transfer(Command):
    """Transfer the role."""

    synopsis = "%prog [options]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "credopts": options.CredentialsOptions,
        "versionopts": options.VersionOptions,
    }

    takes_options = [
        Option("-H", "--URL", help="LDB URL for database or target server",
               type=str, metavar="URL", dest="H"),
        Option("--role", type="choice", choices=["rid", "pdc", "infrastructure",
                                                 "schema", "naming", "domaindns", "forestdns", "all"],
               help="""The FSMO role to seize or transfer.\n
rid=RidAllocationMasterRole\n
schema=SchemaMasterRole\n
pdc=PdcEmulationMasterRole\n
naming=DomainNamingMasterRole\n
infrastructure=InfrastructureMasterRole\n
domaindns=DomainDnsZonesMasterRole\n
forestdns=ForestDnsZonesMasterRole\n
all=all of the above\n
You must provide an Admin user and password."""),
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
            transfer_dns_role(self.outf, sambaopts, credopts,
                              "domaindns", samdb)
            transfer_dns_role(self.outf, sambaopts, credopts, "forestdns",
                              samdb)
        else:
            if role == "domaindns" or role == "forestdns":
                transfer_dns_role(self.outf, sambaopts, credopts, role, samdb)
            else:
                transfer_role(self.outf, role, samdb)


class cmd_fsmo(SuperCommand):
    """Flexible Single Master Operations (FSMO) roles management."""

    subcommands = {}
    subcommands["seize"] = cmd_fsmo_seize()
    subcommands["show"] = cmd_fsmo_show()
    subcommands["transfer"] = cmd_fsmo_transfer()
