# domain management - domain demote
#
# Copyright Matthias Dieter Wallnoefer 2009
# Copyright Andrew Kroeger 2009
# Copyright Jelmer Vernooij 2007-2012
# Copyright Giampaolo Lauria 2011
# Copyright Matthieu Patou <mat@matws.net> 2011
# Copyright Andrew Bartlett 2008-2015
# Copyright Stefan Metzmacher 2012
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

import ldb
import samba.getopt as options
from samba import dsdb, remove_dc, werror
from samba.auth import system_session
from samba.dcerpc import drsuapi, misc
from samba.drs_utils import drsuapi_connect
from samba.dsdb import (
    DS_NTDSDSA_OPT_DISABLE_INBOUND_REPL,
    DS_NTDSDSA_OPT_DISABLE_OUTBOUND_REPL,
    UF_PARTIAL_SECRETS_ACCOUNT,
    UF_SERVER_TRUST_ACCOUNT,
    UF_TRUSTED_FOR_DELEGATION,
    UF_WORKSTATION_TRUST_ACCOUNT
)
from samba.net import Net
from samba.netcmd import Command, CommandError, Option
from samba.samdb import SamDB


class cmd_domain_demote(Command):
    """Demote ourselves from the role of Domain Controller."""

    synopsis = "%prog [options]"

    takes_options = [
        Option("--server", help="writable DC to write demotion changes on", type=str),
        Option("-H", "--URL", help="LDB URL for database or target server", type=str,
               metavar="URL", dest="H"),
        Option("--remove-other-dead-server", help="Dead DC (name or NTDS GUID) "
               "to remove ALL references to (rather than this DC)", type=str),
        Option("-q", "--quiet", help="Be quiet", action="store_true"),
        Option("-v", "--verbose", help="Be verbose", action="store_true"),
    ]

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "credopts": options.CredentialsOptions,
        "versionopts": options.VersionOptions,
    }

    def run(self, sambaopts=None, credopts=None,
            versionopts=None, server=None,
            remove_other_dead_server=None, H=None,
            verbose=False, quiet=False):
        lp = sambaopts.get_loadparm()
        creds = credopts.get_credentials(lp)

        logger = self.get_logger(verbose=verbose, quiet=quiet)

        if remove_other_dead_server is not None:
            if server is not None:
                samdb = SamDB(url="ldap://%s" % server,
                              session_info=system_session(),
                              credentials=creds, lp=lp)
            else:
                samdb = SamDB(url=H, session_info=system_session(), credentials=creds, lp=lp)
            try:
                remove_dc.remove_dc(samdb, logger, remove_other_dead_server)
            except remove_dc.DemoteException as err:
                raise CommandError("Demote failed: %s" % err)
            return

        netbios_name = lp.get("netbios name")
        samdb = SamDB(url=H, session_info=system_session(), credentials=creds, lp=lp)
        if not server:
            res = samdb.search(expression='(&(objectClass=computer)(serverReferenceBL=*))', attrs=["dnsHostName", "name"])
            if (len(res) == 0):
                raise CommandError("Unable to search for servers")

            if (len(res) == 1):
                raise CommandError("You are the last server in the domain")

            server = None
            for e in res:
                if str(e["name"]).lower() != netbios_name.lower():
                    server = e["dnsHostName"]
                    break

        ntds_guid = samdb.get_ntds_GUID()
        msg = samdb.search(base=str(samdb.get_config_basedn()),
                           scope=ldb.SCOPE_SUBTREE, expression="(objectGUID=%s)" % ntds_guid,
                           attrs=['options'])
        if len(msg) == 0 or "options" not in msg[0]:
            raise CommandError("Failed to find options on %s" % ntds_guid)

        ntds_dn = msg[0].dn
        dsa_options = int(str(msg[0]['options']))

        res = samdb.search(expression="(fSMORoleOwner=%s)" % str(ntds_dn),
                           controls=["search_options:1:2"])

        if len(res) != 0:
            raise CommandError("Current DC is still the owner of %d role(s), "
                               "use the role command to transfer roles to "
                               "another DC" %
                               len(res))

        self.errf.write("Using %s as partner server for the demotion\n" %
                        server)
        (drsuapiBind, drsuapi_handle, supportedExtensions) = drsuapi_connect(server, lp, creds)

        self.errf.write("Deactivating inbound replication\n")

        nmsg = ldb.Message()
        nmsg.dn = msg[0].dn

        if not (dsa_options & DS_NTDSDSA_OPT_DISABLE_OUTBOUND_REPL) and not samdb.am_rodc():
            dsa_options |= DS_NTDSDSA_OPT_DISABLE_INBOUND_REPL
            nmsg["options"] = ldb.MessageElement(str(dsa_options), ldb.FLAG_MOD_REPLACE, "options")
            samdb.modify(nmsg)

            self.errf.write("Asking partner server %s to synchronize from us\n"
                            % server)
            for part in (samdb.get_schema_basedn(),
                         samdb.get_config_basedn(),
                         samdb.get_root_basedn()):
                nc = drsuapi.DsReplicaObjectIdentifier()
                nc.dn = str(part)

                req1 = drsuapi.DsReplicaSyncRequest1()
                req1.naming_context = nc
                req1.options = drsuapi.DRSUAPI_DRS_WRIT_REP
                req1.source_dsa_guid = misc.GUID(ntds_guid)

                try:
                    drsuapiBind.DsReplicaSync(drsuapi_handle, 1, req1)
                except RuntimeError as e1:
                    (werr, string) = e1.args
                    if werr == werror.WERR_DS_DRA_NO_REPLICA:
                        pass
                    else:
                        self.errf.write(
                            "Error while replicating out last local changes from '%s' for demotion, "
                            "re-enabling inbound replication\n" % part)
                        dsa_options ^= DS_NTDSDSA_OPT_DISABLE_INBOUND_REPL
                        nmsg["options"] = ldb.MessageElement(str(dsa_options), ldb.FLAG_MOD_REPLACE, "options")
                        samdb.modify(nmsg)
                        raise CommandError("Error while sending a DsReplicaSync for partition '%s'" % str(part), string)
        try:
            remote_samdb = SamDB(url="ldap://%s" % server,
                                 session_info=system_session(),
                                 credentials=creds, lp=lp)

            self.errf.write("Changing userControl and container\n")
            res = remote_samdb.search(base=str(remote_samdb.domain_dn()),
                                      expression="(&(objectClass=user)(sAMAccountName=%s$))" %
                                      netbios_name.upper(),
                                      attrs=["userAccountControl"])
            dc_dn = res[0].dn
            uac = int(str(res[0]["userAccountControl"]))

        except Exception as e:
            if not (dsa_options & DS_NTDSDSA_OPT_DISABLE_OUTBOUND_REPL) and not samdb.am_rodc():
                self.errf.write(
                    "Error while demoting, re-enabling inbound replication\n")
                dsa_options ^= DS_NTDSDSA_OPT_DISABLE_INBOUND_REPL
                nmsg["options"] = ldb.MessageElement(str(dsa_options), ldb.FLAG_MOD_REPLACE, "options")
                samdb.modify(nmsg)
            raise CommandError("Error while changing account control", e)

        if (len(res) != 1):
            if not (dsa_options & DS_NTDSDSA_OPT_DISABLE_OUTBOUND_REPL) and not samdb.am_rodc():
                self.errf.write(
                    "Error while demoting, re-enabling inbound replication")
                dsa_options ^= DS_NTDSDSA_OPT_DISABLE_INBOUND_REPL
                nmsg["options"] = ldb.MessageElement(str(dsa_options), ldb.FLAG_MOD_REPLACE, "options")
                samdb.modify(nmsg)
            raise CommandError("Unable to find object with samaccountName = %s$"
                               " in the remote dc" % netbios_name.upper())

        uac &= ~(UF_SERVER_TRUST_ACCOUNT |
                 UF_TRUSTED_FOR_DELEGATION |
                 UF_PARTIAL_SECRETS_ACCOUNT)
        uac |= UF_WORKSTATION_TRUST_ACCOUNT

        msg = ldb.Message()
        msg.dn = dc_dn

        msg["userAccountControl"] = ldb.MessageElement("%d" % uac,
                                                       ldb.FLAG_MOD_REPLACE,
                                                       "userAccountControl")
        try:
            remote_samdb.modify(msg)
        except Exception as e:
            if not (dsa_options & DS_NTDSDSA_OPT_DISABLE_OUTBOUND_REPL) and not samdb.am_rodc():
                self.errf.write(
                    "Error while demoting, re-enabling inbound replication")
                dsa_options ^= DS_NTDSDSA_OPT_DISABLE_INBOUND_REPL
                nmsg["options"] = ldb.MessageElement(str(dsa_options), ldb.FLAG_MOD_REPLACE, "options")
                samdb.modify(nmsg)

            raise CommandError("Error while changing account control", e)

        dc_name = res[0].dn.get_rdn_value()
        rdn = "CN=%s" % dc_name

        # Let's move to the Computer container
        i = 0
        newrdn = str(rdn)

        computer_dn = remote_samdb.get_wellknown_dn(
            remote_samdb.get_default_basedn(),
            dsdb.DS_GUID_COMPUTERS_CONTAINER)
        res = remote_samdb.search(base=computer_dn, expression=rdn, scope=ldb.SCOPE_ONELEVEL)

        if (len(res) != 0):
            res = remote_samdb.search(base=computer_dn, expression="%s-%d" % (rdn, i),
                                      scope=ldb.SCOPE_ONELEVEL)
            while(len(res) != 0 and i < 100):
                i = i + 1
                res = remote_samdb.search(base=computer_dn, expression="%s-%d" % (rdn, i),
                                          scope=ldb.SCOPE_ONELEVEL)

            if i == 100:
                if not (dsa_options & DS_NTDSDSA_OPT_DISABLE_OUTBOUND_REPL) and not samdb.am_rodc():
                    self.errf.write(
                        "Error while demoting, re-enabling inbound replication\n")
                    dsa_options ^= DS_NTDSDSA_OPT_DISABLE_INBOUND_REPL
                    nmsg["options"] = ldb.MessageElement(str(dsa_options), ldb.FLAG_MOD_REPLACE, "options")
                    samdb.modify(nmsg)

                msg = ldb.Message()
                msg.dn = dc_dn

                msg["userAccountControl"] = ldb.MessageElement("%d" % uac,
                                                               ldb.FLAG_MOD_REPLACE,
                                                               "userAccountControl")

                remote_samdb.modify(msg)

                raise CommandError("Unable to find a slot for renaming %s,"
                                   " all names from %s-1 to %s-%d seemed used" %
                                   (str(dc_dn), rdn, rdn, i - 9))

            newrdn = "%s-%d" % (rdn, i)

        try:
            newdn = ldb.Dn(remote_samdb, "%s,%s" % (newrdn, str(computer_dn)))
            remote_samdb.rename(dc_dn, newdn)
        except Exception as e:
            if not (dsa_options & DS_NTDSDSA_OPT_DISABLE_OUTBOUND_REPL) and not samdb.am_rodc():
                self.errf.write(
                    "Error while demoting, re-enabling inbound replication\n")
                dsa_options ^= DS_NTDSDSA_OPT_DISABLE_INBOUND_REPL
                nmsg["options"] = ldb.MessageElement(str(dsa_options), ldb.FLAG_MOD_REPLACE, "options")
                samdb.modify(nmsg)

            msg = ldb.Message()
            msg.dn = dc_dn

            msg["userAccountControl"] = ldb.MessageElement("%d" % uac,
                                                           ldb.FLAG_MOD_REPLACE,
                                                           "userAccountControl")

            remote_samdb.modify(msg)
            raise CommandError("Error while renaming %s to %s" % (str(dc_dn), str(newdn)), e)

        server_dsa_dn = samdb.get_serverName()
        domain = remote_samdb.get_root_basedn()

        try:
            req1 = drsuapi.DsRemoveDSServerRequest1()
            req1.server_dn = str(server_dsa_dn)
            req1.domain_dn = str(domain)
            req1.commit = 1

            drsuapiBind.DsRemoveDSServer(drsuapi_handle, 1, req1)
        except RuntimeError as e3:
            (werr, string) = e3.args
            if not (dsa_options & DS_NTDSDSA_OPT_DISABLE_OUTBOUND_REPL) and not samdb.am_rodc():
                self.errf.write(
                    "Error while demoting, re-enabling inbound replication\n")
                dsa_options ^= DS_NTDSDSA_OPT_DISABLE_INBOUND_REPL
                nmsg["options"] = ldb.MessageElement(str(dsa_options), ldb.FLAG_MOD_REPLACE, "options")
                samdb.modify(nmsg)

            msg = ldb.Message()
            msg.dn = newdn

            msg["userAccountControl"] = ldb.MessageElement("%d" % uac,
                                                           ldb.FLAG_MOD_REPLACE,
                                                           "userAccountControl")
            remote_samdb.modify(msg)
            remote_samdb.rename(newdn, dc_dn)
            if werr == werror.WERR_DS_DRA_NO_REPLICA:
                raise CommandError("The DC %s is not present on (already "
                                   "removed from) the remote server: %s" %
                                   (server_dsa_dn, e3))
            else:
                raise CommandError("Error while sending a removeDsServer "
                                   "of %s: %s" %
                                   (server_dsa_dn, e3))

        remove_dc.remove_sysvol_references(remote_samdb, logger, dc_name)

        # These are objects under the computer account that should be deleted
        for s in ("CN=Enterprise,CN=NTFRS Subscriptions",
                  "CN=%s, CN=NTFRS Subscriptions" % lp.get("realm"),
                  "CN=Domain system Volumes (SYSVOL Share), CN=NTFRS Subscriptions",
                  "CN=NTFRS Subscriptions"):
            try:
                remote_samdb.delete(ldb.Dn(remote_samdb,
                                           "%s,%s" % (s, str(newdn))))
            except ldb.LdbError:
                pass

        # get dns host name for target server to demote, remove dns references
        remove_dc.remove_dns_references(remote_samdb, logger, samdb.host_dns_name(),
                                        ignore_no_name=True)

        self.errf.write("Demote successful\n")
