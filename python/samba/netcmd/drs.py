# implement samba_tool drs commands
#
# Copyright Andrew Tridgell 2010
# Copyright Andrew Bartlett 2017
#
# based on C implementation by Kamen Mazdrashki <kamen.mazdrashki@postpath.com>
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
from __future__ import print_function

import samba.getopt as options
import ldb
import logging
from . import common
import json

from samba.auth import system_session
from samba.netcmd import (
    Command,
    CommandError,
    Option,
    SuperCommand,
)
from samba.samdb import SamDB
from samba import drs_utils, nttime2string, dsdb
from samba.dcerpc import drsuapi, misc
from samba.join import join_clone
from samba import colour

from samba.uptodateness import (
    get_partition_maps,
    get_utdv_edges,
    get_utdv_distances,
    get_utdv_summary,
    get_kcc_and_dsas,
)
from samba.compat import get_string
from samba.samdb import get_default_backend_store

def drsuapi_connect(ctx):
    '''make a DRSUAPI connection to the server'''
    try:
        (ctx.drsuapi, ctx.drsuapi_handle, ctx.bind_supported_extensions) = drs_utils.drsuapi_connect(ctx.server, ctx.lp, ctx.creds)
    except Exception as e:
        raise CommandError("DRS connection to %s failed" % ctx.server, e)


def samdb_connect(ctx):
    '''make a ldap connection to the server'''
    try:
        ctx.samdb = SamDB(url="ldap://%s" % ctx.server,
                          session_info=system_session(),
                          credentials=ctx.creds, lp=ctx.lp)
    except Exception as e:
        raise CommandError("LDAP connection to %s failed" % ctx.server, e)


def drs_errmsg(werr):
    '''return "was successful" or an error string'''
    (ecode, estring) = werr
    if ecode == 0:
        return "was successful"
    return "failed, result %u (%s)" % (ecode, estring)


def attr_default(msg, attrname, default):
    '''get an attribute from a ldap msg with a default'''
    if attrname in msg:
        return msg[attrname][0]
    return default


def drs_parse_ntds_dn(ntds_dn):
    '''parse a NTDS DN returning a site and server'''
    a = ntds_dn.split(',')
    if a[0] != "CN=NTDS Settings" or a[2] != "CN=Servers" or a[4] != 'CN=Sites':
        raise RuntimeError("bad NTDS DN %s" % ntds_dn)
    server = a[1].split('=')[1]
    site   = a[3].split('=')[1]
    return (site, server)


DEFAULT_SHOWREPL_FORMAT = 'classic'


class cmd_drs_showrepl(Command):
    """Show replication status."""

    synopsis = "%prog [<DC>] [options]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "versionopts": options.VersionOptions,
        "credopts": options.CredentialsOptions,
    }

    takes_options = [
        Option("--json", help="replication details in JSON format",
               dest='format', action='store_const', const='json'),
        Option("--summary", help=("summarize overall DRS health as seen "
                                  "from this server"),
               dest='format', action='store_const', const='summary'),
        Option("--pull-summary", help=("Have we successfully replicated "
                                       "from all relevent servers?"),
               dest='format', action='store_const', const='pull_summary'),
        Option("--notify-summary", action='store_const',
               const='notify_summary', dest='format',
               help=("Have we successfully notified all relevent servers of "
                     "local changes, and did they say they successfully "
                     "replicated?")),
        Option("--classic", help="print local replication details",
               dest='format', action='store_const', const='classic',
               default=DEFAULT_SHOWREPL_FORMAT),
        Option("-v", "--verbose", help="Be verbose", action="store_true"),
        Option("--color", help="Use colour output (yes|no|auto)",
               default='no'),
    ]

    takes_args = ["DC?"]

    def parse_neighbour(self, n):
        """Convert an ldb neighbour object into a python dictionary"""
        dsa_objectguid = str(n.source_dsa_obj_guid)
        d = {
            'NC dn': n.naming_context_dn,
            "DSA objectGUID": dsa_objectguid,
            "last attempt time": nttime2string(n.last_attempt),
            "last attempt message": drs_errmsg(n.result_last_attempt),
            "consecutive failures": n.consecutive_sync_failures,
            "last success": nttime2string(n.last_success),
            "NTDS DN": str(n.source_dsa_obj_dn),
            'is deleted': False
        }

        try:
            self.samdb.search(base="<GUID=%s>" % dsa_objectguid,
                              scope=ldb.SCOPE_BASE,
                              attrs=[])
        except ldb.LdbError as e:
            (errno, _) = e.args
            if errno == ldb.ERR_NO_SUCH_OBJECT:
                d['is deleted'] = True
            else:
                raise
        try:
            (site, server) = drs_parse_ntds_dn(n.source_dsa_obj_dn)
            d["DSA"] = "%s\\%s" % (site, server)
        except RuntimeError:
            pass
        return d

    def print_neighbour(self, d):
        '''print one set of neighbour information'''
        self.message("%s" % d['NC dn'])
        if 'DSA' in d:
            self.message("\t%s via RPC" % d['DSA'])
        else:
            self.message("\tNTDS DN: %s" % d['NTDS DN'])
        self.message("\t\tDSA object GUID: %s" % d['DSA objectGUID'])
        self.message("\t\tLast attempt @ %s %s" % (d['last attempt time'],
                                                   d['last attempt message']))
        self.message("\t\t%u consecutive failure(s)." %
                     d['consecutive failures'])
        self.message("\t\tLast success @ %s" % d['last success'])
        self.message("")

    def get_neighbours(self, info_type):
        req1 = drsuapi.DsReplicaGetInfoRequest1()
        req1.info_type = info_type
        try:
            (info_type, info) = self.drsuapi.DsReplicaGetInfo(
                self.drsuapi_handle, 1, req1)
        except Exception as e:
            raise CommandError("DsReplicaGetInfo of type %u failed" % info_type, e)

        reps = [self.parse_neighbour(n) for n in info.array]
        return reps

    def run(self, DC=None, sambaopts=None,
            credopts=None, versionopts=None,
            format=DEFAULT_SHOWREPL_FORMAT,
            verbose=False, color='no'):
        self.apply_colour_choice(color)
        self.lp = sambaopts.get_loadparm()
        if DC is None:
            DC = common.netcmd_dnsname(self.lp)
        self.server = DC
        self.creds = credopts.get_credentials(self.lp, fallback_machine=True)
        self.verbose = verbose

        output_function = {
            'summary': self.summary_output,
            'notify_summary': self.notify_summary_output,
            'pull_summary': self.pull_summary_output,
            'json': self.json_output,
            'classic': self.classic_output,
        }.get(format)
        if output_function is None:
            raise CommandError("unknown showrepl format %s" % format)

        return output_function()

    def json_output(self):
        data = self.get_local_repl_data()
        del data['site']
        del data['server']
        json.dump(data, self.outf, indent=2)

    def summary_output_handler(self, typeof_output):
        """Print a short message if every seems fine, but print details of any
        links that seem broken."""
        failing_repsto = []
        failing_repsfrom = []

        local_data = self.get_local_repl_data()

        if typeof_output != "pull_summary":
            for rep in local_data['repsTo']:
                if rep['is deleted']:
                    continue
                if rep["consecutive failures"] != 0 or rep["last success"] == 0:
                    failing_repsto.append(rep)

        if typeof_output != "notify_summary":
            for rep in local_data['repsFrom']:
                if rep['is deleted']:
                    continue
                if rep["consecutive failures"] != 0 or rep["last success"] == 0:
                    failing_repsfrom.append(rep)

        if failing_repsto or failing_repsfrom:
            self.message(colour.c_RED("There are failing connections"))
            if failing_repsto:
                self.message(colour.c_RED("Failing outbound connections:"))
                for rep in failing_repsto:
                    self.print_neighbour(rep)
            if failing_repsfrom:
                self.message(colour.c_RED("Failing inbound connection:"))
                for rep in failing_repsfrom:
                    self.print_neighbour(rep)

            return 1

        self.message(colour.c_GREEN("[ALL GOOD]"))

    def summary_output(self):
        return self.summary_output_handler("summary")

    def notify_summary_output(self):
        return self.summary_output_handler("notify_summary")

    def pull_summary_output(self):
        return self.summary_output_handler("pull_summary")

    def get_local_repl_data(self):
        drsuapi_connect(self)
        samdb_connect(self)

        # show domain information
        ntds_dn = self.samdb.get_dsServiceName()

        (site, server) = drs_parse_ntds_dn(ntds_dn)
        try:
            ntds = self.samdb.search(base=ntds_dn, scope=ldb.SCOPE_BASE, attrs=['options', 'objectGUID', 'invocationId'])
        except Exception as e:
            raise CommandError("Failed to search NTDS DN %s" % ntds_dn)

        dsa_details = {
            "options": int(attr_default(ntds[0], "options", 0)),
            "objectGUID": get_string(self.samdb.schema_format_value(
                "objectGUID", ntds[0]["objectGUID"][0])),
            "invocationId": get_string(self.samdb.schema_format_value(
                "objectGUID", ntds[0]["invocationId"][0]))
        }

        conn = self.samdb.search(base=ntds_dn, expression="(objectClass=nTDSConnection)")
        repsfrom = self.get_neighbours(drsuapi.DRSUAPI_DS_REPLICA_INFO_NEIGHBORS)
        repsto = self.get_neighbours(drsuapi.DRSUAPI_DS_REPLICA_INFO_REPSTO)

        conn_details = []
        for c in conn:
            c_rdn, sep, c_server_dn = str(c['fromServer'][0]).partition(',')
            d = {
                'name': str(c['name']),
                'remote DN': str(c['fromServer'][0]),
                'options': int(attr_default(c, 'options', 0)),
                'enabled': (get_string(attr_default(c, 'enabledConnection',
                                         'TRUE')).upper() == 'TRUE')
            }

            conn_details.append(d)
            try:
                c_server_res = self.samdb.search(base=c_server_dn,
                                                 scope=ldb.SCOPE_BASE,
                                                 attrs=["dnsHostName"])
                d['dns name'] = str(c_server_res[0]["dnsHostName"][0])
            except ldb.LdbError as e:
                (errno, _) = e.args
                if errno == ldb.ERR_NO_SUCH_OBJECT:
                    d['is deleted'] = True
            except (KeyError, IndexError):
                pass

            d['replicates NC'] = []
            for r in c.get('mS-DS-ReplicatesNCReason', []):
                a = str(r).split(':')
                d['replicates NC'].append((a[3], int(a[2])))

        return {
            'dsa': dsa_details,
            'repsFrom': repsfrom,
            'repsTo': repsto,
            'NTDSConnections': conn_details,
            'site': site,
            'server': server
        }

    def classic_output(self):
        data = self.get_local_repl_data()
        dsa_details = data['dsa']
        repsfrom = data['repsFrom']
        repsto = data['repsTo']
        conn_details = data['NTDSConnections']
        site = data['site']
        server = data['server']

        self.message("%s\\%s" % (site, server))
        self.message("DSA Options: 0x%08x" % dsa_details["options"])
        self.message("DSA object GUID: %s" % dsa_details["objectGUID"])
        self.message("DSA invocationId: %s\n" % dsa_details["invocationId"])

        self.message("==== INBOUND NEIGHBORS ====\n")
        for n in repsfrom:
            self.print_neighbour(n)

        self.message("==== OUTBOUND NEIGHBORS ====\n")
        for n in repsto:
            self.print_neighbour(n)

        reasons = ['NTDSCONN_KCC_GC_TOPOLOGY',
                   'NTDSCONN_KCC_RING_TOPOLOGY',
                   'NTDSCONN_KCC_MINIMIZE_HOPS_TOPOLOGY',
                   'NTDSCONN_KCC_STALE_SERVERS_TOPOLOGY',
                   'NTDSCONN_KCC_OSCILLATING_CONNECTION_TOPOLOGY',
                   'NTDSCONN_KCC_INTERSITE_GC_TOPOLOGY',
                   'NTDSCONN_KCC_INTERSITE_TOPOLOGY',
                   'NTDSCONN_KCC_SERVER_FAILOVER_TOPOLOGY',
                   'NTDSCONN_KCC_SITE_FAILOVER_TOPOLOGY',
                   'NTDSCONN_KCC_REDUNDANT_SERVER_TOPOLOGY']

        self.message("==== KCC CONNECTION OBJECTS ====\n")
        for d in conn_details:
            self.message("Connection --")
            if d.get('is deleted'):
                self.message("\tWARNING: Connection to DELETED server!")

            self.message("\tConnection name: %s" % d['name'])
            self.message("\tEnabled        : %s" % str(d['enabled']).upper())
            self.message("\tServer DNS name : %s" % d.get('dns name'))
            self.message("\tServer DN name  : %s" % d['remote DN'])
            self.message("\t\tTransportType: RPC")
            self.message("\t\toptions: 0x%08X" % d['options'])

            if d['replicates NC']:
                for nc, reason in d['replicates NC']:
                    self.message("\t\tReplicatesNC: %s" % nc)
                    self.message("\t\tReason: 0x%08x" % reason)
                    for s in reasons:
                        if getattr(dsdb, s, 0) & reason:
                            self.message("\t\t\t%s" % s)
            else:
                self.message("Warning: No NC replicated for Connection!")


class cmd_drs_kcc(Command):
    """Trigger knowledge consistency center run."""

    synopsis = "%prog [<DC>] [options]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "versionopts": options.VersionOptions,
        "credopts": options.CredentialsOptions,
    }

    takes_args = ["DC?"]

    def run(self, DC=None, sambaopts=None,
            credopts=None, versionopts=None):

        self.lp = sambaopts.get_loadparm()
        if DC is None:
            DC = common.netcmd_dnsname(self.lp)
        self.server = DC

        self.creds = credopts.get_credentials(self.lp, fallback_machine=True)

        drsuapi_connect(self)

        req1 = drsuapi.DsExecuteKCC1()
        try:
            self.drsuapi.DsExecuteKCC(self.drsuapi_handle, 1, req1)
        except Exception as e:
            raise CommandError("DsExecuteKCC failed", e)
        self.message("Consistency check on %s successful." % DC)


class cmd_drs_replicate(Command):
    """Replicate a naming context between two DCs."""

    synopsis = "%prog <destinationDC> <sourceDC> <NC> [options]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "versionopts": options.VersionOptions,
        "credopts": options.CredentialsOptions,
    }

    takes_args = ["DEST_DC", "SOURCE_DC", "NC"]

    takes_options = [
        Option("--add-ref", help="use ADD_REF to add to repsTo on source", action="store_true"),
        Option("--sync-forced", help="use SYNC_FORCED to force inbound replication", action="store_true"),
        Option("--sync-all", help="use SYNC_ALL to replicate from all DCs", action="store_true"),
        Option("--full-sync", help="resync all objects", action="store_true"),
        Option("--local", help="pull changes directly into the local database (destination DC is ignored)", action="store_true"),
        Option("--local-online", help="pull changes into the local database (destination DC is ignored) as a normal online replication", action="store_true"),
        Option("--async-op", help="use ASYNC_OP for the replication", action="store_true"),
        Option("--single-object", help="Replicate only the object specified, instead of the whole Naming Context (only with --local)", action="store_true"),
    ]

    def drs_local_replicate(self, SOURCE_DC, NC, full_sync=False,
                            single_object=False,
                            sync_forced=False):
        '''replicate from a source DC to the local SAM'''

        self.server = SOURCE_DC
        drsuapi_connect(self)

        # Override the default flag LDB_FLG_DONT_CREATE_DB
        self.local_samdb = SamDB(session_info=system_session(), url=None,
                                 credentials=self.creds, lp=self.lp,
                                 flags=0)

        self.samdb = SamDB(url="ldap://%s" % self.server,
                           session_info=system_session(),
                           credentials=self.creds, lp=self.lp)

        # work out the source and destination GUIDs
        res = self.local_samdb.search(base="", scope=ldb.SCOPE_BASE,
                                      attrs=["dsServiceName"])
        self.ntds_dn = res[0]["dsServiceName"][0]

        res = self.local_samdb.search(base=self.ntds_dn, scope=ldb.SCOPE_BASE,
                                      attrs=["objectGUID"])
        self.ntds_guid = misc.GUID(
            self.samdb.schema_format_value("objectGUID",
                                           res[0]["objectGUID"][0]))

        source_dsa_invocation_id = misc.GUID(self.samdb.get_invocation_id())
        dest_dsa_invocation_id = misc.GUID(self.local_samdb.get_invocation_id())
        destination_dsa_guid = self.ntds_guid

        exop = drsuapi.DRSUAPI_EXOP_NONE

        if single_object:
            exop = drsuapi.DRSUAPI_EXOP_REPL_OBJ
            full_sync = True

        self.samdb.transaction_start()
        repl = drs_utils.drs_Replicate("ncacn_ip_tcp:%s[seal]" % self.server,
                                       self.lp,
                                       self.creds, self.local_samdb,
                                       dest_dsa_invocation_id)

        # Work out if we are an RODC, so that a forced local replicate
        # with the admin pw does not sync passwords
        rodc = self.local_samdb.am_rodc()
        try:
            (num_objects, num_links) = repl.replicate(NC,
                                                      source_dsa_invocation_id,
                                                      destination_dsa_guid,
                                                      rodc=rodc,
                                                      full_sync=full_sync,
                                                      exop=exop,
                                                      sync_forced=sync_forced)
        except Exception as e:
            raise CommandError("Error replicating DN %s" % NC, e)
        self.samdb.transaction_commit()

        if full_sync:
            self.message("Full Replication of all %d objects and %d links "
                         "from %s to %s was successful." %
                         (num_objects, num_links, SOURCE_DC,
                          self.local_samdb.url))
        else:
            self.message("Incremental replication of %d objects and %d links "
                         "from %s to %s was successful." %
                         (num_objects, num_links, SOURCE_DC,
                          self.local_samdb.url))

    def run(self, DEST_DC, SOURCE_DC, NC,
            add_ref=False, sync_forced=False, sync_all=False, full_sync=False,
            local=False, local_online=False, async_op=False, single_object=False,
            sambaopts=None, credopts=None, versionopts=None):

        self.server = DEST_DC
        self.lp = sambaopts.get_loadparm()

        self.creds = credopts.get_credentials(self.lp, fallback_machine=True)

        if local:
            self.drs_local_replicate(SOURCE_DC, NC, full_sync=full_sync,
                                     single_object=single_object,
                                     sync_forced=sync_forced)
            return

        if local_online:
            server_bind = drsuapi.drsuapi("irpc:dreplsrv", lp_ctx=self.lp)
            server_bind_handle = misc.policy_handle()
        else:
            drsuapi_connect(self)
            server_bind = self.drsuapi
            server_bind_handle = self.drsuapi_handle

        if not async_op:
            # Give the sync replication 5 minutes time
            server_bind.request_timeout = 5 * 60

        samdb_connect(self)

        # we need to find the NTDS GUID of the source DC
        msg = self.samdb.search(base=self.samdb.get_config_basedn(),
                                expression="(&(objectCategory=server)(|(name=%s)(dNSHostName=%s)))" % (
            ldb.binary_encode(SOURCE_DC),
            ldb.binary_encode(SOURCE_DC)),
                                attrs=[])
        if len(msg) == 0:
            raise CommandError("Failed to find source DC %s" % SOURCE_DC)
        server_dn = msg[0]['dn']

        msg = self.samdb.search(base=server_dn, scope=ldb.SCOPE_ONELEVEL,
                                expression="(|(objectCategory=nTDSDSA)(objectCategory=nTDSDSARO))",
                                attrs=['objectGUID', 'options'])
        if len(msg) == 0:
            raise CommandError("Failed to find source NTDS DN %s" % SOURCE_DC)
        source_dsa_guid = msg[0]['objectGUID'][0]
        dsa_options = int(attr_default(msg, 'options', 0))

        req_options = 0
        if not (dsa_options & dsdb.DS_NTDSDSA_OPT_DISABLE_OUTBOUND_REPL):
            req_options |= drsuapi.DRSUAPI_DRS_WRIT_REP
        if add_ref:
            req_options |= drsuapi.DRSUAPI_DRS_ADD_REF
        if sync_forced:
            req_options |= drsuapi.DRSUAPI_DRS_SYNC_FORCED
        if sync_all:
            req_options |= drsuapi.DRSUAPI_DRS_SYNC_ALL
        if full_sync:
            req_options |= drsuapi.DRSUAPI_DRS_FULL_SYNC_NOW
        if async_op:
            req_options |= drsuapi.DRSUAPI_DRS_ASYNC_OP

        try:
            drs_utils.sendDsReplicaSync(server_bind, server_bind_handle, source_dsa_guid, NC, req_options)
        except drs_utils.drsException as estr:
            raise CommandError("DsReplicaSync failed", estr)
        if async_op:
            self.message("Replicate from %s to %s was started." % (SOURCE_DC, DEST_DC))
        else:
            self.message("Replicate from %s to %s was successful." % (SOURCE_DC, DEST_DC))


class cmd_drs_bind(Command):
    """Show DRS capabilities of a server."""

    synopsis = "%prog [<DC>] [options]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "versionopts": options.VersionOptions,
        "credopts": options.CredentialsOptions,
    }

    takes_args = ["DC?"]

    def run(self, DC=None, sambaopts=None,
            credopts=None, versionopts=None):

        self.lp = sambaopts.get_loadparm()
        if DC is None:
            DC = common.netcmd_dnsname(self.lp)
        self.server = DC
        self.creds = credopts.get_credentials(self.lp, fallback_machine=True)

        drsuapi_connect(self)

        bind_info = drsuapi.DsBindInfoCtr()
        bind_info.length = 28
        bind_info.info = drsuapi.DsBindInfo28()
        (info, handle) = self.drsuapi.DsBind(misc.GUID(drsuapi.DRSUAPI_DS_BIND_GUID), bind_info)

        optmap = [
            ("DRSUAPI_SUPPORTED_EXTENSION_BASE", "DRS_EXT_BASE"),
            ("DRSUAPI_SUPPORTED_EXTENSION_ASYNC_REPLICATION", "DRS_EXT_ASYNCREPL"),
            ("DRSUAPI_SUPPORTED_EXTENSION_REMOVEAPI", "DRS_EXT_REMOVEAPI"),
            ("DRSUAPI_SUPPORTED_EXTENSION_MOVEREQ_V2", "DRS_EXT_MOVEREQ_V2"),
            ("DRSUAPI_SUPPORTED_EXTENSION_GETCHG_COMPRESS", "DRS_EXT_GETCHG_DEFLATE"),
            ("DRSUAPI_SUPPORTED_EXTENSION_DCINFO_V1", "DRS_EXT_DCINFO_V1"),
            ("DRSUAPI_SUPPORTED_EXTENSION_RESTORE_USN_OPTIMIZATION", "DRS_EXT_RESTORE_USN_OPTIMIZATION"),
            ("DRSUAPI_SUPPORTED_EXTENSION_ADDENTRY", "DRS_EXT_ADDENTRY"),
            ("DRSUAPI_SUPPORTED_EXTENSION_KCC_EXECUTE", "DRS_EXT_KCC_EXECUTE"),
            ("DRSUAPI_SUPPORTED_EXTENSION_ADDENTRY_V2", "DRS_EXT_ADDENTRY_V2"),
            ("DRSUAPI_SUPPORTED_EXTENSION_LINKED_VALUE_REPLICATION", "DRS_EXT_LINKED_VALUE_REPLICATION"),
            ("DRSUAPI_SUPPORTED_EXTENSION_DCINFO_V2", "DRS_EXT_DCINFO_V2"),
            ("DRSUAPI_SUPPORTED_EXTENSION_INSTANCE_TYPE_NOT_REQ_ON_MOD", "DRS_EXT_INSTANCE_TYPE_NOT_REQ_ON_MOD"),
            ("DRSUAPI_SUPPORTED_EXTENSION_CRYPTO_BIND", "DRS_EXT_CRYPTO_BIND"),
            ("DRSUAPI_SUPPORTED_EXTENSION_GET_REPL_INFO", "DRS_EXT_GET_REPL_INFO"),
            ("DRSUAPI_SUPPORTED_EXTENSION_STRONG_ENCRYPTION", "DRS_EXT_STRONG_ENCRYPTION"),
            ("DRSUAPI_SUPPORTED_EXTENSION_DCINFO_V01", "DRS_EXT_DCINFO_VFFFFFFFF"),
            ("DRSUAPI_SUPPORTED_EXTENSION_TRANSITIVE_MEMBERSHIP", "DRS_EXT_TRANSITIVE_MEMBERSHIP"),
            ("DRSUAPI_SUPPORTED_EXTENSION_ADD_SID_HISTORY", "DRS_EXT_ADD_SID_HISTORY"),
            ("DRSUAPI_SUPPORTED_EXTENSION_POST_BETA3", "DRS_EXT_POST_BETA3"),
            ("DRSUAPI_SUPPORTED_EXTENSION_GETCHGREQ_V5", "DRS_EXT_GETCHGREQ_V5"),
            ("DRSUAPI_SUPPORTED_EXTENSION_GET_MEMBERSHIPS2", "DRS_EXT_GETMEMBERSHIPS2"),
            ("DRSUAPI_SUPPORTED_EXTENSION_GETCHGREQ_V6", "DRS_EXT_GETCHGREQ_V6"),
            ("DRSUAPI_SUPPORTED_EXTENSION_NONDOMAIN_NCS", "DRS_EXT_NONDOMAIN_NCS"),
            ("DRSUAPI_SUPPORTED_EXTENSION_GETCHGREQ_V8", "DRS_EXT_GETCHGREQ_V8"),
            ("DRSUAPI_SUPPORTED_EXTENSION_GETCHGREPLY_V5", "DRS_EXT_GETCHGREPLY_V5"),
            ("DRSUAPI_SUPPORTED_EXTENSION_GETCHGREPLY_V6", "DRS_EXT_GETCHGREPLY_V6"),
            ("DRSUAPI_SUPPORTED_EXTENSION_ADDENTRYREPLY_V3", "DRS_EXT_WHISTLER_BETA3"),
            ("DRSUAPI_SUPPORTED_EXTENSION_GETCHGREPLY_V7", "DRS_EXT_WHISTLER_BETA3"),
            ("DRSUAPI_SUPPORTED_EXTENSION_VERIFY_OBJECT", "DRS_EXT_WHISTLER_BETA3"),
            ("DRSUAPI_SUPPORTED_EXTENSION_XPRESS_COMPRESS", "DRS_EXT_W2K3_DEFLATE"),
            ("DRSUAPI_SUPPORTED_EXTENSION_GETCHGREQ_V10", "DRS_EXT_GETCHGREQ_V10"),
            ("DRSUAPI_SUPPORTED_EXTENSION_RESERVED_PART2", "DRS_EXT_RESERVED_FOR_WIN2K_OR_DOTNET_PART2"),
            ("DRSUAPI_SUPPORTED_EXTENSION_RESERVED_PART3", "DRS_EXT_RESERVED_FOR_WIN2K_OR_DOTNET_PART3")
        ]

        optmap_ext = [
            ("DRSUAPI_SUPPORTED_EXTENSION_ADAM", "DRS_EXT_ADAM"),
            ("DRSUAPI_SUPPORTED_EXTENSION_LH_BETA2", "DRS_EXT_LH_BETA2"),
            ("DRSUAPI_SUPPORTED_EXTENSION_RECYCLE_BIN", "DRS_EXT_RECYCLE_BIN")]

        self.message("Bind to %s succeeded." % DC)
        self.message("Extensions supported:")
        for (opt, str) in optmap:
            optval = getattr(drsuapi, opt, 0)
            if info.info.supported_extensions & optval:
                yesno = "Yes"
            else:
                yesno = "No "
            self.message("  %-60s: %s (%s)" % (opt, yesno, str))

        if isinstance(info.info, drsuapi.DsBindInfo48):
            self.message("\nExtended Extensions supported:")
            for (opt, str) in optmap_ext:
                optval = getattr(drsuapi, opt, 0)
                if info.info.supported_extensions_ext & optval:
                    yesno = "Yes"
                else:
                    yesno = "No "
                self.message("  %-60s: %s (%s)" % (opt, yesno, str))

        self.message("\nSite GUID: %s" % info.info.site_guid)
        self.message("Repl epoch: %u" % info.info.repl_epoch)
        if isinstance(info.info, drsuapi.DsBindInfo48):
            self.message("Forest GUID: %s" % info.info.config_dn_guid)


class cmd_drs_options(Command):
    """Query or change 'options' for NTDS Settings object of a Domain Controller."""

    synopsis = "%prog [<DC>] [options]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "versionopts": options.VersionOptions,
        "credopts": options.CredentialsOptions,
    }

    takes_args = ["DC?"]

    takes_options = [
        Option("--dsa-option", help="DSA option to enable/disable", type="str",
               metavar="{+|-}IS_GC | {+|-}DISABLE_INBOUND_REPL | {+|-}DISABLE_OUTBOUND_REPL | {+|-}DISABLE_NTDSCONN_XLATE"),
    ]

    option_map = {"IS_GC": 0x00000001,
                  "DISABLE_INBOUND_REPL": 0x00000002,
                  "DISABLE_OUTBOUND_REPL": 0x00000004,
                  "DISABLE_NTDSCONN_XLATE": 0x00000008}

    def run(self, DC=None, dsa_option=None,
            sambaopts=None, credopts=None, versionopts=None):

        self.lp = sambaopts.get_loadparm()
        if DC is None:
            DC = common.netcmd_dnsname(self.lp)
        self.server = DC
        self.creds = credopts.get_credentials(self.lp, fallback_machine=True)

        samdb_connect(self)

        ntds_dn = self.samdb.get_dsServiceName()
        res = self.samdb.search(base=ntds_dn, scope=ldb.SCOPE_BASE, attrs=["options"])
        dsa_opts = int(res[0]["options"][0])

        # print out current DSA options
        cur_opts = [x for x in self.option_map if self.option_map[x] & dsa_opts]
        self.message("Current DSA options: " + ", ".join(cur_opts))

        # modify options
        if dsa_option:
            if dsa_option[:1] not in ("+", "-"):
                raise CommandError("Unknown option %s" % dsa_option)
            flag = dsa_option[1:]
            if flag not in self.option_map.keys():
                raise CommandError("Unknown option %s" % dsa_option)
            if dsa_option[:1] == "+":
                dsa_opts |= self.option_map[flag]
            else:
                dsa_opts &= ~self.option_map[flag]
            # save new options
            m = ldb.Message()
            m.dn = ldb.Dn(self.samdb, ntds_dn)
            m["options"] = ldb.MessageElement(str(dsa_opts), ldb.FLAG_MOD_REPLACE, "options")
            self.samdb.modify(m)
            # print out new DSA options
            cur_opts = [x for x in self.option_map if self.option_map[x] & dsa_opts]
            self.message("New DSA options: " + ", ".join(cur_opts))


class cmd_drs_clone_dc_database(Command):
    """Replicate an initial clone of domain, but DO NOT JOIN it."""

    synopsis = "%prog <dnsdomain> [options]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "versionopts": options.VersionOptions,
        "credopts": options.CredentialsOptions,
    }

    takes_options = [
        Option("--server", help="DC to join", type=str),
        Option("--targetdir", help="where to store provision (required)", type=str),
        Option("-q", "--quiet", help="Be quiet", action="store_true"),
        Option("--include-secrets", help="Also replicate secret values", action="store_true"),
        Option("--backend-store", type="choice", metavar="BACKENDSTORE",
               choices=["tdb", "mdb"],
               help="Specify the database backend to be used "
                    "(default is %s)" % get_default_backend_store()),
        Option("--backend-store-size", type="bytes", metavar="SIZE",
               help="Specify the size of the backend database, currently" +
                    "only supported by lmdb backends (default is 8 Gb).")
    ]

    takes_args = ["domain"]

    def run(self, domain, sambaopts=None, credopts=None,
            versionopts=None, server=None, targetdir=None,
            quiet=False, verbose=False, include_secrets=False,
            backend_store=None, backend_store_size=None):
        lp = sambaopts.get_loadparm()
        creds = credopts.get_credentials(lp)

        logger = self.get_logger(verbose=verbose, quiet=quiet)

        if targetdir is None:
            raise CommandError("--targetdir option must be specified")

        join_clone(logger=logger, server=server, creds=creds, lp=lp,
                   domain=domain, dns_backend='SAMBA_INTERNAL',
                   targetdir=targetdir, include_secrets=include_secrets,
                   backend_store=backend_store,
                   backend_store_size=backend_store_size)


class cmd_drs_uptodateness(Command):
    """Show uptodateness status"""

    synopsis = "%prog [options]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "versionopts": options.VersionOptions,
        "credopts": options.CredentialsOptions,
    }

    takes_options = [
        Option("-H", "--URL", metavar="URL", dest="H",
               help="LDB URL for database or target server"),
        Option("-p", "--partition",
               help="restrict to this partition"),
        Option("--json", action='store_true',
               help="Print data in json format"),
        Option("--maximum", action='store_true',
               help="Print maximum out-of-date-ness only"),
        Option("--median", action='store_true',
               help="Print median out-of-date-ness only"),
        Option("--full", action='store_true',
               help="Print full out-of-date-ness data"),
    ]

    def format_as_json(self, partitions_summaries):
        return json.dumps(partitions_summaries, indent=2)

    def format_as_text(self, partitions_summaries):
        lines = []
        for part_name, summary in partitions_summaries.items():
            items = ['%s: %s' % (k, v) for k, v in summary.items()]
            line = '%-15s %s' % (part_name, '  '.join(items))
            lines.append(line)
        return '\n'.join(lines)

    def run(self, H=None, partition=None,
            json=False, maximum=False, median=False, full=False,
            sambaopts=None, credopts=None, versionopts=None,
            quiet=False, verbose=False):

        lp = sambaopts.get_loadparm()
        creds = credopts.get_credentials(lp, fallback_machine=True)
        local_kcc, dsas = get_kcc_and_dsas(H, lp, creds)
        samdb = local_kcc.samdb
        short_partitions, _ = get_partition_maps(samdb)
        if partition:
            if partition in short_partitions:
                part_dn = short_partitions[partition]
                # narrow down to specified partition only
                short_partitions = {partition: part_dn}
            else:
                raise CommandError("unknown partition %s" % partition)

        filters = []
        if maximum:
            filters.append('maximum')
        if median:
            filters.append('median')

        partitions_distances = {}
        partitions_summaries = {}
        for part_name, part_dn in short_partitions.items():
            utdv_edges = get_utdv_edges(local_kcc, dsas, part_dn, lp, creds)
            distances = get_utdv_distances(utdv_edges, dsas)
            summary = get_utdv_summary(distances, filters=filters)
            partitions_distances[part_name] = distances
            partitions_summaries[part_name] = summary

        if full:
            # always print json format
            output = self.format_as_json(partitions_distances)
        else:
            if json:
                output = self.format_as_json(partitions_summaries)
            else:
                output = self.format_as_text(partitions_summaries)

        print(output, file=self.outf)


class cmd_drs(SuperCommand):
    """Directory Replication Services (DRS) management."""

    subcommands = {}
    subcommands["bind"] = cmd_drs_bind()
    subcommands["kcc"] = cmd_drs_kcc()
    subcommands["replicate"] = cmd_drs_replicate()
    subcommands["showrepl"] = cmd_drs_showrepl()
    subcommands["options"] = cmd_drs_options()
    subcommands["clone-dc-database"] = cmd_drs_clone_dc_database()
    subcommands["uptodateness"] = cmd_drs_uptodateness()
