# python join code
# Copyright Andrew Tridgell 2010
# Copyright Andrew Bartlett 2010
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
"""Joining a domain."""

from samba.auth import system_session
from samba.samdb import SamDB
from samba import gensec, Ldb, drs_utils, arcfour_encrypt, string_to_byte_array
import ldb
import samba
import uuid
from samba.ndr import ndr_pack, ndr_unpack
from samba.dcerpc import security, drsuapi, misc, nbt, lsa, drsblobs, dnsserver, dnsp
from samba.dsdb import DS_DOMAIN_FUNCTION_2003
from samba.credentials import Credentials, DONT_USE_KERBEROS
from samba.provision import (secretsdb_self_join, provision, provision_fill,
                             FILL_DRS, FILL_SUBDOMAIN, DEFAULTSITE)
from samba.provision.common import setup_path
from samba.schema import Schema
from samba import descriptor
from samba.net import Net
from samba.provision.sambadns import setup_bind9_dns
from samba import read_and_sub_file
from samba import werror
from base64 import b64encode
from samba import WERRORError, NTSTATUSError
from samba import sd_utils
from samba.dnsserver import ARecord, AAAARecord, CNameRecord
import logging
import random
import time
import re
import os
import tempfile
from collections import OrderedDict
from samba.compat import text_type
from samba.compat import get_string
from samba.netcmd import CommandError


class DCJoinException(Exception):

    def __init__(self, msg):
        super(DCJoinException, self).__init__("Can't join, error: %s" % msg)


class DCJoinContext(object):
    """Perform a DC join."""

    def __init__(ctx, logger=None, server=None, creds=None, lp=None, site=None,
                 netbios_name=None, targetdir=None, domain=None,
                 machinepass=None, use_ntvfs=False, dns_backend=None,
                 promote_existing=False, plaintext_secrets=False,
                 backend_store=None,
                 backend_store_size=None,
                 forced_local_samdb=None):

        ctx.logger = logger
        ctx.creds = creds
        ctx.lp = lp
        ctx.site = site
        ctx.targetdir = targetdir
        ctx.use_ntvfs = use_ntvfs
        ctx.plaintext_secrets = plaintext_secrets
        ctx.backend_store = backend_store
        ctx.backend_store_size = backend_store_size

        ctx.promote_existing = promote_existing
        ctx.promote_from_dn = None

        ctx.nc_list = []
        ctx.full_nc_list = []

        ctx.creds.set_gensec_features(creds.get_gensec_features() | gensec.FEATURE_SEAL)
        ctx.net = Net(creds=ctx.creds, lp=ctx.lp)

        ctx.server = server
        ctx.forced_local_samdb = forced_local_samdb

        if forced_local_samdb:
            ctx.samdb = forced_local_samdb
            ctx.server = ctx.samdb.url
        else:
            if ctx.server:
                # work out the DC's site (if not already specified)
                if site is None:
                    ctx.site = ctx.find_dc_site(ctx.server)
            else:
                # work out the Primary DC for the domain (as well as an
                # appropriate site for the new DC)
                ctx.logger.info("Finding a writeable DC for domain '%s'" % domain)
                ctx.server = ctx.find_dc(domain)
                ctx.logger.info("Found DC %s" % ctx.server)
            ctx.samdb = SamDB(url="ldap://%s" % ctx.server,
                              session_info=system_session(),
                              credentials=ctx.creds, lp=ctx.lp)

        if ctx.site is None:
            ctx.site = DEFAULTSITE

        try:
            ctx.samdb.search(scope=ldb.SCOPE_BASE, attrs=[])
        except ldb.LdbError as e:
            (enum, estr) = e.args
            raise DCJoinException(estr)

        ctx.base_dn = str(ctx.samdb.get_default_basedn())
        ctx.root_dn = str(ctx.samdb.get_root_basedn())
        ctx.schema_dn = str(ctx.samdb.get_schema_basedn())
        ctx.config_dn = str(ctx.samdb.get_config_basedn())
        ctx.domsid = security.dom_sid(ctx.samdb.get_domain_sid())
        ctx.forestsid = ctx.domsid
        ctx.domain_name = ctx.get_domain_name()
        ctx.forest_domain_name = ctx.get_forest_domain_name()
        ctx.invocation_id = misc.GUID(str(uuid.uuid4()))

        ctx.dc_ntds_dn = ctx.samdb.get_dsServiceName()
        ctx.dc_dnsHostName = ctx.get_dnsHostName()
        ctx.behavior_version = ctx.get_behavior_version()

        if machinepass is not None:
            ctx.acct_pass = machinepass
        else:
            ctx.acct_pass = samba.generate_random_machine_password(128, 255)

        ctx.dnsdomain = ctx.samdb.domain_dns_name()

        # the following are all dependent on the new DC's netbios_name (which
        # we expect to always be specified, except when cloning a DC)
        if netbios_name:
            # work out the DNs of all the objects we will be adding
            ctx.myname = netbios_name
            ctx.samname = "%s$" % ctx.myname
            ctx.server_dn = "CN=%s,CN=Servers,CN=%s,CN=Sites,%s" % (ctx.myname, ctx.site, ctx.config_dn)
            ctx.ntds_dn = "CN=NTDS Settings,%s" % ctx.server_dn
            ctx.acct_dn = "CN=%s,OU=Domain Controllers,%s" % (ctx.myname, ctx.base_dn)
            ctx.dnshostname = "%s.%s" % (ctx.myname.lower(), ctx.dnsdomain)
            ctx.dnsforest = ctx.samdb.forest_dns_name()

            topology_base = "CN=Topology,CN=Domain System Volume,CN=DFSR-GlobalSettings,CN=System,%s" % ctx.base_dn
            if ctx.dn_exists(topology_base):
                ctx.topology_dn = "CN=%s,%s" % (ctx.myname, topology_base)
            else:
                ctx.topology_dn = None

            ctx.SPNs = ["HOST/%s" % ctx.myname,
                        "HOST/%s" % ctx.dnshostname,
                        "GC/%s/%s" % (ctx.dnshostname, ctx.dnsforest)]

            res_rid_manager = ctx.samdb.search(scope=ldb.SCOPE_BASE,
                                               attrs=["rIDManagerReference"],
                                               base=ctx.base_dn)

            ctx.rid_manager_dn = res_rid_manager[0]["rIDManagerReference"][0]

        ctx.domaindns_zone = 'DC=DomainDnsZones,%s' % ctx.base_dn
        ctx.forestdns_zone = 'DC=ForestDnsZones,%s' % ctx.root_dn

        expr = "(&(objectClass=crossRef)(ncName=%s))" % ldb.binary_encode(ctx.domaindns_zone)
        res_domaindns = ctx.samdb.search(scope=ldb.SCOPE_ONELEVEL,
                                         attrs=[],
                                         base=ctx.samdb.get_partitions_dn(),
                                         expression=expr)
        if dns_backend is None:
            ctx.dns_backend = "NONE"
        else:
            if len(res_domaindns) == 0:
                ctx.dns_backend = "NONE"
                print("NO DNS zone information found in source domain, not replicating DNS")
            else:
                ctx.dns_backend = dns_backend

        ctx.realm = ctx.dnsdomain

        ctx.tmp_samdb = None

        ctx.replica_flags = (drsuapi.DRSUAPI_DRS_INIT_SYNC |
                             drsuapi.DRSUAPI_DRS_PER_SYNC |
                             drsuapi.DRSUAPI_DRS_GET_ANC |
                             drsuapi.DRSUAPI_DRS_GET_NC_SIZE |
                             drsuapi.DRSUAPI_DRS_NEVER_SYNCED)

        # these elements are optional
        ctx.never_reveal_sid = None
        ctx.reveal_sid = None
        ctx.connection_dn = None
        ctx.RODC = False
        ctx.krbtgt_dn = None
        ctx.drsuapi = None
        ctx.managedby = None
        ctx.subdomain = False
        ctx.adminpass = None
        ctx.partition_dn = None

        ctx.dns_a_dn = None
        ctx.dns_cname_dn = None

        # Do not normally register 127. addresses but allow override for selftest
        ctx.force_all_ips = False

    def del_noerror(ctx, dn, recursive=False):
        if recursive:
            try:
                res = ctx.samdb.search(base=dn, scope=ldb.SCOPE_ONELEVEL, attrs=["dn"])
            except Exception:
                return
            for r in res:
                ctx.del_noerror(r.dn, recursive=True)
        try:
            ctx.samdb.delete(dn)
            print("Deleted %s" % dn)
        except Exception:
            pass

    def cleanup_old_accounts(ctx, force=False):
        res = ctx.samdb.search(base=ctx.samdb.get_default_basedn(),
                               expression='sAMAccountName=%s' % ldb.binary_encode(ctx.samname),
                               attrs=["msDS-krbTgtLink", "objectSID"])
        if len(res) == 0:
            return

        if not force:
            creds = Credentials()
            creds.guess(ctx.lp)
            try:
                creds.set_machine_account(ctx.lp)
                creds.set_kerberos_state(ctx.creds.get_kerberos_state())
                machine_samdb = SamDB(url="ldap://%s" % ctx.server,
                                      session_info=system_session(),
                                      credentials=creds, lp=ctx.lp)
            except:
                pass
            else:
                token_res = machine_samdb.search(scope=ldb.SCOPE_BASE, base="", attrs=["tokenGroups"])
                if token_res[0]["tokenGroups"][0] \
                   == res[0]["objectSID"][0]:
                    raise DCJoinException("Not removing account %s which "
                                          "looks like a Samba DC account "
                                          "matching the password we already have.  "
                                          "To override, remove secrets.ldb and secrets.tdb"
                                          % ctx.samname)

        ctx.del_noerror(res[0].dn, recursive=True)

        krbtgt_dn = res[0].get('msDS-KrbTgtLink', idx=0)
        if krbtgt_dn is not None:
            ctx.new_krbtgt_dn = krbtgt_dn
            ctx.del_noerror(ctx.new_krbtgt_dn)

        res = ctx.samdb.search(base=ctx.samdb.get_default_basedn(),
                               expression='(&(sAMAccountName=%s)(servicePrincipalName=%s))' %
                               (ldb.binary_encode("dns-%s" % ctx.myname),
                                ldb.binary_encode("dns/%s" % ctx.dnshostname)),
                               attrs=[])
        if res:
            ctx.del_noerror(res[0].dn, recursive=True)

        res = ctx.samdb.search(base=ctx.samdb.get_default_basedn(),
                               expression='(sAMAccountName=%s)' % ldb.binary_encode("dns-%s" % ctx.myname),
                               attrs=[])
        if res:
            raise DCJoinException("Not removing account %s which looks like "
                                  "a Samba DNS service account but does not "
                                  "have servicePrincipalName=%s" %
                                  (ldb.binary_encode("dns-%s" % ctx.myname),
                                   ldb.binary_encode("dns/%s" % ctx.dnshostname)))

    def cleanup_old_join(ctx, force=False):
        """Remove any DNs from a previous join."""
        # find the krbtgt link
        if not ctx.subdomain:
            ctx.cleanup_old_accounts(force=force)

        if ctx.connection_dn is not None:
            ctx.del_noerror(ctx.connection_dn)
        if ctx.krbtgt_dn is not None:
            ctx.del_noerror(ctx.krbtgt_dn)
        ctx.del_noerror(ctx.ntds_dn)
        ctx.del_noerror(ctx.server_dn, recursive=True)
        if ctx.topology_dn:
            ctx.del_noerror(ctx.topology_dn)
        if ctx.partition_dn:
            ctx.del_noerror(ctx.partition_dn)

        if ctx.subdomain:
            binding_options = "sign"
            lsaconn = lsa.lsarpc("ncacn_ip_tcp:%s[%s]" % (ctx.server, binding_options),
                                 ctx.lp, ctx.creds)

            objectAttr = lsa.ObjectAttribute()
            objectAttr.sec_qos = lsa.QosInfo()

            pol_handle = lsaconn.OpenPolicy2('',
                                             objectAttr,
                                             security.SEC_FLAG_MAXIMUM_ALLOWED)

            name = lsa.String()
            name.string = ctx.realm
            info = lsaconn.QueryTrustedDomainInfoByName(pol_handle, name, lsa.LSA_TRUSTED_DOMAIN_INFO_FULL_INFO)

            lsaconn.DeleteTrustedDomain(pol_handle, info.info_ex.sid)

            name = lsa.String()
            name.string = ctx.forest_domain_name
            info = lsaconn.QueryTrustedDomainInfoByName(pol_handle, name, lsa.LSA_TRUSTED_DOMAIN_INFO_FULL_INFO)

            lsaconn.DeleteTrustedDomain(pol_handle, info.info_ex.sid)

        if ctx.dns_a_dn:
            ctx.del_noerror(ctx.dns_a_dn)

        if ctx.dns_cname_dn:
            ctx.del_noerror(ctx.dns_cname_dn)

    def promote_possible(ctx):
        """confirm that the account is just a bare NT4 BDC or a member server, so can be safely promoted"""
        if ctx.subdomain:
            # This shouldn't happen
            raise Exception("Can not promote into a subdomain")

        res = ctx.samdb.search(base=ctx.samdb.get_default_basedn(),
                               expression='sAMAccountName=%s' % ldb.binary_encode(ctx.samname),
                               attrs=["msDS-krbTgtLink", "userAccountControl", "serverReferenceBL", "rIDSetReferences"])
        if len(res) == 0:
            raise Exception("Could not find domain member account '%s' to promote to a DC, use 'samba-tool domain join' instead'" % ctx.samname)
        if "msDS-KrbTgtLink" in res[0] or "serverReferenceBL" in res[0] or "rIDSetReferences" in res[0]:
            raise Exception("Account '%s' appears to be an active DC, use 'samba-tool domain join' if you must re-create this account" % ctx.samname)
        if (int(res[0]["userAccountControl"][0]) & (samba.dsdb.UF_WORKSTATION_TRUST_ACCOUNT |
                                                    samba.dsdb.UF_SERVER_TRUST_ACCOUNT) == 0):
            raise Exception("Account %s is not a domain member or a bare NT4 BDC, use 'samba-tool domain join' instead'" % ctx.samname)

        ctx.promote_from_dn = res[0].dn

    def find_dc(ctx, domain):
        """find a writeable DC for the given domain"""
        try:
            ctx.cldap_ret = ctx.net.finddc(domain=domain, flags=nbt.NBT_SERVER_LDAP | nbt.NBT_SERVER_DS | nbt.NBT_SERVER_WRITABLE)
        except NTSTATUSError as error:
            raise CommandError("Failed to find a writeable DC for domain '%s': %s" %
                               (domain, error.args[1]))
        except Exception:
            raise CommandError("Failed to find a writeable DC for domain '%s'" % domain)
        if ctx.cldap_ret.client_site is not None and ctx.cldap_ret.client_site != "":
            ctx.site = ctx.cldap_ret.client_site
        return ctx.cldap_ret.pdc_dns_name

    def find_dc_site(ctx, server):
        site = None
        cldap_ret = ctx.net.finddc(address=server,
                                   flags=nbt.NBT_SERVER_LDAP | nbt.NBT_SERVER_DS)
        if cldap_ret.client_site is not None and cldap_ret.client_site != "":
            site = cldap_ret.client_site
        return site

    def get_behavior_version(ctx):
        res = ctx.samdb.search(base=ctx.base_dn, scope=ldb.SCOPE_BASE, attrs=["msDS-Behavior-Version"])
        if "msDS-Behavior-Version" in res[0]:
            return int(res[0]["msDS-Behavior-Version"][0])
        else:
            return samba.dsdb.DS_DOMAIN_FUNCTION_2000

    def get_dnsHostName(ctx):
        res = ctx.samdb.search(base="", scope=ldb.SCOPE_BASE, attrs=["dnsHostName"])
        return str(res[0]["dnsHostName"][0])

    def get_domain_name(ctx):
        '''get netbios name of the domain from the partitions record'''
        partitions_dn = ctx.samdb.get_partitions_dn()
        res = ctx.samdb.search(base=partitions_dn, scope=ldb.SCOPE_ONELEVEL, attrs=["nETBIOSName"],
                               expression='ncName=%s' % ldb.binary_encode(str(ctx.samdb.get_default_basedn())))
        return str(res[0]["nETBIOSName"][0])

    def get_forest_domain_name(ctx):
        '''get netbios name of the domain from the partitions record'''
        partitions_dn = ctx.samdb.get_partitions_dn()
        res = ctx.samdb.search(base=partitions_dn, scope=ldb.SCOPE_ONELEVEL, attrs=["nETBIOSName"],
                               expression='ncName=%s' % ldb.binary_encode(str(ctx.samdb.get_root_basedn())))
        return str(res[0]["nETBIOSName"][0])

    def get_parent_partition_dn(ctx):
        '''get the parent domain partition DN from parent DNS name'''
        res = ctx.samdb.search(base=ctx.config_dn, attrs=[],
                               expression='(&(objectclass=crossRef)(dnsRoot=%s)(systemFlags:%s:=%u))' %
                               (ldb.binary_encode(ctx.parent_dnsdomain),
                                ldb.OID_COMPARATOR_AND, samba.dsdb.SYSTEM_FLAG_CR_NTDS_DOMAIN))
        return str(res[0].dn)

    def get_naming_master(ctx):
        '''get the parent domain partition DN from parent DNS name'''
        res = ctx.samdb.search(base='CN=Partitions,%s' % ctx.config_dn, attrs=['fSMORoleOwner'],
                               scope=ldb.SCOPE_BASE, controls=["extended_dn:1:1"])
        if 'fSMORoleOwner' not in res[0]:
            raise DCJoinException("Can't find naming master on partition DN %s in %s" % (ctx.partition_dn, ctx.samdb.url))
        try:
            master_guid = str(misc.GUID(ldb.Dn(ctx.samdb, res[0]['fSMORoleOwner'][0].decode('utf8')).get_extended_component('GUID')))
        except KeyError:
            raise DCJoinException("Can't find GUID in naming master on partition DN %s" % res[0]['fSMORoleOwner'][0])

        master_host = '%s._msdcs.%s' % (master_guid, ctx.dnsforest)
        return master_host

    def get_mysid(ctx):
        '''get the SID of the connected user. Only works with w2k8 and later,
           so only used for RODC join'''
        res = ctx.samdb.search(base="", scope=ldb.SCOPE_BASE, attrs=["tokenGroups"])
        binsid = res[0]["tokenGroups"][0]
        return get_string(ctx.samdb.schema_format_value("objectSID", binsid))

    def dn_exists(ctx, dn):
        '''check if a DN exists'''
        try:
            res = ctx.samdb.search(base=dn, scope=ldb.SCOPE_BASE, attrs=[])
        except ldb.LdbError as e5:
            (enum, estr) = e5.args
            if enum == ldb.ERR_NO_SUCH_OBJECT:
                return False
            raise
        return True

    def add_krbtgt_account(ctx):
        '''RODCs need a special krbtgt account'''
        print("Adding %s" % ctx.krbtgt_dn)
        rec = {
            "dn": ctx.krbtgt_dn,
            "objectclass": "user",
            "useraccountcontrol": str(samba.dsdb.UF_NORMAL_ACCOUNT |
                                      samba.dsdb.UF_ACCOUNTDISABLE),
            "showinadvancedviewonly": "TRUE",
            "description": "krbtgt for %s" % ctx.samname}
        ctx.samdb.add(rec, ["rodc_join:1:1"])

        # now we need to search for the samAccountName attribute on the krbtgt DN,
        # as this will have been magically set to the krbtgt number
        res = ctx.samdb.search(base=ctx.krbtgt_dn, scope=ldb.SCOPE_BASE, attrs=["samAccountName"])
        ctx.krbtgt_name = res[0]["samAccountName"][0]

        print("Got krbtgt_name=%s" % ctx.krbtgt_name)

        m = ldb.Message()
        m.dn = ldb.Dn(ctx.samdb, ctx.acct_dn)
        m["msDS-krbTgtLink"] = ldb.MessageElement(ctx.krbtgt_dn,
                                                  ldb.FLAG_MOD_REPLACE, "msDS-krbTgtLink")
        ctx.samdb.modify(m)

        ctx.new_krbtgt_dn = "CN=%s,CN=Users,%s" % (ctx.krbtgt_name, ctx.base_dn)
        print("Renaming %s to %s" % (ctx.krbtgt_dn, ctx.new_krbtgt_dn))
        ctx.samdb.rename(ctx.krbtgt_dn, ctx.new_krbtgt_dn)

    def drsuapi_connect(ctx):
        '''make a DRSUAPI connection to the naming master'''
        binding_options = "seal"
        if ctx.lp.log_level() >= 9:
            binding_options += ",print"
        binding_string = "ncacn_ip_tcp:%s[%s]" % (ctx.server, binding_options)
        ctx.drsuapi = drsuapi.drsuapi(binding_string, ctx.lp, ctx.creds)
        (ctx.drsuapi_handle, ctx.bind_supported_extensions) = drs_utils.drs_DsBind(ctx.drsuapi)

    def create_tmp_samdb(ctx):
        '''create a temporary samdb object for schema queries'''
        ctx.tmp_schema = Schema(ctx.domsid,
                                schemadn=ctx.schema_dn)
        ctx.tmp_samdb = SamDB(session_info=system_session(), url=None, auto_connect=False,
                              credentials=ctx.creds, lp=ctx.lp, global_schema=False,
                              am_rodc=False)
        ctx.tmp_samdb.set_schema(ctx.tmp_schema)

    def build_DsReplicaAttribute(ctx, attrname, attrvalue):
        '''build a DsReplicaAttributeCtr object'''
        r = drsuapi.DsReplicaAttribute()
        r.attid = ctx.tmp_samdb.get_attid_from_lDAPDisplayName(attrname)
        r.value_ctr = 1

    def DsAddEntry(ctx, recs):
        '''add a record via the DRSUAPI DsAddEntry call'''
        if ctx.drsuapi is None:
            ctx.drsuapi_connect()
        if ctx.tmp_samdb is None:
            ctx.create_tmp_samdb()

        objects = []
        for rec in recs:
            id = drsuapi.DsReplicaObjectIdentifier()
            id.dn = rec['dn']

            attrs = []
            for a in rec:
                if a == 'dn':
                    continue
                if not isinstance(rec[a], list):
                    v = [rec[a]]
                else:
                    v = rec[a]
                v = [x.encode('utf8') if isinstance(x, text_type) else x for x in v]
                rattr = ctx.tmp_samdb.dsdb_DsReplicaAttribute(ctx.tmp_samdb, a, v)
                attrs.append(rattr)

            attribute_ctr = drsuapi.DsReplicaAttributeCtr()
            attribute_ctr.num_attributes = len(attrs)
            attribute_ctr.attributes = attrs

            object = drsuapi.DsReplicaObject()
            object.identifier = id
            object.attribute_ctr = attribute_ctr

            list_object = drsuapi.DsReplicaObjectListItem()
            list_object.object = object
            objects.append(list_object)

        req2 = drsuapi.DsAddEntryRequest2()
        req2.first_object = objects[0]
        prev = req2.first_object
        for o in objects[1:]:
            prev.next_object = o
            prev = o

        (level, ctr) = ctx.drsuapi.DsAddEntry(ctx.drsuapi_handle, 2, req2)
        if level == 2:
            if ctr.dir_err != drsuapi.DRSUAPI_DIRERR_OK:
                print("DsAddEntry failed with dir_err %u" % ctr.dir_err)
                raise RuntimeError("DsAddEntry failed")
            if ctr.extended_err[0] != werror.WERR_SUCCESS:
                print("DsAddEntry failed with status %s info %s" % (ctr.extended_err))
                raise RuntimeError("DsAddEntry failed")
        if level == 3:
            if ctr.err_ver != 1:
                raise RuntimeError("expected err_ver 1, got %u" % ctr.err_ver)
            if ctr.err_data.status[0] != werror.WERR_SUCCESS:
                if ctr.err_data.info is None:
                    print("DsAddEntry failed with status %s, info omitted" % (ctr.err_data.status[1]))
                else:
                    print("DsAddEntry failed with status %s info %s" % (ctr.err_data.status[1],
                                                                        ctr.err_data.info.extended_err))
                raise RuntimeError("DsAddEntry failed")
            if ctr.err_data.dir_err != drsuapi.DRSUAPI_DIRERR_OK:
                print("DsAddEntry failed with dir_err %u" % ctr.err_data.dir_err)
                raise RuntimeError("DsAddEntry failed")

        return ctr.objects

    def join_ntdsdsa_obj(ctx):
        '''return the ntdsdsa object to add'''

        print("Adding %s" % ctx.ntds_dn)

        # When joining Windows, the order of certain attributes (mostly only
        # msDS-HasMasterNCs and HasMasterNCs) seems to matter
        rec = OrderedDict([
            ("dn", ctx.ntds_dn),
            ("objectclass", "nTDSDSA"),
            ("systemFlags", str(samba.dsdb.SYSTEM_FLAG_DISALLOW_MOVE_ON_DELETE)),
            ("dMDLocation", ctx.schema_dn)])

        nc_list = [ctx.base_dn, ctx.config_dn, ctx.schema_dn]

        if ctx.behavior_version >= samba.dsdb.DS_DOMAIN_FUNCTION_2003:
            rec["msDS-Behavior-Version"] = str(samba.dsdb.DS_DOMAIN_FUNCTION_2008_R2)

        if ctx.behavior_version >= samba.dsdb.DS_DOMAIN_FUNCTION_2003:
            rec["msDS-HasDomainNCs"] = ctx.base_dn

        if ctx.RODC:
            rec["objectCategory"] = "CN=NTDS-DSA-RO,%s" % ctx.schema_dn
            rec["msDS-HasFullReplicaNCs"] = ctx.full_nc_list
            rec["options"] = "37"
        else:
            rec["objectCategory"] = "CN=NTDS-DSA,%s" % ctx.schema_dn

            # Note that Windows seems to have an undocumented requirement that
            # the msDS-HasMasterNCs attribute occurs before HasMasterNCs
            if ctx.behavior_version >= samba.dsdb.DS_DOMAIN_FUNCTION_2003:
                rec["msDS-HasMasterNCs"] = ctx.full_nc_list

            rec["HasMasterNCs"]      = []
            for nc in nc_list:
                if nc in ctx.full_nc_list:
                    rec["HasMasterNCs"].append(nc)

            rec["options"] = "1"
            rec["invocationId"] = ndr_pack(ctx.invocation_id)

        return rec

    def join_add_ntdsdsa(ctx):
        '''add the ntdsdsa object'''

        rec = ctx.join_ntdsdsa_obj()
        if ctx.forced_local_samdb:
            ctx.samdb.add(rec, controls=["relax:0"])
        elif ctx.RODC:
            ctx.samdb.add(rec, ["rodc_join:1:1"])
        else:
            ctx.DsAddEntry([rec])

        # find the GUID of our NTDS DN
        res = ctx.samdb.search(base=ctx.ntds_dn, scope=ldb.SCOPE_BASE, attrs=["objectGUID"])
        ctx.ntds_guid = misc.GUID(ctx.samdb.schema_format_value("objectGUID", res[0]["objectGUID"][0]))

    def join_add_objects(ctx, specified_sid=None):
        '''add the various objects needed for the join'''
        if ctx.acct_dn:
            print("Adding %s" % ctx.acct_dn)
            rec = {
                "dn": ctx.acct_dn,
                "objectClass": "computer",
                "displayname": ctx.samname,
                "samaccountname": ctx.samname,
                "userAccountControl": str(ctx.userAccountControl | samba.dsdb.UF_ACCOUNTDISABLE),
                "dnshostname": ctx.dnshostname}
            if ctx.behavior_version >= samba.dsdb.DS_DOMAIN_FUNCTION_2008:
                rec['msDS-SupportedEncryptionTypes'] = str(samba.dsdb.ENC_ALL_TYPES)
            elif ctx.promote_existing:
                rec['msDS-SupportedEncryptionTypes'] = []
            if ctx.managedby:
                rec["managedby"] = ctx.managedby
            elif ctx.promote_existing:
                rec["managedby"] = []

            if ctx.never_reveal_sid:
                rec["msDS-NeverRevealGroup"] = ctx.never_reveal_sid
            elif ctx.promote_existing:
                rec["msDS-NeverRevealGroup"] = []

            if ctx.reveal_sid:
                rec["msDS-RevealOnDemandGroup"] = ctx.reveal_sid
            elif ctx.promote_existing:
                rec["msDS-RevealOnDemandGroup"] = []

            if specified_sid:
                rec["objectSid"] = ndr_pack(specified_sid)

            if ctx.promote_existing:
                if ctx.promote_from_dn != ctx.acct_dn:
                    ctx.samdb.rename(ctx.promote_from_dn, ctx.acct_dn)
                ctx.samdb.modify(ldb.Message.from_dict(ctx.samdb, rec, ldb.FLAG_MOD_REPLACE))
            else:
                controls = None
                if specified_sid is not None:
                    controls = ["relax:0"]
                ctx.samdb.add(rec, controls=controls)

        if ctx.krbtgt_dn:
            ctx.add_krbtgt_account()

        if ctx.server_dn:
            print("Adding %s" % ctx.server_dn)
            rec = {
                "dn": ctx.server_dn,
                "objectclass": "server",
                # windows uses 50000000 decimal for systemFlags. A windows hex/decimal mixup bug?
                "systemFlags": str(samba.dsdb.SYSTEM_FLAG_CONFIG_ALLOW_RENAME |
                                   samba.dsdb.SYSTEM_FLAG_CONFIG_ALLOW_LIMITED_MOVE |
                                   samba.dsdb.SYSTEM_FLAG_DISALLOW_MOVE_ON_DELETE),
                # windows seems to add the dnsHostName later
                "dnsHostName": ctx.dnshostname}

            if ctx.acct_dn:
                rec["serverReference"] = ctx.acct_dn

            ctx.samdb.add(rec)

        if ctx.subdomain:
            # the rest is done after replication
            ctx.ntds_guid = None
            return

        if ctx.ntds_dn:
            ctx.join_add_ntdsdsa()

            # Add the Replica-Locations or RO-Replica-Locations attributes
            # TODO Is this supposed to be for the schema partition too?
            expr = "(&(objectClass=crossRef)(ncName=%s))" % ldb.binary_encode(ctx.domaindns_zone)
            domain = (ctx.samdb.search(scope=ldb.SCOPE_ONELEVEL,
                                       attrs=[],
                                       base=ctx.samdb.get_partitions_dn(),
                                       expression=expr), ctx.domaindns_zone)

            expr = "(&(objectClass=crossRef)(ncName=%s))" % ldb.binary_encode(ctx.forestdns_zone)
            forest = (ctx.samdb.search(scope=ldb.SCOPE_ONELEVEL,
                                       attrs=[],
                                       base=ctx.samdb.get_partitions_dn(),
                                       expression=expr), ctx.forestdns_zone)

            for part, zone in (domain, forest):
                if zone not in ctx.nc_list:
                    continue

                if len(part) == 1:
                    m = ldb.Message()
                    m.dn = part[0].dn
                    attr = "msDS-NC-Replica-Locations"
                    if ctx.RODC:
                        attr = "msDS-NC-RO-Replica-Locations"

                    m[attr] = ldb.MessageElement(ctx.ntds_dn,
                                                 ldb.FLAG_MOD_ADD, attr)
                    ctx.samdb.modify(m)

        if ctx.connection_dn is not None:
            print("Adding %s" % ctx.connection_dn)
            rec = {
                "dn": ctx.connection_dn,
                "objectclass": "nTDSConnection",
                "enabledconnection": "TRUE",
                "options": "65",
                "fromServer": ctx.dc_ntds_dn}
            ctx.samdb.add(rec)

        if ctx.acct_dn:
            print("Adding SPNs to %s" % ctx.acct_dn)
            m = ldb.Message()
            m.dn = ldb.Dn(ctx.samdb, ctx.acct_dn)
            for i in range(len(ctx.SPNs)):
                ctx.SPNs[i] = ctx.SPNs[i].replace("$NTDSGUID", str(ctx.ntds_guid))
            m["servicePrincipalName"] = ldb.MessageElement(ctx.SPNs,
                                                           ldb.FLAG_MOD_REPLACE,
                                                           "servicePrincipalName")
            ctx.samdb.modify(m)

            # The account password set operation should normally be done over
            # LDAP. Windows 2000 DCs however allow this only with SSL
            # connections which are hard to set up and otherwise refuse with
            # ERR_UNWILLING_TO_PERFORM. In this case we fall back to libnet
            # over SAMR.
            print("Setting account password for %s" % ctx.samname)
            try:
                ctx.samdb.setpassword("(&(objectClass=user)(sAMAccountName=%s))"
                                      % ldb.binary_encode(ctx.samname),
                                      ctx.acct_pass,
                                      force_change_at_next_login=False,
                                      username=ctx.samname)
            except ldb.LdbError as e2:
                (num, _) = e2.args
                if num != ldb.ERR_UNWILLING_TO_PERFORM:
                    raise
                ctx.net.set_password(account_name=ctx.samname,
                                     domain_name=ctx.domain_name,
                                     newpassword=ctx.acct_pass)

            res = ctx.samdb.search(base=ctx.acct_dn, scope=ldb.SCOPE_BASE,
                                   attrs=["msDS-KeyVersionNumber",
                                          "objectSID"])
            if "msDS-KeyVersionNumber" in res[0]:
                ctx.key_version_number = int(res[0]["msDS-KeyVersionNumber"][0])
            else:
                ctx.key_version_number = None

            ctx.new_dc_account_sid = ndr_unpack(security.dom_sid,
                                                res[0]["objectSid"][0])

            print("Enabling account")
            m = ldb.Message()
            m.dn = ldb.Dn(ctx.samdb, ctx.acct_dn)
            m["userAccountControl"] = ldb.MessageElement(str(ctx.userAccountControl),
                                                         ldb.FLAG_MOD_REPLACE,
                                                         "userAccountControl")
            ctx.samdb.modify(m)

        if ctx.dns_backend.startswith("BIND9_"):
            ctx.dnspass = samba.generate_random_password(128, 255)

            recs = ctx.samdb.parse_ldif(read_and_sub_file(setup_path("provision_dns_add_samba.ldif"),
                                                          {"DNSDOMAIN": ctx.dnsdomain,
                                                           "DOMAINDN": ctx.base_dn,
                                                           "HOSTNAME": ctx.myname,
                                                           "DNSPASS_B64": b64encode(ctx.dnspass.encode('utf-16-le')).decode('utf8'),
                                                           "DNSNAME": ctx.dnshostname}))
            for changetype, msg in recs:
                assert changetype == ldb.CHANGETYPE_NONE
                dns_acct_dn = msg["dn"]
                print("Adding DNS account %s with dns/ SPN" % msg["dn"])

                # Remove dns password (we will set it as a modify, as we can't do clearTextPassword over LDAP)
                del msg["clearTextPassword"]
                # Remove isCriticalSystemObject for similar reasons, it cannot be set over LDAP
                del msg["isCriticalSystemObject"]
                # Disable account until password is set
                msg["userAccountControl"] = str(samba.dsdb.UF_NORMAL_ACCOUNT |
                                                samba.dsdb.UF_ACCOUNTDISABLE)
                try:
                    ctx.samdb.add(msg)
                except ldb.LdbError as e:
                    (num, _) = e.args
                    if num != ldb.ERR_ENTRY_ALREADY_EXISTS:
                        raise

            # The account password set operation should normally be done over
            # LDAP. Windows 2000 DCs however allow this only with SSL
            # connections which are hard to set up and otherwise refuse with
            # ERR_UNWILLING_TO_PERFORM. In this case we fall back to libnet
            # over SAMR.
            print("Setting account password for dns-%s" % ctx.myname)
            try:
                ctx.samdb.setpassword("(&(objectClass=user)(samAccountName=dns-%s))"
                                      % ldb.binary_encode(ctx.myname),
                                      ctx.dnspass,
                                      force_change_at_next_login=False,
                                      username=ctx.samname)
            except ldb.LdbError as e3:
                (num, _) = e3.args
                if num != ldb.ERR_UNWILLING_TO_PERFORM:
                    raise
                ctx.net.set_password(account_name="dns-%s" % ctx.myname,
                                     domain_name=ctx.domain_name,
                                     newpassword=ctx.dnspass)

            res = ctx.samdb.search(base=dns_acct_dn, scope=ldb.SCOPE_BASE,
                                   attrs=["msDS-KeyVersionNumber"])
            if "msDS-KeyVersionNumber" in res[0]:
                ctx.dns_key_version_number = int(res[0]["msDS-KeyVersionNumber"][0])
            else:
                ctx.dns_key_version_number = None

    def join_add_objects2(ctx):
        """add the various objects needed for the join, for subdomains post replication"""

        print("Adding %s" % ctx.partition_dn)
        name_map = {'SubdomainAdmins': "%s-%s" % (str(ctx.domsid), security.DOMAIN_RID_ADMINS)}
        sd_binary = descriptor.get_paritions_crossref_subdomain_descriptor(ctx.forestsid, name_map=name_map)
        rec = {
            "dn": ctx.partition_dn,
            "objectclass": "crossRef",
            "objectCategory": "CN=Cross-Ref,%s" % ctx.schema_dn,
            "nCName": ctx.base_dn,
            "nETBIOSName": ctx.domain_name,
            "dnsRoot": ctx.dnsdomain,
            "trustParent": ctx.parent_partition_dn,
            "systemFlags": str(samba.dsdb.SYSTEM_FLAG_CR_NTDS_NC |samba.dsdb.SYSTEM_FLAG_CR_NTDS_DOMAIN),
            "ntSecurityDescriptor": sd_binary,
        }

        if ctx.behavior_version >= samba.dsdb.DS_DOMAIN_FUNCTION_2003:
            rec["msDS-Behavior-Version"] = str(ctx.behavior_version)

        rec2 = ctx.join_ntdsdsa_obj()

        objects = ctx.DsAddEntry([rec, rec2])
        if len(objects) != 2:
            raise DCJoinException("Expected 2 objects from DsAddEntry")

        ctx.ntds_guid = objects[1].guid

        print("Replicating partition DN")
        ctx.repl.replicate(ctx.partition_dn,
                           misc.GUID("00000000-0000-0000-0000-000000000000"),
                           ctx.ntds_guid,
                           exop=drsuapi.DRSUAPI_EXOP_REPL_OBJ,
                           replica_flags=drsuapi.DRSUAPI_DRS_WRIT_REP)

        print("Replicating NTDS DN")
        ctx.repl.replicate(ctx.ntds_dn,
                           misc.GUID("00000000-0000-0000-0000-000000000000"),
                           ctx.ntds_guid,
                           exop=drsuapi.DRSUAPI_EXOP_REPL_OBJ,
                           replica_flags=drsuapi.DRSUAPI_DRS_WRIT_REP)

    def join_provision(ctx):
        """Provision the local SAM."""

        print("Calling bare provision")

        smbconf = ctx.lp.configfile

        presult = provision(ctx.logger, system_session(), smbconf=smbconf,
                            targetdir=ctx.targetdir, samdb_fill=FILL_DRS, realm=ctx.realm,
                            rootdn=ctx.root_dn, domaindn=ctx.base_dn,
                            schemadn=ctx.schema_dn, configdn=ctx.config_dn,
                            serverdn=ctx.server_dn, domain=ctx.domain_name,
                            hostname=ctx.myname, domainsid=ctx.domsid,
                            machinepass=ctx.acct_pass, serverrole="active directory domain controller",
                            sitename=ctx.site, lp=ctx.lp, ntdsguid=ctx.ntds_guid,
                            use_ntvfs=ctx.use_ntvfs, dns_backend=ctx.dns_backend,
                            plaintext_secrets=ctx.plaintext_secrets,
                            backend_store=ctx.backend_store,
                            backend_store_size=ctx.backend_store_size,
                            batch_mode=True)
        print("Provision OK for domain DN %s" % presult.domaindn)
        ctx.local_samdb = presult.samdb
        ctx.lp          = presult.lp
        ctx.paths       = presult.paths
        ctx.names       = presult.names

        # Fix up the forestsid, it may be different if we are joining as a subdomain
        ctx.names.forestsid = ctx.forestsid

    def join_provision_own_domain(ctx):
        """Provision the local SAM."""

        # we now operate exclusively on the local database, which
        # we need to reopen in order to get the newly created schema
        # we set the transaction_index_cache_size to 200,000 to ensure it is
        # not too small, if it's too small the performance of the join will
        # be negatively impacted.
        print("Reconnecting to local samdb")
        ctx.samdb = SamDB(url=ctx.local_samdb.url,
                         options=[
                             "transaction_index_cache_size:200000"],
                          session_info=system_session(),
                          lp=ctx.local_samdb.lp,
                          global_schema=False)
        ctx.samdb.set_invocation_id(str(ctx.invocation_id))
        ctx.local_samdb = ctx.samdb

        ctx.logger.info("Finding domain GUID from ncName")
        res = ctx.local_samdb.search(base=ctx.partition_dn, scope=ldb.SCOPE_BASE, attrs=['ncName'],
                                     controls=["extended_dn:1:1", "reveal_internals:0"])

        if 'nCName' not in res[0]:
            raise DCJoinException("Can't find naming context on partition DN %s in %s" % (ctx.partition_dn, ctx.samdb.url))

        try:
            ctx.names.domainguid = str(misc.GUID(ldb.Dn(ctx.samdb, res[0]['ncName'][0].decode('utf8')).get_extended_component('GUID')))
        except KeyError:
            raise DCJoinException("Can't find GUID in naming master on partition DN %s" % res[0]['ncName'][0])

        ctx.logger.info("Got domain GUID %s" % ctx.names.domainguid)

        ctx.logger.info("Calling own domain provision")

        secrets_ldb = Ldb(ctx.paths.secrets, session_info=system_session(), lp=ctx.lp)

        presult = provision_fill(ctx.local_samdb, secrets_ldb,
                                 ctx.logger, ctx.names, ctx.paths,
                                 dom_for_fun_level=DS_DOMAIN_FUNCTION_2003,
                                 targetdir=ctx.targetdir, samdb_fill=FILL_SUBDOMAIN,
                                 machinepass=ctx.acct_pass, serverrole="active directory domain controller",
                                 lp=ctx.lp, hostip=ctx.names.hostip, hostip6=ctx.names.hostip6,
                                 dns_backend=ctx.dns_backend, adminpass=ctx.adminpass)
        print("Provision OK for domain %s" % ctx.names.dnsdomain)

    def create_replicator(ctx, repl_creds, binding_options):
        '''Creates a new DRS object for managing replications'''
        return drs_utils.drs_Replicate(
                "ncacn_ip_tcp:%s[%s]" % (ctx.server, binding_options),
                ctx.lp, repl_creds, ctx.local_samdb, ctx.invocation_id)

    def join_replicate(ctx):
        """Replicate the SAM."""

        print("Starting replication")
        ctx.local_samdb.transaction_start()
        try:
            source_dsa_invocation_id = misc.GUID(ctx.samdb.get_invocation_id())
            if ctx.ntds_guid is None:
                print("Using DS_BIND_GUID_W2K3")
                destination_dsa_guid = misc.GUID(drsuapi.DRSUAPI_DS_BIND_GUID_W2K3)
            else:
                destination_dsa_guid = ctx.ntds_guid

            if ctx.RODC:
                repl_creds = Credentials()
                repl_creds.guess(ctx.lp)
                repl_creds.set_kerberos_state(DONT_USE_KERBEROS)
                repl_creds.set_username(ctx.samname)
                repl_creds.set_password(ctx.acct_pass)
            else:
                repl_creds = ctx.creds

            binding_options = "seal"
            if ctx.lp.log_level() >= 9:
                binding_options += ",print"

            repl = ctx.create_replicator(repl_creds, binding_options)

            repl.replicate(ctx.schema_dn, source_dsa_invocation_id,
                           destination_dsa_guid, schema=True, rodc=ctx.RODC,
                           replica_flags=ctx.replica_flags)
            repl.replicate(ctx.config_dn, source_dsa_invocation_id,
                           destination_dsa_guid, rodc=ctx.RODC,
                           replica_flags=ctx.replica_flags)
            if not ctx.subdomain:
                # Replicate first the critical object for the basedn
                if not ctx.domain_replica_flags & drsuapi.DRSUAPI_DRS_CRITICAL_ONLY:
                    print("Replicating critical objects from the base DN of the domain")
                    ctx.domain_replica_flags |= drsuapi.DRSUAPI_DRS_CRITICAL_ONLY
                    repl.replicate(ctx.base_dn, source_dsa_invocation_id,
                                   destination_dsa_guid, rodc=ctx.RODC,
                                   replica_flags=ctx.domain_replica_flags)
                    ctx.domain_replica_flags ^= drsuapi.DRSUAPI_DRS_CRITICAL_ONLY
                repl.replicate(ctx.base_dn, source_dsa_invocation_id,
                               destination_dsa_guid, rodc=ctx.RODC,
                               replica_flags=ctx.domain_replica_flags)
            print("Done with always replicated NC (base, config, schema)")

            # At this point we should already have an entry in the ForestDNS
            # and DomainDNS NC (those under CN=Partions,DC=...) in order to
            # indicate that we hold a replica for this NC.
            for nc in (ctx.domaindns_zone, ctx.forestdns_zone):
                if nc in ctx.nc_list:
                    print("Replicating %s" % (str(nc)))
                    repl.replicate(nc, source_dsa_invocation_id,
                                   destination_dsa_guid, rodc=ctx.RODC,
                                   replica_flags=ctx.replica_flags)

            if ctx.RODC:
                repl.replicate(ctx.acct_dn, source_dsa_invocation_id,
                               destination_dsa_guid,
                               exop=drsuapi.DRSUAPI_EXOP_REPL_SECRET, rodc=True)
                repl.replicate(ctx.new_krbtgt_dn, source_dsa_invocation_id,
                               destination_dsa_guid,
                               exop=drsuapi.DRSUAPI_EXOP_REPL_SECRET, rodc=True)
            elif ctx.rid_manager_dn is not None:
                # Try and get a RID Set if we can.  This is only possible against the RID Master.  Warn otherwise.
                try:
                    repl.replicate(ctx.rid_manager_dn, source_dsa_invocation_id,
                                   destination_dsa_guid,
                                   exop=drsuapi.DRSUAPI_EXOP_FSMO_RID_ALLOC)
                except samba.DsExtendedError as e1:
                    (enum, estr) = e1.args
                    if enum == drsuapi.DRSUAPI_EXOP_ERR_FSMO_NOT_OWNER:
                        print("WARNING: Unable to replicate own RID Set, as server %s (the server we joined) is not the RID Master." % ctx.server)
                        print("NOTE: This is normal and expected, Samba will be able to create users after it contacts the RID Master at first startup.")
                    else:
                        raise

            ctx.repl = repl
            ctx.source_dsa_invocation_id = source_dsa_invocation_id
            ctx.destination_dsa_guid = destination_dsa_guid

            print("Committing SAM database")
        except:
            ctx.local_samdb.transaction_cancel()
            raise
        else:
            ctx.local_samdb.transaction_commit()

        # A large replication may have caused our LDB connection to the
        # remote DC to timeout, so check the connection is still alive
        ctx.refresh_ldb_connection()

    def refresh_ldb_connection(ctx):
        try:
            # query the rootDSE to check the connection
            ctx.samdb.search(scope=ldb.SCOPE_BASE, attrs=[])
        except ldb.LdbError as e:
            (enum, estr) = e.args

            # if the connection was disconnected, then reconnect
            if (enum == ldb.ERR_OPERATIONS_ERROR and
                ('NT_STATUS_CONNECTION_DISCONNECTED' in estr or
                 'NT_STATUS_CONNECTION_RESET' in estr)):
                ctx.logger.warning("LDB connection disconnected. Reconnecting")
                ctx.samdb = SamDB(url="ldap://%s" % ctx.server,
                                  session_info=system_session(),
                                  credentials=ctx.creds, lp=ctx.lp)
            else:
                raise DCJoinException(estr)

    def send_DsReplicaUpdateRefs(ctx, dn):
        r = drsuapi.DsReplicaUpdateRefsRequest1()
        r.naming_context = drsuapi.DsReplicaObjectIdentifier()
        r.naming_context.dn = str(dn)
        r.naming_context.guid = misc.GUID("00000000-0000-0000-0000-000000000000")
        r.naming_context.sid = security.dom_sid("S-0-0")
        r.dest_dsa_guid = ctx.ntds_guid
        r.dest_dsa_dns_name = "%s._msdcs.%s" % (str(ctx.ntds_guid), ctx.dnsforest)
        r.options = drsuapi.DRSUAPI_DRS_ADD_REF | drsuapi.DRSUAPI_DRS_DEL_REF
        if not ctx.RODC:
            r.options |= drsuapi.DRSUAPI_DRS_WRIT_REP

        if ctx.drsuapi is None:
            ctx.drsuapi_connect()

        ctx.drsuapi.DsReplicaUpdateRefs(ctx.drsuapi_handle, 1, r)

    def join_add_dns_records(ctx):
        """Remotely Add a DNS record to the target DC.  We assume that if we
           replicate DNS that the server holds the DNS roles and can accept
           updates.

           This avoids issues getting replication going after the DC
           first starts as the rest of the domain does not have to
           wait for samba_dnsupdate to run successfully.

           Specifically, we add the records implied by the DsReplicaUpdateRefs
           call above.

           We do not just run samba_dnsupdate as we want to strictly
           operate against the DC we just joined:
            - We do not want to query another DNS server
            - We do not want to obtain a Kerberos ticket
              (as the KDC we select may not be the DC we just joined,
              and so may not be in sync with the password we just set)
            - We do not wish to set the _ldap records until we have started
            - We do not wish to use NTLM (the --use-samba-tool mode forces
              NTLM)

        """

        client_version = dnsserver.DNS_CLIENT_VERSION_LONGHORN
        select_flags = dnsserver.DNS_RPC_VIEW_AUTHORITY_DATA |\
            dnsserver.DNS_RPC_VIEW_NO_CHILDREN

        zone = ctx.dnsdomain
        msdcs_zone = "_msdcs.%s" % ctx.dnsforest
        name = ctx.myname
        msdcs_cname = str(ctx.ntds_guid)
        cname_target = "%s.%s" % (name, zone)
        IPs = samba.interface_ips(ctx.lp, ctx.force_all_ips)

        ctx.logger.info("Adding %d remote DNS records for %s.%s" %
                        (len(IPs), name, zone))

        binding_options = "sign"
        dns_conn = dnsserver.dnsserver("ncacn_ip_tcp:%s[%s]" % (ctx.server, binding_options),
                                       ctx.lp, ctx.creds)

        name_found = True

        sd_helper = sd_utils.SDUtils(ctx.samdb)

        change_owner_sd = security.descriptor()
        change_owner_sd.owner_sid = ctx.new_dc_account_sid
        change_owner_sd.group_sid = security.dom_sid("%s-%d" %
                                                     (str(ctx.domsid),
                                                      security.DOMAIN_RID_DCS))

        # TODO: Remove any old records from the primary DNS name
        try:
            (buflen, res) \
                = dns_conn.DnssrvEnumRecords2(client_version,
                                              0,
                                              ctx.server,
                                              zone,
                                              name,
                                              None,
                                              dnsp.DNS_TYPE_ALL,
                                              select_flags,
                                              None,
                                              None)
        except WERRORError as e:
            if e.args[0] == werror.WERR_DNS_ERROR_NAME_DOES_NOT_EXIST:
                name_found = False
                pass

        if name_found:
            for rec in res.rec:
                for record in rec.records:
                    if record.wType == dnsp.DNS_TYPE_A or \
                       record.wType == dnsp.DNS_TYPE_AAAA:
                        # delete record
                        del_rec_buf = dnsserver.DNS_RPC_RECORD_BUF()
                        del_rec_buf.rec = record
                        try:
                            dns_conn.DnssrvUpdateRecord2(client_version,
                                                         0,
                                                         ctx.server,
                                                         zone,
                                                         name,
                                                         None,
                                                         del_rec_buf)
                        except WERRORError as e:
                            if e.args[0] == werror.WERR_DNS_ERROR_NAME_DOES_NOT_EXIST:
                                pass
                            else:
                                raise

        for IP in IPs:
            if IP.find(':') != -1:
                ctx.logger.info("Adding DNS AAAA record %s.%s for IPv6 IP: %s"
                                % (name, zone, IP))
                rec = AAAARecord(IP)
            else:
                ctx.logger.info("Adding DNS A record %s.%s for IPv4 IP: %s"
                                % (name, zone, IP))
                rec = ARecord(IP)

            # Add record
            add_rec_buf = dnsserver.DNS_RPC_RECORD_BUF()
            add_rec_buf.rec = rec
            dns_conn.DnssrvUpdateRecord2(client_version,
                                         0,
                                         ctx.server,
                                         zone,
                                         name,
                                         add_rec_buf,
                                         None)

        if (len(IPs) > 0):
            domaindns_zone_dn = ldb.Dn(ctx.samdb, ctx.domaindns_zone)
            (ctx.dns_a_dn, ldap_record) \
                = ctx.samdb.dns_lookup("%s.%s" % (name, zone),
                                       dns_partition=domaindns_zone_dn)

            # Make the DC own the DNS record, not the administrator
            sd_helper.modify_sd_on_dn(ctx.dns_a_dn, change_owner_sd,
                                      controls=["sd_flags:1:%d"
                                                % (security.SECINFO_OWNER
                                                   | security.SECINFO_GROUP)])

            # Add record
            ctx.logger.info("Adding DNS CNAME record %s.%s for %s"
                            % (msdcs_cname, msdcs_zone, cname_target))

            add_rec_buf = dnsserver.DNS_RPC_RECORD_BUF()
            rec = CNameRecord(cname_target)
            add_rec_buf.rec = rec
            dns_conn.DnssrvUpdateRecord2(client_version,
                                         0,
                                         ctx.server,
                                         msdcs_zone,
                                         msdcs_cname,
                                         add_rec_buf,
                                         None)

            forestdns_zone_dn = ldb.Dn(ctx.samdb, ctx.forestdns_zone)
            (ctx.dns_cname_dn, ldap_record) \
                = ctx.samdb.dns_lookup("%s.%s" % (msdcs_cname, msdcs_zone),
                                       dns_partition=forestdns_zone_dn)

            # Make the DC own the DNS record, not the administrator
            sd_helper.modify_sd_on_dn(ctx.dns_cname_dn, change_owner_sd,
                                      controls=["sd_flags:1:%d"
                                                % (security.SECINFO_OWNER
                                                   | security.SECINFO_GROUP)])

        ctx.logger.info("All other DNS records (like _ldap SRV records) " +
                        "will be created samba_dnsupdate on first startup")

    def join_replicate_new_dns_records(ctx):
        for nc in (ctx.domaindns_zone, ctx.forestdns_zone):
            if nc in ctx.nc_list:
                ctx.logger.info("Replicating new DNS records in %s" % (str(nc)))
                ctx.repl.replicate(nc, ctx.source_dsa_invocation_id,
                                   ctx.ntds_guid, rodc=ctx.RODC,
                                   replica_flags=ctx.replica_flags,
                                   full_sync=False)

    def join_finalise(ctx):
        """Finalise the join, mark us synchronised and setup secrets db."""

        # FIXME we shouldn't do this in all cases

        # If for some reasons we joined in another site than the one of
        # DC we just replicated from then we don't need to send the updatereplicateref
        # as replication between sites is time based and on the initiative of the
        # requesting DC
        ctx.logger.info("Sending DsReplicaUpdateRefs for all the replicated partitions")
        for nc in ctx.nc_list:
            ctx.send_DsReplicaUpdateRefs(nc)

        if ctx.RODC:
            print("Setting RODC invocationId")
            ctx.local_samdb.set_invocation_id(str(ctx.invocation_id))
            ctx.local_samdb.set_opaque_integer("domainFunctionality",
                                               ctx.behavior_version)
            m = ldb.Message()
            m.dn = ldb.Dn(ctx.local_samdb, "%s" % ctx.ntds_dn)
            m["invocationId"] = ldb.MessageElement(ndr_pack(ctx.invocation_id),
                                                   ldb.FLAG_MOD_REPLACE,
                                                   "invocationId")
            ctx.local_samdb.modify(m)

            # Note: as RODC the invocationId is only stored
            # on the RODC itself, the other DCs never see it.
            #
            # Thats is why we fix up the replPropertyMetaData stamp
            # for the 'invocationId' attribute, we need to change
            # the 'version' to '0', this is what windows 2008r2 does as RODC
            #
            # This means if the object on a RWDC ever gets a invocationId
            # attribute, it will have version '1' (or higher), which will
            # will overwrite the RODC local value.
            ctx.local_samdb.set_attribute_replmetadata_version(m.dn,
                                                               "invocationId",
                                                               0)

        ctx.logger.info("Setting isSynchronized and dsServiceName")
        m = ldb.Message()
        m.dn = ldb.Dn(ctx.local_samdb, '@ROOTDSE')
        m["isSynchronized"] = ldb.MessageElement("TRUE", ldb.FLAG_MOD_REPLACE, "isSynchronized")

        guid = ctx.ntds_guid
        m["dsServiceName"] = ldb.MessageElement("<GUID=%s>" % str(guid),
                                                ldb.FLAG_MOD_REPLACE, "dsServiceName")
        ctx.local_samdb.modify(m)

        if ctx.subdomain:
            return

        secrets_ldb = Ldb(ctx.paths.secrets, session_info=system_session(), lp=ctx.lp)

        ctx.logger.info("Setting up secrets database")
        secretsdb_self_join(secrets_ldb, domain=ctx.domain_name,
                            realm=ctx.realm,
                            dnsdomain=ctx.dnsdomain,
                            netbiosname=ctx.myname,
                            domainsid=ctx.domsid,
                            machinepass=ctx.acct_pass,
                            secure_channel_type=ctx.secure_channel_type,
                            key_version_number=ctx.key_version_number)

        if ctx.dns_backend.startswith("BIND9_"):
            setup_bind9_dns(ctx.local_samdb, secrets_ldb,
                            ctx.names, ctx.paths, ctx.lp, ctx.logger,
                            dns_backend=ctx.dns_backend,
                            dnspass=ctx.dnspass, os_level=ctx.behavior_version,
                            targetdir=ctx.targetdir,
                            key_version_number=ctx.dns_key_version_number)

    def join_setup_trusts(ctx):
        """provision the local SAM."""

        print("Setup domain trusts with server %s" % ctx.server)
        binding_options = ""  # why doesn't signing work here? w2k8r2 claims no session key
        lsaconn = lsa.lsarpc("ncacn_np:%s[%s]" % (ctx.server, binding_options),
                             ctx.lp, ctx.creds)

        objectAttr = lsa.ObjectAttribute()
        objectAttr.sec_qos = lsa.QosInfo()

        pol_handle = lsaconn.OpenPolicy2(''.decode('utf-8'),
                                         objectAttr, security.SEC_FLAG_MAXIMUM_ALLOWED)

        info = lsa.TrustDomainInfoInfoEx()
        info.domain_name.string = ctx.dnsdomain
        info.netbios_name.string = ctx.domain_name
        info.sid = ctx.domsid
        info.trust_direction = lsa.LSA_TRUST_DIRECTION_INBOUND | lsa.LSA_TRUST_DIRECTION_OUTBOUND
        info.trust_type = lsa.LSA_TRUST_TYPE_UPLEVEL
        info.trust_attributes = lsa.LSA_TRUST_ATTRIBUTE_WITHIN_FOREST

        try:
            oldname = lsa.String()
            oldname.string = ctx.dnsdomain
            oldinfo = lsaconn.QueryTrustedDomainInfoByName(pol_handle, oldname,
                                                           lsa.LSA_TRUSTED_DOMAIN_INFO_FULL_INFO)
            print("Removing old trust record for %s (SID %s)" % (ctx.dnsdomain, oldinfo.info_ex.sid))
            lsaconn.DeleteTrustedDomain(pol_handle, oldinfo.info_ex.sid)
        except RuntimeError:
            pass

        password_blob = string_to_byte_array(ctx.trustdom_pass.encode('utf-16-le'))

        clear_value = drsblobs.AuthInfoClear()
        clear_value.size = len(password_blob)
        clear_value.password = password_blob

        clear_authentication_information = drsblobs.AuthenticationInformation()
        clear_authentication_information.LastUpdateTime = samba.unix2nttime(int(time.time()))
        clear_authentication_information.AuthType = lsa.TRUST_AUTH_TYPE_CLEAR
        clear_authentication_information.AuthInfo = clear_value

        authentication_information_array = drsblobs.AuthenticationInformationArray()
        authentication_information_array.count = 1
        authentication_information_array.array = [clear_authentication_information]

        outgoing = drsblobs.trustAuthInOutBlob()
        outgoing.count = 1
        outgoing.current = authentication_information_array

        trustpass = drsblobs.trustDomainPasswords()
        confounder = [3] * 512

        for i in range(512):
            confounder[i] = random.randint(0, 255)

        trustpass.confounder = confounder

        trustpass.outgoing = outgoing
        trustpass.incoming = outgoing

        trustpass_blob = ndr_pack(trustpass)

        encrypted_trustpass = arcfour_encrypt(lsaconn.session_key, trustpass_blob)

        auth_blob = lsa.DATA_BUF2()
        auth_blob.size = len(encrypted_trustpass)
        auth_blob.data = string_to_byte_array(encrypted_trustpass)

        auth_info = lsa.TrustDomainInfoAuthInfoInternal()
        auth_info.auth_blob = auth_blob

        trustdom_handle = lsaconn.CreateTrustedDomainEx2(pol_handle,
                                                         info,
                                                         auth_info,
                                                         security.SEC_STD_DELETE)

        rec = {
            "dn": "cn=%s,cn=system,%s" % (ctx.dnsforest, ctx.base_dn),
            "objectclass": "trustedDomain",
            "trustType": str(info.trust_type),
            "trustAttributes": str(info.trust_attributes),
            "trustDirection": str(info.trust_direction),
            "flatname": ctx.forest_domain_name,
            "trustPartner": ctx.dnsforest,
            "trustAuthIncoming": ndr_pack(outgoing),
            "trustAuthOutgoing": ndr_pack(outgoing),
            "securityIdentifier": ndr_pack(ctx.forestsid)
        }
        ctx.local_samdb.add(rec)

        rec = {
            "dn": "cn=%s$,cn=users,%s" % (ctx.forest_domain_name, ctx.base_dn),
            "objectclass": "user",
            "userAccountControl": str(samba.dsdb.UF_INTERDOMAIN_TRUST_ACCOUNT),
            "clearTextPassword": ctx.trustdom_pass.encode('utf-16-le'),
            "samAccountName": "%s$" % ctx.forest_domain_name
        }
        ctx.local_samdb.add(rec)

    def build_nc_lists(ctx):
        # nc_list is the list of naming context (NC) for which we will
        # replicate in and send a updateRef command to the partner DC

        # full_nc_list is the list of naming context (NC) we hold
        # read/write copies of.  These are not subsets of each other.
        ctx.nc_list = [ctx.config_dn, ctx.schema_dn]
        ctx.full_nc_list = [ctx.base_dn, ctx.config_dn, ctx.schema_dn]

        if ctx.subdomain and ctx.dns_backend != "NONE":
            ctx.full_nc_list += [ctx.domaindns_zone]

        elif not ctx.subdomain:
            ctx.nc_list += [ctx.base_dn]

            if ctx.dns_backend != "NONE":
                ctx.nc_list += [ctx.domaindns_zone]
                ctx.nc_list += [ctx.forestdns_zone]
                ctx.full_nc_list += [ctx.domaindns_zone]
                ctx.full_nc_list += [ctx.forestdns_zone]

    def do_join(ctx):
        ctx.build_nc_lists()

        if ctx.promote_existing:
            ctx.promote_possible()
        else:
            ctx.cleanup_old_join()

        try:
            ctx.join_add_objects()
            ctx.join_provision()
            ctx.join_replicate()
            if ctx.subdomain:
                ctx.join_add_objects2()
                ctx.join_provision_own_domain()
                ctx.join_setup_trusts()

            if ctx.dns_backend != "NONE":
                ctx.join_add_dns_records()
                ctx.join_replicate_new_dns_records()

            ctx.join_finalise()
        except:
            try:
                print("Join failed - cleaning up")
            except IOError:
                pass

            # cleanup the failed join (checking we still have a live LDB
            # connection to the remote DC first)
            ctx.refresh_ldb_connection()
            ctx.cleanup_old_join()
            raise


def join_RODC(logger=None, server=None, creds=None, lp=None, site=None, netbios_name=None,
              targetdir=None, domain=None, domain_critical_only=False,
              machinepass=None, use_ntvfs=False, dns_backend=None,
              promote_existing=False, plaintext_secrets=False,
              backend_store=None,
              backend_store_size=None):
    """Join as a RODC."""

    ctx = DCJoinContext(logger, server, creds, lp, site, netbios_name,
                        targetdir, domain, machinepass, use_ntvfs, dns_backend,
                        promote_existing, plaintext_secrets,
                        backend_store=backend_store,
                        backend_store_size=backend_store_size)

    lp.set("workgroup", ctx.domain_name)
    logger.info("workgroup is %s" % ctx.domain_name)

    lp.set("realm", ctx.realm)
    logger.info("realm is %s" % ctx.realm)

    ctx.krbtgt_dn = "CN=krbtgt_%s,CN=Users,%s" % (ctx.myname, ctx.base_dn)

    # setup some defaults for accounts that should be replicated to this RODC
    ctx.never_reveal_sid = [
        "<SID=%s-%s>" % (ctx.domsid, security.DOMAIN_RID_RODC_DENY),
        "<SID=%s>" % security.SID_BUILTIN_ADMINISTRATORS,
        "<SID=%s>" % security.SID_BUILTIN_SERVER_OPERATORS,
        "<SID=%s>" % security.SID_BUILTIN_BACKUP_OPERATORS,
        "<SID=%s>" % security.SID_BUILTIN_ACCOUNT_OPERATORS]
    ctx.reveal_sid = "<SID=%s-%s>" % (ctx.domsid, security.DOMAIN_RID_RODC_ALLOW)

    mysid = ctx.get_mysid()
    admin_dn = "<SID=%s>" % mysid
    ctx.managedby = admin_dn

    ctx.userAccountControl = (samba.dsdb.UF_WORKSTATION_TRUST_ACCOUNT |
                              samba.dsdb.UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION |
                              samba.dsdb.UF_PARTIAL_SECRETS_ACCOUNT)

    ctx.SPNs.extend(["RestrictedKrbHost/%s" % ctx.myname,
                     "RestrictedKrbHost/%s" % ctx.dnshostname])

    ctx.connection_dn = "CN=RODC Connection (FRS),%s" % ctx.ntds_dn
    ctx.secure_channel_type = misc.SEC_CHAN_RODC
    ctx.RODC = True
    ctx.replica_flags |= (drsuapi.DRSUAPI_DRS_SPECIAL_SECRET_PROCESSING |
                          drsuapi.DRSUAPI_DRS_GET_ALL_GROUP_MEMBERSHIP)
    ctx.domain_replica_flags = ctx.replica_flags
    if domain_critical_only:
        ctx.domain_replica_flags |= drsuapi.DRSUAPI_DRS_CRITICAL_ONLY

    ctx.do_join()

    logger.info("Joined domain %s (SID %s) as an RODC" % (ctx.domain_name, ctx.domsid))


def join_DC(logger=None, server=None, creds=None, lp=None, site=None, netbios_name=None,
            targetdir=None, domain=None, domain_critical_only=False,
            machinepass=None, use_ntvfs=False, dns_backend=None,
            promote_existing=False, plaintext_secrets=False,
            backend_store=None,
            backend_store_size=None):
    """Join as a DC."""
    ctx = DCJoinContext(logger, server, creds, lp, site, netbios_name,
                        targetdir, domain, machinepass, use_ntvfs, dns_backend,
                        promote_existing, plaintext_secrets,
                        backend_store=backend_store,
                        backend_store_size=backend_store_size)

    lp.set("workgroup", ctx.domain_name)
    logger.info("workgroup is %s" % ctx.domain_name)

    lp.set("realm", ctx.realm)
    logger.info("realm is %s" % ctx.realm)

    ctx.userAccountControl = samba.dsdb.UF_SERVER_TRUST_ACCOUNT | samba.dsdb.UF_TRUSTED_FOR_DELEGATION

    ctx.SPNs.append('E3514235-4B06-11D1-AB04-00C04FC2DCD2/$NTDSGUID/%s' % ctx.dnsdomain)
    ctx.secure_channel_type = misc.SEC_CHAN_BDC

    ctx.replica_flags |= (drsuapi.DRSUAPI_DRS_WRIT_REP |
                          drsuapi.DRSUAPI_DRS_FULL_SYNC_IN_PROGRESS)
    ctx.domain_replica_flags = ctx.replica_flags
    if domain_critical_only:
        ctx.domain_replica_flags |= drsuapi.DRSUAPI_DRS_CRITICAL_ONLY

    ctx.do_join()
    logger.info("Joined domain %s (SID %s) as a DC" % (ctx.domain_name, ctx.domsid))


def join_clone(logger=None, server=None, creds=None, lp=None,
               targetdir=None, domain=None, include_secrets=False,
               dns_backend="NONE", backend_store=None,
               backend_store_size=None):
    """Creates a local clone of a remote DC."""
    ctx = DCCloneContext(logger, server, creds, lp, targetdir=targetdir,
                         domain=domain, dns_backend=dns_backend,
                         include_secrets=include_secrets,
                         backend_store=backend_store,
                         backend_store_size=backend_store_size)

    lp.set("workgroup", ctx.domain_name)
    logger.info("workgroup is %s" % ctx.domain_name)

    lp.set("realm", ctx.realm)
    logger.info("realm is %s" % ctx.realm)

    ctx.do_join()
    logger.info("Cloned domain %s (SID %s)" % (ctx.domain_name, ctx.domsid))
    return ctx


class DCCloneContext(DCJoinContext):
    """Clones a remote DC."""

    def __init__(ctx, logger=None, server=None, creds=None, lp=None,
                 targetdir=None, domain=None, dns_backend=None,
                 include_secrets=False, backend_store=None,
                 backend_store_size=None):
        super(DCCloneContext, ctx).__init__(logger, server, creds, lp,
                                            targetdir=targetdir, domain=domain,
                                            dns_backend=dns_backend,
                                            backend_store=backend_store,
                                            backend_store_size=backend_store_size)

        # As we don't want to create or delete these DNs, we set them to None
        ctx.server_dn = None
        ctx.ntds_dn = None
        ctx.acct_dn = None
        ctx.myname = ctx.server.split('.')[0]
        ctx.ntds_guid = None
        ctx.rid_manager_dn = None

        # Save this early
        ctx.remote_dc_ntds_guid = ctx.samdb.get_ntds_GUID()

        ctx.replica_flags |= (drsuapi.DRSUAPI_DRS_WRIT_REP |
                              drsuapi.DRSUAPI_DRS_FULL_SYNC_IN_PROGRESS)
        if not include_secrets:
            ctx.replica_flags |= drsuapi.DRSUAPI_DRS_SPECIAL_SECRET_PROCESSING
        ctx.domain_replica_flags = ctx.replica_flags

    def join_finalise(ctx):
        ctx.logger.info("Setting isSynchronized and dsServiceName")
        m = ldb.Message()
        m.dn = ldb.Dn(ctx.local_samdb, '@ROOTDSE')
        m["isSynchronized"] = ldb.MessageElement("TRUE", ldb.FLAG_MOD_REPLACE,
                                                 "isSynchronized")

        # We want to appear to be the server we just cloned
        guid = ctx.remote_dc_ntds_guid
        m["dsServiceName"] = ldb.MessageElement("<GUID=%s>" % str(guid),
                                                ldb.FLAG_MOD_REPLACE,
                                                "dsServiceName")
        ctx.local_samdb.modify(m)

    def do_join(ctx):
        ctx.build_nc_lists()

        # When cloning a DC, we just want to provision a DC locally, then
        # grab the remote DC's entire DB via DRS replication
        ctx.join_provision()
        ctx.join_replicate()
        ctx.join_finalise()


# Used to create a renamed backup of a DC. Renaming the domain means that the
# cloned/backup DC can be started without interfering with the production DC.
class DCCloneAndRenameContext(DCCloneContext):
    """Clones a remote DC, renaming the domain along the way."""

    def __init__(ctx, new_base_dn, new_domain_name, new_realm, logger=None,
                 server=None, creds=None, lp=None, targetdir=None, domain=None,
                 dns_backend=None, include_secrets=True, backend_store=None):
        super(DCCloneAndRenameContext, ctx).__init__(logger, server, creds, lp,
                                                     targetdir=targetdir,
                                                     domain=domain,
                                                     dns_backend=dns_backend,
                                                     include_secrets=include_secrets,
                                                     backend_store=backend_store)
        # store the new DN (etc) that we want the cloned DB to use
        ctx.new_base_dn = new_base_dn
        ctx.new_domain_name = new_domain_name
        ctx.new_realm = new_realm

    def create_replicator(ctx, repl_creds, binding_options):
        """Creates a new DRS object for managing replications"""

        # We want to rename all the domain objects, and the simplest way to do
        # this is during replication. This is because the base DN of the top-
        # level replicated object will flow through to all the objects below it
        binding_str = "ncacn_ip_tcp:%s[%s]" % (ctx.server, binding_options)
        return drs_utils.drs_ReplicateRenamer(binding_str, ctx.lp, repl_creds,
                                              ctx.local_samdb,
                                              ctx.invocation_id,
                                              ctx.base_dn, ctx.new_base_dn)

    def create_non_global_lp(ctx, global_lp):
        '''Creates a non-global LoadParm based on the global LP's settings'''

        # the samba code shares a global LoadParm by default. Here we create a
        # new LoadParm that retains the global settings, but any changes we
        # make to it won't automatically affect the rest of the samba code.
        # The easiest way to do this is to dump the global settings to a
        # temporary smb.conf file, and then load the temp file into a new
        # non-global LoadParm
        fd, tmp_file = tempfile.mkstemp()
        global_lp.dump(False, tmp_file)
        local_lp = samba.param.LoadParm(filename_for_non_global_lp=tmp_file)
        os.remove(tmp_file)
        return local_lp

    def rename_dn(ctx, dn_str):
        '''Uses string substitution to replace the base DN'''
        old_base_dn = ctx.base_dn
        return re.sub('%s$' % old_base_dn, ctx.new_base_dn, dn_str)

    # we want to override the normal DCCloneContext's join_provision() so that
    # use the new domain DNs during the provision. We do this because:
    # - it sets up smb.conf/secrets.ldb with the new realm/workgroup values
    # - it sets up a default SAM DB that uses the new Schema DNs (without which
    #   we couldn't apply the renamed DRS objects during replication)
    def join_provision(ctx):
        """Provision the local (renamed) SAM."""

        print("Provisioning the new (renamed) domain...")

        # the provision() calls make_smbconf() which uses lp.dump()/lp.load()
        # to create a new smb.conf. By default, it uses the global LoadParm to
        # do this, and so it would overwrite the realm/domain values globally.
        # We still need the global LoadParm to retain the old domain's details,
        # so we can connect to (and clone) the existing DC.
        # So, copy the global settings into a non-global LoadParm, which we can
        # then pass into provision(). This generates a new smb.conf correctly,
        # without overwriting the global realm/domain values just yet.
        non_global_lp = ctx.create_non_global_lp(ctx.lp)

        # do the provision with the new/renamed domain DN values
        presult = provision(ctx.logger, system_session(),
                            targetdir=ctx.targetdir, samdb_fill=FILL_DRS,
                            realm=ctx.new_realm, lp=non_global_lp,
                            rootdn=ctx.rename_dn(ctx.root_dn), domaindn=ctx.new_base_dn,
                            schemadn=ctx.rename_dn(ctx.schema_dn),
                            configdn=ctx.rename_dn(ctx.config_dn),
                            domain=ctx.new_domain_name, domainsid=ctx.domsid,
                            serverrole="active directory domain controller",
                            dns_backend=ctx.dns_backend,
                            backend_store=ctx.backend_store)

        print("Provision OK for renamed domain DN %s" % presult.domaindn)
        ctx.local_samdb = presult.samdb
        ctx.paths = presult.paths
