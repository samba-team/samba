#!/usr/bin/env python
#
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

import samba.getopt as options
from samba.auth import system_session
from samba.samdb import SamDB
from samba import gensec
import ldb, samba, sys
from samba.ndr import ndr_pack, ndr_unpack, ndr_print
from samba.dcerpc import security
from samba.dcerpc import drsuapi, misc, netlogon
from samba.credentials import Credentials, DONT_USE_KERBEROS
from samba.provision import secretsdb_self_join, provision, FILL_DRS, find_setup_dir
from samba.net import Net
import logging

class join_ctx:
    '''hold join context variables'''
    pass

def join_rodc(server=None, creds=None, lp=None, site=None, netbios_name=None,
              targetdir=None):
    """join as a RODC"""

    if server is None:
        raise Exception("You must supply a server for a RODC join")

    def del_noerror(samdb, dn):
        try:
            samdb.delete(dn)
            print "Deleted %s" % dn
        except:
            pass

    def cleanup_old_join(ctx):
        '''remove any DNs from a previous join'''
        try:
            # find the krbtgt link
            res = ctx.samdb.search(base=ctx.acct_dn, scope=ldb.SCOPE_BASE, attrs=["msDS-krbTgtLink"])
            del_noerror(ctx.samdb, ctx.acct_dn)
            del_noerror(ctx.samdb, ctx.connection_dn)
            del_noerror(ctx.samdb, ctx.krbtgt_dn)
            del_noerror(ctx.samdb, ctx.ntds_dn)
            del_noerror(ctx.samdb, ctx.server_dn)
            del_noerror(ctx.samdb, ctx.topology_dn)
            ctx.new_krbtgt_dn = res[0]["msDS-Krbtgtlink"][0]
            del_noerror(ctx.samdb, ctx.new_krbtgt_dn)
        except:
            pass

    def get_dsServiceName(samdb):
        res = samdb.search(base="", scope=ldb.SCOPE_BASE, attrs=["dsServiceName"])
        return res[0]["dsServiceName"][0]

    def get_dnsHostName(samdb):
        res = samdb.search(base="", scope=ldb.SCOPE_BASE, attrs=["dnsHostName"])
        return res[0]["dnsHostName"][0]

    def get_mysid(samdb):
        res = samdb.search(base="", scope=ldb.SCOPE_BASE, attrs=["tokenGroups"])
        binsid = res[0]["tokenGroups"][0]
        return samdb.schema_format_value("objectSID", binsid)

    def get_domain_name(samdb):
        # this should be done via CLDAP
        res = samdb.search(base=samdb.get_default_basedn(), scope=ldb.SCOPE_BASE, attrs=["name"])
        return res[0]["name"][0]

    def do_DsBind(drs):
        '''make a DsBind call, returning the binding handle'''
        bind_info = drsuapi.DsBindInfoCtr()
        bind_info.length = 28
        bind_info.info = drsuapi.DsBindInfo28()
        bind_info.info.supported_extensions	|= drsuapi.DRSUAPI_SUPPORTED_EXTENSION_BASE;
	bind_info.info.supported_extensions	|= drsuapi.DRSUAPI_SUPPORTED_EXTENSION_ASYNC_REPLICATION;
	bind_info.info.supported_extensions	|= drsuapi.DRSUAPI_SUPPORTED_EXTENSION_REMOVEAPI;
	bind_info.info.supported_extensions	|= drsuapi.DRSUAPI_SUPPORTED_EXTENSION_MOVEREQ_V2;
	bind_info.info.supported_extensions	|= drsuapi.DRSUAPI_SUPPORTED_EXTENSION_GETCHG_COMPRESS;
	bind_info.info.supported_extensions	|= drsuapi.DRSUAPI_SUPPORTED_EXTENSION_DCINFO_V1;
	bind_info.info.supported_extensions	|= drsuapi.DRSUAPI_SUPPORTED_EXTENSION_RESTORE_USN_OPTIMIZATION;
	bind_info.info.supported_extensions	|= drsuapi.DRSUAPI_SUPPORTED_EXTENSION_KCC_EXECUTE;
	bind_info.info.supported_extensions	|= drsuapi.DRSUAPI_SUPPORTED_EXTENSION_ADDENTRY_V2;
	bind_info.info.supported_extensions	|= drsuapi.DRSUAPI_SUPPORTED_EXTENSION_LINKED_VALUE_REPLICATION;
	bind_info.info.supported_extensions	|= drsuapi.DRSUAPI_SUPPORTED_EXTENSION_DCINFO_V2;
	bind_info.info.supported_extensions	|= drsuapi.DRSUAPI_SUPPORTED_EXTENSION_INSTANCE_TYPE_NOT_REQ_ON_MOD;
	bind_info.info.supported_extensions	|= drsuapi.DRSUAPI_SUPPORTED_EXTENSION_CRYPTO_BIND;
	bind_info.info.supported_extensions	|= drsuapi.DRSUAPI_SUPPORTED_EXTENSION_GET_REPL_INFO;
	bind_info.info.supported_extensions	|= drsuapi.DRSUAPI_SUPPORTED_EXTENSION_STRONG_ENCRYPTION;
	bind_info.info.supported_extensions	|= drsuapi.DRSUAPI_SUPPORTED_EXTENSION_DCINFO_V01;
	bind_info.info.supported_extensions	|= drsuapi.DRSUAPI_SUPPORTED_EXTENSION_TRANSITIVE_MEMBERSHIP;
	bind_info.info.supported_extensions	|= drsuapi.DRSUAPI_SUPPORTED_EXTENSION_ADD_SID_HISTORY;
	bind_info.info.supported_extensions	|= drsuapi.DRSUAPI_SUPPORTED_EXTENSION_POST_BETA3;
	bind_info.info.supported_extensions	|= drsuapi.DRSUAPI_SUPPORTED_EXTENSION_GET_MEMBERSHIPS2;
	bind_info.info.supported_extensions	|= drsuapi.DRSUAPI_SUPPORTED_EXTENSION_GETCHGREQ_V6;
	bind_info.info.supported_extensions	|= drsuapi.DRSUAPI_SUPPORTED_EXTENSION_NONDOMAIN_NCS;
	bind_info.info.supported_extensions	|= drsuapi.DRSUAPI_SUPPORTED_EXTENSION_GETCHGREQ_V8;
	bind_info.info.supported_extensions	|= drsuapi.DRSUAPI_SUPPORTED_EXTENSION_GETCHGREPLY_V5;
	bind_info.info.supported_extensions	|= drsuapi.DRSUAPI_SUPPORTED_EXTENSION_GETCHGREPLY_V6;
	bind_info.info.supported_extensions	|= drsuapi.DRSUAPI_SUPPORTED_EXTENSION_ADDENTRYREPLY_V3;
	bind_info.info.supported_extensions	|= drsuapi.DRSUAPI_SUPPORTED_EXTENSION_GETCHGREPLY_V7;
	bind_info.info.supported_extensions	|= drsuapi.DRSUAPI_SUPPORTED_EXTENSION_VERIFY_OBJECT;
        (info, handle) = drs.DsBind(misc.GUID(drsuapi.DRSUAPI_DS_BIND_GUID), bind_info)
        return handle

    def get_rodc_partial_attribute_set(ctx):
        '''get a list of attributes for RODC replication'''
        partial_attribute_set = drsuapi.DsPartialAttributeSet()
        partial_attribute_set.version = 1

        ctx.attids = []

        # the exact list of attids we send is quite critical. Note that
        # we do ask for the secret attributes, but set set SPECIAL_SECRET_PROCESSING
        # to zero them out
        res = ctx.local_samdb.search(base=ctx.schema_dn, scope=ldb.SCOPE_SUBTREE,
                                     expression="objectClass=attributeSchema",
                                     attrs=["lDAPDisplayName", "systemFlags",
                                            "searchFlags"])
        for r in res:
            ldap_display_name = r["lDAPDisplayName"][0]
            if "systemFlags" in r:
                system_flags      = r["systemFlags"][0]
                if (int(system_flags) & (samba.dsdb.DS_FLAG_ATTR_NOT_REPLICATED |
                                         samba.dsdb.DS_FLAG_ATTR_IS_CONSTRUCTED)):
                    continue
            search_flags = r["searchFlags"][0]
            if (int(search_flags) & samba.dsdb.SEARCH_FLAG_RODC_ATTRIBUTE):
                continue
            attid = ctx.local_samdb.get_attid_from_lDAPDisplayName(ldap_display_name)
            ctx.attids.append(int(attid))

        # the attids do need to be sorted, or windows doesn't return
        # all the attributes we need
        ctx.attids.sort()
        partial_attribute_set.attids         = ctx.attids
        partial_attribute_set.num_attids = len(ctx.attids)
        return partial_attribute_set


    def replicate_partition(ctx, dn, schema=False, exop=drsuapi.DRSUAPI_EXOP_NONE):
        '''replicate a partition'''

        # setup for a GetNCChanges call
        req8 = drsuapi.DsGetNCChangesRequest8()

        req8.destination_dsa_guid           = ctx.ntds_guid
        req8.source_dsa_invocation_id	    = misc.GUID(ctx.samdb.get_invocation_id())
        req8.naming_context		    = drsuapi.DsReplicaObjectIdentifier()
        req8.naming_context.dn              = dn.decode("utf-8")
        req8.highwatermark                  = drsuapi.DsReplicaHighWaterMark()
        req8.highwatermark.tmp_highest_usn  = 0
        req8.highwatermark.reserved_usn	    = 0
        req8.highwatermark.highest_usn	    = 0
        req8.uptodateness_vector	    = None
        if exop == drsuapi.DRSUAPI_EXOP_REPL_SECRET:
            req8.replica_flags		    = 0
        else:
            req8.replica_flags		    =  (drsuapi.DRSUAPI_DRS_INIT_SYNC |
                                                drsuapi.DRSUAPI_DRS_PER_SYNC |
                                                drsuapi.DRSUAPI_DRS_GET_ANC |
                                                drsuapi.DRSUAPI_DRS_NEVER_SYNCED |
                                                drsuapi.DRSUAPI_DRS_SPECIAL_SECRET_PROCESSING)
        req8.max_object_count		     = 402
        req8.max_ndr_size		     = 402116
        req8.extended_op		     = exop
        req8.fsmo_info			     = 0
        req8.partial_attribute_set	     = None
        req8.partial_attribute_set_ex	     = None
        req8.mapping_ctr.num_mappings	     = 0
        req8.mapping_ctr.mappings	     = None

        while True:
            if not schema:
                req8.partial_attribute_set = get_rodc_partial_attribute_set(ctx)
            (level, ctr) = ctx.drs.DsGetNCChanges(ctx.drs_handle, 8, req8)
            net.replicate_chunk(ctx.replication_state, level, ctr, schema=schema)
            if ctr.more_data == 0:
                break
            req8.highwatermark.tmp_highest_usn = ctr.new_highwatermark.tmp_highest_usn


    # main join code
    ctx = join_ctx()
    ctx.creds = creds
    ctx.lp = lp
    ctx.site = site
    ctx.netbios_name = netbios_name
    ctx.targetdir = targetdir
    ctx.server = server

    ctx.creds.set_gensec_features(creds.get_gensec_features() | gensec.FEATURE_SEAL)

    ctx.samdb = SamDB(url="ldap://%s" % ctx.server,
                      session_info=system_session(),
                      credentials=ctx.creds, lp=ctx.lp)

    ctx.myname = netbios_name
    ctx.samname = "%s$" % ctx.myname
    ctx.base_dn = str(ctx.samdb.get_default_basedn())
    ctx.root_dn = str(ctx.samdb.get_root_basedn())
    ctx.schema_dn = str(ctx.samdb.get_schema_basedn())
    ctx.config_dn = str(ctx.samdb.get_config_basedn())
    ctx.domsid = ctx.samdb.get_domain_sid()

    ctx.dc_ntds_dn = get_dsServiceName(ctx.samdb)
    ctx.dc_dnsHostName = get_dnsHostName(ctx.samdb)
    ctx.acct_pass = samba.generate_random_password(12, 32)
    ctx.mysid = get_mysid(ctx.samdb)

    # work out the DNs of all the objects we will be adding
    ctx.admin_dn = "<SID=%s>" % ctx.mysid
    ctx.krbtgt_dn = "CN=krbtgt_%s,CN=Users,%s" % (ctx.myname, ctx.base_dn)
    ctx.server_dn = "CN=%s,CN=Servers,CN=%s,CN=Sites,%s" % (ctx.myname, ctx.site, ctx.config_dn)
    ctx.ntds_dn = "CN=NTDS Settings,%s" % ctx.server_dn
    ctx.connection_dn = "CN=RODC Connection (FRS),%s" % ctx.ntds_dn
    ctx.topology_dn = "CN=%s,CN=Topology,CN=Domain System Volume,CN=DFSR-GlobalSettings,CN=System,%s" % (ctx.myname, ctx.base_dn)

    # we should lookup these SIDs, and have far more never reveal SIDs
    ctx.never_reveal_sid = "%s-572" % ctx.domsid;
    ctx.reveal_sid = "%s-571" % ctx.domsid;

    ctx.dnsdomain = ldb.Dn(ctx.samdb, ctx.base_dn).canonical_str().split('/')[0]
    ctx.realm = ctx.dnsdomain
    ctx.dnshostname = "%s.%s" % (ctx.myname, ctx.dnsdomain)

    ctx.acct_dn = "CN=%s,OU=Domain Controllers,%s" % (ctx.myname, ctx.base_dn)

    cleanup_old_join(ctx)

    print "Adding %s" % ctx.acct_dn
    rec = {
        "dn" : ctx.acct_dn,
        "objectClass": "computer",
        "displayname": ctx.samname,
        "samaccountname" : ctx.samname,
        "useraccountcontrol" : "83890176",
        "managedby" : ctx.admin_dn,
        "dnshostname" : ctx.dnshostname,
        "msDS-NeverRevealGroup" : "<SID=%s>" % ctx.never_reveal_sid,
        "msDS-RevealOnDemandGroup" : "<SID=%s>" % ctx.reveal_sid}
    ctx.samdb.add(rec)

    print "Adding %s" % ctx.krbtgt_dn
    rec = {
        "dn" : ctx.krbtgt_dn,
        "objectclass" : "user",
        "useraccountcontrol" : "514",
        "showinadvancedviewonly" : "TRUE",
        "description" : "tricky account"}
    ctx.samdb.add(rec, ["rodc_join:1:1"])

    # now we need to search for the samAccountName attribute on the krbtgt DN,
    # as this will have been magically set to the krbtgt number
    res = ctx.samdb.search(base=ctx.krbtgt_dn, scope=ldb.SCOPE_BASE, attrs=["samAccountName"])
    ctx.krbtgt_name = res[0]["samAccountName"][0]

    print "Got krbtgt_name=%s" % ctx.krbtgt_name

    m = ldb.Message()
    m.dn = ldb.Dn(ctx.samdb, ctx.acct_dn)
    m["msDS-krbTgtLink"] = ldb.MessageElement(ctx.krbtgt_dn,
                                              ldb.FLAG_MOD_REPLACE, "msDS-krbTgtLink")
    ctx.samdb.modify(m)

    ctx.new_krbtgt_dn = "CN=%s,CN=Users,%s" % (ctx.krbtgt_name, ctx.base_dn)
    print "Renaming %s to %s" % (ctx.krbtgt_dn, ctx.new_krbtgt_dn)
    ctx.samdb.rename(ctx.krbtgt_dn, ctx.new_krbtgt_dn)

    print "Adding %s" % ctx.server_dn
    rec = {
        "dn": ctx.server_dn,
        "objectclass" : "server",
        "systemFlags" : "1375731712",
        "serverReference" : ctx.acct_dn,
        "dnsHostName" : ctx.dnshostname}
    ctx.samdb.add(rec)

    print "Adding %s" % ctx.ntds_dn
    rec = {
        "dn" : ctx.ntds_dn,
        "objectclass" : "nTDSDSA",
        "objectCategory" : "CN=NTDS-DSA-RO,%s" % ctx.schema_dn,
        "systemFlags" : "33554432",
        "dMDLocation" : ctx.schema_dn,
        "options" : "37",
        "msDS-Behavior-Version" : "4",
        "msDS-HasDomainNCs" : ctx.base_dn,
        "msDS-HasFullReplicaNCs" : [ ctx.base_dn, ctx.config_dn, ctx.schema_dn ]}
    ctx.samdb.add(rec, ["rodc_join:1:1"])

    # find the GUID of our NTDS DN
    res = ctx.samdb.search(base=ctx.ntds_dn, scope=ldb.SCOPE_BASE, attrs=["objectGUID"])
    ctx.ntds_guid = misc.GUID(ctx.samdb.schema_format_value("objectGUID", res[0]["objectGUID"][0]))

    print "Adding %s" % ctx.connection_dn
    rec = {
        "dn" : ctx.connection_dn,
        "objectclass" : "nTDSConnection",
        "enabledconnection" : "TRUE",
        "options" : "65",
        "fromServer" : ctx.dc_ntds_dn}
    ctx.samdb.add(rec)

    print "Adding %s" % ctx.topology_dn
    rec = {
        "dn" : ctx.topology_dn,
        "objectclass" : "msDFSR-Member",
        "msDFSR-ComputerReference" : ctx.acct_dn,
        "serverReference" : ctx.ntds_dn}
    ctx.samdb.add(rec)

    print "Adding HOST SPNs to %s" % ctx.acct_dn
    m = ldb.Message()
    m.dn = ldb.Dn(ctx.samdb, ctx.acct_dn)
    SPNs = [ "HOST/%s" % ctx.myname,
             "HOST/%s" % ctx.dnshostname ]
    m["servicePrincipalName"] = ldb.MessageElement(SPNs,
                                                   ldb.FLAG_MOD_ADD,
                                                   "servicePrincipalName")
    ctx.samdb.modify(m)

    print "Adding RestrictedKrbHost SPNs to %s" % ctx.acct_dn
    m = ldb.Message()
    m.dn = ldb.Dn(ctx.samdb, ctx.acct_dn)
    SPNs = [ "RestrictedKrbHost/%s" % ctx.myname,
             "RestrictedKrbHost/%s" % ctx.dnshostname ]
    m["servicePrincipalName"] = ldb.MessageElement(SPNs,
                                                   ldb.FLAG_MOD_ADD,
                                                   "servicePrincipalName")
    ctx.samdb.modify(m)

    print "Setting account password for %s" % ctx.samname
    ctx.samdb.setpassword("(&(objectClass=user)(sAMAccountName=%s))" % ctx.samname,
                      ctx.acct_pass,
                      force_change_at_next_login=False,
                      username=ctx.samname)

    print "Enabling account %s" % ctx.acct_dn
    # weird, its already enabled, but w2k8r2 disables then re-enables again
    m = ldb.Message()
    m.dn = ldb.Dn(ctx.samdb, ctx.acct_dn)
    m["userAccountControl"] = ldb.MessageElement("83890178",
                                                 ldb.FLAG_MOD_REPLACE,
                                                 "userAccountControl")
    ctx.samdb.modify(m)

    m["userAccountControl"] = ldb.MessageElement("83890176",
                                                 ldb.FLAG_MOD_REPLACE,
                                                 "userAccountControl")
    ctx.samdb.modify(m)

    print "Doing DsBind as %s" % ctx.samname

    ctx.acct_creds = Credentials()
    ctx.acct_creds.guess(ctx.lp)
    ctx.acct_creds.set_kerberos_state(DONT_USE_KERBEROS)
    ctx.acct_creds.set_username(ctx.samname)
    ctx.acct_creds.set_password(ctx.acct_pass)

    ctx.drs = drsuapi.drsuapi("ncacn_ip_tcp:%s[seal,print]" % ctx.server, ctx.lp, ctx.acct_creds)
    ctx.drs_handle = do_DsBind(ctx.drs)
    print "DRS Handle: %s" % ctx.drs_handle

    print "Calling DsRGetDCNameEx2"
    netr = netlogon.netlogon("ncacn_np:%s[print]" % ctx.server, ctx.lp, ctx.acct_creds)
    dcname = netr.netr_DsRGetDCNameEx2(server_unc=ctx.dc_dnsHostName.decode("utf-8"),
                                       client_account=None,
                                       mask=0,
                                       domain_name=ctx.dnsdomain.decode("utf-8"),
                                       domain_guid=None, site_name=None,
                                       flags=0x40001020)

    print ndr_print(dcname)
    print "Calling bare provision"

    setup_dir = find_setup_dir()
    logger = logging.getLogger("provision")
    logger.addHandler(logging.StreamHandler(sys.stdout))
    smbconf = lp.configfile

    presult = provision(setup_dir, logger, system_session(), None,
                        smbconf=smbconf, targetdir=targetdir, samdb_fill=FILL_DRS,
                        realm=ctx.realm, rootdn=ctx.root_dn, domaindn=ctx.base_dn,
                        schemadn=ctx.schema_dn,
                        configdn=ctx.config_dn,
                        serverdn=ctx.server_dn, domain=get_domain_name(ctx.samdb),
                        hostname=ctx.myname, hostip="127.0.0.1", domainsid=ctx.domsid,
                        machinepass=ctx.acct_pass, serverrole="domain controller",
                        sitename=ctx.site)
    print "Provision OK for domain DN %s" % presult.domaindn
    ctx.local_samdb = presult.samdb
    ctx.lp          = presult.lp


    print "Starting replication"
    ctx.local_samdb.transaction_start()

    net = Net(creds=ctx.creds, lp=ctx.lp)
    ctx.replication_state = net.replicate_init(ctx.local_samdb, ctx.lp, ctx.drs)

    replicate_partition(ctx, ctx.schema_dn, schema=True)
    replicate_partition(ctx, ctx.config_dn)
    replicate_partition(ctx, ctx.base_dn)
    ctx.local_samdb.transaction_commit()

    ctx.local_samdb.transaction_start()
    replicate_partition(ctx, ctx.acct_dn, exop=drsuapi.DRSUAPI_EXOP_REPL_SECRET)
    replicate_partition(ctx, ctx.new_krbtgt_dn, exop=drsuapi.DRSUAPI_EXOP_REPL_SECRET)

    print "Committing SAM database"
    ctx.local_samdb.transaction_commit()
