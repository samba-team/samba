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
from samba import gensec, Ldb
import ldb, samba, sys
from samba.ndr import ndr_pack, ndr_unpack, ndr_print
from samba.dcerpc import security
from samba.dcerpc import drsuapi, misc, netlogon, nbt
from samba.credentials import Credentials, DONT_USE_KERBEROS
from samba.provision import secretsdb_self_join, provision, FILL_DRS, find_setup_dir
from samba.net import Net
import logging
from samba.drs_utils import drs_Replicate
from samba.dsdb import DS_DOMAIN_FUNCTION_2008_R2

# this makes debugging easier
samba.talloc_enable_null_tracking()

class join_ctx:
    '''hold join context variables'''
    pass

def join_rodc(server=None, creds=None, lp=None, site=None, netbios_name=None,
              targetdir=None, domain=None):
    """join as a RODC"""

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

    def find_dc(ctx, domain):
        '''find a writeable DC for the given domain'''
        ctx.cldap_ret = ctx.net.finddc(domain, nbt.NBT_SERVER_LDAP | nbt.NBT_SERVER_DS | nbt.NBT_SERVER_WRITABLE)
        if ctx.cldap_ret.client_site is not None and ctx.cldap_ret.client_site != "":
            ctx.site = ctx.cldap_ret.client_site
        return ctx.cldap_ret.pdc_dns_name;


    def get_dsServiceName(samdb):
        res = samdb.search(base="", scope=ldb.SCOPE_BASE, attrs=["dsServiceName"])
        return res[0]["dsServiceName"][0]

    def get_dnsHostName(samdb):
        res = samdb.search(base="", scope=ldb.SCOPE_BASE, attrs=["dnsHostName"])
        return res[0]["dnsHostName"][0]

    def get_domain_name(samdb):
        '''get netbios name of the domain from the partitions record'''
        partitions_dn = samdb.get_partitions_dn()
        res = samdb.search(base=partitions_dn, scope=ldb.SCOPE_ONELEVEL, attrs=["nETBIOSName"],
                           expression='ncName=%s' % samdb.get_default_basedn())
        return res[0]["nETBIOSName"][0]

    def get_mysid(samdb):
        res = samdb.search(base="", scope=ldb.SCOPE_BASE, attrs=["tokenGroups"])
        binsid = res[0]["tokenGroups"][0]
        return samdb.schema_format_value("objectSID", binsid)

    def join_add_objects(ctx):
        '''add the various objects needed for the join'''
        print "Adding %s" % ctx.acct_dn
        rec = {
            "dn" : ctx.acct_dn,
            "objectClass": "computer",
            "displayname": ctx.samname,
            "samaccountname" : ctx.samname,
            "useraccountcontrol" : str(samba.dsdb.UF_WORKSTATION_TRUST_ACCOUNT |
                                       samba.dsdb.UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION |
                                       samba.dsdb.UF_PARTIAL_SECRETS_ACCOUNT),
            "managedby" : ctx.admin_dn,
            "dnshostname" : ctx.dnshostname,
            "msDS-NeverRevealGroup" : ctx.never_reveal_sid,
            "msDS-RevealOnDemandGroup" : ctx.reveal_sid}
        ctx.samdb.add(rec)

        print "Adding %s" % ctx.krbtgt_dn
        rec = {
            "dn" : ctx.krbtgt_dn,
            "objectclass" : "user",
            "useraccountcontrol" : str(samba.dsdb.UF_NORMAL_ACCOUNT |
                                       samba.dsdb.UF_ACCOUNTDISABLE),
            "showinadvancedviewonly" : "TRUE",
            "description" : "krbtgt for %s" % ctx.samname}
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
            "systemFlags" : str(samba.dsdb.SYSTEM_FLAG_CONFIG_ALLOW_RENAME |
                                samba.dsdb.SYSTEM_FLAG_CONFIG_ALLOW_LIMITED_MOVE |
                                samba.dsdb.SYSTEM_FLAG_DISALLOW_MOVE_ON_DELETE),
            "serverReference" : ctx.acct_dn,
            "dnsHostName" : ctx.dnshostname}
        ctx.samdb.add(rec)

        # FIXME: the partition (NC) assignment has to be made dynamic
        print "Adding %s" % ctx.ntds_dn
        rec = {
            "dn" : ctx.ntds_dn,
            "objectclass" : "nTDSDSA",
            "objectCategory" : "CN=NTDS-DSA-RO,%s" % ctx.schema_dn,
            "systemFlags" : str(samba.dsdb.SYSTEM_FLAG_DISALLOW_MOVE_ON_DELETE),
            "dMDLocation" : ctx.schema_dn,
            "options" : "37",
            "msDS-Behavior-Version" : str(DS_DOMAIN_FUNCTION_2008_R2),
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
        res = ctx.samdb.search(base=ctx.acct_dn, scope=ldb.SCOPE_BASE, attrs=["msDS-keyVersionNumber"])
        ctx.key_version_number = res[0]["msDS-keyVersionNumber"]


    def join_provision(ctx):
        '''provision the local SAM'''

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
                            serverdn=ctx.server_dn, domain=ctx.domain_name,
                            hostname=ctx.myname, hostip="127.0.0.1", domainsid=ctx.domsid,
                            machinepass=ctx.acct_pass, serverrole="domain controller",
                            sitename=ctx.site)
        print "Provision OK for domain DN %s" % presult.domaindn
        ctx.local_samdb = presult.samdb
        ctx.lp          = presult.lp
        ctx.paths       = presult.paths


    def join_replicate(ctx):
        '''replicate the SAM'''

        print "Starting replication"
        ctx.local_samdb.transaction_start()

        source_dsa_invocation_id = misc.GUID(ctx.samdb.get_invocation_id())

        acct_creds = Credentials()
        acct_creds.guess(ctx.lp)
        acct_creds.set_kerberos_state(DONT_USE_KERBEROS)
        acct_creds.set_username(ctx.samname)
        acct_creds.set_password(ctx.acct_pass)

        repl = drs_Replicate("ncacn_ip_tcp:%s[seal]" % ctx.server, ctx.lp, acct_creds, ctx.local_samdb)

        repl.replicate(ctx.schema_dn, source_dsa_invocation_id, ctx.ntds_guid, schema=True)
        repl.replicate(ctx.config_dn, source_dsa_invocation_id, ctx.ntds_guid)
        repl.replicate(ctx.base_dn, source_dsa_invocation_id, ctx.ntds_guid)
        repl.replicate(ctx.acct_dn, source_dsa_invocation_id, ctx.ntds_guid, exop=drsuapi.DRSUAPI_EXOP_REPL_SECRET)
        repl.replicate(ctx.new_krbtgt_dn, source_dsa_invocation_id, ctx.ntds_guid, exop=drsuapi.DRSUAPI_EXOP_REPL_SECRET)

        print "Committing SAM database"
        ctx.local_samdb.transaction_commit()


    def join_finalise(ctx):
        '''finalise the join, mark us synchronised and setup secrets db'''

        print "Setting isSynchronized"
        m = ldb.Message()
        m.dn = ldb.Dn(ctx.samdb, '@ROOTDSE')
        m["isSynchronized"] = ldb.MessageElement("TRUE", ldb.FLAG_MOD_REPLACE, "isSynchronized")
        ctx.samdb.modify(m)

        secrets_ldb = Ldb(ctx.paths.secrets, session_info=system_session(), lp=ctx.lp)

        print "Setting up secrets database"
        secretsdb_self_join(secrets_ldb, domain=ctx.domain_name,
                            realm=ctx.realm,
                            dnsdomain=ctx.dnsdomain,
                            netbiosname=ctx.myname,
                            domainsid=security.dom_sid(ctx.domsid),
                            machinepass=ctx.acct_pass,
                            secure_channel_type=misc.SEC_CHAN_RODC,
                            key_version_number=ctx.key_version_number)



    # main join code
    ctx = join_ctx()
    ctx.creds = creds
    ctx.lp = lp
    ctx.site = site
    ctx.netbios_name = netbios_name
    ctx.targetdir = targetdir

    ctx.creds.set_gensec_features(creds.get_gensec_features() | gensec.FEATURE_SEAL)
    ctx.net = Net(creds=ctx.creds, lp=ctx.lp)

    if server is not None:
        ctx.server = server
    else:
        ctx.server = find_dc(ctx, domain)

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
    ctx.domain_name = get_domain_name(ctx.samdb)

    lp.set("realm", ctx.domain_name)

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

    # setup some defaults for accounts that should be replicated to this RODC
    ctx.never_reveal_sid = [ "<SID=%s-%s>" % (ctx.domsid, security.DOMAIN_RID_RODC_DENY),
                             "<SID=%s>" % security.SID_BUILTIN_ADMINISTRATORS,
                             "<SID=%s>" % security.SID_BUILTIN_SERVER_OPERATORS,
                             "<SID=%s>" % security.SID_BUILTIN_BACKUP_OPERATORS,
                             "<SID=%s>" % security.SID_BUILTIN_ACCOUNT_OPERATORS ]
    ctx.reveal_sid = "<SID=%s-%s>" % (ctx.domsid, security.DOMAIN_RID_RODC_ALLOW)

    ctx.dnsdomain = ldb.Dn(ctx.samdb, ctx.base_dn).canonical_str().split('/')[0]
    ctx.realm = ctx.dnsdomain
    ctx.dnshostname = "%s.%s" % (ctx.myname, ctx.dnsdomain)

    ctx.acct_dn = "CN=%s,OU=Domain Controllers,%s" % (ctx.myname, ctx.base_dn)

    cleanup_old_join(ctx)
    try:
        join_add_objects(ctx)
        join_provision(ctx)
        join_replicate(ctx)
        join_finalise(ctx)
    except:
        print "Join failed - cleaning up"
        cleanup_old_join(ctx)
        raise

    print "Joined domain %s (SID %s) as an RODC" % (ctx.domain_name, ctx.domsid)

