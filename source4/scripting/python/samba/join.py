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
import ldb, samba
from samba.ndr import ndr_pack, ndr_unpack, ndr_print
from samba.dcerpc import security
from samba.dcerpc import drsuapi, misc, netlogon
from samba.credentials import Credentials, DONT_USE_KERBEROS
from samba.provision import secretsdb_self_join

def join_rodc(server=None, creds=None, lp=None, site=None, netbios_name=None):
    """join as a RODC"""

    if server is None:
        raise Exception("You must supply a server for a RODC join")

    def del_noerror(samdb, dn):
        try:
            samdb.delete(dn)
            print "Deleted %s" % dn
        except:
            pass

    def cleanup_old_join(samdb, acct_dn, server_dn, ntds_dn,
                         krbtgt_dn, connection_dn, topology_dn):
        try:
            # find the krbtgt link
            res = samdb.search(base=acct_dn, scope=ldb.SCOPE_BASE, attrs=["msDS-krbTgtLink"])
            del_noerror(samdb, acct_dn)
            del_noerror(samdb, connection_dn)
            del_noerror(samdb, krbtgt_dn)
            del_noerror(samdb, ntds_dn)
            del_noerror(samdb, server_dn)
            del_noerror(samdb, topology_dn)
            new_krbtgt_dn = res[0]["msDS-Krbtgtlink"][0]
            del_noerror(samdb, new_krbtgt_dn)
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


    creds.set_gensec_features(creds.get_gensec_features() | gensec.FEATURE_SEAL)

    samdb = SamDB(url="ldap://%s" % server,
                  session_info=system_session(),
                  credentials=creds, lp=lp)

    myname = netbios_name
    samname = "%s$" % myname
    base_dn = str(samdb.get_default_basedn())
    domsid = samdb.get_domain_sid()
    dc_ntds_dn = get_dsServiceName(samdb)
    dc_dnsHostName = get_dnsHostName(samdb)
    acct_pass = samba.generate_random_password(12, 32)
    mysid = get_mysid(samdb)

    # work out the DNs of all the objects we will be adding
    admin_dn = "<SID=%s>" % mysid
    krbtgt_dn = "CN=krbtgt_%s,CN=Users,%s" % (myname, base_dn)
    server_dn = "CN=%s,CN=Servers,CN=%s,CN=Sites,%s" % (myname, site, samdb.get_config_basedn())
    ntds_dn = "CN=NTDS Settings,%s" % server_dn
    connection_dn = "CN=RODC Connection (FRS),%s" % ntds_dn
    topology_dn = "CN=%s,CN=Topology,CN=Domain System Volume,CN=DFSR-GlobalSettings,CN=System,%s" % (myname, base_dn)

    never_reveal_sid = "%s-572" % domsid;
    reveal_sid = "%s-571" % domsid;

    dnsdomain = ldb.Dn(samdb, base_dn).canonical_str().split('/')[0]
    dnshostname = "%s.%s" % (myname, dnsdomain)

    acct_dn = "CN=%s,OU=Domain Controllers,%s" % (myname, base_dn)

    cleanup_old_join(samdb, acct_dn, server_dn, ntds_dn,
                          krbtgt_dn, connection_dn, topology_dn)

    print "Adding %s" % acct_dn
    rec = {
        "dn" : acct_dn,
        "objectClass": "computer",
        "displayname": samname,
        "samaccountname" : samname,
        "useraccountcontrol" : "83890176",
        "managedby" : admin_dn,
        "dnshostname" : dnshostname,
        "msDS-NeverRevealGroup" : "<SID=%s>" % never_reveal_sid,
        "msDS-RevealOnDemandGroup" : "<SID=%s>" % reveal_sid}
    samdb.add(rec)

    print "Adding %s" % krbtgt_dn
    rec = {
        "dn" : krbtgt_dn,
        "objectclass" : "user",
        "useraccountcontrol" : "514",
        "showinadvancedviewonly" : "TRUE",
        "description" : "tricky account"}
    samdb.add(rec, ["rodc_join:1:1"])

    # now we need to search for the samAccountName attribute on the krbtgt DN,
    # as this will have been magically set to the krbtgt number
    res = samdb.search(base=krbtgt_dn, scope=ldb.SCOPE_BASE, attrs=["samAccountName"])
    krbtgt_name = res[0]["samAccountName"][0]

    print "Got krbtgt_name=%s" % krbtgt_name

    m = ldb.Message()
    m.dn = ldb.Dn(samdb, acct_dn)
    m["msDS-krbTgtLink"] = ldb.MessageElement(krbtgt_dn,
                                              ldb.FLAG_MOD_REPLACE, "msDS-krbTgtLink")
    samdb.modify(m)

    new_krbtgt_dn = "CN=%s,CN=Users,%s" % (krbtgt_name, base_dn)
    print "Renaming %s to %s" % (krbtgt_dn, new_krbtgt_dn)
    samdb.rename(krbtgt_dn, new_krbtgt_dn)

    print "Adding %s" % server_dn
    rec = {
        "dn": server_dn,
        "objectclass" : "server",
        "systemFlags" : "1375731712",
        "serverReference" : acct_dn,
        "dnsHostName" : dnshostname}
    samdb.add(rec)

    print "Adding %s" % ntds_dn
    rec = {
        "dn" : ntds_dn,
        "objectclass" : "nTDSDSA",
        "objectCategory" : "CN=NTDS-DSA-RO,%s" % samdb.get_schema_basedn(),
        "systemFlags" : "33554432",
        "dMDLocation" : str(samdb.get_schema_basedn()),
        "options" : "37",
        "msDS-Behavior-Version" : "4",
        "msDS-HasDomainNCs" : str(samdb.get_default_basedn()),
        "msDS-HasFullReplicaNCs" : [ str(samdb.get_default_basedn()),
                                     str(samdb.get_config_basedn()),
                                     str(samdb.get_schema_basedn()) ]}
    samdb.add(rec, ["rodc_join:1:1"])

    print "Adding %s" % connection_dn
    rec = {
        "dn" : connection_dn,
        "objectclass" : "nTDSConnection",
        "enabledconnection" : "TRUE",
        "options" : "65",
        "fromServer" : dc_ntds_dn}
    samdb.add(rec)

    print "Adding %s" % topology_dn
    rec = {
        "dn" : topology_dn,
        "objectclass" : "msDFSR-Member",
        "msDFSR-ComputerReference" : acct_dn,
        "serverReference" : ntds_dn}
    samdb.add(rec)

    print "Adding HOST SPNs to %s" % acct_dn
    m = ldb.Message()
    m.dn = ldb.Dn(samdb, acct_dn)
    SPNs = [ "HOST/%s" % myname,
             "HOST/%s" % dnshostname ]
    m["servicePrincipalName"] = ldb.MessageElement(SPNs,
                                                   ldb.FLAG_MOD_ADD,
                                                   "servicePrincipalName")
    samdb.modify(m)

    print "Adding RestrictedKrbHost SPNs to %s" % acct_dn
    m = ldb.Message()
    m.dn = ldb.Dn(samdb, acct_dn)
    SPNs = [ "RestrictedKrbHost/%s" % myname,
             "RestrictedKrbHost/%s" % dnshostname ]
    m["servicePrincipalName"] = ldb.MessageElement(SPNs,
                                                   ldb.FLAG_MOD_ADD,
                                                   "servicePrincipalName")
    samdb.modify(m)

    print "Setting account password for %s" % samname
    samdb.setpassword("(&(objectClass=user)(sAMAccountName=%s))" % samname,
                           acct_pass,
                           force_change_at_next_login=False,
                           username=samname)

    print "Enabling account %s" % acct_dn
    # weird, its already enabled, but w2k8r2 disables then re-enables again
    m = ldb.Message()
    m.dn = ldb.Dn(samdb, acct_dn)
    m["userAccountControl"] = ldb.MessageElement("83890178",
                                                 ldb.FLAG_MOD_REPLACE,
                                                 "userAccountControl")
    samdb.modify(m)

    m["userAccountControl"] = ldb.MessageElement("83890176",
                                                 ldb.FLAG_MOD_REPLACE,
                                                 "userAccountControl")
    samdb.modify(m)

    print "Doing DsBind as %s" % samname

    acct_creds = Credentials()
    acct_creds.guess(lp)
    acct_creds.set_kerberos_state(DONT_USE_KERBEROS)
    acct_creds.set_username(samname)
    acct_creds.set_password(acct_pass)

    drs = drsuapi.drsuapi("ncacn_ip_tcp:w2k8[seal,print]", lp, acct_creds)
    drs_handle = do_DsBind(drs)
    print "DRS Handle: %s" % drs_handle

    print "Calling DsRGetDCNameEx2"
    netr = netlogon.netlogon("ncacn_np:w2k8[print]", lp, acct_creds)
    dcname = netr.netr_DsRGetDCNameEx2(server_unc=dc_dnsHostName.decode("utf-8"),
                                            client_account=None,
                                            mask=0,
                                            domain_name=dnsdomain.decode("utf-8"),
                                            domain_guid=None, site_name=None, flags=0x40001020)

    print "Calling secrets self join"
    secretsdb_self_join()

    print "Note: RODC join is a work in progress - replication not done"
    #print ndr_print(dcname)
