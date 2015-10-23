# Unix SMB/CIFS implementation.
# Copyright Matthieu Patou <mat@matws.net> 2011
# Copyright Andrew Bartlett <abartlet@samba.org> 2008-2015
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
from ldb import LdbError
from samba.ndr import ndr_unpack
from samba.dcerpc import misc

class DemoteException(Exception):
    """Base element for demote errors"""

    def __init__(self, value):
        self.value = value

    def __str__(self):
        return "DemoteException: " + self.value


def remove_sysvol_references(samdb, rdn):
    realm = samdb.domain_dns_name()
    for s in ("CN=Enterprise,CN=Microsoft System Volumes,CN=System",
              "CN=%s,CN=Microsoft System Volumes,CN=System" % realm):
        try:
            samdb.delete(ldb.Dn(samdb,
                                "%s,%s,%s" % (str(rdn), s, str(samdb.get_config_basedn()))))
        except ldb.LdbError, l:
            pass

    for s in ("CN=Topology,CN=Domain System Volume,CN=DFSR-GlobalSettings,CN=System",
              "CN=Domain System Volumes (SYSVOL share),CN=File Replication Service,CN=System"):
        try:
            samdb.delete(ldb.Dn(samdb,
                                "%s,%s,%s" % (str(rdn), s, str(samdb.get_default_basedn()))))
        except ldb.LdbError, l:
            pass

def remove_dns_references(samdb, dnsHostName):

    # Check we are using in-database DNS
    zones = samdb.search(base="", scope=ldb.SCOPE_SUBTREE,
                         expression="(&(objectClass=dnsZone)(!(dc=RootDNSServers)))",
                         attrs=[],
                         controls=["search_options:0:2"])
    if len(zones) == 0:
        return

    try:
        rec = samdb.dns_lookup(dnsHostName)
    except RuntimeError as (enum, estr):
        if enum == 0x000025F2: #WERR_DNS_ERROR_NAME_DOES_NOT_EXIST
              return
        raise DemoteException("lookup of %s failed: %s" % (dnsHostName, estr))
    samdb.dns_replace(dnsHostName, [])

def offline_remove_server(samdb, server_dn,
                          remove_computer_obj=False,
                          remove_server_obj=False,
                          remove_sysvol_obj=False,
                          remove_dns_names=False):
    res = samdb.search("",
                       scope=ldb.SCOPE_BASE, attrs=["dsServiceName"])
    assert len(res) == 1
    my_serviceName = res[0]["dsServiceName"][0]

    # Confirm this is really a server object
    msgs = samdb.search(base=server_dn,
                        attrs=["serverReference", "cn",
                               "dnsHostName"],
                        scope=ldb.SCOPE_BASE,
                        expression="(objectClass=server)")
    msg = msgs[0]
    dc_name = msgs[0]["cn"]

    try:
        computer_dn = ldb.Dn(samdb, msgs[0]["serverReference"][0])
    except KeyError:
        computer_dn = None

    try:
        dnsHostName = msgs[0]["dnsHostName"][0]
    except KeyError:
        dnsHostName = None

    if remove_server_obj:
        # Remove the server DN
        samdb.delete(server_dn)

    if computer_dn is not None:
        computer_msgs = samdb.search(base=computer_dn,
                                     expression="objectclass=computer",
                                     attrs=["msDS-KrbTgtLink",
                                            "rIDSetReferences"],
                                     scope=ldb.SCOPE_BASE)
        if "rIDSetReferences" in computer_msgs[0]:
            samdb.delete(computer_msgs[0]["rIDSetReferences"][0])
        if "msDS-KrbTgtLink" in computer_msgs[0]:
            samdb.delete(computer_msgs[0]["msDS-KrbTgtLink"][0])

        if remove_computer_obj:
            # Delete the computer tree
            samdb.delete(computer_dn, ["tree_delete:0"])

        if "dnsHostName" in msgs[0]:
            dnsHostName = msgs[0]["dnsHostName"][0]

    if dnsHostName is not None and remove_dns_names:
        remove_dns_references(samdb, dnsHostName)

    if remove_sysvol_obj:
        remove_sysvol_references(samdb, "CN=%s" % dc_name)

def offline_remove_ntds_dc(samdb, ntds_dn,
                           remove_computer_obj=False,
                           remove_server_obj=False,
                           remove_connection_obj=False,
                           seize_stale_fsmo=False,
                           remove_sysvol_obj=False,
                           remove_dns_names=False):
    res = samdb.search("",
                       scope=ldb.SCOPE_BASE, attrs=["dsServiceName"])
    assert len(res) == 1
    my_serviceName = ldb.Dn(samdb, res[0]["dsServiceName"][0])
    server_dn = ntds_dn.parent()

    if my_serviceName == ntds_dn:
        raise DemoteException("Refusing to demote our own DSA: %s " % my_serviceName)

    try:
        msgs = samdb.search(base=ntds_dn, expression="objectClass=ntdsDSA",
                        attrs=["objectGUID"], scope=ldb.SCOPE_BASE)
    except LdbError as (enum, estr):
        if enum == ldb.ERR_NO_SUCH_OBJECT:
              raise DemoteException("Given DN %s doesn't exist" % ntds_dn)
        else:
            raise
    if (len(msgs) == 0):
        raise DemoteException("%s is not an ntdsda in %s"
                              % (ntds_dn, samdb.domain_dns_name()))

    msg = msgs[0]
    if (msg.dn.get_rdn_name() != "CN" or
        msg.dn.get_rdn_value() != "NTDS Settings"):
        raise DemoteException("Given DN (%s) wasn't the NTDS Settings DN" %
                              ntds_dn)

    ntds_guid = ndr_unpack(misc.GUID, msg["objectGUID"][0])

    if remove_connection_obj:
        # Find any nTDSConnection objects with that DC as the fromServer.
        # We use the GUID to avoid issues with any () chars in a server
        # name.
        stale_connections = samdb.search(base=samdb.get_config_basedn(),
                                         expression="(&(objectclass=nTDSConnection)"
                                         "(fromServer=<GUID=%s>))" % ntds_guid)
        for conn in stale_connections:
            samdb.delete(conn.dn)

    if seize_stale_fsmo:
        stale_fsmo_roles = samdb.search(base="", scope=ldb.SCOPE_SUBTREE,
                                        expression="(fsmoRoleOwner=<GUID=%s>))"
                                        % ntds_guid,
                                        controls=["search_options:0:2"])
        # Find any FSMO roles they have, give them to this server

        for role in stale_fsmo_roles:
            val = str(my_serviceName)
            m = ldb.Message()
            m.dn = role.dn
            m['value'] = ldb.MessageElement(val, ldb.FLAG_MOD_REPLACE,
                                            'fsmoRoleOwner')
            samdb.modify(m)

    # Remove the NTDS setting tree
    try:
        samdb.delete(ntds_dn, ["tree_delete:0"])
    except LdbError as (enum, estr):
        raise DemoteException("Failed to remove the DCs NTDS DSA object: %s"
                              % estr)

    offline_remove_server(samdb, server_dn,
                          remove_computer_obj=remove_computer_obj,
                          remove_server_obj=remove_server_obj,
                          remove_sysvol_obj=remove_sysvol_obj,
                          remove_dns_names=remove_dns_names)


def remove_dc(samdb, dc_name):

    # TODO: Check if this is the last server (covered mostly by
    # refusing to remove our own name)

    samdb.transaction_start()

    msgs = samdb.search(base=samdb.get_config_basedn(),
                        attrs=["serverReference"],
                        expression="(&(objectClass=server)(cn=%s))"
                    % ldb.binary_encode(dc_name))
    if (len(msgs) == 0):
        raise DemoteException("%s is not an AD DC in %s"
                              % (dc_name, samdb.domain_dns_name()))
    server_dn = msgs[0].dn

    ntds_dn = ldb.Dn(samdb, "CN=NTDS Settings")
    ntds_dn.add_base(msgs[0].dn)

    # Confirm this is really an ntdsDSA object
    try:
        msgs = samdb.search(base=ntds_dn, attrs=[], scope=ldb.SCOPE_BASE,
                            expression="(objectClass=ntdsdsa)")
    except LdbError as (enum, estr):
        if enum == ldb.ERR_NO_SUCH_OBJECT:
            offline_remove_server(samdb, msgs[0].dn,
                                  remove_computer_obj=True,
                                  remove_server_obj=True,
                                  remove_sysvol_obj=True,
                                  remove_dns_names=True)

            samdb.transaction_commit()
            return
        else:
            pass

    offline_remove_ntds_dc(samdb, msgs[0].dn,
                           remove_computer_obj=True,
                           remove_server_obj=True,
                           remove_connection_obj=True,
                           seize_stale_fsmo=True,
                           remove_sysvol_obj=True,
                           remove_dns_names=True)

    samdb.transaction_commit()



def offline_remove_dc_RemoveDsServer(samdb, ntds_dn):

    samdb.start_transaction()

    offline_remove_ntds_dc(samdb, ntds_dn)

    samdb.commit_transaction()
