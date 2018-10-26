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

import uuid
import ldb
from ldb import LdbError
from samba import werror
from samba.ndr import ndr_unpack
from samba.dcerpc import misc, dnsp
from samba.dcerpc.dnsp import DNS_TYPE_NS, DNS_TYPE_A, DNS_TYPE_AAAA, \
    DNS_TYPE_CNAME, DNS_TYPE_SRV, DNS_TYPE_PTR


class DemoteException(Exception):
    """Base element for demote errors"""

    def __init__(self, value):
        self.value = value

    def __str__(self):
        return "DemoteException: " + self.value


def remove_sysvol_references(samdb, logger, dc_name):
    # DNs under the Configuration DN:
    realm = samdb.domain_dns_name()
    for s in ("CN=Enterprise,CN=Microsoft System Volumes,CN=System",
              "CN=%s,CN=Microsoft System Volumes,CN=System" % realm):
        dn = ldb.Dn(samdb, s)

        # This is verbose, but it is the safe, escape-proof way
        # to add a base and add an arbitrary RDN.
        if dn.add_base(samdb.get_config_basedn()) == False:
            raise DemoteException("Failed constructing DN %s by adding base %s"
                                  % (dn, samdb.get_config_basedn()))
        if dn.add_child("CN=X") == False:
            raise DemoteException("Failed constructing DN %s by adding child CN=X"
                                  % (dn))
        dn.set_component(0, "CN", dc_name)
        try:
            logger.info("Removing Sysvol reference: %s" % dn)
            samdb.delete(dn)
        except ldb.LdbError as e:
            (enum, estr) = e.args
            if enum == ldb.ERR_NO_SUCH_OBJECT:
                pass
            else:
                raise

    # DNs under the Domain DN:
    for s in ("CN=Domain System Volumes (SYSVOL share),CN=File Replication Service,CN=System",
              "CN=Topology,CN=Domain System Volume,CN=DFSR-GlobalSettings,CN=System"):
        # This is verbose, but it is the safe, escape-proof way
        # to add a base and add an arbitrary RDN.
        dn = ldb.Dn(samdb, s)
        if dn.add_base(samdb.get_default_basedn()) == False:
            raise DemoteException("Failed constructing DN %s by adding base %s"
                                  % (dn, samdb.get_default_basedn()))
        if dn.add_child("CN=X") == False:
            raise DemoteException("Failed constructing DN %s by adding child "
                                  "CN=X (soon to be CN=%s)" % (dn, dc_name))
        dn.set_component(0, "CN", dc_name)

        try:
            logger.info("Removing Sysvol reference: %s" % dn)
            samdb.delete(dn)
        except ldb.LdbError as e1:
            (enum, estr) = e1.args
            if enum == ldb.ERR_NO_SUCH_OBJECT:
                pass
            else:
                raise


def remove_dns_references(samdb, logger, dnsHostName, ignore_no_name=False):

    # Check we are using in-database DNS
    zones = samdb.search(base="", scope=ldb.SCOPE_SUBTREE,
                         expression="(&(objectClass=dnsZone)(!(dc=RootDNSServers)))",
                         attrs=[],
                         controls=["search_options:0:2"])
    if len(zones) == 0:
        return

    dnsHostNameUpper = dnsHostName.upper()

    try:
        (dn, primary_recs) = samdb.dns_lookup(dnsHostName)
    except RuntimeError as e4:
        (enum, estr) = e4.args
        if (enum == werror.WERR_DNS_ERROR_NAME_DOES_NOT_EXIST or
            enum == werror.WERR_DNS_ERROR_RCODE_NAME_ERROR):
            if ignore_no_name:
                remove_hanging_dns_references(samdb, logger,
                                              dnsHostNameUpper,
                                              zones)
            return
        raise DemoteException("lookup of %s failed: %s" % (dnsHostName, estr))
    samdb.dns_replace(dnsHostName, [])

    res = samdb.search("",
                       scope=ldb.SCOPE_BASE, attrs=["namingContexts"])
    assert len(res) == 1
    ncs = res[0]["namingContexts"]

    # Work out the set of names we will likely have an A record on by
    # default.  This is by default all the partitions of type
    # domainDNS.  By finding the canocial name of all the partitions,
    # we find the likely candidates.  We only remove the record if it
    # maches the IP that was used by the dnsHostName.  This avoids us
    # needing to look a the dns_update_list file from in the demote
    # script.

    def dns_name_from_dn(dn):
        # The canonical string of DC=example,DC=com is
        # example.com/
        #
        # The canonical string of CN=Configuration,DC=example,DC=com
        # is example.com/Configuration
        return ldb.Dn(samdb, dn).canonical_str().split('/', 1)[0]

    # By using a set here, duplicates via (eg) example.com/Configuration
    # do not matter, they become just example.com
    a_names_to_remove_from \
        = set(dns_name_from_dn(str(dn)) for dn in ncs)

    def a_rec_to_remove(dnsRecord):
        if dnsRecord.wType == DNS_TYPE_A or dnsRecord.wType == DNS_TYPE_AAAA:
            for rec in primary_recs:
                if rec.wType == dnsRecord.wType and rec.data == dnsRecord.data:
                    return True
        return False

    for a_name in a_names_to_remove_from:
        try:
            logger.debug("checking for DNS records to remove on %s" % a_name)
            (a_rec_dn, a_recs) = samdb.dns_lookup(a_name)
        except RuntimeError as e2:
            (enum, estr) = e2.args
            if enum == werror.WERR_DNS_ERROR_NAME_DOES_NOT_EXIST:
                return
            raise DemoteException("lookup of %s failed: %s" % (a_name, estr))

        orig_num_recs = len(a_recs)
        a_recs = [r for r in a_recs if not a_rec_to_remove(r)]

        if len(a_recs) != orig_num_recs:
            logger.info("updating %s keeping %d values, removing %s values" %
                        (a_name, len(a_recs), orig_num_recs - len(a_recs)))
            samdb.dns_replace(a_name, a_recs)

    remove_hanging_dns_references(samdb, logger, dnsHostNameUpper, zones)


def remove_hanging_dns_references(samdb, logger, dnsHostNameUpper, zones):

    # Find all the CNAME, NS, PTR and SRV records that point at the
    # name we are removing

    def to_remove(value):
        dnsRecord = ndr_unpack(dnsp.DnssrvRpcRecord, value)
        if dnsRecord.wType == DNS_TYPE_NS \
           or dnsRecord.wType == DNS_TYPE_CNAME \
           or dnsRecord.wType == DNS_TYPE_PTR:
            if dnsRecord.data.upper() == dnsHostNameUpper:
                return True
        elif dnsRecord.wType == DNS_TYPE_SRV:
            if dnsRecord.data.nameTarget.upper() == dnsHostNameUpper:
                return True
        return False

    for zone in zones:
        logger.debug("checking %s" % zone.dn)
        records = samdb.search(base=zone.dn, scope=ldb.SCOPE_SUBTREE,
                               expression="(&(objectClass=dnsNode)"
                               "(!(dNSTombstoned=TRUE)))",
                               attrs=["dnsRecord"])
        for record in records:
            try:
                orig_values = record["dnsRecord"]
            except KeyError:
                continue

            # Remove references to dnsHostName in A, AAAA, NS, CNAME and SRV
            values = [ndr_unpack(dnsp.DnssrvRpcRecord, v)
                      for v in orig_values if not to_remove(v)]

            if len(values) != len(orig_values):
                logger.info("updating %s keeping %d values, removing %s values"
                            % (record.dn, len(values),
                               len(orig_values) - len(values)))

                # This requires the values to be unpacked, so this
                # has been done in the list comprehension above
                samdb.dns_replace_by_dn(record.dn, values)


def offline_remove_server(samdb, logger,
                          server_dn,
                          remove_computer_obj=False,
                          remove_server_obj=False,
                          remove_sysvol_obj=False,
                          remove_dns_names=False,
                          remove_dns_account=False):
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
    dc_name = str(msg["cn"][0])

    try:
        computer_dn = ldb.Dn(samdb, msg["serverReference"][0].decode('utf8'))
    except KeyError:
        computer_dn = None

    try:
        dnsHostName = str(msg["dnsHostName"][0])
    except KeyError:
        dnsHostName = None

    if remove_server_obj:
        # Remove the server DN (do a tree-delete as it could still have a
        # 'DNS Settings' child object if it's a Windows DC)
        samdb.delete(server_dn, ["tree_delete:0"])

    if computer_dn is not None:
        computer_msgs = samdb.search(base=computer_dn,
                                     expression="objectclass=computer",
                                     attrs=["msDS-KrbTgtLink",
                                            "rIDSetReferences",
                                            "cn"],
                                     scope=ldb.SCOPE_BASE)
        if "rIDSetReferences" in computer_msgs[0]:
            rid_set_dn = str(computer_msgs[0]["rIDSetReferences"][0])
            logger.info("Removing RID Set: %s" % rid_set_dn)
            samdb.delete(rid_set_dn)
        if "msDS-KrbTgtLink" in computer_msgs[0]:
            krbtgt_link_dn = str(computer_msgs[0]["msDS-KrbTgtLink"][0])
            logger.info("Removing RODC KDC account: %s" % krbtgt_link_dn)
            samdb.delete(krbtgt_link_dn)

        if remove_computer_obj:
            # Delete the computer tree
            logger.info("Removing computer account: %s (and any child objects)" % computer_dn)
            samdb.delete(computer_dn, ["tree_delete:0"])

        if "dnsHostName" in msg:
            dnsHostName = str(msg["dnsHostName"][0])

    if remove_dns_account:
        res = samdb.search(expression="(&(objectclass=user)(cn=dns-%s)(servicePrincipalName=DNS/%s))" %
                           (ldb.binary_encode(dc_name), dnsHostName),
                           attrs=[], scope=ldb.SCOPE_SUBTREE,
                           base=samdb.get_default_basedn())
        if len(res) == 1:
            logger.info("Removing Samba-specific DNS service account: %s" % res[0].dn)
            samdb.delete(res[0].dn)

    if dnsHostName is not None and remove_dns_names:
        remove_dns_references(samdb, logger, dnsHostName)

    if remove_sysvol_obj:
        remove_sysvol_references(samdb, logger, dc_name)


def offline_remove_ntds_dc(samdb,
                           logger,
                           ntds_dn,
                           remove_computer_obj=False,
                           remove_server_obj=False,
                           remove_connection_obj=False,
                           seize_stale_fsmo=False,
                           remove_sysvol_obj=False,
                           remove_dns_names=False,
                           remove_dns_account=False):
    res = samdb.search("",
                       scope=ldb.SCOPE_BASE, attrs=["dsServiceName"])
    assert len(res) == 1
    my_serviceName = ldb.Dn(samdb, res[0]["dsServiceName"][0].decode('utf8'))
    server_dn = ntds_dn.parent()

    if my_serviceName == ntds_dn:
        raise DemoteException("Refusing to demote our own DSA: %s " % my_serviceName)

    try:
        msgs = samdb.search(base=ntds_dn, expression="objectClass=ntdsDSA",
                            attrs=["objectGUID"], scope=ldb.SCOPE_BASE)
    except LdbError as e5:
        (enum, estr) = e5.args
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
            logger.info("Removing nTDSConnection: %s" % conn.dn)
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
            logger.warning("Seizing FSMO role on: %s (now owned by %s)"
                           % (role.dn, my_serviceName))
            samdb.modify(m)

    # Remove the NTDS setting tree
    try:
        logger.info("Removing nTDSDSA: %s (and any children)" % ntds_dn)
        samdb.delete(ntds_dn, ["tree_delete:0"])
    except LdbError as e6:
        (enum, estr) = e6.args
        raise DemoteException("Failed to remove the DCs NTDS DSA object: %s"
                              % estr)

    offline_remove_server(samdb, logger, server_dn,
                          remove_computer_obj=remove_computer_obj,
                          remove_server_obj=remove_server_obj,
                          remove_sysvol_obj=remove_sysvol_obj,
                          remove_dns_names=remove_dns_names,
                          remove_dns_account=remove_dns_account)


def remove_dc(samdb, logger, dc_name):

    # TODO: Check if this is the last server (covered mostly by
    # refusing to remove our own name)

    samdb.transaction_start()

    server_dn = None

    # Allow the name to be a the nTDS-DSA GUID
    try:
        ntds_guid = uuid.UUID(hex=dc_name)
        ntds_dn = "<GUID=%s>" % ntds_guid
    except ValueError:
        try:
            server_msgs = samdb.search(base=samdb.get_config_basedn(),
                                       attrs=[],
                                       expression="(&(objectClass=server)"
                                       "(cn=%s))"
                                       % ldb.binary_encode(dc_name))
        except LdbError as e3:
            (enum, estr) = e3.args
            raise DemoteException("Failure checking if %s is an server "
                                  "object in %s: %s"
                                  % (dc_name, samdb.domain_dns_name(), estr))

        if (len(server_msgs) == 0):
            samdb.transaction_cancel()
            raise DemoteException("%s is not an AD DC in %s"
                                  % (dc_name, samdb.domain_dns_name()))
        server_dn = server_msgs[0].dn

        ntds_dn = ldb.Dn(samdb, "CN=NTDS Settings")
        ntds_dn.add_base(server_dn)
        pass

    # Confirm this is really an ntdsDSA object
    try:
        ntds_msgs = samdb.search(base=ntds_dn, attrs=[], scope=ldb.SCOPE_BASE,
                                 expression="(objectClass=ntdsdsa)")
    except LdbError as e7:
        (enum, estr) = e7.args
        if enum == ldb.ERR_NO_SUCH_OBJECT:
            ntds_msgs = []
            pass
        else:
            samdb.transaction_cancel()
            raise DemoteException(
                "Failure checking if %s is an NTDS DSA in %s: %s" %
                (ntds_dn, samdb.domain_dns_name(), estr))

    # If the NTDS Settings child DN wasn't found or wasnt an ntdsDSA
    # object, just remove the server object located above
    if (len(ntds_msgs) == 0):
        if server_dn is None:
            samdb.transaction_cancel()
            raise DemoteException("%s is not an AD DC in %s"
                                  % (dc_name, samdb.domain_dns_name()))

        offline_remove_server(samdb, logger,
                              server_dn,
                              remove_computer_obj=True,
                              remove_server_obj=True,
                              remove_sysvol_obj=True,
                              remove_dns_names=True,
                              remove_dns_account=True)
    else:
        offline_remove_ntds_dc(samdb, logger,
                               ntds_msgs[0].dn,
                               remove_computer_obj=True,
                               remove_server_obj=True,
                               remove_connection_obj=True,
                               seize_stale_fsmo=True,
                               remove_sysvol_obj=True,
                               remove_dns_names=True,
                               remove_dns_account=True)

    samdb.transaction_commit()


def offline_remove_dc_RemoveDsServer(samdb, ntds_dn):

    samdb.start_transaction()

    offline_remove_ntds_dc(samdb, ntds_dn, None)

    samdb.commit_transaction()
