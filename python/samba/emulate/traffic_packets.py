# Dispatch for various request types.
#
# Copyright (C) Catalyst IT Ltd. 2017
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
import os
import ctypes
import random

from samba.net import Net
from samba.dcerpc import security, drsuapi, nbt, lsa, netlogon, ntlmssp
from samba.dcerpc.netlogon import netr_WorkstationInformation
from samba.dcerpc.security import dom_sid
from samba.netbios import Node
from samba.ndr import ndr_pack
from samba.credentials import (
    CLI_CRED_NTLMv2_AUTH,
    MUST_USE_KERBEROS,
    DONT_USE_KERBEROS
)
from samba import NTSTATUSError
from samba.ntstatus import (
    NT_STATUS_OBJECT_NAME_NOT_FOUND,
    NT_STATUS_NO_SUCH_DOMAIN
)
import samba
import dns.resolver
from ldb import SCOPE_BASE

def uint32(v):
    return ctypes.c_uint32(v).value


def check_runtime_error(runtime, val):
    if runtime is None:
        return False

    err32 = uint32(runtime.args[0])
    if err32 == val:
        return True

    return False


name_formats = [
    drsuapi.DRSUAPI_DS_NAME_FORMAT_FQDN_1779,
    drsuapi.DRSUAPI_DS_NAME_FORMAT_NT4_ACCOUNT,
    drsuapi.DRSUAPI_DS_NAME_FORMAT_DISPLAY,
    drsuapi.DRSUAPI_DS_NAME_FORMAT_GUID,
    drsuapi.DRSUAPI_DS_NAME_FORMAT_CANONICAL,
    drsuapi.DRSUAPI_DS_NAME_FORMAT_USER_PRINCIPAL,
    drsuapi.DRSUAPI_DS_NAME_FORMAT_CANONICAL_EX,
    drsuapi.DRSUAPI_DS_NAME_FORMAT_SERVICE_PRINCIPAL,
    drsuapi.DRSUAPI_DS_NAME_FORMAT_SID_OR_SID_HISTORY,
    drsuapi.DRSUAPI_DS_NAME_FORMAT_DNS_DOMAIN,
    drsuapi.DRSUAPI_DS_NAME_FORMAT_UPN_AND_ALTSECID,
    drsuapi.DRSUAPI_DS_NAME_FORMAT_NT4_ACCOUNT_NAME_SANS_DOMAIN_EX,
    drsuapi.DRSUAPI_DS_NAME_FORMAT_LIST_GLOBAL_CATALOG_SERVERS,
    drsuapi.DRSUAPI_DS_NAME_FORMAT_UPN_FOR_LOGON,
    drsuapi.DRSUAPI_DS_NAME_FORMAT_LIST_SERVERS_WITH_DCS_IN_SITE,
    drsuapi.DRSUAPI_DS_NAME_FORMAT_STRING_SID_NAME,
    drsuapi.DRSUAPI_DS_NAME_FORMAT_ALT_SECURITY_IDENTITIES_NAME,
    drsuapi.DRSUAPI_DS_NAME_FORMAT_LIST_NCS,
    drsuapi.DRSUAPI_DS_NAME_FORMAT_LIST_DOMAINS,
    drsuapi.DRSUAPI_DS_NAME_FORMAT_MAP_SCHEMA_GUID,
    drsuapi.DRSUAPI_DS_NAME_FORMAT_NT4_ACCOUNT_NAME_SANS_DOMAIN,
    drsuapi.DRSUAPI_DS_NAME_FORMAT_LIST_ROLES,
    drsuapi.DRSUAPI_DS_NAME_FORMAT_LIST_INFO_FOR_SERVER,
    drsuapi.DRSUAPI_DS_NAME_FORMAT_LIST_SERVERS_FOR_DOMAIN_IN_SITE,
    drsuapi.DRSUAPI_DS_NAME_FORMAT_LIST_DOMAINS_IN_SITE,
    drsuapi.DRSUAPI_DS_NAME_FORMAT_LIST_SERVERS_IN_SITE,
    drsuapi.DRSUAPI_DS_NAME_FORMAT_LIST_SITES,
]


def warning(message):
    print("\033[37;41;1m" "Warning: %s" "\033[00m" % (message))

###############################################################################
#
# Packet generation functions:
#
# All the packet generation functions have the following form:
#  packet_${protocol}_${opcode}(packet, conversation, context)
#
#  The functions return true, if statistics should be collected for the packet
#                      false, the packet has been ignored.
#
# Where:
#   protocol is the protocol, i.e. cldap, dcerpc, ...
#   opcode   is the protocol op code i.e. type of the packet to be
#            generated.
#
#   packet contains data about the captured/generated packet
#          provides any extra data needed to generate the packet
#
#   conversation Details of the current client/server interaction
#
#   context state data for the current interaction
#
#
#
# The following protocols are not currently handled:
#     smb
#     smb2
#     browser
#     smb_netlogon
#
# The following drsuapi replication packets are currently ignored:
#     DsReplicaSync
#     DsGetNCChanges
#     DsReplicaUpdateRefs


# Packet generators that do NOTHING are assigned to the null_packet
# function which allows the conversation generators to notice this and
# avoid a whole lot of pointless work.
def null_packet(packet, conversation, context):
    return False


def packet_cldap_3(packet, conversation, context):
    # searchRequest
    net = Net(creds=context.creds, lp=context.lp)
    net.finddc(domain=context.lp.get('realm'),
               flags=(nbt.NBT_SERVER_LDAP |
                      nbt.NBT_SERVER_DS |
                      nbt.NBT_SERVER_WRITABLE))
    return True


packet_cldap_5 = null_packet
# searchResDone

packet_dcerpc_0  = null_packet
# Request
# Can be ignored, it's the continuation of an existing conversation

packet_dcerpc_2 = null_packet
# Request
# Server response, so should be ignored

packet_dcerpc_3 = null_packet

packet_dcerpc_11 = null_packet
# Bind
# creation of the rpc dcerpc connection is managed by the higher level
# protocol drivers. So we ignore it when generating traffic


packet_dcerpc_12 = null_packet
# Bind_ack
# Server response, so should be ignored


packet_dcerpc_13 = null_packet
# Bind_nak
# Server response, so should be ignored


packet_dcerpc_14 = null_packet
# Alter_context
# Generated as part of the connect process


def packet_dcerpc_15(packet, conversation, context):
    # Alter_context_resp
    # This means it was GSSAPI/krb5 (probably)
    # Check the kerberos_state and issue a diagnostic if kerberos not enabled
    if context.user_creds.get_kerberos_state() == DONT_USE_KERBEROS:
        warning("Kerberos disabled but have dcerpc Alter_context_resp "
                "indicating Kerberos was used")
    return False


def packet_dcerpc_16(packet, conversation, context):
    # AUTH3
    # This means it was NTLMSSP
    # Check the kerberos_state and issue a diagnostic if kerberos enabled
    if context.user_creds.get_kerberos_state() == MUST_USE_KERBEROS:
        warning("Kerberos enabled but have dcerpc AUTH3 "
                "indicating NTLMSSP was used")
    return False


def packet_dns_0(packet, conversation, context):
    # query
    name, rtype = context.guess_a_dns_lookup()
    dns.resolver.query(name, rtype)
    return True


packet_dns_1 = null_packet
# response
# Server response, so should be ignored


def packet_drsuapi_0(packet, conversation, context):
    # DsBind
    context.get_drsuapi_connection_pair(True)
    return True


NAME_FORMATS = [getattr(drsuapi, _x) for _x in dir(drsuapi)
                if 'NAME_FORMAT' in _x]


def packet_drsuapi_12(packet, conversation, context):
    # DsCrackNames
    drs, handle = context.get_drsuapi_connection_pair()

    names = drsuapi.DsNameString()
    names.str = context.server

    req = drsuapi.DsNameRequest1()
    req.format_flags = 0
    req.format_offered = 7
    req.format_desired = random.choice(name_formats)
    req.codepage = 1252
    req.language = 1033  # German, I think
    req.format_flags = 0
    req.count = 1
    req.names = [names]

    (result, ctr) = drs.DsCrackNames(handle, 1, req)
    return True


def packet_drsuapi_13(packet, conversation, context):
    # DsWriteAccountSpn
    req = drsuapi.DsWriteAccountSpnRequest1()
    req.operation = drsuapi.DRSUAPI_DS_SPN_OPERATION_REPLACE
    req.unknown1 = 0  # Unused, must be 0
    req.object_dn = context.user_dn
    req.count = 1  # only 1 name
    spn_name = drsuapi.DsNameString()
    spn_name.str = 'foo/{}'.format(context.username)
    req.spn_names = [spn_name]
    (drs, handle) = context.get_drsuapi_connection_pair()
    (level, res) = drs.DsWriteAccountSpn(handle, 1, req)
    return True


def packet_drsuapi_1(packet, conversation, context):
    # DsUnbind
    (drs, handle) = context.get_drsuapi_connection_pair()
    drs.DsUnbind(handle)
    del context.drsuapi_connections[-1]
    return True


packet_drsuapi_2 = null_packet
# DsReplicaSync
# This is between DCs, triggered on a DB change
# Ignoring for now


packet_drsuapi_3 = null_packet
# DsGetNCChanges
# This is between DCs, trigger with DB operation,
# or DsReplicaSync between DCs.
# Ignoring for now


packet_drsuapi_4 = null_packet
# DsReplicaUpdateRefs
# Ignoring for now


packet_epm_3 = null_packet
# Map
# Will be generated by higher level protocol calls


def packet_kerberos_(packet, conversation, context):
    # Use the presence of kerberos packets as a hint to enable kerberos
    # for the rest of the conversation.
    # i.e. kerberos packets are not explicitly generated.
    context.user_creds.set_kerberos_state(MUST_USE_KERBEROS)
    context.user_creds_bad.set_kerberos_state(MUST_USE_KERBEROS)
    context.machine_creds.set_kerberos_state(MUST_USE_KERBEROS)
    context.machine_creds_bad.set_kerberos_state(MUST_USE_KERBEROS)
    context.creds.set_kerberos_state(MUST_USE_KERBEROS)
    return False


packet_ldap_ = null_packet
# Unknown
# The ldap payload was probably encrypted so just ignore it.


def packet_ldap_0(packet, conversation, context):
    # bindRequest
    if packet.extra[5] == "simple":
        # Perform a simple bind.
        context.get_ldap_connection(new=True, simple=True)
    else:
        # Perform a sasl bind.
        context.get_ldap_connection(new=True, simple=False)
    return True


packet_ldap_1 = null_packet
# bindResponse
# Server response ignored for traffic generation


def packet_ldap_2(packet, conversation, context):
    # unbindRequest
    # pop the last one off -- most likely we're in a bind/unbind ping.
    del context.ldap_connections[-1:]
    return False


def packet_ldap_3(packet, conversation, context):
    # searchRequest

    (scope, dn_sig, filter, attrs, extra, desc, oid) = packet.extra
    if not scope:
        scope = SCOPE_BASE

    samdb = context.get_ldap_connection()
    dn = context.get_matching_dn(dn_sig)

    # try to guess the search expression (don't bother for base searches, as
    # they're only looking up a single object)
    if (filter is None or filter == '') and scope != SCOPE_BASE:
        filter = context.guess_search_filter(attrs, dn_sig, dn)

    samdb.search(dn,
                 expression=filter,
                 scope=int(scope),
                 attrs=attrs.split(','),
                 controls=["paged_results:1:1000"])
    return True


packet_ldap_4 = null_packet
# searchResEntry
# Server response ignored for traffic generation


packet_ldap_5 = null_packet
# Server response ignored for traffic generation

packet_ldap_6 = null_packet

packet_ldap_7 = null_packet

packet_ldap_8 = null_packet

packet_ldap_9 = null_packet

packet_ldap_16 = null_packet

packet_lsarpc_0 = null_packet
# lsarClose

packet_lsarpc_1 = null_packet
# lsarDelete

packet_lsarpc_2 = null_packet
# lsarEnumeratePrivileges

packet_lsarpc_3 = null_packet
# LsarQuerySecurityObject

packet_lsarpc_4 = null_packet
# LsarSetSecurityObject

packet_lsarpc_5 = null_packet
# LsarChangePassword

packet_lsarpc_6 = null_packet
# lsa_OpenPolicy
# We ignore this, but take it as a hint that the lsarpc handle should
# be over a named pipe.
#


def packet_lsarpc_14(packet, conversation, context):
    # lsa_LookupNames
    c = context.get_lsarpc_named_pipe_connection()

    objectAttr = lsa.ObjectAttribute()
    pol_handle = c.OpenPolicy2(u'', objectAttr,
                               security.SEC_FLAG_MAXIMUM_ALLOWED)

    sids  = lsa.TransSidArray()
    names = [lsa.String("This Organization"),
             lsa.String("Digest Authentication")]
    level = lsa.LSA_LOOKUP_NAMES_ALL
    count = 0
    c.LookupNames(pol_handle, names, sids, level, count)
    return True


def packet_lsarpc_15(packet, conversation, context):
    # lsa_LookupSids
    c = context.get_lsarpc_named_pipe_connection()

    objectAttr = lsa.ObjectAttribute()
    pol_handle = c.OpenPolicy2(u'', objectAttr,
                               security.SEC_FLAG_MAXIMUM_ALLOWED)

    sids = lsa.SidArray()
    sid = lsa.SidPtr()

    x = dom_sid("S-1-5-7")
    sid.sid = x
    sids.sids = [sid]
    sids.num_sids = 1
    names = lsa.TransNameArray()
    level = lsa.LSA_LOOKUP_NAMES_ALL
    count = 0

    c.LookupSids(pol_handle, sids, names, level, count)
    return True


def packet_lsarpc_39(packet, conversation, context):
    # lsa_QueryTrustedDomainInfoBySid
    # Samba does not support trusted domains, so this call is expected to fail
    #
    c = context.get_lsarpc_named_pipe_connection()

    objectAttr = lsa.ObjectAttribute()

    pol_handle = c.OpenPolicy2(u'', objectAttr,
                               security.SEC_FLAG_MAXIMUM_ALLOWED)

    domsid = security.dom_sid(context.domain_sid)
    level = 1
    try:
        c.QueryTrustedDomainInfoBySid(pol_handle, domsid, level)
    except NTSTATUSError as error:
        # Object Not found is the expected result from samba,
        # while No Such Domain is the expected result from windows,
        # anything else is a failure.
        if not check_runtime_error(error, NT_STATUS_OBJECT_NAME_NOT_FOUND) \
                and not check_runtime_error(error, NT_STATUS_NO_SUCH_DOMAIN):
            raise
    return True


packet_lsarpc_40 = null_packet
# lsa_SetTrustedDomainInfo
# Not currently supported


packet_lsarpc_43 = null_packet
# LsaStorePrivateData


packet_lsarpc_44 = null_packet
# LsaRetrievePrivateData


packet_lsarpc_68 = null_packet
# LsarLookupNames3


def packet_lsarpc_76(packet, conversation, context):
    # lsa_LookupSids3
    c = context.get_lsarpc_connection()
    sids = lsa.SidArray()
    sid = lsa.SidPtr()
    # Need a set
    x = dom_sid("S-1-5-7")
    sid.sid = x
    sids.sids = [sid]
    sids.num_sids = 1
    names = lsa.TransNameArray2()
    level = lsa.LSA_LOOKUP_NAMES_ALL
    count = 0
    lookup_options = lsa.LSA_LOOKUP_OPTION_SEARCH_ISOLATED_NAMES
    client_revision = lsa.LSA_CLIENT_REVISION_2
    c.LookupSids3(sids, names, level, count, lookup_options, client_revision)
    return True


def packet_lsarpc_77(packet, conversation, context):
    # lsa_LookupNames4
    c = context.get_lsarpc_connection()
    sids  = lsa.TransSidArray3()
    names = [lsa.String("This Organization"),
             lsa.String("Digest Authentication")]
    level = lsa.LSA_LOOKUP_NAMES_ALL
    count = 0
    lookup_options = lsa.LSA_LOOKUP_OPTION_SEARCH_ISOLATED_NAMES
    client_revision = lsa.LSA_CLIENT_REVISION_2
    c.LookupNames4(names, sids, level, count, lookup_options, client_revision)
    return True


def packet_nbns_0(packet, conversation, context):
    # query
    n = Node()
    try:
        n.query_name("ANAME", context.server, timeout=4, broadcast=False)
    except:
        pass
    return True


packet_nbns_1 = null_packet
# response
# Server response, not generated by the client


packet_rpc_netlogon_0 = null_packet

packet_rpc_netlogon_1 = null_packet

packet_rpc_netlogon_4 = null_packet
# NetrServerReqChallenge
# generated by higher level protocol drivers
# ignored for traffic generation

packet_rpc_netlogon_14 = null_packet

packet_rpc_netlogon_15 = null_packet

packet_rpc_netlogon_21 = null_packet
# NetrLogonDummyRoutine1
# Used to determine security settings. Triggered from schannel setup
# So no need for an explicit generator


packet_rpc_netlogon_26 = null_packet
# NetrServerAuthenticate3
# Triggered from schannel set up, no need for an explicit generator


def packet_rpc_netlogon_29(packet, conversation, context):
    # NetrLogonGetDomainInfo [531]
    c = context.get_netlogon_connection()
    (auth, succ) = context.get_authenticator()
    query = netr_WorkstationInformation()

    c.netr_LogonGetDomainInfo(context.server,
                              context.netbios_name,
                              auth,
                              succ,
                              2,      # TODO are there other values?
                              query)
    return True


def packet_rpc_netlogon_30(packet, conversation, context):
    # NetrServerPasswordSet2
    c = context.get_netlogon_connection()
    (auth, succ) = context.get_authenticator()
    DATA_LEN = 512
    # Set the new password to the existing password, this generates the same
    # work load as a new value, and leaves the account password intact for
    # subsequent runs
    newpass = context.machine_creds.get_password().encode('utf-16-le')
    pwd_len = len(newpass)
    filler  = [x if isinstance(x, int) else ord(x) for x in os.urandom(DATA_LEN - pwd_len)]
    pwd = netlogon.netr_CryptPassword()
    pwd.length = pwd_len
    pwd.data = filler + [x if isinstance(x, int) else ord(x) for x in newpass]
    context.machine_creds.encrypt_netr_crypt_password(pwd)
    c.netr_ServerPasswordSet2(context.server,
                              # must ends with $, so use get_username instead
                              # of get_workstation here
                              context.machine_creds.get_username(),
                              context.machine_creds.get_secure_channel_type(),
                              context.netbios_name,
                              auth,
                              pwd)
    return True


packet_rpc_netlogon_34 = null_packet


def packet_rpc_netlogon_39(packet, conversation, context):
    # NetrLogonSamLogonEx [4331]
    def connect(creds):
        c = context.get_netlogon_connection()

        # Disable Kerberos in cli creds to extract NTLM response
        old_state = creds.get_kerberos_state()
        creds.set_kerberos_state(DONT_USE_KERBEROS)

        logon = samlogon_logon_info(context.domain,
                                    context.netbios_name,
                                    creds)
        logon_level = netlogon.NetlogonNetworkTransitiveInformation
        validation_level = netlogon.NetlogonValidationSamInfo4
        netr_flags = 0
        c.netr_LogonSamLogonEx(context.server,
                               context.machine_creds.get_workstation(),
                               logon_level,
                               logon,
                               validation_level,
                               netr_flags)

        creds.set_kerberos_state(old_state)

    context.last_samlogon_bad =\
        context.with_random_bad_credentials(connect,
                                            context.user_creds,
                                            context.user_creds_bad,
                                            context.last_samlogon_bad)
    return True


def samlogon_target(domain_name, computer_name):
    target_info = ntlmssp.AV_PAIR_LIST()
    target_info.count = 3
    computername = ntlmssp.AV_PAIR()
    computername.AvId = ntlmssp.MsvAvNbComputerName
    computername.Value = computer_name

    domainname = ntlmssp.AV_PAIR()
    domainname.AvId = ntlmssp.MsvAvNbDomainName
    domainname.Value = domain_name

    eol = ntlmssp.AV_PAIR()
    eol.AvId = ntlmssp.MsvAvEOL
    target_info.pair = [domainname, computername, eol]

    return ndr_pack(target_info)


def samlogon_logon_info(domain_name, computer_name, creds):

    target_info_blob = samlogon_target(domain_name, computer_name)

    challenge = b"abcdefgh"
    # User account under test
    response = creds.get_ntlm_response(flags=CLI_CRED_NTLMv2_AUTH,
                                       challenge=challenge,
                                       target_info=target_info_blob)

    logon = netlogon.netr_NetworkInfo()

    logon.challenge     = [x if isinstance(x, int) else ord(x) for x in challenge]
    logon.nt            = netlogon.netr_ChallengeResponse()
    logon.nt.length     = len(response["nt_response"])
    logon.nt.data       = [x if isinstance(x, int) else ord(x) for x in response["nt_response"]]

    logon.identity_info = netlogon.netr_IdentityInfo()

    (username, domain)  = creds.get_ntlm_username_domain()
    logon.identity_info.domain_name.string  = domain
    logon.identity_info.account_name.string = username
    logon.identity_info.workstation.string  = creds.get_workstation()

    return logon


def packet_rpc_netlogon_40(packet, conversation, context):
    # DsrEnumerateDomainTrusts
    c = context.get_netlogon_connection()
    c.netr_DsrEnumerateDomainTrusts(
        context.server,
        netlogon.NETR_TRUST_FLAG_IN_FOREST |
        netlogon.NETR_TRUST_FLAG_OUTBOUND  |
        netlogon.NETR_TRUST_FLAG_INBOUND)
    return True


def packet_rpc_netlogon_45(packet, conversation, context):
    # NetrLogonSamLogonWithFlags [7]
    def connect(creds):
        c = context.get_netlogon_connection()
        (auth, succ) = context.get_authenticator()

        # Disable Kerberos in cli creds to extract NTLM response
        old_state = creds.get_kerberos_state()
        creds.set_kerberos_state(DONT_USE_KERBEROS)

        logon = samlogon_logon_info(context.domain,
                                    context.netbios_name,
                                    creds)
        logon_level = netlogon.NetlogonNetworkTransitiveInformation
        validation_level = netlogon.NetlogonValidationSamInfo4
        netr_flags = 0
        c.netr_LogonSamLogonWithFlags(context.server,
                                      context.machine_creds.get_workstation(),
                                      auth,
                                      succ,
                                      logon_level,
                                      logon,
                                      validation_level,
                                      netr_flags)

        creds.set_kerberos_state(old_state)

    context.last_samlogon_bad =\
        context.with_random_bad_credentials(connect,
                                            context.user_creds,
                                            context.user_creds_bad,
                                            context.last_samlogon_bad)
    return True


def packet_samr_0(packet, conversation, context):
    # Open
    c = context.get_samr_context()
    c.get_handle()
    return True


def packet_samr_1(packet, conversation, context):
    # Close
    c = context.get_samr_context()
    s = c.get_connection()
    # close the last opened handle, may not always be accurate
    # but will do for load simulation
    if c.user_handle is not None:
        s.Close(c.user_handle)
        c.user_handle = None
    elif c.group_handle is not None:
        s.Close(c.group_handle)
        c.group_handle = None
    elif c.domain_handle is not None:
        s.Close(c.domain_handle)
        c.domain_handle = None
        c.rids          = None
    elif c.handle is not None:
        s.Close(c.handle)
        c.handle     = None
        c.domain_sid = None
    return True


def packet_samr_3(packet, conversation, context):
    # QuerySecurity
    c = context.get_samr_context()
    s = c.get_connection()
    if c.user_handle is None:
        packet_samr_34(packet, conversation, context)
    s.QuerySecurity(c.user_handle, 1)
    return True


def packet_samr_5(packet, conversation, context):
    # LookupDomain
    c = context.get_samr_context()
    s = c.get_connection()
    h = c.get_handle()
    d = lsa.String()
    d.string = context.domain
    c.domain_sid = s.LookupDomain(h, d)
    return True


def packet_samr_6(packet, conversation, context):
    # EnumDomains
    c = context.get_samr_context()
    s = c.get_connection()
    h = c.get_handle()
    s.EnumDomains(h, 0, 0)
    return True


def packet_samr_7(packet, conversation, context):
    # OpenDomain
    c = context.get_samr_context()
    s = c.get_connection()
    h = c.get_handle()
    if c.domain_sid is None:
        packet_samr_5(packet, conversation, context)

    c.domain_handle = s.OpenDomain(h,
                                   security.SEC_FLAG_MAXIMUM_ALLOWED,
                                   c.domain_sid)
    return True


SAMR_QUERY_DOMAIN_INFO_LEVELS = [8, 12]


def packet_samr_8(packet, conversation, context):
    # QueryDomainInfo [228]
    c = context.get_samr_context()
    s = c.get_connection()
    if c.domain_handle is None:
        packet_samr_7(packet, conversation, context)
    level = random.choice(SAMR_QUERY_DOMAIN_INFO_LEVELS)
    s.QueryDomainInfo(c.domain_handle, level)
    return True


packet_samr_14 = null_packet
# CreateDomainAlias
# Ignore these for now.


def packet_samr_15(packet, conversation, context):
    # EnumDomainAliases
    c = context.get_samr_context()
    s = c.get_connection()
    if c.domain_handle is None:
        packet_samr_7(packet, conversation, context)

    s.EnumDomainAliases(c.domain_handle, 100, 0)
    return True


def packet_samr_16(packet, conversation, context):
    # GetAliasMembership
    c = context.get_samr_context()
    s = c.get_connection()
    if c.domain_handle is None:
        packet_samr_7(packet, conversation, context)

    sids = lsa.SidArray()
    sid  = lsa.SidPtr()
    sid.sid = c.domain_sid
    sids.sids = [sid]
    s.GetAliasMembership(c.domain_handle, sids)
    return True


def packet_samr_17(packet, conversation, context):
    # LookupNames
    c = context.get_samr_context()
    s = c.get_connection()
    if c.domain_handle is None:
        packet_samr_7(packet, conversation, context)

    name = lsa.String(context.username)
    c.rids = s.LookupNames(c.domain_handle, [name])
    return True


def packet_samr_18(packet, conversation, context):
    # LookupRids
    c = context.get_samr_context()
    s = c.get_connection()
    if c.rids is None:
        packet_samr_17(packet, conversation, context)
    rids = []
    for r in c.rids:
        for i in r.ids:
            rids.append(i)
    s.LookupRids(c.domain_handle, rids)
    return True


def packet_samr_19(packet, conversation, context):
    # OpenGroup
    c = context.get_samr_context()
    s = c.get_connection()
    if c.domain_handle is None:
        packet_samr_7(packet, conversation, context)

    rid = 0x202  # Users I think.
    c.group_handle = s.OpenGroup(c.domain_handle,
                                 security.SEC_FLAG_MAXIMUM_ALLOWED,
                                 rid)
    return True


def packet_samr_25(packet, conversation, context):
    # QueryGroupMember
    c = context.get_samr_context()
    s = c.get_connection()
    if c.group_handle is None:
        packet_samr_19(packet, conversation, context)
    s.QueryGroupMember(c.group_handle)
    return True


def packet_samr_34(packet, conversation, context):
    # OpenUser
    c = context.get_samr_context()
    s = c.get_connection()
    if c.rids is None:
        packet_samr_17(packet, conversation, context)
    c.user_handle = s.OpenUser(c.domain_handle,
                               security.SEC_FLAG_MAXIMUM_ALLOWED,
                               c.rids[0].ids[0])
    return True


def packet_samr_36(packet, conversation, context):
    # QueryUserInfo
    c = context.get_samr_context()
    s = c.get_connection()
    if c.user_handle is None:
        packet_samr_34(packet, conversation, context)
    level = 1
    s.QueryUserInfo(c.user_handle, level)
    return True


packet_samr_37 = null_packet


def packet_samr_39(packet, conversation, context):
    # GetGroupsForUser
    c = context.get_samr_context()
    s = c.get_connection()
    if c.user_handle is None:
        packet_samr_34(packet, conversation, context)
    s.GetGroupsForUser(c.user_handle)
    return True


packet_samr_40 = null_packet

packet_samr_44 = null_packet


def packet_samr_57(packet, conversation, context):
    # Connect2
    c = context.get_samr_context()
    c.get_handle()
    return True


def packet_samr_64(packet, conversation, context):
    # Connect5
    c = context.get_samr_context()
    c.get_handle()
    return True


packet_samr_68 = null_packet


def packet_srvsvc_16(packet, conversation, context):
    # NetShareGetInfo
    s = context.get_srvsvc_connection()
    server_unc = "\\\\" + context.server
    share_name = "IPC$"
    level = 1
    s.NetShareGetInfo(server_unc, share_name, level)
    return True


def packet_srvsvc_21(packet, conversation, context):
    """NetSrvGetInfo

    FIXME: Level changed from 102 to 101 here, to bypass Windows error.

    Level 102 will cause WERR_ACCESS_DENIED error against Windows, because:

        > If the level is 102 or 502, the Windows implementation checks whether
        > the caller is a member of one of the groups previously mentioned or
        > is a member of the Power Users local group.

    It passed against Samba since this check is not implemented by Samba yet.

    refer to:

        https://msdn.microsoft.com/en-us/library/cc247297.aspx#Appendix_A_80

    """
    srvsvc = context.get_srvsvc_connection()
    server_unc = "\\\\" + context.server
    level = 101
    srvsvc.NetSrvGetInfo(server_unc, level)
    return True
