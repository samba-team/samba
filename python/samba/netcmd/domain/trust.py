# domain management - domain trust
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

import ctypes
from getpass import getpass

import ldb
import samba.getopt as options
import samba.ntacls
from samba import NTSTATUSError, ntstatus, werror
from samba.auth import system_session
from samba.dcerpc import drsblobs, lsa, nbt, netlogon, security
from samba.net import Net
from samba.netcmd import Command, CommandError, Option, SuperCommand
from samba.samdb import SamDB
from samba.lsa_utils import OpenPolicyFallback, CreateTrustedDomainFallback


class LocalDCCredentialsOptions(options.CredentialsOptions):
    def __init__(self, parser):
        options.CredentialsOptions.__init__(self, parser, special_name="local-dc")


class DomainTrustCommand(Command):
    """List domain trusts."""

    def __init__(self):
        Command.__init__(self)
        self.local_lp = None

        self.local_server = None
        self.local_binding_string = None
        self.local_creds = None

        self.remote_server = None
        self.remote_binding_string = None
        self.remote_creds = None

    def _uint32(self, v):
        return ctypes.c_uint32(v).value

    def check_runtime_error(self, runtime, val):
        if runtime is None:
            return False

        err32 = self._uint32(runtime.args[0])
        if err32 == val:
            return True

        return False

    class LocalRuntimeError(CommandError):
        def __init__(exception_self, self, runtime, message):
            err32 = self._uint32(runtime.args[0])
            errstr = runtime.args[1]
            msg = "LOCAL_DC[%s]: %s - ERROR(0x%08X) - %s" % (
                  self.local_server, message, err32, errstr)
            CommandError.__init__(exception_self, msg)

    class RemoteRuntimeError(CommandError):
        def __init__(exception_self, self, runtime, message):
            err32 = self._uint32(runtime.args[0])
            errstr = runtime.args[1]
            msg = "REMOTE_DC[%s]: %s - ERROR(0x%08X) - %s" % (
                  self.remote_server, message, err32, errstr)
            CommandError.__init__(exception_self, msg)

    class LocalLdbError(CommandError):
        def __init__(exception_self, self, ldb_error, message):
            errval = ldb_error.args[0]
            errstr = ldb_error.args[1]
            msg = "LOCAL_DC[%s]: %s - ERROR(%d) - %s" % (
                  self.local_server, message, errval, errstr)
            CommandError.__init__(exception_self, msg)

    def setup_local_server(self, sambaopts, localdcopts):
        if self.local_server is not None:
            return self.local_server

        lp = sambaopts.get_loadparm()

        local_server = localdcopts.ipaddress
        if local_server is None:
            server_role = lp.server_role()
            if server_role != "ROLE_ACTIVE_DIRECTORY_DC":
                raise CommandError("Invalid server_role %s" % (server_role))
            local_server = lp.get('netbios name')
            local_transport = "ncalrpc"
            local_binding_options = ""
            local_binding_options += ",auth_type=ncalrpc_as_system"
            local_ldap_url = None
            local_creds = None
        else:
            local_transport = "ncacn_np"
            local_binding_options = ""
            local_ldap_url = "ldap://%s" % local_server
            local_creds = localdcopts.get_credentials(lp)

        self.local_lp = lp

        self.local_server = local_server
        self.local_binding_string = "%s:%s[%s]" % (local_transport, local_server, local_binding_options)
        self.local_ldap_url = local_ldap_url
        self.local_creds = local_creds
        return self.local_server

    def new_local_lsa_connection(self):
        return lsa.lsarpc(self.local_binding_string, self.local_lp, self.local_creds)

    def new_local_netlogon_connection(self):
        return netlogon.netlogon(self.local_binding_string, self.local_lp, self.local_creds)

    def new_local_ldap_connection(self):
        return SamDB(url=self.local_ldap_url,
                     session_info=system_session(),
                     credentials=self.local_creds,
                     lp=self.local_lp)

    def setup_remote_server(self, credopts, domain,
                            require_pdc=True,
                            require_writable=True):

        if require_pdc:
            assert require_writable

        if self.remote_server is not None:
            return self.remote_server

        self.remote_server = "__unknown__remote_server__.%s" % domain
        assert self.local_server is not None

        remote_creds = credopts.get_credentials(self.local_lp)
        remote_server = credopts.ipaddress
        remote_binding_options = ""

        # TODO: we should also support NT4 domains
        # we could use local_netlogon.netr_DsRGetDCNameEx2() with the remote domain name
        # and delegate NBT or CLDAP to the local netlogon server
        try:
            remote_net = Net(remote_creds, self.local_lp, server=remote_server)
            remote_flags = nbt.NBT_SERVER_LDAP | nbt.NBT_SERVER_DS
            if require_writable:
                remote_flags |= nbt.NBT_SERVER_WRITABLE
            if require_pdc:
                remote_flags |= nbt.NBT_SERVER_PDC
            remote_info = remote_net.finddc(flags=remote_flags, domain=domain, address=remote_server)
        except NTSTATUSError as error:
            raise CommandError("Failed to find a writeable DC for domain '%s': %s" %
                               (domain, error.args[1]))
        except Exception:
            raise CommandError("Failed to find a writeable DC for domain '%s'" % domain)
        flag_map = {
            nbt.NBT_SERVER_PDC: "PDC",
            nbt.NBT_SERVER_GC: "GC",
            nbt.NBT_SERVER_LDAP: "LDAP",
            nbt.NBT_SERVER_DS: "DS",
            nbt.NBT_SERVER_KDC: "KDC",
            nbt.NBT_SERVER_TIMESERV: "TIMESERV",
            nbt.NBT_SERVER_CLOSEST: "CLOSEST",
            nbt.NBT_SERVER_WRITABLE: "WRITABLE",
            nbt.NBT_SERVER_GOOD_TIMESERV: "GOOD_TIMESERV",
            nbt.NBT_SERVER_NDNC: "NDNC",
            nbt.NBT_SERVER_SELECT_SECRET_DOMAIN_6: "SELECT_SECRET_DOMAIN_6",
            nbt.NBT_SERVER_FULL_SECRET_DOMAIN_6: "FULL_SECRET_DOMAIN_6",
            nbt.NBT_SERVER_ADS_WEB_SERVICE: "ADS_WEB_SERVICE",
            nbt.NBT_SERVER_DS_8: "DS_8",
            nbt.NBT_SERVER_DS_9: "DS_9",
            nbt.NBT_SERVER_DS_10: "DS_10",
            nbt.NBT_SERVER_HAS_DNS_NAME: "HAS_DNS_NAME",
            nbt.NBT_SERVER_IS_DEFAULT_NC: "IS_DEFAULT_NC",
            nbt.NBT_SERVER_FOREST_ROOT: "FOREST_ROOT",
        }
        server_type_string = self.generic_bitmap_to_string(flag_map,
                                                           remote_info.server_type, names_only=True)
        self.outf.write("RemoteDC Netbios[%s] DNS[%s] ServerType[%s]\n" % (
                        remote_info.pdc_name,
                        remote_info.pdc_dns_name,
                        server_type_string))

        self.remote_server = remote_info.pdc_dns_name
        self.remote_binding_string = "ncacn_np:%s[%s]" % (self.remote_server, remote_binding_options)
        self.remote_creds = remote_creds
        return self.remote_server

    def new_remote_lsa_connection(self):
        return lsa.lsarpc(self.remote_binding_string, self.local_lp, self.remote_creds)

    def new_remote_netlogon_connection(self):
        return netlogon.netlogon(self.remote_binding_string, self.local_lp, self.remote_creds)

    def get_lsa_info(self, conn, policy_access):
        in_version = 1
        in_revision_info1 = lsa.revision_info1()
        in_revision_info1.revision = 1
        in_revision_info1.supported_features = (
            lsa.LSA_FEATURE_TDO_AUTH_INFO_AES_CIPHER
        )

        out_version, out_revision_info1, policy = OpenPolicyFallback(
            conn,
            b''.decode('utf-8'),
            in_version,
            in_revision_info1,
            False,
            policy_access
        )

        info = conn.QueryInfoPolicy2(policy, lsa.LSA_POLICY_INFO_DNS)

        return (policy, out_version, out_revision_info1, info)

    def get_netlogon_dc_unc(self, conn, server, domain):
        try:
            info = conn.netr_DsRGetDCNameEx2(server,
                                             None, 0, None, None, None,
                                             netlogon.DS_RETURN_DNS_NAME)
            return info.dc_unc
        except RuntimeError:
            return conn.netr_GetDcName(server, domain)

    def get_netlogon_dc_info(self, conn, server):
        info = conn.netr_DsRGetDCNameEx2(server,
                                         None, 0, None, None, None,
                                         netlogon.DS_RETURN_DNS_NAME)
        return info

    def netr_DomainTrust_to_name(self, t):
        if t.trust_type == lsa.LSA_TRUST_TYPE_DOWNLEVEL:
            return t.netbios_name

        return t.dns_name

    def netr_DomainTrust_to_type(self, a, t):
        primary = None
        primary_parent = None
        for _t in a:
            if _t.trust_flags & netlogon.NETR_TRUST_FLAG_PRIMARY:
                primary = _t
                if not _t.trust_flags & netlogon.NETR_TRUST_FLAG_TREEROOT:
                    primary_parent = a[_t.parent_index]
                break

        if t.trust_flags & netlogon.NETR_TRUST_FLAG_IN_FOREST:
            if t is primary_parent:
                return "Parent"

            if t.trust_flags & netlogon.NETR_TRUST_FLAG_TREEROOT:
                return "TreeRoot"

            parent = a[t.parent_index]
            if parent is primary:
                return "Child"

            return "Shortcut"

        if t.trust_attributes & lsa.LSA_TRUST_ATTRIBUTE_FOREST_TRANSITIVE:
            return "Forest"

        return "External"

    def netr_DomainTrust_to_transitive(self, t):
        if t.trust_flags & netlogon.NETR_TRUST_FLAG_IN_FOREST:
            return "Yes"

        if t.trust_attributes & lsa.LSA_TRUST_ATTRIBUTE_NON_TRANSITIVE:
            return "No"

        if t.trust_attributes & lsa.LSA_TRUST_ATTRIBUTE_FOREST_TRANSITIVE:
            return "Yes"

        return "No"

    def netr_DomainTrust_to_direction(self, t):
        if t.trust_flags & netlogon.NETR_TRUST_FLAG_INBOUND and \
           t.trust_flags & netlogon.NETR_TRUST_FLAG_OUTBOUND:
            return "BOTH"

        if t.trust_flags & netlogon.NETR_TRUST_FLAG_INBOUND:
            return "INCOMING"

        if t.trust_flags & netlogon.NETR_TRUST_FLAG_OUTBOUND:
            return "OUTGOING"

        return "INVALID"

    def generic_enum_to_string(self, e_dict, v, names_only=False):
        try:
            w = e_dict[v]
        except KeyError:
            v32 = self._uint32(v)
            w = "__unknown__%08X__" % v32

        r = "0x%x (%s)" % (v, w)
        return r

    def generic_bitmap_to_string(self, b_dict, v, names_only=False):

        s = []

        c = v
        for b in sorted(b_dict.keys()):
            if not (c & b):
                continue
            c &= ~b
            s += [b_dict[b]]

        if c != 0:
            c32 = self._uint32(c)
            s += ["__unknown_%08X__" % c32]

        w = ",".join(s)
        if names_only:
            return w
        r = "0x%x (%s)" % (v, w)
        return r

    def trustType_string(self, v):
        types = {
            lsa.LSA_TRUST_TYPE_DOWNLEVEL: "DOWNLEVEL",
            lsa.LSA_TRUST_TYPE_UPLEVEL: "UPLEVEL",
            lsa.LSA_TRUST_TYPE_MIT: "MIT",
            lsa.LSA_TRUST_TYPE_DCE: "DCE",
        }
        return self.generic_enum_to_string(types, v)

    def trustDirection_string(self, v):
        directions = {
            lsa.LSA_TRUST_DIRECTION_INBOUND |
            lsa.LSA_TRUST_DIRECTION_OUTBOUND: "BOTH",
            lsa.LSA_TRUST_DIRECTION_INBOUND: "INBOUND",
            lsa.LSA_TRUST_DIRECTION_OUTBOUND: "OUTBOUND",
        }
        return self.generic_enum_to_string(directions, v)

    def trustAttributes_string(self, v):
        attributes = {
            lsa.LSA_TRUST_ATTRIBUTE_NON_TRANSITIVE: "NON_TRANSITIVE",
            lsa.LSA_TRUST_ATTRIBUTE_UPLEVEL_ONLY: "UPLEVEL_ONLY",
            lsa.LSA_TRUST_ATTRIBUTE_QUARANTINED_DOMAIN: "QUARANTINED_DOMAIN",
            lsa.LSA_TRUST_ATTRIBUTE_FOREST_TRANSITIVE: "FOREST_TRANSITIVE",
            lsa.LSA_TRUST_ATTRIBUTE_CROSS_ORGANIZATION: "CROSS_ORGANIZATION",
            lsa.LSA_TRUST_ATTRIBUTE_WITHIN_FOREST: "WITHIN_FOREST",
            lsa.LSA_TRUST_ATTRIBUTE_TREAT_AS_EXTERNAL: "TREAT_AS_EXTERNAL",
            lsa.LSA_TRUST_ATTRIBUTE_USES_RC4_ENCRYPTION: "USES_RC4_ENCRYPTION",
        }
        return self.generic_bitmap_to_string(attributes, v)

    def kerb_EncTypes_string(self, v):
        enctypes = {
            security.KERB_ENCTYPE_DES_CBC_CRC: "DES_CBC_CRC",
            security.KERB_ENCTYPE_DES_CBC_MD5: "DES_CBC_MD5",
            security.KERB_ENCTYPE_RC4_HMAC_MD5: "RC4_HMAC_MD5",
            security.KERB_ENCTYPE_AES128_CTS_HMAC_SHA1_96: "AES128_CTS_HMAC_SHA1_96",
            security.KERB_ENCTYPE_AES256_CTS_HMAC_SHA1_96: "AES256_CTS_HMAC_SHA1_96",
            security.KERB_ENCTYPE_AES256_CTS_HMAC_SHA1_96_SK: "AES256_CTS_HMAC_SHA1_96-SK",
            security.KERB_ENCTYPE_FAST_SUPPORTED: "FAST_SUPPORTED",
            security.KERB_ENCTYPE_COMPOUND_IDENTITY_SUPPORTED: "COMPOUND_IDENTITY_SUPPORTED",
            security.KERB_ENCTYPE_CLAIMS_SUPPORTED: "CLAIMS_SUPPORTED",
            security.KERB_ENCTYPE_RESOURCE_SID_COMPRESSION_DISABLED: "RESOURCE_SID_COMPRESSION_DISABLED",
        }
        return self.generic_bitmap_to_string(enctypes, v)

    def entry_tln_status(self, e_flags, ):
        if e_flags == 0:
            return "Status[Enabled]"

        flags = {
            lsa.LSA_TLN_DISABLED_NEW: "Disabled-New",
            lsa.LSA_TLN_DISABLED_ADMIN: "Disabled",
            lsa.LSA_TLN_DISABLED_CONFLICT: "Disabled-Conflicting",
        }
        return "Status[%s]" % self.generic_bitmap_to_string(flags, e_flags, names_only=True)

    def entry_dom_status(self, e_flags):
        if e_flags == 0:
            return "Status[Enabled]"

        flags = {
            lsa.LSA_SID_DISABLED_ADMIN: "Disabled-SID",
            lsa.LSA_SID_DISABLED_CONFLICT: "Disabled-SID-Conflicting",
            lsa.LSA_NB_DISABLED_ADMIN: "Disabled-NB",
            lsa.LSA_NB_DISABLED_CONFLICT: "Disabled-NB-Conflicting",
        }
        return "Status[%s]" % self.generic_bitmap_to_string(flags, e_flags, names_only=True)

    def write_forest_trust_info(self, fti, tln=None, collisions=None):
        if tln is not None:
            tln_string = " TDO[%s]" % tln
        else:
            tln_string = ""

        self.outf.write("Namespaces[%d]%s:\n" % (
                        len(fti.entries), tln_string))

        for i, e in enumerate(fti.entries):

            flags = e.flags
            collision_string = ""

            if collisions is not None:
                for c in collisions.entries:
                    if c.index != i:
                        continue
                    flags = c.flags
                    collision_string = " Collision[%s]" % (c.name.string)

            d = e.forest_trust_data
            if e.type == lsa.LSA_FOREST_TRUST_TOP_LEVEL_NAME:
                self.outf.write("TLN: %-32s DNS[*.%s]%s\n" % (
                                self.entry_tln_status(flags),
                                d.string, collision_string))
            elif e.type == lsa.LSA_FOREST_TRUST_TOP_LEVEL_NAME_EX:
                self.outf.write("TLN_EX: %-29s DNS[*.%s]\n" % (
                                "", d.string))
            elif e.type == lsa.LSA_FOREST_TRUST_DOMAIN_INFO:
                self.outf.write("DOM: %-32s DNS[%s] Netbios[%s] SID[%s]%s\n" % (
                                self.entry_dom_status(flags),
                                d.dns_domain_name.string,
                                d.netbios_domain_name.string,
                                d.domain_sid, collision_string))
        return


class cmd_domain_trust_list(DomainTrustCommand):
    """List domain trusts."""

    synopsis = "%prog [options]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "versionopts": options.VersionOptions,
        "localdcopts": LocalDCCredentialsOptions,
    }

    takes_options = [
    ]

    def run(self, sambaopts=None, versionopts=None, localdcopts=None):

        local_server = self.setup_local_server(sambaopts, localdcopts)
        try:
            local_netlogon = self.new_local_netlogon_connection()
        except RuntimeError as error:
            raise self.LocalRuntimeError(self, error, "failed to connect netlogon server")

        try:
            local_netlogon_trusts = \
                local_netlogon.netr_DsrEnumerateDomainTrusts(local_server,
                                                             netlogon.NETR_TRUST_FLAG_IN_FOREST |
                                                             netlogon.NETR_TRUST_FLAG_OUTBOUND |
                                                             netlogon.NETR_TRUST_FLAG_INBOUND)
        except RuntimeError as error:
            if self.check_runtime_error(error, werror.WERR_RPC_S_PROCNUM_OUT_OF_RANGE):
                # TODO: we could implement a fallback to lsa.EnumTrustDom()
                raise CommandError("LOCAL_DC[%s]: netr_DsrEnumerateDomainTrusts not supported." % (
                                   local_server))
            raise self.LocalRuntimeError(self, error, "netr_DsrEnumerateDomainTrusts failed")

        a = local_netlogon_trusts.array
        for t in a:
            if t.trust_flags & netlogon.NETR_TRUST_FLAG_PRIMARY:
                continue
            self.outf.write("%-14s %-15s %-19s %s\n" % (
                            "Type[%s]" % self.netr_DomainTrust_to_type(a, t),
                            "Transitive[%s]" % self.netr_DomainTrust_to_transitive(t),
                            "Direction[%s]" % self.netr_DomainTrust_to_direction(t),
                            "Name[%s]" % self.netr_DomainTrust_to_name(t)))
        return


class cmd_domain_trust_show(DomainTrustCommand):
    """Show trusted domain details."""

    synopsis = "%prog NAME [options]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "versionopts": options.VersionOptions,
        "localdcopts": LocalDCCredentialsOptions,
    }

    takes_options = [
    ]

    takes_args = ["domain"]

    def run(self, domain, sambaopts=None, versionopts=None, localdcopts=None):

        self.setup_local_server(sambaopts, localdcopts)
        try:
            local_lsa = self.new_local_lsa_connection()
        except RuntimeError as error:
            raise self.LocalRuntimeError(self, error, "failed to connect lsa server")

        try:
            local_policy_access = lsa.LSA_POLICY_VIEW_LOCAL_INFORMATION
            (
                local_policy,
                local_version,
                local_revision_info1,
                local_lsa_info
            ) = self.get_lsa_info(local_lsa, local_policy_access)
        except RuntimeError as error:
            raise self.LocalRuntimeError(self, error, "failed to query LSA_POLICY_INFO_DNS")

        self.outf.write("LocalDomain Netbios[%s] DNS[%s] SID[%s]\n" % (
                        local_lsa_info.name.string,
                        local_lsa_info.dns_domain.string,
                        local_lsa_info.sid))

        lsaString = lsa.String()
        lsaString.string = domain
        try:
            local_tdo_full = \
                local_lsa.QueryTrustedDomainInfoByName(local_policy,
                                                       lsaString,
                                                       lsa.LSA_TRUSTED_DOMAIN_INFO_FULL_INFO)
            local_tdo_info = local_tdo_full.info_ex
            local_tdo_posix = local_tdo_full.posix_offset
        except NTSTATUSError as error:
            if self.check_runtime_error(error, ntstatus.NT_STATUS_OBJECT_NAME_NOT_FOUND):
                raise CommandError("trusted domain object does not exist for domain [%s]" % domain)

            raise self.LocalRuntimeError(self, error, "QueryTrustedDomainInfoByName(FULL_INFO) failed")

        try:
            local_tdo_enctypes = \
                local_lsa.QueryTrustedDomainInfoByName(local_policy,
                                                       lsaString,
                                                       lsa.LSA_TRUSTED_DOMAIN_SUPPORTED_ENCRYPTION_TYPES)
        except NTSTATUSError as error:
            if self.check_runtime_error(error, ntstatus.NT_STATUS_INVALID_PARAMETER):
                error = None
            if self.check_runtime_error(error, ntstatus.NT_STATUS_INVALID_INFO_CLASS):
                error = None

            if error is not None:
                raise self.LocalRuntimeError(self, error,
                                             "QueryTrustedDomainInfoByName(SUPPORTED_ENCRYPTION_TYPES) failed")

            local_tdo_enctypes = lsa.TrustDomainInfoSupportedEncTypes()
            local_tdo_enctypes.enc_types = 0

        try:
            local_tdo_forest = None
            if local_tdo_info.trust_attributes & lsa.LSA_TRUST_ATTRIBUTE_FOREST_TRANSITIVE:
                local_tdo_forest = \
                    local_lsa.lsaRQueryForestTrustInformation(local_policy,
                                                              lsaString,
                                                              lsa.LSA_FOREST_TRUST_DOMAIN_INFO)
        except RuntimeError as error:
            if self.check_runtime_error(error, ntstatus.NT_STATUS_RPC_PROCNUM_OUT_OF_RANGE):
                error = None
            if self.check_runtime_error(error, ntstatus.NT_STATUS_NOT_FOUND):
                error = None
            if error is not None:
                raise self.LocalRuntimeError(self, error, "lsaRQueryForestTrustInformation failed")

            local_tdo_forest = lsa.ForestTrustInformation()
            local_tdo_forest.count = 0
            local_tdo_forest.entries = []

        self.outf.write("TrustedDomain:\n\n")
        self.outf.write("NetbiosName:    %s\n" % local_tdo_info.netbios_name.string)
        if local_tdo_info.netbios_name.string != local_tdo_info.domain_name.string:
            self.outf.write("DnsName:        %s\n" % local_tdo_info.domain_name.string)
        self.outf.write("SID:            %s\n" % local_tdo_info.sid)
        self.outf.write("Type:           %s\n" % self.trustType_string(local_tdo_info.trust_type))
        self.outf.write("Direction:      %s\n" % self.trustDirection_string(local_tdo_info.trust_direction))
        self.outf.write("Attributes:     %s\n" % self.trustAttributes_string(local_tdo_info.trust_attributes))
        posix_offset_u32 = ctypes.c_uint32(local_tdo_posix.posix_offset).value
        posix_offset_i32 = ctypes.c_int32(local_tdo_posix.posix_offset).value
        self.outf.write("PosixOffset:    0x%08X (%d)\n" % (posix_offset_u32, posix_offset_i32))
        self.outf.write("kerb_EncTypes:  %s\n" % self.kerb_EncTypes_string(local_tdo_enctypes.enc_types))

        if local_tdo_info.trust_attributes & lsa.LSA_TRUST_ATTRIBUTE_FOREST_TRANSITIVE:
            self.write_forest_trust_info(local_tdo_forest,
                                         tln=local_tdo_info.domain_name.string)

        return

class cmd_domain_trust_modify(DomainTrustCommand):
    """Show trusted domain details."""

    synopsis = "%prog NAME [options]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "versionopts": options.VersionOptions,
        "localdcopts": LocalDCCredentialsOptions,
    }

    takes_options = [
        Option("--use-aes-keys", action="store_true",
               help="The trust uses AES kerberos keys.",
               dest='use_aes_keys',
               default=None),
        Option("--no-aes-keys", action="store_true",
               help="The trust does not have any support for AES kerberos keys.",
               dest='disable_aes_keys',
               default=None),
        Option("--raw-kerb-enctypes", action="store",
               help="The raw kerberos enctype bits",
               dest='kerb_enctypes',
               default=None),
    ]

    takes_args = ["domain"]

    def run(self, domain, sambaopts=None, versionopts=None, localdcopts=None,
            disable_aes_keys=None, use_aes_keys=None, kerb_enctypes=None):

        num_modifications = 0

        enctype_args = 0
        if kerb_enctypes is not None:
            enctype_args += 1
        if use_aes_keys is not None:
            enctype_args += 1
        if disable_aes_keys is not None:
            enctype_args += 1
        if enctype_args > 1:
            raise CommandError("--no-aes-keys, --use-aes-keys and --raw-kerb-enctypes are mutually exclusive")
        if enctype_args == 1:
            num_modifications += 1

        if num_modifications == 0:
            raise CommandError("modification arguments are required, try --help")

        self.setup_local_server(sambaopts, localdcopts)
        try:
            local_lsa = self.new_local_lsa_connection()
        except RuntimeError as error:
            raise self.LocalRuntimeError(self, error, "failed to connect to lsa server")

        try:
            local_policy_access = lsa.LSA_POLICY_VIEW_LOCAL_INFORMATION
            (
                local_policy,
                local_version,
                local_revision_info1,
                local_lsa_info
            ) = self.get_lsa_info(local_lsa, local_policy_access)
        except RuntimeError as error:
            raise self.LocalRuntimeError(self, error, "failed to query LSA_POLICY_INFO_DNS")

        self.outf.write("LocalDomain Netbios[%s] DNS[%s] SID[%s]\n" % (
                        local_lsa_info.name.string,
                        local_lsa_info.dns_domain.string,
                        local_lsa_info.sid))

        if enctype_args == 1:
            lsaString = lsa.String()
            lsaString.string = domain

            try:
                local_tdo_enctypes = \
                    local_lsa.QueryTrustedDomainInfoByName(local_policy,
                                                           lsaString,
                                                           lsa.LSA_TRUSTED_DOMAIN_SUPPORTED_ENCRYPTION_TYPES)
            except NTSTATUSError as error:
                if self.check_runtime_error(error, ntstatus.NT_STATUS_INVALID_PARAMETER):
                    error = None
                if self.check_runtime_error(error, ntstatus.NT_STATUS_INVALID_INFO_CLASS):
                    error = None

                if error is not None:
                    raise self.LocalRuntimeError(self, error,
                                                 "QueryTrustedDomainInfoByName(SUPPORTED_ENCRYPTION_TYPES) failed")

                local_tdo_enctypes = lsa.TrustDomainInfoSupportedEncTypes()
                local_tdo_enctypes.enc_types = 0

            self.outf.write("Old kerb_EncTypes:  %s\n" % self.kerb_EncTypes_string(local_tdo_enctypes.enc_types))

            enc_types = lsa.TrustDomainInfoSupportedEncTypes()
            if kerb_enctypes is not None:
                enc_types.enc_types = int(kerb_enctypes, base=0)
            elif use_aes_keys is not None:
                enc_types.enc_types = security.KERB_ENCTYPE_AES128_CTS_HMAC_SHA1_96
                enc_types.enc_types |= security.KERB_ENCTYPE_AES256_CTS_HMAC_SHA1_96
            elif disable_aes_keys is not None:
                # CVE-2022-37966: Trust objects are no longer assumed to support
                # RC4, so we must indicate support explicitly.
                enc_types.enc_types = security.KERB_ENCTYPE_RC4_HMAC_MD5
            else:
                raise CommandError("Internal error should be checked above")

            if enc_types.enc_types != local_tdo_enctypes.enc_types:
                try:
                    local_tdo_enctypes = \
                        local_lsa.SetTrustedDomainInfoByName(local_policy,
                                                             lsaString,
                                                             lsa.LSA_TRUSTED_DOMAIN_SUPPORTED_ENCRYPTION_TYPES,
                                                             enc_types)
                    self.outf.write("New kerb_EncTypes:  %s\n" % self.kerb_EncTypes_string(enc_types.enc_types))
                except NTSTATUSError as error:
                    if error is not None:
                        raise self.LocalRuntimeError(self, error,
                                                     "SetTrustedDomainInfoByName(SUPPORTED_ENCRYPTION_TYPES) failed")
            else:
                self.outf.write("No kerb_EncTypes update needed\n")

        return

class cmd_domain_trust_create(DomainTrustCommand):
    """Create a domain or forest trust."""

    synopsis = "%prog DOMAIN [options]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "versionopts": options.VersionOptions,
        "credopts": options.CredentialsOptions,
        "localdcopts": LocalDCCredentialsOptions,
    }

    takes_options = [
        Option("--type", type="choice", metavar="TYPE",
               choices=["external", "forest"],
               help="The type of the trust: 'external' or 'forest'.",
               dest='trust_type',
               default="external"),
        Option("--direction", type="choice", metavar="DIRECTION",
               choices=["incoming", "outgoing", "both"],
               help="The trust direction: 'incoming', 'outgoing' or 'both'.",
               dest='trust_direction',
               default="both"),
        Option("--create-location", type="choice", metavar="LOCATION",
               choices=["local", "both"],
               help="Where to create the trusted domain object: 'local' or 'both'.",
               dest='create_location',
               default="both"),
        Option("--cross-organisation", action="store_true",
               help="The related domains does not belong to the same organisation.",
               dest='cross_organisation',
               default=False),
        Option("--quarantined", type="choice", metavar="yes|no",
               choices=["yes", "no", None],
               help="Special SID filtering rules are applied to the trust. "
                    "With --type=external the default is yes. "
                    "With --type=forest the default is no.",
               dest='quarantined_arg',
               default=None),
        Option("--not-transitive", action="store_true",
               help="The forest trust is not transitive.",
               dest='not_transitive',
               default=False),
        Option("--treat-as-external", action="store_true",
               help="The treat the forest trust as external.",
               dest='treat_as_external',
               default=False),
        Option("--no-aes-keys", action="store_false",
               help="The trust does not use AES kerberos keys.",
               dest='use_aes_keys',
               default=True),
        Option("--skip-validation", action="store_false",
               help="Skip validation of the trust.",
               dest='validate',
               default=True),
    ]

    takes_args = ["domain"]

    def run(self, domain, sambaopts=None, localdcopts=None, credopts=None, versionopts=None,
            trust_type=None, trust_direction=None, create_location=None,
            cross_organisation=False, quarantined_arg=None,
            not_transitive=False, treat_as_external=False,
            use_aes_keys=False, validate=True):

        lsaString = lsa.String()

        quarantined = False
        if quarantined_arg is None:
            if trust_type == 'external':
                quarantined = True
        elif quarantined_arg == 'yes':
            quarantined = True

        if trust_type != 'forest':
            if not_transitive:
                raise CommandError("--not-transitive requires --type=forest")
            if treat_as_external:
                raise CommandError("--treat-as-external requires --type=forest")

        enc_types = lsa.TrustDomainInfoSupportedEncTypes()
        if use_aes_keys:
            enc_types.enc_types = security.KERB_ENCTYPE_AES128_CTS_HMAC_SHA1_96
            enc_types.enc_types |= security.KERB_ENCTYPE_AES256_CTS_HMAC_SHA1_96
        else:
            # CVE-2022-37966: Trust objects are no longer assumed to support
            # RC4, so we must indicate support explicitly.
            enc_types.enc_types = security.KERB_ENCTYPE_RC4_HMAC_MD5

        local_policy_access = lsa.LSA_POLICY_VIEW_LOCAL_INFORMATION
        local_policy_access |= lsa.LSA_POLICY_TRUST_ADMIN
        local_policy_access |= lsa.LSA_POLICY_CREATE_SECRET

        local_trust_info = lsa.TrustDomainInfoInfoEx()
        local_trust_info.trust_type = lsa.LSA_TRUST_TYPE_UPLEVEL
        local_trust_info.trust_direction = 0
        if trust_direction == "both":
            local_trust_info.trust_direction |= lsa.LSA_TRUST_DIRECTION_INBOUND
            local_trust_info.trust_direction |= lsa.LSA_TRUST_DIRECTION_OUTBOUND
        elif trust_direction == "incoming":
            local_trust_info.trust_direction |= lsa.LSA_TRUST_DIRECTION_INBOUND
        elif trust_direction == "outgoing":
            local_trust_info.trust_direction |= lsa.LSA_TRUST_DIRECTION_OUTBOUND
        local_trust_info.trust_attributes = 0
        if cross_organisation:
            local_trust_info.trust_attributes |= lsa.LSA_TRUST_ATTRIBUTE_CROSS_ORGANIZATION
        if quarantined:
            local_trust_info.trust_attributes |= lsa.LSA_TRUST_ATTRIBUTE_QUARANTINED_DOMAIN
        if trust_type == "forest":
            local_trust_info.trust_attributes |= lsa.LSA_TRUST_ATTRIBUTE_FOREST_TRANSITIVE
        if not_transitive:
            local_trust_info.trust_attributes |= lsa.LSA_TRUST_ATTRIBUTE_NON_TRANSITIVE
        if treat_as_external:
            local_trust_info.trust_attributes |= lsa.LSA_TRUST_ATTRIBUTE_TREAT_AS_EXTERNAL

        def get_password(name):
            password = None
            while True:
                if password is not None and password != '':
                    return password
                password = getpass("New %s Password: " % name)
                passwordverify = getpass("Retype %s Password: " % name)
                if not password == passwordverify:
                    password = None
                    self.outf.write("Sorry, passwords do not match.\n")

        incoming_secret = None
        outgoing_secret = None
        remote_policy_access = lsa.LSA_POLICY_VIEW_LOCAL_INFORMATION
        if create_location == "local":
            if local_trust_info.trust_direction & lsa.LSA_TRUST_DIRECTION_INBOUND:
                incoming_password = get_password("Incoming Trust")
                incoming_secret = list(incoming_password.encode('utf-16-le'))
            if local_trust_info.trust_direction & lsa.LSA_TRUST_DIRECTION_OUTBOUND:
                outgoing_password = get_password("Outgoing Trust")
                outgoing_secret = list(outgoing_password.encode('utf-16-le'))

            remote_trust_info = None
        else:
            # We use 240 random bytes.
            # Windows uses 28 or 240 random bytes. I guess it's
            # based on the trust type external vs. forest.
            #
            # The initial trust password can be up to 512 bytes
            # while the versioned passwords used for periodic updates
            # can only be up to 498 bytes, as netr_ServerPasswordSet2()
            # needs to pass the NL_PASSWORD_VERSION structure within the
            # 512 bytes and a 2 bytes confounder is required.
            #
            def random_trust_secret(length):
                pw = samba.generate_random_machine_password(length // 2, length // 2)
                return list(pw.encode('utf-16-le'))

            if local_trust_info.trust_direction & lsa.LSA_TRUST_DIRECTION_INBOUND:
                incoming_secret = random_trust_secret(240)
            if local_trust_info.trust_direction & lsa.LSA_TRUST_DIRECTION_OUTBOUND:
                outgoing_secret = random_trust_secret(240)

            remote_policy_access |= lsa.LSA_POLICY_TRUST_ADMIN
            remote_policy_access |= lsa.LSA_POLICY_CREATE_SECRET

            remote_trust_info = lsa.TrustDomainInfoInfoEx()
            remote_trust_info.trust_type = lsa.LSA_TRUST_TYPE_UPLEVEL
            remote_trust_info.trust_direction = 0
            if trust_direction == "both":
                remote_trust_info.trust_direction |= lsa.LSA_TRUST_DIRECTION_INBOUND
                remote_trust_info.trust_direction |= lsa.LSA_TRUST_DIRECTION_OUTBOUND
            elif trust_direction == "incoming":
                remote_trust_info.trust_direction |= lsa.LSA_TRUST_DIRECTION_OUTBOUND
            elif trust_direction == "outgoing":
                remote_trust_info.trust_direction |= lsa.LSA_TRUST_DIRECTION_INBOUND
            remote_trust_info.trust_attributes = 0
            if cross_organisation:
                remote_trust_info.trust_attributes |= lsa.LSA_TRUST_ATTRIBUTE_CROSS_ORGANIZATION
            if quarantined:
                remote_trust_info.trust_attributes |= lsa.LSA_TRUST_ATTRIBUTE_QUARANTINED_DOMAIN
            if trust_type == "forest":
                remote_trust_info.trust_attributes |= lsa.LSA_TRUST_ATTRIBUTE_FOREST_TRANSITIVE
            if not_transitive:
                remote_trust_info.trust_attributes |= lsa.LSA_TRUST_ATTRIBUTE_NON_TRANSITIVE
            if treat_as_external:
                remote_trust_info.trust_attributes |= lsa.LSA_TRUST_ATTRIBUTE_TREAT_AS_EXTERNAL

        local_server = self.setup_local_server(sambaopts, localdcopts)
        try:
            local_lsa = self.new_local_lsa_connection()
        except RuntimeError as error:
            raise self.LocalRuntimeError(self, error, "failed to connect lsa server")

        try:
            (
                local_policy,
                local_version,
                local_revision_info1,
                local_lsa_info
            ) = self.get_lsa_info(local_lsa, local_policy_access)
        except RuntimeError as error:
            raise self.LocalRuntimeError(self, error, "failed to query LSA_POLICY_INFO_DNS")

        self.outf.write("LocalDomain Netbios[%s] DNS[%s] SID[%s]\n" % (
                        local_lsa_info.name.string,
                        local_lsa_info.dns_domain.string,
                        local_lsa_info.sid))

        try:
            remote_server = self.setup_remote_server(credopts, domain)
        except RuntimeError as error:
            raise self.RemoteRuntimeError(self, error, "failed to locate remote server")

        try:
            remote_lsa = self.new_remote_lsa_connection()
        except RuntimeError as error:
            raise self.RemoteRuntimeError(self, error, "failed to connect lsa server")

        try:
            (
                remote_policy,
                remote_version,
                remote_revision_info1,
                remote_lsa_info
            ) = self.get_lsa_info(remote_lsa, remote_policy_access)
        except RuntimeError as error:
            raise self.RemoteRuntimeError(self, error, "failed to query LSA_POLICY_INFO_DNS")

        self.outf.write("RemoteDomain Netbios[%s] DNS[%s] SID[%s]\n" % (
                        remote_lsa_info.name.string,
                        remote_lsa_info.dns_domain.string,
                        remote_lsa_info.sid))

        local_trust_info.domain_name.string = remote_lsa_info.dns_domain.string
        local_trust_info.netbios_name.string = remote_lsa_info.name.string
        local_trust_info.sid = remote_lsa_info.sid

        if remote_trust_info:
            remote_trust_info.domain_name.string = local_lsa_info.dns_domain.string
            remote_trust_info.netbios_name.string = local_lsa_info.name.string
            remote_trust_info.sid = local_lsa_info.sid

        try:
            lsaString.string = local_trust_info.domain_name.string
            local_lsa.QueryTrustedDomainInfoByName(local_policy,
                                                   lsaString,
                                                   lsa.LSA_TRUSTED_DOMAIN_INFO_FULL_INFO)
            raise CommandError("TrustedDomain %s already exist'" % lsaString.string)
        except NTSTATUSError as error:
            if not self.check_runtime_error(error, ntstatus.NT_STATUS_OBJECT_NAME_NOT_FOUND):
                raise self.LocalRuntimeError(self, error,
                                             "QueryTrustedDomainInfoByName(%s, FULL_INFO) failed" % (
                                                 lsaString.string))

        try:
            lsaString.string = local_trust_info.netbios_name.string
            local_lsa.QueryTrustedDomainInfoByName(local_policy,
                                                   lsaString,
                                                   lsa.LSA_TRUSTED_DOMAIN_INFO_FULL_INFO)
            raise CommandError("TrustedDomain %s already exist'" % lsaString.string)
        except NTSTATUSError as error:
            if not self.check_runtime_error(error, ntstatus.NT_STATUS_OBJECT_NAME_NOT_FOUND):
                raise self.LocalRuntimeError(self, error,
                                             "QueryTrustedDomainInfoByName(%s, FULL_INFO) failed" % (
                                                 lsaString.string))

        if remote_trust_info:
            try:
                lsaString.string = remote_trust_info.domain_name.string
                remote_lsa.QueryTrustedDomainInfoByName(remote_policy,
                                                        lsaString,
                                                        lsa.LSA_TRUSTED_DOMAIN_INFO_FULL_INFO)
                raise CommandError("TrustedDomain %s already exist'" % lsaString.string)
            except NTSTATUSError as error:
                if not self.check_runtime_error(error, ntstatus.NT_STATUS_OBJECT_NAME_NOT_FOUND):
                    raise self.RemoteRuntimeError(self, error,
                                                  "QueryTrustedDomainInfoByName(%s, FULL_INFO) failed" % (
                                                      lsaString.string))

            try:
                lsaString.string = remote_trust_info.netbios_name.string
                remote_lsa.QueryTrustedDomainInfoByName(remote_policy,
                                                        lsaString,
                                                        lsa.LSA_TRUSTED_DOMAIN_INFO_FULL_INFO)
                raise CommandError("TrustedDomain %s already exist'" % lsaString.string)
            except NTSTATUSError as error:
                if not self.check_runtime_error(error, ntstatus.NT_STATUS_OBJECT_NAME_NOT_FOUND):
                    raise self.RemoteRuntimeError(self, error,
                                                  "QueryTrustedDomainInfoByName(%s, FULL_INFO) failed" % (
                                                      lsaString.string))

        try:
            local_netlogon = self.new_local_netlogon_connection()
        except RuntimeError as error:
            raise self.LocalRuntimeError(self, error, "failed to connect netlogon server")

        try:
            local_netlogon_info = self.get_netlogon_dc_info(local_netlogon, local_server)
        except RuntimeError as error:
            raise self.LocalRuntimeError(self, error, "failed to get netlogon dc info")

        if remote_trust_info:
            try:
                remote_netlogon = self.new_remote_netlogon_connection()
            except RuntimeError as error:
                raise self.RemoteRuntimeError(self, error, "failed to connect netlogon server")

            try:
                remote_netlogon_dc_unc = self.get_netlogon_dc_unc(remote_netlogon,
                                                                  remote_server, domain)
            except RuntimeError as error:
                raise self.RemoteRuntimeError(self, error, "failed to get netlogon dc info")

        def generate_AuthInOutBlob(secret, update_time):
            if secret is None:
                blob = drsblobs.trustAuthInOutBlob()
                blob.count = 0

                return blob

            clear = drsblobs.AuthInfoClear()
            clear.size = len(secret)
            clear.password = secret

            info = drsblobs.AuthenticationInformation()
            info.LastUpdateTime = samba.unix2nttime(update_time)
            info.AuthType = lsa.TRUST_AUTH_TYPE_CLEAR
            info.AuthInfo = clear

            array = drsblobs.AuthenticationInformationArray()
            array.count = 1
            array.array = [info]

            blob = drsblobs.trustAuthInOutBlob()
            blob.count = 1
            blob.current = array

            return blob

        update_time = samba.current_unix_time()
        incoming_blob = generate_AuthInOutBlob(incoming_secret, update_time)
        outgoing_blob = generate_AuthInOutBlob(outgoing_secret, update_time)

        local_tdo_handle = None
        remote_tdo_handle = None

        try:
            if remote_trust_info:
                self.outf.write("Creating remote TDO.\n")
                current_request = {"location": "remote", "name": "CreateTrustedDomainEx2"}
                remote_tdo_handle = CreateTrustedDomainFallback(
                    remote_lsa,
                    remote_policy,
                    remote_trust_info,
                    lsa.LSA_TRUSTED_DOMAIN_ALL_ACCESS,
                    remote_version,
                    remote_revision_info1,
                    outgoing_blob,
                    incoming_blob
                )
                self.outf.write("Remote TDO created.\n")
                if enc_types:
                    self.outf.write("Setting supported encryption types on remote TDO.\n")
                    current_request = {"location": "remote", "name": "SetInformationTrustedDomain"}
                    remote_lsa.SetInformationTrustedDomain(remote_tdo_handle,
                                                           lsa.LSA_TRUSTED_DOMAIN_SUPPORTED_ENCRYPTION_TYPES,
                                                           enc_types)

            self.outf.write("Creating local TDO.\n")
            current_request = {"location": "local", "name": "CreateTrustedDomainEx2"}
            local_tdo_handle = CreateTrustedDomainFallback(
                local_lsa,
                local_policy,
                local_trust_info,
                lsa.LSA_TRUSTED_DOMAIN_ALL_ACCESS,
                local_version,
                local_revision_info1,
                incoming_blob,
                outgoing_blob
            )
            self.outf.write("Local TDO created\n")
            if enc_types:
                self.outf.write("Setting supported encryption types on local TDO.\n")
                current_request = {"location": "local", "name": "SetInformationTrustedDomain"}
                local_lsa.SetInformationTrustedDomain(local_tdo_handle,
                                                      lsa.LSA_TRUSTED_DOMAIN_SUPPORTED_ENCRYPTION_TYPES,
                                                      enc_types)
        except RuntimeError as error:
            self.outf.write("Error: %s failed %sly - cleaning up\n" % (
                            current_request['name'], current_request['location']))
            if remote_tdo_handle:
                self.outf.write("Deleting remote TDO.\n")
                remote_lsa.DeleteObject(remote_tdo_handle)
                remote_tdo_handle = None
            if local_tdo_handle:
                self.outf.write("Deleting local TDO.\n")
                local_lsa.DeleteObject(local_tdo_handle)
                local_tdo_handle = None
            if current_request['location'] == "remote":
                raise self.RemoteRuntimeError(self, error, "%s" % (
                                              current_request['name']))
            raise self.LocalRuntimeError(self, error, "%s" % (
                                         current_request['name']))

        if validate:
            if local_trust_info.trust_attributes & lsa.LSA_TRUST_ATTRIBUTE_FOREST_TRANSITIVE:
                self.outf.write("Setup local forest trust information...\n")
                try:
                    # get all information about the remote trust
                    # this triggers netr_GetForestTrustInformation to the remote domain
                    # and lsaRSetForestTrustInformation() locally, but new top level
                    # names are disabled by default.
                    local_forest_info = \
                        local_netlogon.netr_DsRGetForestTrustInformation(local_netlogon_info.dc_unc,
                                                                         remote_lsa_info.dns_domain.string,
                                                                         netlogon.DS_GFTI_UPDATE_TDO)
                except RuntimeError as error:
                    raise self.LocalRuntimeError(self, error, "netr_DsRGetForestTrustInformation() failed")

                try:
                    # here we try to enable all top level names
                    local_forest_collision = \
                        local_lsa.lsaRSetForestTrustInformation(local_policy,
                                                                remote_lsa_info.dns_domain,
                                                                lsa.LSA_FOREST_TRUST_DOMAIN_INFO,
                                                                local_forest_info,
                                                                0)
                except RuntimeError as error:
                    raise self.LocalRuntimeError(self, error, "lsaRSetForestTrustInformation() failed")

                self.write_forest_trust_info(local_forest_info,
                                             tln=remote_lsa_info.dns_domain.string,
                                             collisions=local_forest_collision)

                if remote_trust_info:
                    self.outf.write("Setup remote forest trust information...\n")
                    try:
                        # get all information about the local trust (from the perspective of the remote domain)
                        # this triggers netr_GetForestTrustInformation to our domain.
                        # and lsaRSetForestTrustInformation() remotely, but new top level
                        # names are disabled by default.
                        remote_forest_info = \
                            remote_netlogon.netr_DsRGetForestTrustInformation(remote_netlogon_dc_unc,
                                                                              local_lsa_info.dns_domain.string,
                                                                              netlogon.DS_GFTI_UPDATE_TDO)
                    except RuntimeError as error:
                        raise self.RemoteRuntimeError(self, error, "netr_DsRGetForestTrustInformation() failed")

                    try:
                        # here we try to enable all top level names
                        remote_forest_collision = \
                            remote_lsa.lsaRSetForestTrustInformation(remote_policy,
                                                                     local_lsa_info.dns_domain,
                                                                     lsa.LSA_FOREST_TRUST_DOMAIN_INFO,
                                                                     remote_forest_info,
                                                                     0)
                    except RuntimeError as error:
                        raise self.RemoteRuntimeError(self, error, "lsaRSetForestTrustInformation() failed")

                    self.write_forest_trust_info(remote_forest_info,
                                                 tln=local_lsa_info.dns_domain.string,
                                                 collisions=remote_forest_collision)

            if local_trust_info.trust_direction & lsa.LSA_TRUST_DIRECTION_OUTBOUND:
                self.outf.write("Validating outgoing trust...\n")
                try:
                    local_trust_verify = local_netlogon.netr_LogonControl2Ex(local_netlogon_info.dc_unc,
                                                                             netlogon.NETLOGON_CONTROL_TC_VERIFY,
                                                                             2,
                                                                             remote_lsa_info.dns_domain.string)
                except RuntimeError as error:
                    raise self.LocalRuntimeError(self, error, "NETLOGON_CONTROL_TC_VERIFY failed")

                local_trust_status = self._uint32(local_trust_verify.pdc_connection_status[0])
                local_conn_status = self._uint32(local_trust_verify.tc_connection_status[0])

                if local_trust_verify.flags & netlogon.NETLOGON_VERIFY_STATUS_RETURNED:
                    local_validation = "LocalValidation: DC[%s] CONNECTION[%s] TRUST[%s] VERIFY_STATUS_RETURNED" % (
                                       local_trust_verify.trusted_dc_name,
                                       local_trust_verify.tc_connection_status[1],
                                       local_trust_verify.pdc_connection_status[1])
                else:
                    local_validation = "LocalValidation: DC[%s] CONNECTION[%s] TRUST[%s]" % (
                                       local_trust_verify.trusted_dc_name,
                                       local_trust_verify.tc_connection_status[1],
                                       local_trust_verify.pdc_connection_status[1])

                if local_trust_status != werror.WERR_SUCCESS or local_conn_status != werror.WERR_SUCCESS:
                    raise CommandError(local_validation)
                else:
                    self.outf.write("OK: %s\n" % local_validation)

            if remote_trust_info:
                if remote_trust_info.trust_direction & lsa.LSA_TRUST_DIRECTION_OUTBOUND:
                    self.outf.write("Validating incoming trust...\n")
                    try:
                        remote_trust_verify = \
                            remote_netlogon.netr_LogonControl2Ex(remote_netlogon_dc_unc,
                                                                 netlogon.NETLOGON_CONTROL_TC_VERIFY,
                                                                 2,
                                                                 local_lsa_info.dns_domain.string)
                    except RuntimeError as error:
                        raise self.RemoteRuntimeError(self, error, "NETLOGON_CONTROL_TC_VERIFY failed")

                    remote_trust_status = self._uint32(remote_trust_verify.pdc_connection_status[0])
                    remote_conn_status = self._uint32(remote_trust_verify.tc_connection_status[0])

                    if remote_trust_verify.flags & netlogon.NETLOGON_VERIFY_STATUS_RETURNED:
                        remote_validation = "RemoteValidation: DC[%s] CONNECTION[%s] TRUST[%s] VERIFY_STATUS_RETURNED" % (
                                           remote_trust_verify.trusted_dc_name,
                                           remote_trust_verify.tc_connection_status[1],
                                           remote_trust_verify.pdc_connection_status[1])
                    else:
                        remote_validation = "RemoteValidation: DC[%s] CONNECTION[%s] TRUST[%s]" % (
                                           remote_trust_verify.trusted_dc_name,
                                           remote_trust_verify.tc_connection_status[1],
                                           remote_trust_verify.pdc_connection_status[1])

                    if remote_trust_status != werror.WERR_SUCCESS or remote_conn_status != werror.WERR_SUCCESS:
                        raise CommandError(remote_validation)
                    else:
                        self.outf.write("OK: %s\n" % remote_validation)

        if remote_tdo_handle is not None:
            try:
                remote_lsa.Close(remote_tdo_handle)
            except RuntimeError:
                pass
            remote_tdo_handle = None
        if local_tdo_handle is not None:
            try:
                local_lsa.Close(local_tdo_handle)
            except RuntimeError:
                pass
            local_tdo_handle = None

        self.outf.write("Success.\n")
        return


class cmd_domain_trust_delete(DomainTrustCommand):
    """Delete a domain trust."""

    synopsis = "%prog DOMAIN [options]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "versionopts": options.VersionOptions,
        "credopts": options.CredentialsOptions,
        "localdcopts": LocalDCCredentialsOptions,
    }

    takes_options = [
        Option("--delete-location", type="choice", metavar="LOCATION",
               choices=["local", "both"],
               help="Where to delete the trusted domain object: 'local' or 'both'.",
               dest='delete_location',
               default="both"),
    ]

    takes_args = ["domain"]

    def run(self, domain, sambaopts=None, localdcopts=None, credopts=None, versionopts=None,
            delete_location=None):

        local_policy_access = lsa.LSA_POLICY_VIEW_LOCAL_INFORMATION
        local_policy_access |= lsa.LSA_POLICY_TRUST_ADMIN
        local_policy_access |= lsa.LSA_POLICY_CREATE_SECRET

        if delete_location == "local":
            remote_policy_access = None
        else:
            remote_policy_access = lsa.LSA_POLICY_VIEW_LOCAL_INFORMATION
            remote_policy_access |= lsa.LSA_POLICY_TRUST_ADMIN
            remote_policy_access |= lsa.LSA_POLICY_CREATE_SECRET

        self.setup_local_server(sambaopts, localdcopts)
        try:
            local_lsa = self.new_local_lsa_connection()
        except RuntimeError as error:
            raise self.LocalRuntimeError(self, error, "failed to connect lsa server")

        try:
            (
                local_policy,
                local_version,
                local_revision_info1,
                local_lsa_info
            ) = self.get_lsa_info(local_lsa, local_policy_access)
        except RuntimeError as error:
            raise self.LocalRuntimeError(self, error, "failed to query LSA_POLICY_INFO_DNS")

        self.outf.write("LocalDomain Netbios[%s] DNS[%s] SID[%s]\n" % (
                        local_lsa_info.name.string,
                        local_lsa_info.dns_domain.string,
                        local_lsa_info.sid))

        local_tdo_info = None
        local_tdo_handle = None
        remote_tdo_info = None
        remote_tdo_handle = None

        lsaString = lsa.String()
        try:
            lsaString.string = domain
            local_tdo_info = local_lsa.QueryTrustedDomainInfoByName(local_policy,
                                                                    lsaString, lsa.LSA_TRUSTED_DOMAIN_INFO_INFO_EX)
        except NTSTATUSError as error:
            if self.check_runtime_error(error, ntstatus.NT_STATUS_OBJECT_NAME_NOT_FOUND):
                raise CommandError("Failed to find trust for domain '%s'" % domain)
            raise self.RemoteRuntimeError(self, error, "failed to locate remote server")

        if remote_policy_access is not None:
            try:
                self.setup_remote_server(credopts, domain)
            except RuntimeError as error:
                raise self.RemoteRuntimeError(self, error, "failed to locate remote server")

            try:
                remote_lsa = self.new_remote_lsa_connection()
            except RuntimeError as error:
                raise self.RemoteRuntimeError(self, error, "failed to connect lsa server")

            try:
                (
                    remote_policy,
                    remote_version,
                    remote_revision_info1,
                    remote_lsa_info
                ) = self.get_lsa_info(remote_lsa, remote_policy_access)
            except RuntimeError as error:
                raise self.RemoteRuntimeError(self, error, "failed to query LSA_POLICY_INFO_DNS")

            self.outf.write("RemoteDomain Netbios[%s] DNS[%s] SID[%s]\n" % (
                            remote_lsa_info.name.string,
                            remote_lsa_info.dns_domain.string,
                            remote_lsa_info.sid))

            if remote_lsa_info.sid != local_tdo_info.sid or \
               remote_lsa_info.name.string != local_tdo_info.netbios_name.string or \
               remote_lsa_info.dns_domain.string != local_tdo_info.domain_name.string:
                raise CommandError("LocalTDO inconsistent: Netbios[%s] DNS[%s] SID[%s]" % (
                                   local_tdo_info.netbios_name.string,
                                   local_tdo_info.domain_name.string,
                                   local_tdo_info.sid))

            try:
                lsaString.string = local_lsa_info.dns_domain.string
                remote_tdo_info = \
                    remote_lsa.QueryTrustedDomainInfoByName(remote_policy,
                                                            lsaString,
                                                            lsa.LSA_TRUSTED_DOMAIN_INFO_INFO_EX)
            except NTSTATUSError as error:
                if not self.check_runtime_error(error, ntstatus.NT_STATUS_OBJECT_NAME_NOT_FOUND):
                    raise self.RemoteRuntimeError(self, error, "QueryTrustedDomainInfoByName(%s)" % (
                                                  lsaString.string))

            if remote_tdo_info is not None:
                if local_lsa_info.sid != remote_tdo_info.sid or \
                   local_lsa_info.name.string != remote_tdo_info.netbios_name.string or \
                   local_lsa_info.dns_domain.string != remote_tdo_info.domain_name.string:
                    raise CommandError("RemoteTDO inconsistent: Netbios[%s] DNS[%s] SID[%s]" % (
                                       remote_tdo_info.netbios_name.string,
                                       remote_tdo_info.domain_name.string,
                                       remote_tdo_info.sid))

        if local_tdo_info is not None:
            try:
                lsaString.string = local_tdo_info.domain_name.string
                local_tdo_handle = \
                    local_lsa.OpenTrustedDomainByName(local_policy,
                                                      lsaString,
                                                      security.SEC_STD_DELETE)
            except RuntimeError as error:
                raise self.LocalRuntimeError(self, error, "OpenTrustedDomainByName(%s)" % (
                                             lsaString.string))

            local_lsa.DeleteObject(local_tdo_handle)
            local_tdo_handle = None

        if remote_tdo_info is not None:
            try:
                lsaString.string = remote_tdo_info.domain_name.string
                remote_tdo_handle = \
                    remote_lsa.OpenTrustedDomainByName(remote_policy,
                                                       lsaString,
                                                       security.SEC_STD_DELETE)
            except RuntimeError as error:
                raise self.RemoteRuntimeError(self, error, "OpenTrustedDomainByName(%s)" % (
                                              lsaString.string))

        if remote_tdo_handle is not None:
            try:
                remote_lsa.DeleteObject(remote_tdo_handle)
                remote_tdo_handle = None
                self.outf.write("RemoteTDO deleted.\n")
            except RuntimeError as error:
                self.outf.write("%s\n" % self.RemoteRuntimeError(self, error, "DeleteObject() failed"))

        return


class cmd_domain_trust_validate(DomainTrustCommand):
    """Validate a domain trust."""

    synopsis = "%prog DOMAIN [options]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "versionopts": options.VersionOptions,
        "credopts": options.CredentialsOptions,
        "localdcopts": LocalDCCredentialsOptions,
    }

    takes_options = [
        Option("--validate-location", type="choice", metavar="LOCATION",
               choices=["local", "both"],
               help="Where to validate the trusted domain object: 'local' or 'both'.",
               dest='validate_location',
               default="both"),
    ]

    takes_args = ["domain"]

    def run(self, domain, sambaopts=None, versionopts=None, credopts=None, localdcopts=None,
            validate_location=None):

        local_policy_access = lsa.LSA_POLICY_VIEW_LOCAL_INFORMATION

        local_server = self.setup_local_server(sambaopts, localdcopts)
        try:
            local_lsa = self.new_local_lsa_connection()
        except RuntimeError as error:
            raise self.LocalRuntimeError(self, error, "failed to connect lsa server")

        try:
            (
                local_policy,
                local_version,
                local_revision_info1,
                local_lsa_info
            ) = self.get_lsa_info(local_lsa, local_policy_access)
        except RuntimeError as error:
            raise self.LocalRuntimeError(self, error, "failed to query LSA_POLICY_INFO_DNS")

        self.outf.write("LocalDomain Netbios[%s] DNS[%s] SID[%s]\n" % (
                        local_lsa_info.name.string,
                        local_lsa_info.dns_domain.string,
                        local_lsa_info.sid))

        try:
            lsaString = lsa.String()
            lsaString.string = domain
            local_tdo_info = \
                local_lsa.QueryTrustedDomainInfoByName(local_policy,
                                                       lsaString,
                                                       lsa.LSA_TRUSTED_DOMAIN_INFO_INFO_EX)
        except NTSTATUSError as error:
            if self.check_runtime_error(error, ntstatus.NT_STATUS_OBJECT_NAME_NOT_FOUND):
                raise CommandError("trusted domain object does not exist for domain [%s]" % domain)

            raise self.LocalRuntimeError(self, error, "QueryTrustedDomainInfoByName(INFO_EX) failed")

        self.outf.write("LocalTDO Netbios[%s] DNS[%s] SID[%s]\n" % (
                        local_tdo_info.netbios_name.string,
                        local_tdo_info.domain_name.string,
                        local_tdo_info.sid))

        try:
            local_netlogon = self.new_local_netlogon_connection()
        except RuntimeError as error:
            raise self.LocalRuntimeError(self, error, "failed to connect netlogon server")

        try:
            local_trust_verify = \
                local_netlogon.netr_LogonControl2Ex(local_server,
                                                    netlogon.NETLOGON_CONTROL_TC_VERIFY,
                                                    2,
                                                    local_tdo_info.domain_name.string)
        except RuntimeError as error:
            raise self.LocalRuntimeError(self, error, "NETLOGON_CONTROL_TC_VERIFY failed")

        local_trust_status = self._uint32(local_trust_verify.pdc_connection_status[0])
        local_conn_status = self._uint32(local_trust_verify.tc_connection_status[0])

        if local_trust_verify.flags & netlogon.NETLOGON_VERIFY_STATUS_RETURNED:
            local_validation = "LocalValidation: DC[%s] CONNECTION[%s] TRUST[%s] VERIFY_STATUS_RETURNED" % (
                               local_trust_verify.trusted_dc_name,
                               local_trust_verify.tc_connection_status[1],
                               local_trust_verify.pdc_connection_status[1])
        else:
            local_validation = "LocalValidation: DC[%s] CONNECTION[%s] TRUST[%s]" % (
                               local_trust_verify.trusted_dc_name,
                               local_trust_verify.tc_connection_status[1],
                               local_trust_verify.pdc_connection_status[1])

        if local_trust_status != werror.WERR_SUCCESS or local_conn_status != werror.WERR_SUCCESS:
            raise CommandError(local_validation)
        else:
            self.outf.write("OK: %s\n" % local_validation)

        try:
            server = local_trust_verify.trusted_dc_name.replace('\\', '')
            domain_and_server = "%s\\%s" % (local_tdo_info.domain_name.string, server)
            local_trust_rediscover = \
                local_netlogon.netr_LogonControl2Ex(local_server,
                                                    netlogon.NETLOGON_CONTROL_REDISCOVER,
                                                    2,
                                                    domain_and_server)
        except RuntimeError as error:
            raise self.LocalRuntimeError(self, error, "NETLOGON_CONTROL_REDISCOVER failed")

        local_conn_status = self._uint32(local_trust_rediscover.tc_connection_status[0])
        local_rediscover = "LocalRediscover: DC[%s] CONNECTION[%s]" % (
                               local_trust_rediscover.trusted_dc_name,
                               local_trust_rediscover.tc_connection_status[1])

        if local_conn_status != werror.WERR_SUCCESS:
            raise CommandError(local_rediscover)
        else:
            self.outf.write("OK: %s\n" % local_rediscover)

        if validate_location != "local":
            try:
                remote_server = self.setup_remote_server(credopts, domain, require_pdc=False)
            except RuntimeError as error:
                raise self.RemoteRuntimeError(self, error, "failed to locate remote server")

            try:
                remote_netlogon = self.new_remote_netlogon_connection()
            except RuntimeError as error:
                raise self.RemoteRuntimeError(self, error, "failed to connect netlogon server")

            try:
                remote_trust_verify = \
                    remote_netlogon.netr_LogonControl2Ex(remote_server,
                                                         netlogon.NETLOGON_CONTROL_TC_VERIFY,
                                                         2,
                                                         local_lsa_info.dns_domain.string)
            except RuntimeError as error:
                raise self.RemoteRuntimeError(self, error, "NETLOGON_CONTROL_TC_VERIFY failed")

            remote_trust_status = self._uint32(remote_trust_verify.pdc_connection_status[0])
            remote_conn_status = self._uint32(remote_trust_verify.tc_connection_status[0])

            if remote_trust_verify.flags & netlogon.NETLOGON_VERIFY_STATUS_RETURNED:
                remote_validation = "RemoteValidation: DC[%s] CONNECTION[%s] TRUST[%s] VERIFY_STATUS_RETURNED" % (
                                   remote_trust_verify.trusted_dc_name,
                                   remote_trust_verify.tc_connection_status[1],
                                   remote_trust_verify.pdc_connection_status[1])
            else:
                remote_validation = "RemoteValidation: DC[%s] CONNECTION[%s] TRUST[%s]" % (
                                   remote_trust_verify.trusted_dc_name,
                                   remote_trust_verify.tc_connection_status[1],
                                   remote_trust_verify.pdc_connection_status[1])

            if remote_trust_status != werror.WERR_SUCCESS or remote_conn_status != werror.WERR_SUCCESS:
                raise CommandError(remote_validation)
            else:
                self.outf.write("OK: %s\n" % remote_validation)

            try:
                server = remote_trust_verify.trusted_dc_name.replace('\\', '')
                domain_and_server = "%s\\%s" % (local_lsa_info.dns_domain.string, server)
                remote_trust_rediscover = \
                    remote_netlogon.netr_LogonControl2Ex(remote_server,
                                                         netlogon.NETLOGON_CONTROL_REDISCOVER,
                                                         2,
                                                         domain_and_server)
            except RuntimeError as error:
                raise self.RemoteRuntimeError(self, error, "NETLOGON_CONTROL_REDISCOVER failed")

            remote_conn_status = self._uint32(remote_trust_rediscover.tc_connection_status[0])

            remote_rediscover = "RemoteRediscover: DC[%s] CONNECTION[%s]" % (
                                   remote_trust_rediscover.trusted_dc_name,
                                   remote_trust_rediscover.tc_connection_status[1])

            if remote_conn_status != werror.WERR_SUCCESS:
                raise CommandError(remote_rediscover)
            else:
                self.outf.write("OK: %s\n" % remote_rediscover)

        return


class cmd_domain_trust_namespaces(DomainTrustCommand):
    """Manage forest trust namespaces."""

    synopsis = "%prog [DOMAIN] [options]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "versionopts": options.VersionOptions,
        "localdcopts": LocalDCCredentialsOptions,
    }

    takes_options = [
        Option("--refresh", type="choice", metavar="check|store",
               choices=["check", "store", None],
               help="List and maybe store refreshed forest trust information: 'check' or 'store'.",
               dest='refresh',
               default=None),
        Option("--enable-all", action="store_true",
               help="Try to update disabled entries, not allowed with --refresh=check.",
               dest='enable_all',
               default=False),
        Option("--enable-tln", action="append", metavar='DNSDOMAIN',
               help="Enable a top level name entry. Can be specified multiple times.",
               dest='enable_tln',
               default=[]),
        Option("--disable-tln", action="append", metavar='DNSDOMAIN',
               help="Disable a top level name entry. Can be specified multiple times.",
               dest='disable_tln',
               default=[]),
        Option("--add-tln-ex", action="append", metavar='DNSDOMAIN',
               help="Add a top level exclusion entry. Can be specified multiple times.",
               dest='add_tln_ex',
               default=[]),
        Option("--delete-tln-ex", action="append", metavar='DNSDOMAIN',
               help="Delete a top level exclusion entry. Can be specified multiple times.",
               dest='delete_tln_ex',
               default=[]),
        Option("--enable-nb", action="append", metavar='NETBIOSDOMAIN',
               help="Enable a netbios name in a domain entry. Can be specified multiple times.",
               dest='enable_nb',
               default=[]),
        Option("--disable-nb", action="append", metavar='NETBIOSDOMAIN',
               help="Disable a netbios name in a domain entry. Can be specified multiple times.",
               dest='disable_nb',
               default=[]),
        Option("--enable-sid", action="append", metavar='DOMAINSID',
               help="Enable a SID in a domain entry. Can be specified multiple times.",
               dest='enable_sid_str',
               default=[]),
        Option("--disable-sid", action="append", metavar='DOMAINSID',
               help="Disable a SID in a domain entry. Can be specified multiple times.",
               dest='disable_sid_str',
               default=[]),
        Option("--add-upn-suffix", action="append", metavar='DNSDOMAIN',
               help="Add a new uPNSuffixes attribute for the local forest. Can be specified multiple times.",
               dest='add_upn',
               default=[]),
        Option("--delete-upn-suffix", action="append", metavar='DNSDOMAIN',
               help="Delete an existing uPNSuffixes attribute of the local forest. Can be specified multiple times.",
               dest='delete_upn',
               default=[]),
        Option("--add-spn-suffix", action="append", metavar='DNSDOMAIN',
               help="Add a new msDS-SPNSuffixes attribute for the local forest. Can be specified multiple times.",
               dest='add_spn',
               default=[]),
        Option("--delete-spn-suffix", action="append", metavar='DNSDOMAIN',
               help="Delete an existing msDS-SPNSuffixes attribute of the local forest. Can be specified multiple times.",
               dest='delete_spn',
               default=[]),
    ]

    takes_args = ["domain?"]

    def run(self, domain=None, sambaopts=None, localdcopts=None, versionopts=None,
            refresh=None, enable_all=False,
            enable_tln=None, disable_tln=None, add_tln_ex=None, delete_tln_ex=None,
            enable_sid_str=None, disable_sid_str=None, enable_nb=None, disable_nb=None,
            add_upn=None, delete_upn=None, add_spn=None, delete_spn=None):

        if enable_tln is None:
            enable_tln = []
        if disable_tln is None:
            disable_tln = []
        if add_tln_ex is None:
            add_tln_ex = []
        if delete_tln_ex is None:
            delete_tln_ex = []
        if enable_sid_str is None:
            enable_sid_str = []
        if disable_sid_str is None:
            disable_sid_str = []
        if enable_nb is None:
            enable_nb = []
        if disable_nb is None:
            disable_nb = []
        if add_upn is None:
            add_upn = []
        if delete_upn is None:
            delete_upn = []
        if add_spn is None:
            add_spn = []
        if delete_spn is None:
            delete_spn = []

        require_update = False

        if domain is None:
            if refresh == "store":
                raise CommandError("--refresh=%s not allowed without DOMAIN" % refresh)

            if enable_all:
                raise CommandError("--enable-all not allowed without DOMAIN")

            if len(enable_tln) > 0:
                raise CommandError("--enable-tln not allowed without DOMAIN")
            if len(disable_tln) > 0:
                raise CommandError("--disable-tln not allowed without DOMAIN")

            if len(add_tln_ex) > 0:
                raise CommandError("--add-tln-ex not allowed without DOMAIN")
            if len(delete_tln_ex) > 0:
                raise CommandError("--delete-tln-ex not allowed without DOMAIN")

            if len(enable_nb) > 0:
                raise CommandError("--enable-nb not allowed without DOMAIN")
            if len(disable_nb) > 0:
                raise CommandError("--disable-nb not allowed without DOMAIN")

            if len(enable_sid_str) > 0:
                raise CommandError("--enable-sid not allowed without DOMAIN")
            if len(disable_sid_str) > 0:
                raise CommandError("--disable-sid not allowed without DOMAIN")

            if len(add_upn) > 0:
                for n in add_upn:
                    if not n.startswith("*."):
                        continue
                    raise CommandError("value[%s] specified for --add-upn-suffix should not include with '*.'" % n)
                require_update = True
            if len(delete_upn) > 0:
                for n in delete_upn:
                    if not n.startswith("*."):
                        continue
                    raise CommandError("value[%s] specified for --delete-upn-suffix should not include with '*.'" % n)
                require_update = True
            for a in add_upn:
                for d in delete_upn:
                    if a.lower() != d.lower():
                        continue
                    raise CommandError("value[%s] specified for --add-upn-suffix and --delete-upn-suffix" % a)

            if len(add_spn) > 0:
                for n in add_spn:
                    if not n.startswith("*."):
                        continue
                    raise CommandError("value[%s] specified for --add-spn-suffix should not include with '*.'" % n)
                require_update = True
            if len(delete_spn) > 0:
                for n in delete_spn:
                    if not n.startswith("*."):
                        continue
                    raise CommandError("value[%s] specified for --delete-spn-suffix should not include with '*.'" % n)
                require_update = True
            for a in add_spn:
                for d in delete_spn:
                    if a.lower() != d.lower():
                        continue
                    raise CommandError("value[%s] specified for --add-spn-suffix and --delete-spn-suffix" % a)
        else:
            if len(add_upn) > 0:
                raise CommandError("--add-upn-suffix not allowed together with DOMAIN")
            if len(delete_upn) > 0:
                raise CommandError("--delete-upn-suffix not allowed together with DOMAIN")
            if len(add_spn) > 0:
                raise CommandError("--add-spn-suffix not allowed together with DOMAIN")
            if len(delete_spn) > 0:
                raise CommandError("--delete-spn-suffix not allowed together with DOMAIN")

        if refresh is not None:
            if refresh == "store":
                require_update = True

            if enable_all and refresh != "store":
                raise CommandError("--enable-all not allowed together with --refresh=%s" % refresh)

            if len(enable_tln) > 0:
                raise CommandError("--enable-tln not allowed together with --refresh")
            if len(disable_tln) > 0:
                raise CommandError("--disable-tln not allowed together with --refresh")

            if len(add_tln_ex) > 0:
                raise CommandError("--add-tln-ex not allowed together with --refresh")
            if len(delete_tln_ex) > 0:
                raise CommandError("--delete-tln-ex not allowed together with --refresh")

            if len(enable_nb) > 0:
                raise CommandError("--enable-nb not allowed together with --refresh")
            if len(disable_nb) > 0:
                raise CommandError("--disable-nb not allowed together with --refresh")

            if len(enable_sid_str) > 0:
                raise CommandError("--enable-sid not allowed together with --refresh")
            if len(disable_sid_str) > 0:
                raise CommandError("--disable-sid not allowed together with --refresh")
        else:
            if enable_all:
                require_update = True

                if len(enable_tln) > 0:
                    raise CommandError("--enable-tln not allowed together with --enable-all")

                if len(enable_nb) > 0:
                    raise CommandError("--enable-nb not allowed together with --enable-all")

                if len(enable_sid_str) > 0:
                    raise CommandError("--enable-sid not allowed together with --enable-all")

            if len(enable_tln) > 0:
                require_update = True
            if len(disable_tln) > 0:
                require_update = True
            for e in enable_tln:
                for d in disable_tln:
                    if e.lower() != d.lower():
                        continue
                    raise CommandError("value[%s] specified for --enable-tln and --disable-tln" % e)

            if len(add_tln_ex) > 0:
                for n in add_tln_ex:
                    if not n.startswith("*."):
                        continue
                    raise CommandError("value[%s] specified for --add-tln-ex should not include with '*.'" % n)
                require_update = True
            if len(delete_tln_ex) > 0:
                for n in delete_tln_ex:
                    if not n.startswith("*."):
                        continue
                    raise CommandError("value[%s] specified for --delete-tln-ex should not include with '*.'" % n)
                require_update = True
            for a in add_tln_ex:
                for d in delete_tln_ex:
                    if a.lower() != d.lower():
                        continue
                    raise CommandError("value[%s] specified for --add-tln-ex and --delete-tln-ex" % a)

            if len(enable_nb) > 0:
                require_update = True
            if len(disable_nb) > 0:
                require_update = True
            for e in enable_nb:
                for d in disable_nb:
                    if e.upper() != d.upper():
                        continue
                    raise CommandError("value[%s] specified for --enable-nb and --disable-nb" % e)

            enable_sid = []
            for s in enable_sid_str:
                try:
                    sid = security.dom_sid(s)
                except (ValueError, TypeError):
                    raise CommandError("value[%s] specified for --enable-sid is not a valid SID" % s)
                enable_sid.append(sid)
            disable_sid = []
            for s in disable_sid_str:
                try:
                    sid = security.dom_sid(s)
                except (ValueError, TypeError):
                    raise CommandError("value[%s] specified for --disable-sid is not a valid SID" % s)
                disable_sid.append(sid)
            if len(enable_sid) > 0:
                require_update = True
            if len(disable_sid) > 0:
                require_update = True
            for e in enable_sid:
                for d in disable_sid:
                    if e != d:
                        continue
                    raise CommandError("value[%s] specified for --enable-sid and --disable-sid" % e)

        local_policy_access = lsa.LSA_POLICY_VIEW_LOCAL_INFORMATION
        if require_update:
            local_policy_access |= lsa.LSA_POLICY_TRUST_ADMIN

        local_server = self.setup_local_server(sambaopts, localdcopts)
        try:
            local_lsa = self.new_local_lsa_connection()
        except RuntimeError as error:
            raise self.LocalRuntimeError(self, error, "failed to connect lsa server")

        try:
            (
                local_policy,
                local_version,
                local_revision_info1,
                local_lsa_info
            ) = self.get_lsa_info(local_lsa, local_policy_access)
        except RuntimeError as error:
            raise self.LocalRuntimeError(self, error, "failed to query LSA_POLICY_INFO_DNS")

        self.outf.write("LocalDomain Netbios[%s] DNS[%s] SID[%s]\n" % (
                        local_lsa_info.name.string,
                        local_lsa_info.dns_domain.string,
                        local_lsa_info.sid))

        if domain is None:
            try:
                local_netlogon = self.new_local_netlogon_connection()
            except RuntimeError as error:
                raise self.LocalRuntimeError(self, error, "failed to connect netlogon server")

            try:
                local_netlogon_info = self.get_netlogon_dc_info(local_netlogon, local_server)
            except RuntimeError as error:
                raise self.LocalRuntimeError(self, error, "failed to get netlogon dc info")

            if local_netlogon_info.domain_name != local_netlogon_info.forest_name:
                raise CommandError("The local domain [%s] is not the forest root [%s]" % (
                                   local_netlogon_info.domain_name,
                                   local_netlogon_info.forest_name))

            try:
                # get all information about our own forest
                own_forest_info = local_netlogon.netr_DsRGetForestTrustInformation(local_netlogon_info.dc_unc,
                                                                                   None, 0)
            except RuntimeError as error:
                if self.check_runtime_error(error, werror.WERR_RPC_S_PROCNUM_OUT_OF_RANGE):
                    raise CommandError("LOCAL_DC[%s]: netr_DsRGetForestTrustInformation() not supported." % (
                                       local_server))

                if self.check_runtime_error(error, werror.WERR_INVALID_FUNCTION):
                    raise CommandError("LOCAL_DC[%s]: netr_DsRGetForestTrustInformation() not supported." % (
                                       local_server))

                if self.check_runtime_error(error, werror.WERR_NERR_ACFNOTLOADED):
                    raise CommandError("LOCAL_DC[%s]: netr_DsRGetForestTrustInformation() not supported." % (
                                       local_server))

                raise self.LocalRuntimeError(self, error, "netr_DsRGetForestTrustInformation() failed")

            self.outf.write("Own forest trust information...\n")
            self.write_forest_trust_info(own_forest_info,
                                         tln=local_lsa_info.dns_domain.string)

            try:
                local_samdb = self.new_local_ldap_connection()
            except RuntimeError as error:
                raise self.LocalRuntimeError(self, error, "failed to connect to SamDB")

            local_partitions_dn = "CN=Partitions,%s" % str(local_samdb.get_config_basedn())
            attrs = ['uPNSuffixes', 'msDS-SPNSuffixes']
            try:
                msgs = local_samdb.search(base=local_partitions_dn,
                                          scope=ldb.SCOPE_BASE,
                                          expression="(objectClass=crossRefContainer)",
                                          attrs=attrs)
                stored_msg = msgs[0]
            except ldb.LdbError as error:
                raise self.LocalLdbError(self, error, "failed to search partition dn")

            stored_upn_vals = []
            if 'uPNSuffixes' in stored_msg:
                stored_upn_vals.extend(stored_msg['uPNSuffixes'])

            stored_spn_vals = []
            if 'msDS-SPNSuffixes' in stored_msg:
                stored_spn_vals.extend(stored_msg['msDS-SPNSuffixes'])

            self.outf.write("Stored uPNSuffixes attributes[%d]:\n" % len(stored_upn_vals))
            for v in stored_upn_vals:
                self.outf.write("TLN: %-32s DNS[*.%s]\n" % ("", v))
            self.outf.write("Stored msDS-SPNSuffixes attributes[%d]:\n" % len(stored_spn_vals))
            for v in stored_spn_vals:
                self.outf.write("TLN: %-32s DNS[*.%s]\n" % ("", v))

            if not require_update:
                return

            replace_upn = False
            update_upn_vals = []
            update_upn_vals.extend(stored_upn_vals)

            replace_spn = False
            update_spn_vals = []
            update_spn_vals.extend(stored_spn_vals)

            for upn in add_upn:
                for v in update_upn_vals:
                    if str(v).lower() == upn.lower():
                        raise CommandError("Entry already present for "
                                           "value[%s] specified for "
                                           "--add-upn-suffix" % upn)
                update_upn_vals.append(upn)
                replace_upn = True

            for upn in delete_upn:
                idx = None
                for i, v in enumerate(update_upn_vals):
                    if str(v).lower() != upn.lower():
                        continue
                    idx = i
                    break
                if idx is None:
                    raise CommandError("Entry not found for value[%s] specified for --delete-upn-suffix" % upn)

                update_upn_vals.pop(idx)
                replace_upn = True

            for spn in add_spn:
                for v in update_spn_vals:
                    if str(v).lower() == spn.lower():
                        raise CommandError("Entry already present for "
                                           "value[%s] specified for "
                                           "--add-spn-suffix" % spn)
                update_spn_vals.append(spn)
                replace_spn = True

            for spn in delete_spn:
                idx = None
                for i, v in enumerate(update_spn_vals):
                    if str(v).lower() != spn.lower():
                        continue
                    idx = i
                    break
                if idx is None:
                    raise CommandError("Entry not found for value[%s] specified for --delete-spn-suffix" % spn)

                update_spn_vals.pop(idx)
                replace_spn = True

            self.outf.write("Update uPNSuffixes attributes[%d]:\n" % len(update_upn_vals))
            for v in update_upn_vals:
                self.outf.write("TLN: %-32s DNS[*.%s]\n" % ("", v))
            self.outf.write("Update msDS-SPNSuffixes attributes[%d]:\n" % len(update_spn_vals))
            for v in update_spn_vals:
                self.outf.write("TLN: %-32s DNS[*.%s]\n" % ("", v))

            update_msg = ldb.Message()
            update_msg.dn = stored_msg.dn

            if replace_upn:
                update_msg['uPNSuffixes'] = ldb.MessageElement(update_upn_vals,
                                                               ldb.FLAG_MOD_REPLACE,
                                                               'uPNSuffixes')
            if replace_spn:
                update_msg['msDS-SPNSuffixes'] = ldb.MessageElement(update_spn_vals,
                                                                    ldb.FLAG_MOD_REPLACE,
                                                                    'msDS-SPNSuffixes')
            try:
                local_samdb.modify(update_msg)
            except ldb.LdbError as error:
                raise self.LocalLdbError(self, error, "failed to update partition dn")

            try:
                stored_forest_info = local_netlogon.netr_DsRGetForestTrustInformation(local_netlogon_info.dc_unc,
                                                                                      None, 0)
            except RuntimeError as error:
                raise self.LocalRuntimeError(self, error, "netr_DsRGetForestTrustInformation() failed")

            self.outf.write("Stored forest trust information...\n")
            self.write_forest_trust_info(stored_forest_info,
                                         tln=local_lsa_info.dns_domain.string)
            return

        try:
            lsaString = lsa.String()
            lsaString.string = domain
            local_tdo_info = \
                local_lsa.QueryTrustedDomainInfoByName(local_policy,
                                                       lsaString,
                                                       lsa.LSA_TRUSTED_DOMAIN_INFO_INFO_EX)
        except NTSTATUSError as error:
            if self.check_runtime_error(error, ntstatus.NT_STATUS_OBJECT_NAME_NOT_FOUND):
                raise CommandError("trusted domain object does not exist for domain [%s]" % domain)

            raise self.LocalRuntimeError(self, error, "QueryTrustedDomainInfoByName(INFO_EX) failed")

        self.outf.write("LocalTDO Netbios[%s] DNS[%s] SID[%s]\n" % (
                        local_tdo_info.netbios_name.string,
                        local_tdo_info.domain_name.string,
                        local_tdo_info.sid))

        if not local_tdo_info.trust_attributes & lsa.LSA_TRUST_ATTRIBUTE_FOREST_TRANSITIVE:
            raise CommandError("trusted domain object for domain [%s] is not marked as FOREST_TRANSITIVE." % domain)

        if refresh is not None:
            try:
                local_netlogon = self.new_local_netlogon_connection()
            except RuntimeError as error:
                raise self.LocalRuntimeError(self, error, "failed to connect netlogon server")

            try:
                local_netlogon_info = self.get_netlogon_dc_info(local_netlogon, local_server)
            except RuntimeError as error:
                raise self.LocalRuntimeError(self, error, "failed to get netlogon dc info")

            lsa_update_check = 1
            if refresh == "store":
                netlogon_update_tdo = netlogon.DS_GFTI_UPDATE_TDO
                if enable_all:
                    lsa_update_check = 0
            else:
                netlogon_update_tdo = 0

            try:
                # get all information about the remote trust
                # this triggers netr_GetForestTrustInformation to the remote domain
                # and lsaRSetForestTrustInformation() locally, but new top level
                # names are disabled by default.
                fresh_forest_info = \
                    local_netlogon.netr_DsRGetForestTrustInformation(local_netlogon_info.dc_unc,
                                                                     local_tdo_info.domain_name.string,
                                                                     netlogon_update_tdo)
            except RuntimeError as error:
                raise self.LocalRuntimeError(self, error, "netr_DsRGetForestTrustInformation() failed")

            try:
                fresh_forest_collision = \
                    local_lsa.lsaRSetForestTrustInformation(local_policy,
                                                            local_tdo_info.domain_name,
                                                            lsa.LSA_FOREST_TRUST_DOMAIN_INFO,
                                                            fresh_forest_info,
                                                            lsa_update_check)
            except RuntimeError as error:
                raise self.LocalRuntimeError(self, error, "lsaRSetForestTrustInformation() failed")

            self.outf.write("Fresh forest trust information...\n")
            self.write_forest_trust_info(fresh_forest_info,
                                         tln=local_tdo_info.domain_name.string,
                                         collisions=fresh_forest_collision)

            if refresh == "store":
                try:
                    lsaString = lsa.String()
                    lsaString.string = local_tdo_info.domain_name.string
                    stored_forest_info = \
                        local_lsa.lsaRQueryForestTrustInformation(local_policy,
                                                                  lsaString,
                                                                  lsa.LSA_FOREST_TRUST_DOMAIN_INFO)
                except RuntimeError as error:
                    raise self.LocalRuntimeError(self, error, "lsaRQueryForestTrustInformation() failed")

                self.outf.write("Stored forest trust information...\n")
                self.write_forest_trust_info(stored_forest_info,
                                             tln=local_tdo_info.domain_name.string)

            return

        #
        # The none --refresh path
        #

        try:
            lsaString = lsa.String()
            lsaString.string = local_tdo_info.domain_name.string
            local_forest_info = \
                local_lsa.lsaRQueryForestTrustInformation(local_policy,
                                                          lsaString,
                                                          lsa.LSA_FOREST_TRUST_DOMAIN_INFO)
        except RuntimeError as error:
            raise self.LocalRuntimeError(self, error, "lsaRQueryForestTrustInformation() failed")

        self.outf.write("Local forest trust information...\n")
        self.write_forest_trust_info(local_forest_info,
                                     tln=local_tdo_info.domain_name.string)

        if not require_update:
            return

        entries = []
        entries.extend(local_forest_info.entries)
        update_forest_info = lsa.ForestTrustInformation()
        update_forest_info.count = len(entries)
        update_forest_info.entries = entries

        if enable_all:
            for r in update_forest_info.entries:
                if r.type != lsa.LSA_FOREST_TRUST_TOP_LEVEL_NAME:
                    continue
                if r.flags == 0:
                    continue
                r.time = 0
                r.flags &= ~lsa.LSA_TLN_DISABLED_MASK
            for r in update_forest_info.entries:
                if r.type != lsa.LSA_FOREST_TRUST_DOMAIN_INFO:
                    continue
                if r.flags == 0:
                    continue
                r.time = 0
                r.flags &= ~lsa.LSA_NB_DISABLED_MASK
                r.flags &= ~lsa.LSA_SID_DISABLED_MASK

        for tln in enable_tln:
            idx = None
            for i, r in enumerate(update_forest_info.entries):
                if r.type != lsa.LSA_FOREST_TRUST_TOP_LEVEL_NAME:
                    continue
                if r.forest_trust_data.string.lower() != tln.lower():
                    continue
                idx = i
                break
            if idx is None:
                raise CommandError("Entry not found for value[%s] specified for --enable-tln" % tln)
            if not update_forest_info.entries[idx].flags & lsa.LSA_TLN_DISABLED_MASK:
                raise CommandError("Entry found for value[%s] specified for --enable-tln is already enabled" % tln)
            update_forest_info.entries[idx].time = 0
            update_forest_info.entries[idx].flags &= ~lsa.LSA_TLN_DISABLED_MASK

        for tln in disable_tln:
            idx = None
            for i, r in enumerate(update_forest_info.entries):
                if r.type != lsa.LSA_FOREST_TRUST_TOP_LEVEL_NAME:
                    continue
                if r.forest_trust_data.string.lower() != tln.lower():
                    continue
                idx = i
                break
            if idx is None:
                raise CommandError("Entry not found for value[%s] specified for --disable-tln" % tln)
            if update_forest_info.entries[idx].flags & lsa.LSA_TLN_DISABLED_ADMIN:
                raise CommandError("Entry found for value[%s] specified for --disable-tln is already disabled" % tln)
            update_forest_info.entries[idx].time = 0
            update_forest_info.entries[idx].flags &= ~lsa.LSA_TLN_DISABLED_MASK
            update_forest_info.entries[idx].flags |= lsa.LSA_TLN_DISABLED_ADMIN

        for tln_ex in add_tln_ex:
            idx = None
            for i, r in enumerate(update_forest_info.entries):
                if r.type != lsa.LSA_FOREST_TRUST_TOP_LEVEL_NAME_EX:
                    continue
                if r.forest_trust_data.string.lower() != tln_ex.lower():
                    continue
                idx = i
                break
            if idx is not None:
                raise CommandError("Entry already present for value[%s] specified for --add-tln-ex" % tln_ex)

            tln_dot = ".%s" % tln_ex.lower()
            idx = None
            for i, r in enumerate(update_forest_info.entries):
                if r.type != lsa.LSA_FOREST_TRUST_TOP_LEVEL_NAME:
                    continue
                r_dot = ".%s" % r.forest_trust_data.string.lower()
                if tln_dot == r_dot:
                    raise CommandError("TLN entry present for value[%s] specified for --add-tln-ex" % tln_ex)
                if not tln_dot.endswith(r_dot):
                    continue
                idx = i
                break

            if idx is None:
                raise CommandError("No TLN parent present for value[%s] specified for --add-tln-ex" % tln_ex)

            r = lsa.ForestTrustRecord()
            r.type = lsa.LSA_FOREST_TRUST_TOP_LEVEL_NAME_EX
            r.flags = 0
            r.time = 0
            r.forest_trust_data.string = tln_ex

            entries = []
            entries.extend(update_forest_info.entries)
            entries.insert(idx + 1, r)
            update_forest_info.count = len(entries)
            update_forest_info.entries = entries

        for tln_ex in delete_tln_ex:
            idx = None
            for i, r in enumerate(update_forest_info.entries):
                if r.type != lsa.LSA_FOREST_TRUST_TOP_LEVEL_NAME_EX:
                    continue
                if r.forest_trust_data.string.lower() != tln_ex.lower():
                    continue
                idx = i
                break
            if idx is None:
                raise CommandError("Entry not found for value[%s] specified for --delete-tln-ex" % tln_ex)

            entries = []
            entries.extend(update_forest_info.entries)
            entries.pop(idx)
            update_forest_info.count = len(entries)
            update_forest_info.entries = entries

        for nb in enable_nb:
            idx = None
            for i, r in enumerate(update_forest_info.entries):
                if r.type != lsa.LSA_FOREST_TRUST_DOMAIN_INFO:
                    continue
                if r.forest_trust_data.netbios_domain_name.string.upper() != nb.upper():
                    continue
                idx = i
                break
            if idx is None:
                raise CommandError("Entry not found for value[%s] specified for --enable-nb" % nb)
            if not update_forest_info.entries[idx].flags & lsa.LSA_NB_DISABLED_MASK:
                raise CommandError("Entry found for value[%s] specified for --enable-nb is already enabled" % nb)
            update_forest_info.entries[idx].time = 0
            update_forest_info.entries[idx].flags &= ~lsa.LSA_NB_DISABLED_MASK

        for nb in disable_nb:
            idx = None
            for i, r in enumerate(update_forest_info.entries):
                if r.type != lsa.LSA_FOREST_TRUST_DOMAIN_INFO:
                    continue
                if r.forest_trust_data.netbios_domain_name.string.upper() != nb.upper():
                    continue
                idx = i
                break
            if idx is None:
                raise CommandError("Entry not found for value[%s] specified for --delete-nb" % nb)
            if update_forest_info.entries[idx].flags & lsa.LSA_NB_DISABLED_ADMIN:
                raise CommandError("Entry found for value[%s] specified for --disable-nb is already disabled" % nb)
            update_forest_info.entries[idx].time = 0
            update_forest_info.entries[idx].flags &= ~lsa.LSA_NB_DISABLED_MASK
            update_forest_info.entries[idx].flags |= lsa.LSA_NB_DISABLED_ADMIN

        for sid in enable_sid:
            idx = None
            for i, r in enumerate(update_forest_info.entries):
                if r.type != lsa.LSA_FOREST_TRUST_DOMAIN_INFO:
                    continue
                if r.forest_trust_data.domain_sid != sid:
                    continue
                idx = i
                break
            if idx is None:
                raise CommandError("Entry not found for value[%s] specified for --enable-sid" % sid)
            if not update_forest_info.entries[idx].flags & lsa.LSA_SID_DISABLED_MASK:
                raise CommandError("Entry found for value[%s] specified for --enable-sid is already enabled" % nb)
            update_forest_info.entries[idx].time = 0
            update_forest_info.entries[idx].flags &= ~lsa.LSA_SID_DISABLED_MASK

        for sid in disable_sid:
            idx = None
            for i, r in enumerate(update_forest_info.entries):
                if r.type != lsa.LSA_FOREST_TRUST_DOMAIN_INFO:
                    continue
                if r.forest_trust_data.domain_sid != sid:
                    continue
                idx = i
                break
            if idx is None:
                raise CommandError("Entry not found for value[%s] specified for --delete-sid" % sid)
            if update_forest_info.entries[idx].flags & lsa.LSA_SID_DISABLED_ADMIN:
                raise CommandError("Entry found for value[%s] specified for --disable-sid is already disabled" % nb)
            update_forest_info.entries[idx].time = 0
            update_forest_info.entries[idx].flags &= ~lsa.LSA_SID_DISABLED_MASK
            update_forest_info.entries[idx].flags |= lsa.LSA_SID_DISABLED_ADMIN

        try:
            update_forest_collision = local_lsa.lsaRSetForestTrustInformation(local_policy,
                                                                              local_tdo_info.domain_name,
                                                                              lsa.LSA_FOREST_TRUST_DOMAIN_INFO,
                                                                              update_forest_info, 0)
        except RuntimeError as error:
            raise self.LocalRuntimeError(self, error, "lsaRSetForestTrustInformation() failed")

        self.outf.write("Updated forest trust information...\n")
        self.write_forest_trust_info(update_forest_info,
                                     tln=local_tdo_info.domain_name.string,
                                     collisions=update_forest_collision)

        try:
            lsaString = lsa.String()
            lsaString.string = local_tdo_info.domain_name.string
            stored_forest_info = local_lsa.lsaRQueryForestTrustInformation(local_policy,
                                                                           lsaString,
                                                                           lsa.LSA_FOREST_TRUST_DOMAIN_INFO)
        except RuntimeError as error:
            raise self.LocalRuntimeError(self, error, "lsaRQueryForestTrustInformation() failed")

        self.outf.write("Stored forest trust information...\n")
        self.write_forest_trust_info(stored_forest_info,
                                     tln=local_tdo_info.domain_name.string)
        return


class cmd_domain_trust(SuperCommand):
    """Domain and forest trust management."""

    subcommands = {}
    subcommands["list"] = cmd_domain_trust_list()
    subcommands["show"] = cmd_domain_trust_show()
    subcommands["create"] = cmd_domain_trust_create()
    subcommands["modify"] = cmd_domain_trust_modify()
    subcommands["delete"] = cmd_domain_trust_delete()
    subcommands["validate"] = cmd_domain_trust_validate()
    subcommands["namespaces"] = cmd_domain_trust_namespaces()
