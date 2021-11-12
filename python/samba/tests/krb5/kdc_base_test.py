# Unix SMB/CIFS implementation.
# Copyright (C) Stefan Metzmacher 2020
# Copyright (C) 2020-2021 Catalyst.Net Ltd
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

import sys
import os
from datetime import datetime, timezone
import tempfile
import binascii
import collections
import secrets
from enum import Enum, auto

from collections import namedtuple
import ldb
from ldb import SCOPE_BASE
from samba import generate_random_password
from samba.auth import system_session
from samba.credentials import Credentials, SPECIFIED, MUST_USE_KERBEROS
from samba.dcerpc import drsblobs, drsuapi, misc, krb5pac, krb5ccache, security
from samba.drs_utils import drs_Replicate, drsuapi_connect
from samba.dsdb import (
    DSDB_SYNTAX_BINARY_DN,
    DS_DOMAIN_FUNCTION_2000,
    DS_DOMAIN_FUNCTION_2008,
    DS_GUID_COMPUTERS_CONTAINER,
    DS_GUID_DOMAIN_CONTROLLERS_CONTAINER,
    DS_GUID_USERS_CONTAINER,
    UF_WORKSTATION_TRUST_ACCOUNT,
    UF_NO_AUTH_DATA_REQUIRED,
    UF_NORMAL_ACCOUNT,
    UF_NOT_DELEGATED,
    UF_PARTIAL_SECRETS_ACCOUNT,
    UF_SERVER_TRUST_ACCOUNT,
    UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION
)
from samba.join import DCJoinContext
from samba.ndr import ndr_pack, ndr_unpack
from samba import net
from samba.samdb import SamDB, dsdb_Dn

from samba.tests import delete_force
import samba.tests.krb5.kcrypto as kcrypto
from samba.tests.krb5.raw_testcase import (
    KerberosCredentials,
    KerberosTicketCreds,
    RawKerberosTest
)
import samba.tests.krb5.rfc4120_pyasn1 as krb5_asn1
from samba.tests.krb5.rfc4120_constants import (
    AD_IF_RELEVANT,
    AD_WIN2K_PAC,
    AES256_CTS_HMAC_SHA1_96,
    ARCFOUR_HMAC_MD5,
    KDC_ERR_PREAUTH_REQUIRED,
    KRB_AS_REP,
    KRB_TGS_REP,
    KRB_ERROR,
    KU_AS_REP_ENC_PART,
    KU_ENC_CHALLENGE_CLIENT,
    KU_PA_ENC_TIMESTAMP,
    KU_TICKET,
    NT_PRINCIPAL,
    NT_SRV_HST,
    NT_SRV_INST,
    PADATA_ENCRYPTED_CHALLENGE,
    PADATA_ENC_TIMESTAMP,
    PADATA_ETYPE_INFO2,
)

sys.path.insert(0, "bin/python")
os.environ["PYTHONUNBUFFERED"] = "1"

global_asn1_print = False
global_hexdump = False


class KDCBaseTest(RawKerberosTest):
    """ Base class for KDC tests.
    """

    class AccountType(Enum):
        USER = auto()
        COMPUTER = auto()
        SERVER = auto()
        RODC = auto()

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls._lp = None

        cls._ldb = None
        cls._rodc_ldb = None

        cls._functional_level = None

        # An identifier to ensure created accounts have unique names. Windows
        # caches accounts based on usernames, so account names being different
        # across test runs avoids previous test runs affecting the results.
        cls.account_base = f'{secrets.token_hex(4)}_'
        cls.account_id = 0

        # A set containing DNs of accounts created as part of testing.
        cls.accounts = set()

        cls.account_cache = {}
        cls.tkt_cache = {}

        cls._rodc_ctx = None

        cls.ldb_cleanups = []

    @classmethod
    def tearDownClass(cls):
        # Clean up any accounts created by create_account. This is
        # done in tearDownClass() rather than tearDown(), so that
        # accounts need only be created once for permutation tests.
        if cls._ldb is not None:
            for cleanup in reversed(cls.ldb_cleanups):
                try:
                    cls._ldb.modify(cleanup)
                except ldb.LdbError:
                    pass

            for dn in cls.accounts:
                delete_force(cls._ldb, dn)

        if cls._rodc_ctx is not None:
            cls._rodc_ctx.cleanup_old_join(force=True)

        super().tearDownClass()

    def setUp(self):
        super().setUp()
        self.do_asn1_print = global_asn1_print
        self.do_hexdump = global_hexdump

    def get_lp(self):
        if self._lp is None:
            type(self)._lp = self.get_loadparm()

        return self._lp

    def get_samdb(self):
        if self._ldb is None:
            creds = self.get_admin_creds()
            lp = self.get_lp()

            session = system_session()
            type(self)._ldb = SamDB(url="ldap://%s" % self.dc_host,
                                    session_info=session,
                                    credentials=creds,
                                    lp=lp)

        return self._ldb

    def get_rodc_samdb(self):
        if self._rodc_ldb is None:
            creds = self.get_admin_creds()
            lp = self.get_lp()

            session = system_session()
            type(self)._rodc_ldb = SamDB(url="ldap://%s" % self.host,
                                         session_info=session,
                                         credentials=creds,
                                         lp=lp,
                                         am_rodc=True)

        return self._rodc_ldb

    def get_server_dn(self, samdb):
        server = samdb.get_serverName()

        res = samdb.search(base=server,
                           scope=ldb.SCOPE_BASE,
                           attrs=['serverReference'])
        dn = ldb.Dn(samdb, res[0]['serverReference'][0].decode('utf8'))

        return dn

    def get_mock_rodc_ctx(self):
        if self._rodc_ctx is None:
            admin_creds = self.get_admin_creds()
            lp = self.get_lp()

            rodc_name = 'KRB5RODC'
            site_name = 'Default-First-Site-Name'

            type(self)._rodc_ctx = DCJoinContext(server=self.dc_host,
                                                 creds=admin_creds,
                                                 lp=lp,
                                                 site=site_name,
                                                 netbios_name=rodc_name,
                                                 targetdir=None,
                                                 domain=None)
            self.create_rodc(self._rodc_ctx)

        return self._rodc_ctx

    def get_domain_functional_level(self, ldb):
        if self._functional_level is None:
            res = ldb.search(base='',
                             scope=SCOPE_BASE,
                             attrs=['domainFunctionality'])
            try:
                functional_level = int(res[0]['domainFunctionality'][0])
            except KeyError:
                functional_level = DS_DOMAIN_FUNCTION_2000

            type(self)._functional_level = functional_level

        return self._functional_level

    def get_default_enctypes(self):
        samdb = self.get_samdb()
        functional_level = self.get_domain_functional_level(samdb)

        # RC4 should always be supported
        default_enctypes = {kcrypto.Enctype.RC4}
        if functional_level >= DS_DOMAIN_FUNCTION_2008:
            # AES is only supported at functional level 2008 or higher
            default_enctypes.add(kcrypto.Enctype.AES256)
            default_enctypes.add(kcrypto.Enctype.AES128)

        return default_enctypes

    def create_account(self, samdb, name, account_type=AccountType.USER,
                       spn=None, upn=None, additional_details=None,
                       ou=None, account_control=0, add_dollar=True):
        '''Create an account for testing.
           The dn of the created account is added to self.accounts,
           which is used by tearDownClass to clean up the created accounts.
        '''
        if ou is None:
            if account_type is account_type.COMPUTER:
                guid = DS_GUID_COMPUTERS_CONTAINER
            elif account_type is account_type.SERVER:
                guid = DS_GUID_DOMAIN_CONTROLLERS_CONTAINER
            else:
                guid = DS_GUID_USERS_CONTAINER

            ou = samdb.get_wellknown_dn(samdb.get_default_basedn(), guid)

        dn = "CN=%s,%s" % (name, ou)

        # remove the account if it exists, this will happen if a previous test
        # run failed
        delete_force(samdb, dn)
        account_name = name
        if account_type is self.AccountType.USER:
            object_class = "user"
            account_control |= UF_NORMAL_ACCOUNT
        else:
            object_class = "computer"
            if add_dollar:
                account_name += '$'
            if account_type is self.AccountType.COMPUTER:
                account_control |= UF_WORKSTATION_TRUST_ACCOUNT
            elif account_type is self.AccountType.SERVER:
                account_control |= UF_SERVER_TRUST_ACCOUNT
            else:
                self.fail()

        password = generate_random_password(32, 32)
        utf16pw = ('"%s"' % password).encode('utf-16-le')

        details = {
            "dn": dn,
            "objectclass": object_class,
            "sAMAccountName": account_name,
            "userAccountControl": str(account_control),
            "unicodePwd": utf16pw}
        if spn is not None:
            if isinstance(spn, str):
                spn = spn.format(account=account_name)
            else:
                spn = tuple(s.format(account=account_name) for s in spn)
            details["servicePrincipalName"] = spn
        if upn is not None:
            details["userPrincipalName"] = upn
        if additional_details is not None:
            details.update(additional_details)
        samdb.add(details)

        creds = KerberosCredentials()
        creds.guess(self.get_lp())
        creds.set_realm(samdb.domain_dns_name().upper())
        creds.set_domain(samdb.domain_netbios_name().upper())
        creds.set_password(password)
        creds.set_username(account_name)
        if account_type is self.AccountType.USER:
            creds.set_workstation('')
        else:
            creds.set_workstation(name)
        creds.set_dn(ldb.Dn(samdb, dn))
        creds.set_upn(upn)
        creds.set_spn(spn)
        #
        # Save the account name so it can be deleted in tearDownClass
        self.accounts.add(dn)

        self.creds_set_enctypes(creds)

        res = samdb.search(base=dn,
                           scope=ldb.SCOPE_BASE,
                           attrs=['msDS-KeyVersionNumber'])
        kvno = res[0].get('msDS-KeyVersionNumber', idx=0)
        if kvno is not None:
            self.assertEqual(int(kvno), 1)
        creds.set_kvno(1)

        return (creds, dn)

    def get_security_descriptor(self, dn):
        samdb = self.get_samdb()

        sid = self.get_objectSid(samdb, dn)

        owner_sid = security.dom_sid(security.SID_BUILTIN_ADMINISTRATORS)

        ace = security.ace()
        ace.access_mask = security.SEC_ADS_GENERIC_ALL

        ace.trustee = security.dom_sid(sid)

        dacl = security.acl()
        dacl.revision = security.SECURITY_ACL_REVISION_ADS
        dacl.aces = [ace]
        dacl.num_aces = 1

        security_desc = security.descriptor()
        security_desc.type |= security.SEC_DESC_DACL_PRESENT
        security_desc.owner_sid = owner_sid
        security_desc.dacl = dacl

        return ndr_pack(security_desc)

    def create_rodc(self, ctx):
        ctx.nc_list = [ctx.base_dn, ctx.config_dn, ctx.schema_dn]
        ctx.full_nc_list = [ctx.base_dn, ctx.config_dn, ctx.schema_dn]
        ctx.krbtgt_dn = f'CN=krbtgt_{ctx.myname},CN=Users,{ctx.base_dn}'

        ctx.never_reveal_sid = [f'<SID={ctx.domsid}-{security.DOMAIN_RID_RODC_DENY}>',
                                f'<SID={security.SID_BUILTIN_ADMINISTRATORS}>',
                                f'<SID={security.SID_BUILTIN_SERVER_OPERATORS}>',
                                f'<SID={security.SID_BUILTIN_BACKUP_OPERATORS}>',
                                f'<SID={security.SID_BUILTIN_ACCOUNT_OPERATORS}>']
        ctx.reveal_sid = f'<SID={ctx.domsid}-{security.DOMAIN_RID_RODC_ALLOW}>'

        mysid = ctx.get_mysid()
        admin_dn = f'<SID={mysid}>'
        ctx.managedby = admin_dn

        ctx.userAccountControl = (UF_WORKSTATION_TRUST_ACCOUNT |
                                  UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION |
                                  UF_PARTIAL_SECRETS_ACCOUNT)

        ctx.connection_dn = f'CN=RODC Connection (FRS),{ctx.ntds_dn}'
        ctx.secure_channel_type = misc.SEC_CHAN_RODC
        ctx.RODC = True
        ctx.replica_flags = (drsuapi.DRSUAPI_DRS_INIT_SYNC |
                             drsuapi.DRSUAPI_DRS_PER_SYNC |
                             drsuapi.DRSUAPI_DRS_GET_ANC |
                             drsuapi.DRSUAPI_DRS_NEVER_SYNCED |
                             drsuapi.DRSUAPI_DRS_SPECIAL_SECRET_PROCESSING)
        ctx.domain_replica_flags = ctx.replica_flags | drsuapi.DRSUAPI_DRS_CRITICAL_ONLY

        ctx.build_nc_lists()

        ctx.cleanup_old_join()

        try:
            ctx.join_add_objects()
        except Exception:
            # cleanup the failed join (checking we still have a live LDB
            # connection to the remote DC first)
            ctx.refresh_ldb_connection()
            ctx.cleanup_old_join()
            raise

    def replicate_account_to_rodc(self, dn):
        samdb = self.get_samdb()
        rodc_samdb = self.get_rodc_samdb()

        repl_val = f'{samdb.get_dsServiceName()}:{dn}:SECRETS_ONLY'

        msg = ldb.Message()
        msg.dn = ldb.Dn(rodc_samdb, '')
        msg['replicateSingleObject'] = ldb.MessageElement(
            repl_val,
            ldb.FLAG_MOD_REPLACE,
            'replicateSingleObject')

        try:
            # Try replication using the replicateSingleObject rootDSE
            # operation.
            rodc_samdb.modify(msg)
        except ldb.LdbError as err:
            enum, estr = err.args
            self.assertEqual(enum, ldb.ERR_UNWILLING_TO_PERFORM)
            self.assertIn('rootdse_modify: unknown attribute to change!',
                          estr)

            # If that method wasn't supported, we may be in the rodc:local test
            # environment, where we can try replicating to the local database.

            lp = self.get_lp()

            rodc_creds = Credentials()
            rodc_creds.guess(lp)
            rodc_creds.set_machine_account(lp)

            local_samdb = SamDB(url=None, session_info=system_session(),
                                credentials=rodc_creds, lp=lp)

            destination_dsa_guid = misc.GUID(local_samdb.get_ntds_GUID())

            repl = drs_Replicate(f'ncacn_ip_tcp:{self.dc_host}[seal]',
                                 lp, rodc_creds,
                                 local_samdb, destination_dsa_guid)

            source_dsa_invocation_id = misc.GUID(samdb.invocation_id)

            repl.replicate(dn,
                           source_dsa_invocation_id,
                           destination_dsa_guid,
                           exop=drsuapi.DRSUAPI_EXOP_REPL_SECRET,
                           rodc=True)

    def reveal_account_to_mock_rodc(self, dn):
        samdb = self.get_samdb()
        rodc_ctx = self.get_mock_rodc_ctx()

        self.get_secrets(
            samdb,
            dn,
            destination_dsa_guid=rodc_ctx.ntds_guid,
            source_dsa_invocation_id=misc.GUID(samdb.invocation_id))

    def check_revealed(self, dn, rodc_dn, revealed=True):
        samdb = self.get_samdb()

        res = samdb.search(base=rodc_dn,
                           scope=ldb.SCOPE_BASE,
                           attrs=['msDS-RevealedUsers'])

        revealed_users = res[0].get('msDS-RevealedUsers')
        if revealed_users is None:
            self.assertFalse(revealed)
            return

        revealed_dns = set(str(dsdb_Dn(samdb, str(user),
                                       syntax_oid=DSDB_SYNTAX_BINARY_DN).dn)
                           for user in revealed_users)

        if revealed:
            self.assertIn(str(dn), revealed_dns)
        else:
            self.assertNotIn(str(dn), revealed_dns)

    def get_secrets(self, samdb, dn,
                    destination_dsa_guid,
                    source_dsa_invocation_id):
        admin_creds = self.get_admin_creds()

        dns_hostname = samdb.host_dns_name()
        (bind, handle, _) = drsuapi_connect(dns_hostname,
                                            self.get_lp(),
                                            admin_creds)

        req = drsuapi.DsGetNCChangesRequest8()

        req.destination_dsa_guid = destination_dsa_guid
        req.source_dsa_invocation_id = source_dsa_invocation_id

        naming_context = drsuapi.DsReplicaObjectIdentifier()
        naming_context.dn = dn

        req.naming_context = naming_context

        hwm = drsuapi.DsReplicaHighWaterMark()
        hwm.tmp_highest_usn = 0
        hwm.reserved_usn = 0
        hwm.highest_usn = 0

        req.highwatermark = hwm
        req.uptodateness_vector = None

        req.replica_flags = 0

        req.max_object_count = 1
        req.max_ndr_size = 402116
        req.extended_op = drsuapi.DRSUAPI_EXOP_REPL_SECRET

        attids = [drsuapi.DRSUAPI_ATTID_supplementalCredentials,
                  drsuapi.DRSUAPI_ATTID_unicodePwd]

        partial_attribute_set = drsuapi.DsPartialAttributeSet()
        partial_attribute_set.version = 1
        partial_attribute_set.attids = attids
        partial_attribute_set.num_attids = len(attids)

        req.partial_attribute_set = partial_attribute_set

        req.partial_attribute_set_ex = None
        req.mapping_ctr.num_mappings = 0
        req.mapping_ctr.mappings = None

        _, ctr = bind.DsGetNCChanges(handle, 8, req)

        self.assertEqual(1, ctr.object_count)

        identifier = ctr.first_object.object.identifier
        attributes = ctr.first_object.object.attribute_ctr.attributes

        self.assertEqual(dn, identifier.dn)

        return bind, identifier, attributes

    def get_keys(self, samdb, dn):
        admin_creds = self.get_admin_creds()

        bind, identifier, attributes = self.get_secrets(
            samdb,
            str(dn),
            destination_dsa_guid=misc.GUID(samdb.get_ntds_GUID()),
            source_dsa_invocation_id=misc.GUID())

        rid = identifier.sid.split()[1]

        net_ctx = net.Net(admin_creds)

        keys = {}

        for attr in attributes:
            if attr.attid == drsuapi.DRSUAPI_ATTID_supplementalCredentials:
                net_ctx.replicate_decrypt(bind, attr, rid)
                attr_val = attr.value_ctr.values[0].blob

                spl = ndr_unpack(drsblobs.supplementalCredentialsBlob,
                                 attr_val)
                for pkg in spl.sub.packages:
                    if pkg.name == 'Primary:Kerberos-Newer-Keys':
                        krb5_new_keys_raw = binascii.a2b_hex(pkg.data)
                        krb5_new_keys = ndr_unpack(
                            drsblobs.package_PrimaryKerberosBlob,
                            krb5_new_keys_raw)
                        for key in krb5_new_keys.ctr.keys:
                            keytype = key.keytype
                            if keytype in (kcrypto.Enctype.AES256,
                                           kcrypto.Enctype.AES128):
                                keys[keytype] = key.value.hex()
            elif attr.attid == drsuapi.DRSUAPI_ATTID_unicodePwd:
                net_ctx.replicate_decrypt(bind, attr, rid)
                pwd = attr.value_ctr.values[0].blob
                keys[kcrypto.Enctype.RC4] = pwd.hex()

        default_enctypes = self.get_default_enctypes()

        self.assertCountEqual(default_enctypes, keys)

        return keys

    def creds_set_keys(self, creds, keys):
        if keys is not None:
            for enctype, key in keys.items():
                creds.set_forced_key(enctype, key)

    def creds_set_enctypes(self, creds):
        samdb = self.get_samdb()

        res = samdb.search(creds.get_dn(),
                           scope=ldb.SCOPE_BASE,
                           attrs=['msDS-SupportedEncryptionTypes'])
        supported_enctypes = res[0].get('msDS-SupportedEncryptionTypes', idx=0)

        if supported_enctypes is None:
            supported_enctypes = 0

        creds.set_as_supported_enctypes(supported_enctypes)
        creds.set_tgs_supported_enctypes(supported_enctypes)
        creds.set_ap_supported_enctypes(supported_enctypes)

    def creds_set_default_enctypes(self, creds, fast_support=False):
        default_enctypes = self.get_default_enctypes()
        supported_enctypes = KerberosCredentials.etypes_to_bits(
            default_enctypes)

        if fast_support:
            supported_enctypes |= KerberosCredentials.fast_supported_bits

        creds.set_as_supported_enctypes(supported_enctypes)
        creds.set_tgs_supported_enctypes(supported_enctypes)
        creds.set_ap_supported_enctypes(supported_enctypes)

    def add_to_group(self, account_dn, group_dn, group_attr):
        samdb = self.get_samdb()

        res = samdb.search(base=group_dn,
                           scope=ldb.SCOPE_BASE,
                           attrs=[group_attr])
        orig_msg = res[0]
        self.assertIn(group_attr, orig_msg)

        members = list(orig_msg[group_attr])
        members.append(account_dn)

        msg = ldb.Message()
        msg.dn = group_dn
        msg[group_attr] = ldb.MessageElement(members,
                                             ldb.FLAG_MOD_REPLACE,
                                             group_attr)

        cleanup = samdb.msg_diff(msg, orig_msg)
        self.ldb_cleanups.append(cleanup)
        samdb.modify(msg)

        return cleanup

    def get_cached_creds(self, *,
                         account_type,
                         opts=None,
                         use_cache=True):
        if opts is None:
            opts = {}

        opts_default = {
            'name_prefix': None,
            'name_suffix': None,
            'add_dollar': True,
            'upn': None,
            'spn': None,
            'allowed_replication': False,
            'allowed_replication_mock': False,
            'denied_replication': False,
            'denied_replication_mock': False,
            'revealed_to_rodc': False,
            'revealed_to_mock_rodc': False,
            'no_auth_data_required': False,
            'supported_enctypes': None,
            'not_delegated': False,
            'delegation_to_spn': None,
            'delegation_from_dn': None,
            'trusted_to_auth_for_delegation': False,
            'fast_support': False,
            'id': None
        }

        account_opts = {
            'account_type': account_type,
            **opts_default,
            **opts
        }

        cache_key = tuple(sorted(account_opts.items()))

        if use_cache:
            creds = self.account_cache.get(cache_key)
            if creds is not None:
                return creds

        creds = self.create_account_opts(**account_opts)
        if use_cache:
            self.account_cache[cache_key] = creds

        return creds

    def create_account_opts(self, *,
                            account_type,
                            name_prefix,
                            name_suffix,
                            add_dollar,
                            upn,
                            spn,
                            allowed_replication,
                            allowed_replication_mock,
                            denied_replication,
                            denied_replication_mock,
                            revealed_to_rodc,
                            revealed_to_mock_rodc,
                            no_auth_data_required,
                            supported_enctypes,
                            not_delegated,
                            delegation_to_spn,
                            delegation_from_dn,
                            trusted_to_auth_for_delegation,
                            fast_support,
                            id):
        if account_type is self.AccountType.USER:
            self.assertIsNone(spn)
            self.assertIsNone(delegation_to_spn)
            self.assertIsNone(delegation_from_dn)
            self.assertFalse(trusted_to_auth_for_delegation)
        else:
            self.assertFalse(not_delegated)

        samdb = self.get_samdb()

        user_name = self.get_new_username()
        if name_prefix is not None:
            user_name = name_prefix + user_name
        if name_suffix is not None:
            user_name += name_suffix

        user_account_control = 0
        if trusted_to_auth_for_delegation:
            user_account_control |= UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION
        if not_delegated:
            user_account_control |= UF_NOT_DELEGATED
        if no_auth_data_required:
            user_account_control |= UF_NO_AUTH_DATA_REQUIRED

        details = {}

        enctypes = supported_enctypes
        if fast_support:
            enctypes = enctypes or 0
            enctypes |= KerberosCredentials.fast_supported_bits

        if enctypes is not None:
            details['msDS-SupportedEncryptionTypes'] = str(enctypes)

        if delegation_to_spn:
            details['msDS-AllowedToDelegateTo'] = delegation_to_spn

        if delegation_from_dn:
            security_descriptor = self.get_security_descriptor(
                delegation_from_dn)
            details['msDS-AllowedToActOnBehalfOfOtherIdentity'] = (
                security_descriptor)

        if spn is None and account_type is not self.AccountType.USER:
            spn = 'host/' + user_name

        creds, dn = self.create_account(samdb, user_name,
                                        account_type=account_type,
                                        upn=upn,
                                        spn=spn,
                                        additional_details=details,
                                        account_control=user_account_control,
                                        add_dollar=add_dollar)

        keys = self.get_keys(samdb, dn)
        self.creds_set_keys(creds, keys)

        # Handle secret replication to the RODC.

        if allowed_replication or revealed_to_rodc:
            rodc_samdb = self.get_rodc_samdb()
            rodc_dn = self.get_server_dn(rodc_samdb)

            # Allow replicating this account's secrets if requested, or allow
            # it only temporarily if we're about to replicate them.
            allowed_cleanup = self.add_to_group(
                dn, rodc_dn,
                'msDS-RevealOnDemandGroup')

            if revealed_to_rodc:
                # Replicate this account's secrets to the RODC.
                self.replicate_account_to_rodc(dn)

            if not allowed_replication:
                # If we don't want replicating secrets to be allowed for this
                # account, disable it again.
                samdb.modify(allowed_cleanup)

            self.check_revealed(dn,
                                rodc_dn,
                                revealed=revealed_to_rodc)

        if denied_replication:
            rodc_samdb = self.get_rodc_samdb()
            rodc_dn = self.get_server_dn(rodc_samdb)

            # Deny replicating this account's secrets to the RODC.
            self.add_to_group(dn, rodc_dn, 'msDS-NeverRevealGroup')

        # Handle secret replication to the mock RODC.

        if allowed_replication_mock or revealed_to_mock_rodc:
            # Allow replicating this account's secrets if requested, or allow
            # it only temporarily if we want to add the account to the mock
            # RODC's msDS-RevealedUsers.
            rodc_ctx = self.get_mock_rodc_ctx()
            mock_rodc_dn = ldb.Dn(samdb, rodc_ctx.acct_dn)

            allowed_mock_cleanup = self.add_to_group(
                dn, mock_rodc_dn,
                'msDS-RevealOnDemandGroup')

            if revealed_to_mock_rodc:
                # Request replicating this account's secrets to the mock RODC,
                # which updates msDS-RevealedUsers.
                self.reveal_account_to_mock_rodc(dn)

            if not allowed_replication_mock:
                # If we don't want replicating secrets to be allowed for this
                # account, disable it again.
                samdb.modify(allowed_mock_cleanup)

            self.check_revealed(dn,
                                mock_rodc_dn,
                                revealed=revealed_to_mock_rodc)

        if denied_replication_mock:
            # Deny replicating this account's secrets to the mock RODC.
            rodc_ctx = self.get_mock_rodc_ctx()
            mock_rodc_dn = ldb.Dn(samdb, rodc_ctx.acct_dn)

            self.add_to_group(dn, mock_rodc_dn, 'msDS-NeverRevealGroup')

        return creds

    def get_new_username(self):
        user_name = self.account_base + str(self.account_id)
        type(self).account_id += 1

        return user_name

    def get_client_creds(self,
                         allow_missing_password=False,
                         allow_missing_keys=True):
        def create_client_account():
            return self.get_cached_creds(account_type=self.AccountType.USER)

        c = self._get_krb5_creds(prefix='CLIENT',
                                 allow_missing_password=allow_missing_password,
                                 allow_missing_keys=allow_missing_keys,
                                 fallback_creds_fn=create_client_account)
        return c

    def get_mach_creds(self,
                       allow_missing_password=False,
                       allow_missing_keys=True):
        def create_mach_account():
            return self.get_cached_creds(account_type=self.AccountType.COMPUTER,
                                         opts={'fast_support': True})

        c = self._get_krb5_creds(prefix='MAC',
                                 allow_missing_password=allow_missing_password,
                                 allow_missing_keys=allow_missing_keys,
                                 fallback_creds_fn=create_mach_account)
        return c

    def get_service_creds(self,
                          allow_missing_password=False,
                          allow_missing_keys=True):
        def create_service_account():
            return self.get_cached_creds(
                account_type=self.AccountType.COMPUTER,
                opts={
                    'trusted_to_auth_for_delegation': True,
                    'fast_support': True
                })

        c = self._get_krb5_creds(prefix='SERVICE',
                                 allow_missing_password=allow_missing_password,
                                 allow_missing_keys=allow_missing_keys,
                                 fallback_creds_fn=create_service_account)
        return c

    def get_rodc_krbtgt_creds(self,
                              require_keys=True,
                              require_strongest_key=False):
        if require_strongest_key:
            self.assertTrue(require_keys)

        def download_rodc_krbtgt_creds():
            samdb = self.get_samdb()
            rodc_samdb = self.get_rodc_samdb()

            rodc_dn = self.get_server_dn(rodc_samdb)

            res = samdb.search(rodc_dn,
                               scope=ldb.SCOPE_BASE,
                               attrs=['msDS-KrbTgtLink'])
            krbtgt_dn = res[0]['msDS-KrbTgtLink'][0]

            res = samdb.search(krbtgt_dn,
                               scope=ldb.SCOPE_BASE,
                               attrs=['sAMAccountName',
                                      'msDS-KeyVersionNumber',
                                      'msDS-SecondaryKrbTgtNumber'])
            krbtgt_dn = res[0].dn
            username = str(res[0]['sAMAccountName'])

            creds = KerberosCredentials()
            creds.set_domain(self.env_get_var('DOMAIN', 'RODC_KRBTGT'))
            creds.set_realm(self.env_get_var('REALM', 'RODC_KRBTGT'))
            creds.set_username(username)

            kvno = int(res[0]['msDS-KeyVersionNumber'][0])
            krbtgt_number = int(res[0]['msDS-SecondaryKrbTgtNumber'][0])

            rodc_kvno = krbtgt_number << 16 | kvno
            creds.set_kvno(rodc_kvno)
            creds.set_dn(krbtgt_dn)

            keys = self.get_keys(samdb, krbtgt_dn)
            self.creds_set_keys(creds, keys)

            # The RODC krbtgt account should support the default enctypes,
            # although it might not have the msDS-SupportedEncryptionTypes
            # attribute.
            self.creds_set_default_enctypes(creds)

            return creds

        c = self._get_krb5_creds(prefix='RODC_KRBTGT',
                                 allow_missing_password=True,
                                 allow_missing_keys=not require_keys,
                                 require_strongest_key=require_strongest_key,
                                 fallback_creds_fn=download_rodc_krbtgt_creds)
        return c

    def get_mock_rodc_krbtgt_creds(self,
                                   require_keys=True,
                                   require_strongest_key=False):
        if require_strongest_key:
            self.assertTrue(require_keys)

        def create_rodc_krbtgt_account():
            samdb = self.get_samdb()

            rodc_ctx = self.get_mock_rodc_ctx()

            krbtgt_dn = rodc_ctx.new_krbtgt_dn

            res = samdb.search(base=ldb.Dn(samdb, krbtgt_dn),
                               scope=ldb.SCOPE_BASE,
                               attrs=['msDS-KeyVersionNumber',
                                      'msDS-SecondaryKrbTgtNumber'])
            dn = res[0].dn
            username = str(rodc_ctx.krbtgt_name)

            creds = KerberosCredentials()
            creds.set_domain(self.env_get_var('DOMAIN', 'RODC_KRBTGT'))
            creds.set_realm(self.env_get_var('REALM', 'RODC_KRBTGT'))
            creds.set_username(username)

            kvno = int(res[0]['msDS-KeyVersionNumber'][0])
            krbtgt_number = int(res[0]['msDS-SecondaryKrbTgtNumber'][0])

            rodc_kvno = krbtgt_number << 16 | kvno
            creds.set_kvno(rodc_kvno)
            creds.set_dn(dn)

            keys = self.get_keys(samdb, dn)
            self.creds_set_keys(creds, keys)

            self.creds_set_enctypes(creds)

            return creds

        c = self._get_krb5_creds(prefix='MOCK_RODC_KRBTGT',
                                 allow_missing_password=True,
                                 allow_missing_keys=not require_keys,
                                 require_strongest_key=require_strongest_key,
                                 fallback_creds_fn=create_rodc_krbtgt_account)
        return c

    def get_krbtgt_creds(self,
                         require_keys=True,
                         require_strongest_key=False):
        if require_strongest_key:
            self.assertTrue(require_keys)

        def download_krbtgt_creds():
            samdb = self.get_samdb()

            krbtgt_rid = security.DOMAIN_RID_KRBTGT
            krbtgt_sid = '%s-%d' % (samdb.get_domain_sid(), krbtgt_rid)

            res = samdb.search(base='<SID=%s>' % krbtgt_sid,
                               scope=ldb.SCOPE_BASE,
                               attrs=['sAMAccountName',
                                      'msDS-KeyVersionNumber'])
            dn = res[0].dn
            username = str(res[0]['sAMAccountName'])

            creds = KerberosCredentials()
            creds.set_domain(self.env_get_var('DOMAIN', 'KRBTGT'))
            creds.set_realm(self.env_get_var('REALM', 'KRBTGT'))
            creds.set_username(username)

            kvno = int(res[0]['msDS-KeyVersionNumber'][0])
            creds.set_kvno(kvno)
            creds.set_dn(dn)

            keys = self.get_keys(samdb, dn)
            self.creds_set_keys(creds, keys)

            # The krbtgt account should support the default enctypes, although
            # it might not (on Samba) have the msDS-SupportedEncryptionTypes
            # attribute.
            self.creds_set_default_enctypes(creds,
                                            fast_support=self.kdc_fast_support)

            return creds

        c = self._get_krb5_creds(prefix='KRBTGT',
                                 default_username='krbtgt',
                                 allow_missing_password=True,
                                 allow_missing_keys=not require_keys,
                                 require_strongest_key=require_strongest_key,
                                 fallback_creds_fn=download_krbtgt_creds)
        return c

    def get_dc_creds(self,
                     require_keys=True,
                     require_strongest_key=False):
        if require_strongest_key:
            self.assertTrue(require_keys)

        def download_dc_creds():
            samdb = self.get_samdb()

            dc_rid = 1000
            dc_sid = '%s-%d' % (samdb.get_domain_sid(), dc_rid)

            res = samdb.search(base='<SID=%s>' % dc_sid,
                               scope=ldb.SCOPE_BASE,
                               attrs=['sAMAccountName',
                                      'msDS-KeyVersionNumber'])
            dn = res[0].dn
            username = str(res[0]['sAMAccountName'])

            creds = KerberosCredentials()
            creds.set_domain(self.env_get_var('DOMAIN', 'DC'))
            creds.set_realm(self.env_get_var('REALM', 'DC'))
            creds.set_username(username)

            kvno = int(res[0]['msDS-KeyVersionNumber'][0])
            creds.set_kvno(kvno)
            creds.set_dn(dn)

            keys = self.get_keys(samdb, dn)
            self.creds_set_keys(creds, keys)

            self.creds_set_enctypes(creds)

            return creds

        c = self._get_krb5_creds(prefix='DC',
                                 allow_missing_password=True,
                                 allow_missing_keys=not require_keys,
                                 require_strongest_key=require_strongest_key,
                                 fallback_creds_fn=download_dc_creds)
        return c

    def get_server_creds(self,
                     require_keys=True,
                     require_strongest_key=False):
        if require_strongest_key:
            self.assertTrue(require_keys)

        def download_server_creds():
            samdb = self.get_samdb()

            res = samdb.search(base=samdb.get_default_basedn(),
                               expression=(f'(|(sAMAccountName={self.host}*)'
                                           f'(dNSHostName={self.host}))'),
                               scope=ldb.SCOPE_SUBTREE,
                               attrs=['sAMAccountName',
                                      'msDS-KeyVersionNumber'])
            self.assertEqual(1, len(res))
            dn = res[0].dn
            username = str(res[0]['sAMAccountName'])

            creds = KerberosCredentials()
            creds.set_domain(self.env_get_var('DOMAIN', 'SERVER'))
            creds.set_realm(self.env_get_var('REALM', 'SERVER'))
            creds.set_username(username)

            kvno = int(res[0]['msDS-KeyVersionNumber'][0])
            creds.set_kvno(kvno)
            creds.set_dn(dn)

            keys = self.get_keys(samdb, dn)
            self.creds_set_keys(creds, keys)

            self.creds_set_enctypes(creds)

            return creds

        c = self._get_krb5_creds(prefix='SERVER',
                                 allow_missing_password=True,
                                 allow_missing_keys=not require_keys,
                                 require_strongest_key=require_strongest_key,
                                 fallback_creds_fn=download_server_creds)
        return c

    def as_req(self, cname, sname, realm, etypes, padata=None, kdc_options=0):
        '''Send a Kerberos AS_REQ, returns the undecoded response
        '''

        till = self.get_KerberosTime(offset=36000)

        req = self.AS_REQ_create(padata=padata,
                                 kdc_options=str(kdc_options),
                                 cname=cname,
                                 realm=realm,
                                 sname=sname,
                                 from_time=None,
                                 till_time=till,
                                 renew_time=None,
                                 nonce=0x7fffffff,
                                 etypes=etypes,
                                 addresses=None,
                                 additional_tickets=None)
        rep = self.send_recv_transaction(req)
        return rep

    def get_as_rep_key(self, creds, rep):
        '''Extract the session key from an AS-REP
        '''
        rep_padata = self.der_decode(
            rep['e-data'],
            asn1Spec=krb5_asn1.METHOD_DATA())

        for pa in rep_padata:
            if pa['padata-type'] == PADATA_ETYPE_INFO2:
                padata_value = pa['padata-value']
                break

        etype_info2 = self.der_decode(
            padata_value, asn1Spec=krb5_asn1.ETYPE_INFO2())

        key = self.PasswordKey_from_etype_info2(creds, etype_info2[0],
                                                creds.get_kvno())
        return key

    def get_enc_timestamp_pa_data(self, creds, rep, skew=0):
        '''generate the pa_data data element for an AS-REQ
        '''

        key = self.get_as_rep_key(creds, rep)

        return self.get_enc_timestamp_pa_data_from_key(key, skew=skew)

    def get_enc_timestamp_pa_data_from_key(self, key, skew=0):
        (patime, pausec) = self.get_KerberosTimeWithUsec(offset=skew)
        padata = self.PA_ENC_TS_ENC_create(patime, pausec)
        padata = self.der_encode(padata, asn1Spec=krb5_asn1.PA_ENC_TS_ENC())

        padata = self.EncryptedData_create(key, KU_PA_ENC_TIMESTAMP, padata)
        padata = self.der_encode(padata, asn1Spec=krb5_asn1.EncryptedData())

        padata = self.PA_DATA_create(PADATA_ENC_TIMESTAMP, padata)

        return padata

    def get_challenge_pa_data(self, client_challenge_key, skew=0):
        patime, pausec = self.get_KerberosTimeWithUsec(offset=skew)
        padata = self.PA_ENC_TS_ENC_create(patime, pausec)
        padata = self.der_encode(padata,
                                 asn1Spec=krb5_asn1.PA_ENC_TS_ENC())

        padata = self.EncryptedData_create(client_challenge_key,
                                           KU_ENC_CHALLENGE_CLIENT,
                                           padata)
        padata = self.der_encode(padata,
                                 asn1Spec=krb5_asn1.EncryptedData())

        padata = self.PA_DATA_create(PADATA_ENCRYPTED_CHALLENGE,
                                     padata)

        return padata

    def get_as_rep_enc_data(self, key, rep):
        ''' Decrypt and Decode the encrypted data in an AS-REP
        '''
        enc_part = key.decrypt(KU_AS_REP_ENC_PART, rep['enc-part']['cipher'])
        # MIT KDC encodes both EncASRepPart and EncTGSRepPart with
        # application tag 26
        try:
            enc_part = self.der_decode(
                enc_part, asn1Spec=krb5_asn1.EncASRepPart())
        except Exception:
            enc_part = self.der_decode(
                enc_part, asn1Spec=krb5_asn1.EncTGSRepPart())

        return enc_part

    def check_pre_authentication(self, rep):
        """ Check that the kdc response was pre-authentication required
        """
        self.check_error_rep(rep, KDC_ERR_PREAUTH_REQUIRED)

    def check_as_reply(self, rep):
        """ Check that the kdc response is an AS-REP and that the
            values for:
                msg-type
                pvno
                tkt-pvno
                kvno
            match the expected values
        """
        self.check_reply(rep, msg_type=KRB_AS_REP)

    def check_tgs_reply(self, rep):
        """ Check that the kdc response is an TGS-REP and that the
            values for:
                msg-type
                pvno
                tkt-pvno
                kvno
            match the expected values
        """
        self.check_reply(rep, msg_type=KRB_TGS_REP)

    def check_reply(self, rep, msg_type):

        # Should have a reply, and it should an TGS-REP message.
        self.assertIsNotNone(rep)
        self.assertEqual(rep['msg-type'], msg_type, "rep = {%s}" % rep)

        # Protocol version number should be 5
        pvno = int(rep['pvno'])
        self.assertEqual(5, pvno, "rep = {%s}" % rep)

        # The ticket version number should be 5
        tkt_vno = int(rep['ticket']['tkt-vno'])
        self.assertEqual(5, tkt_vno, "rep = {%s}" % rep)

        # Check that the kvno is not an RODC kvno
        # MIT kerberos does not provide the kvno, so we treat it as optional.
        # This is tested in compatability_test.py
        if 'kvno' in rep['enc-part']:
            kvno = int(rep['enc-part']['kvno'])
            # If the high order bits are set this is an RODC kvno.
            self.assertEqual(0, kvno & 0xFFFF0000, "rep = {%s}" % rep)

    def check_error_rep(self, rep, expected):
        """ Check that the reply is an error message, with the expected
            error-code specified.
        """
        self.assertIsNotNone(rep)
        self.assertEqual(rep['msg-type'], KRB_ERROR, "rep = {%s}" % rep)
        if isinstance(expected, collections.abc.Container):
            self.assertIn(rep['error-code'], expected, "rep = {%s}" % rep)
        else:
            self.assertEqual(rep['error-code'], expected, "rep = {%s}" % rep)

    def tgs_req(self, cname, sname, realm, ticket, key, etypes,
                expected_error_mode=0, padata=None, kdc_options=0,
                to_rodc=False, service_creds=None, expect_pac=True,
                expect_edata=None, expected_flags=None, unexpected_flags=None):
        '''Send a TGS-REQ, returns the response and the decrypted and
           decoded enc-part
        '''

        subkey = self.RandomKey(key.etype)

        (ctime, cusec) = self.get_KerberosTimeWithUsec()

        tgt = KerberosTicketCreds(ticket,
                                  key,
                                  crealm=realm,
                                  cname=cname)

        if service_creds is not None:
            decryption_key = self.TicketDecryptionKey_from_creds(
                service_creds)
            expected_supported_etypes = service_creds.tgs_supported_enctypes
        else:
            decryption_key = None
            expected_supported_etypes = None

        if not expected_error_mode:
            check_error_fn = None
            check_rep_fn = self.generic_check_kdc_rep
        else:
            check_error_fn = self.generic_check_kdc_error
            check_rep_fn = None

        def generate_padata(_kdc_exchange_dict,
                            _callback_dict,
                            req_body):

            return padata, req_body

        kdc_exchange_dict = self.tgs_exchange_dict(
            expected_crealm=realm,
            expected_cname=cname,
            expected_srealm=realm,
            expected_sname=sname,
            expected_error_mode=expected_error_mode,
            expected_flags=expected_flags,
            unexpected_flags=unexpected_flags,
            expected_supported_etypes=expected_supported_etypes,
            check_error_fn=check_error_fn,
            check_rep_fn=check_rep_fn,
            check_kdc_private_fn=self.generic_check_kdc_private,
            ticket_decryption_key=decryption_key,
            generate_padata_fn=generate_padata if padata is not None else None,
            tgt=tgt,
            authenticator_subkey=subkey,
            kdc_options=str(kdc_options),
            expect_edata=expect_edata,
            expect_pac=expect_pac,
            to_rodc=to_rodc)

        rep = self._generic_kdc_exchange(kdc_exchange_dict,
                                         cname=None,
                                         realm=realm,
                                         sname=sname,
                                         etypes=etypes)

        if expected_error_mode:
            enc_part = None
        else:
            ticket_creds = kdc_exchange_dict['rep_ticket_creds']
            enc_part = ticket_creds.encpart_private

        return rep, enc_part

    def get_service_ticket(self, tgt, target_creds, service='host',
                           target_name=None,
                           to_rodc=False, kdc_options=None,
                           expected_flags=None, unexpected_flags=None,
                           pac_request=True, expect_pac=True, fresh=False):
        user_name = tgt.cname['name-string'][0]
        if target_name is None:
            target_name = target_creds.get_username()[:-1]
        cache_key = (user_name, target_name, service, to_rodc, kdc_options,
                     pac_request, str(expected_flags), str(unexpected_flags),
                     expect_pac)

        if not fresh:
            ticket = self.tkt_cache.get(cache_key)

            if ticket is not None:
                return ticket

        etype = (AES256_CTS_HMAC_SHA1_96, ARCFOUR_HMAC_MD5)

        if kdc_options is None:
            kdc_options = '0'
        kdc_options = str(krb5_asn1.KDCOptions(kdc_options))

        sname = self.PrincipalName_create(name_type=NT_PRINCIPAL,
                                          names=[service, target_name])
        srealm = target_creds.get_realm()

        authenticator_subkey = self.RandomKey(kcrypto.Enctype.AES256)

        decryption_key = self.TicketDecryptionKey_from_creds(target_creds)

        kdc_exchange_dict = self.tgs_exchange_dict(
            expected_crealm=tgt.crealm,
            expected_cname=tgt.cname,
            expected_srealm=srealm,
            expected_sname=sname,
            expected_supported_etypes=target_creds.tgs_supported_enctypes,
            expected_flags=expected_flags,
            unexpected_flags=unexpected_flags,
            ticket_decryption_key=decryption_key,
            check_rep_fn=self.generic_check_kdc_rep,
            check_kdc_private_fn=self.generic_check_kdc_private,
            tgt=tgt,
            authenticator_subkey=authenticator_subkey,
            kdc_options=kdc_options,
            pac_request=pac_request,
            expect_pac=expect_pac,
            to_rodc=to_rodc)

        rep = self._generic_kdc_exchange(kdc_exchange_dict,
                                         cname=None,
                                         realm=srealm,
                                         sname=sname,
                                         etypes=etype)
        self.check_tgs_reply(rep)

        service_ticket_creds = kdc_exchange_dict['rep_ticket_creds']

        if to_rodc:
            krbtgt_creds = self.get_rodc_krbtgt_creds()
        else:
            krbtgt_creds = self.get_krbtgt_creds()
        krbtgt_key = self.TicketDecryptionKey_from_creds(krbtgt_creds)
        self.verify_ticket(service_ticket_creds, krbtgt_key,
                           expect_pac=expect_pac,
                           expect_ticket_checksum=self.tkt_sig_support)

        self.tkt_cache[cache_key] = service_ticket_creds

        return service_ticket_creds

    def get_tgt(self, creds, to_rodc=False, kdc_options=None,
                expected_flags=None, unexpected_flags=None,
                expected_account_name=None, expected_upn_name=None,
                expected_sid=None,
                pac_request=True, expect_pac=True,
                expect_pac_attrs=None, expect_pac_attrs_pac_request=None,
                expect_requester_sid=None,
                fresh=False):
        user_name = creds.get_username()
        cache_key = (user_name, to_rodc, kdc_options, pac_request,
                     str(expected_flags), str(unexpected_flags),
                     expected_account_name, expected_upn_name, expected_sid,
                     expect_pac, expect_pac_attrs,
                     expect_pac_attrs_pac_request, expect_requester_sid)

        if not fresh:
            tgt = self.tkt_cache.get(cache_key)

            if tgt is not None:
                return tgt

        realm = creds.get_realm()

        salt = creds.get_salt()

        etype = (AES256_CTS_HMAC_SHA1_96, ARCFOUR_HMAC_MD5)
        cname = self.PrincipalName_create(name_type=NT_PRINCIPAL,
                                          names=[user_name])
        sname = self.PrincipalName_create(name_type=NT_SRV_INST,
                                          names=['krbtgt', realm])

        till = self.get_KerberosTime(offset=36000)

        if to_rodc:
            krbtgt_creds = self.get_rodc_krbtgt_creds()
        else:
            krbtgt_creds = self.get_krbtgt_creds()
        ticket_decryption_key = (
            self.TicketDecryptionKey_from_creds(krbtgt_creds))

        expected_etypes = krbtgt_creds.tgs_supported_enctypes

        if kdc_options is None:
            kdc_options = ('forwardable,'
                           'renewable,'
                           'canonicalize,'
                           'renewable-ok')
        kdc_options = krb5_asn1.KDCOptions(kdc_options)

        pac_options = '1'  # supports claims

        rep, kdc_exchange_dict = self._test_as_exchange(
            cname=cname,
            realm=realm,
            sname=sname,
            till=till,
            client_as_etypes=etype,
            expected_error_mode=KDC_ERR_PREAUTH_REQUIRED,
            expected_crealm=realm,
            expected_cname=cname,
            expected_srealm=realm,
            expected_sname=sname,
            expected_account_name=expected_account_name,
            expected_upn_name=expected_upn_name,
            expected_sid=expected_sid,
            expected_salt=salt,
            expected_flags=expected_flags,
            unexpected_flags=unexpected_flags,
            expected_supported_etypes=expected_etypes,
            etypes=etype,
            padata=None,
            kdc_options=kdc_options,
            preauth_key=None,
            ticket_decryption_key=ticket_decryption_key,
            pac_request=pac_request,
            pac_options=pac_options,
            expect_pac=expect_pac,
            expect_pac_attrs=expect_pac_attrs,
            expect_pac_attrs_pac_request=expect_pac_attrs_pac_request,
            expect_requester_sid=expect_requester_sid,
            to_rodc=to_rodc)
        self.check_pre_authentication(rep)

        etype_info2 = kdc_exchange_dict['preauth_etype_info2']

        preauth_key = self.PasswordKey_from_etype_info2(creds,
                                                        etype_info2[0],
                                                        creds.get_kvno())

        ts_enc_padata = self.get_enc_timestamp_pa_data(creds, rep)

        padata = [ts_enc_padata]

        expected_realm = realm.upper()

        expected_sname = self.PrincipalName_create(
            name_type=NT_SRV_INST, names=['krbtgt', realm.upper()])

        rep, kdc_exchange_dict = self._test_as_exchange(
            cname=cname,
            realm=realm,
            sname=sname,
            till=till,
            client_as_etypes=etype,
            expected_error_mode=0,
            expected_crealm=expected_realm,
            expected_cname=cname,
            expected_srealm=expected_realm,
            expected_sname=expected_sname,
            expected_account_name=expected_account_name,
            expected_upn_name=expected_upn_name,
            expected_sid=expected_sid,
            expected_salt=salt,
            expected_flags=expected_flags,
            unexpected_flags=unexpected_flags,
            expected_supported_etypes=expected_etypes,
            etypes=etype,
            padata=padata,
            kdc_options=kdc_options,
            preauth_key=preauth_key,
            ticket_decryption_key=ticket_decryption_key,
            pac_request=pac_request,
            pac_options=pac_options,
            expect_pac=expect_pac,
            expect_pac_attrs=expect_pac_attrs,
            expect_pac_attrs_pac_request=expect_pac_attrs_pac_request,
            expect_requester_sid=expect_requester_sid,
            to_rodc=to_rodc)
        self.check_as_reply(rep)

        ticket_creds = kdc_exchange_dict['rep_ticket_creds']

        self.tkt_cache[cache_key] = ticket_creds

        return ticket_creds

    # Named tuple to contain values of interest when the PAC is decoded.
    PacData = namedtuple(
        "PacData",
        "account_name account_sid logon_name upn domain_name")

    def get_pac_data(self, authorization_data):
        '''Decode the PAC element contained in the authorization-data element
        '''
        account_name = None
        user_sid = None
        logon_name = None
        upn = None
        domain_name = None

        # The PAC data will be wrapped in an AD_IF_RELEVANT element
        ad_if_relevant_elements = (
            x for x in authorization_data if x['ad-type'] == AD_IF_RELEVANT)
        for dt in ad_if_relevant_elements:
            buf = self.der_decode(
                dt['ad-data'], asn1Spec=krb5_asn1.AD_IF_RELEVANT())
            # The PAC data is further wrapped in a AD_WIN2K_PAC element
            for ad in (x for x in buf if x['ad-type'] == AD_WIN2K_PAC):
                pb = ndr_unpack(krb5pac.PAC_DATA, ad['ad-data'])
                for pac in pb.buffers:
                    if pac.type == krb5pac.PAC_TYPE_LOGON_INFO:
                        account_name = (
                            pac.info.info.info3.base.account_name)
                        user_sid = (
                            str(pac.info.info.info3.base.domain_sid)
                            + "-" + str(pac.info.info.info3.base.rid))
                    elif pac.type == krb5pac.PAC_TYPE_LOGON_NAME:
                        logon_name = pac.info.account_name
                    elif pac.type == krb5pac.PAC_TYPE_UPN_DNS_INFO:
                        upn = pac.info.upn_name
                        domain_name = pac.info.dns_domain_name

        return self.PacData(
            account_name,
            user_sid,
            logon_name,
            upn,
            domain_name)

    def decode_service_ticket(self, creds, ticket):
        '''Decrypt and decode a service ticket
        '''

        name = creds.get_username()
        if name.endswith('$'):
            name = name[:-1]
        realm = creds.get_realm()
        salt = "%s.%s@%s" % (name, realm.lower(), realm.upper())

        key = self.PasswordKey_create(
            ticket['enc-part']['etype'],
            creds.get_password(),
            salt,
            ticket['enc-part']['kvno'])

        enc_part = key.decrypt(KU_TICKET, ticket['enc-part']['cipher'])
        enc_ticket_part = self.der_decode(
            enc_part, asn1Spec=krb5_asn1.EncTicketPart())
        return enc_ticket_part

    def get_objectSid(self, samdb, dn):
        ''' Get the objectSID for a DN
            Note: performs an Ldb query.
        '''
        res = samdb.search(dn, scope=SCOPE_BASE, attrs=["objectSID"])
        self.assertTrue(len(res) == 1, "did not get objectSid for %s" % dn)
        sid = samdb.schema_format_value("objectSID", res[0]["objectSID"][0])
        return sid.decode('utf8')

    def add_attribute(self, samdb, dn_str, name, value):
        if isinstance(value, list):
            values = value
        else:
            values = [value]
        flag = ldb.FLAG_MOD_ADD

        dn = ldb.Dn(samdb, dn_str)
        msg = ldb.Message(dn)
        msg[name] = ldb.MessageElement(values, flag, name)
        samdb.modify(msg)

    def modify_attribute(self, samdb, dn_str, name, value):
        if isinstance(value, list):
            values = value
        else:
            values = [value]
        flag = ldb.FLAG_MOD_REPLACE

        dn = ldb.Dn(samdb, dn_str)
        msg = ldb.Message(dn)
        msg[name] = ldb.MessageElement(values, flag, name)
        samdb.modify(msg)

    def create_ccache(self, cname, ticket, enc_part):
        """ Lay out a version 4 on-disk credentials cache, to be read using the
            FILE: protocol.
        """

        field = krb5ccache.DELTATIME_TAG()
        field.kdc_sec_offset = 0
        field.kdc_usec_offset = 0

        v4tag = krb5ccache.V4TAG()
        v4tag.tag = 1
        v4tag.field = field

        v4tags = krb5ccache.V4TAGS()
        v4tags.tag = v4tag
        v4tags.further_tags = b''

        optional_header = krb5ccache.V4HEADER()
        optional_header.v4tags = v4tags

        cname_string = cname['name-string']

        cprincipal = krb5ccache.PRINCIPAL()
        cprincipal.name_type = cname['name-type']
        cprincipal.component_count = len(cname_string)
        cprincipal.realm = ticket['realm']
        cprincipal.components = cname_string

        sname = ticket['sname']
        sname_string = sname['name-string']

        sprincipal = krb5ccache.PRINCIPAL()
        sprincipal.name_type = sname['name-type']
        sprincipal.component_count = len(sname_string)
        sprincipal.realm = ticket['realm']
        sprincipal.components = sname_string

        key = self.EncryptionKey_import(enc_part['key'])

        key_data = key.export_obj()
        keyblock = krb5ccache.KEYBLOCK()
        keyblock.enctype = key_data['keytype']
        keyblock.data = key_data['keyvalue']

        addresses = krb5ccache.ADDRESSES()
        addresses.count = 0
        addresses.data = []

        authdata = krb5ccache.AUTHDATA()
        authdata.count = 0
        authdata.data = []

        # Re-encode the ticket, since it was decoded by another layer.
        ticket_data = self.der_encode(ticket, asn1Spec=krb5_asn1.Ticket())

        authtime = enc_part['authtime']
        starttime = enc_part.get('starttime', authtime)
        endtime = enc_part['endtime']

        cred = krb5ccache.CREDENTIAL()
        cred.client = cprincipal
        cred.server = sprincipal
        cred.keyblock = keyblock
        cred.authtime = self.get_EpochFromKerberosTime(authtime)
        cred.starttime = self.get_EpochFromKerberosTime(starttime)
        cred.endtime = self.get_EpochFromKerberosTime(endtime)

        # Account for clock skew of up to five minutes.
        self.assertLess(cred.authtime - 5 * 60,
                        datetime.now(timezone.utc).timestamp(),
                        "Ticket not yet valid - clocks may be out of sync.")
        self.assertLess(cred.starttime - 5 * 60,
                        datetime.now(timezone.utc).timestamp(),
                        "Ticket not yet valid - clocks may be out of sync.")
        self.assertGreater(cred.endtime - 60 * 60,
                           datetime.now(timezone.utc).timestamp(),
                           "Ticket already expired/about to expire - "
                           "clocks may be out of sync.")

        cred.renew_till = cred.endtime
        cred.is_skey = 0
        cred.ticket_flags = int(enc_part['flags'], 2)
        cred.addresses = addresses
        cred.authdata = authdata
        cred.ticket = ticket_data
        cred.second_ticket = b''

        ccache = krb5ccache.CCACHE()
        ccache.pvno = 5
        ccache.version = 4
        ccache.optional_header = optional_header
        ccache.principal = cprincipal
        ccache.cred = cred

        # Serialise the credentials cache structure.
        result = ndr_pack(ccache)

        # Create a temporary file and write the credentials.
        cachefile = tempfile.NamedTemporaryFile(dir=self.tempdir, delete=False)
        cachefile.write(result)
        cachefile.close()

        return cachefile

    def create_ccache_with_user(self, user_credentials, mach_credentials,
                                service="host", target_name=None, pac=True):
        # Obtain a service ticket authorising the user and place it into a
        # newly created credentials cache file.

        user_name = user_credentials.get_username()
        realm = user_credentials.get_realm()

        cname = self.PrincipalName_create(name_type=NT_PRINCIPAL,
                                          names=[user_name])

        tgt = self.get_tgt(user_credentials)

        # Request a ticket to the host service on the machine account
        ticket = self.get_service_ticket(tgt, mach_credentials,
                                         service=service,
                                         target_name=target_name)

        if not pac:
            ticket = self.modified_ticket(ticket, exclude_pac=True)

        # Write the ticket into a credentials cache file that can be ingested
        # by the main credentials code.
        cachefile = self.create_ccache(cname, ticket.ticket,
                                       ticket.encpart_private)

        # Create a credentials object to reference the credentials cache.
        creds = Credentials()
        creds.set_kerberos_state(MUST_USE_KERBEROS)
        creds.set_username(user_name, SPECIFIED)
        creds.set_realm(realm)
        creds.set_named_ccache(cachefile.name, SPECIFIED, self.get_lp())

        # Return the credentials along with the cache file.
        return (creds, cachefile)
