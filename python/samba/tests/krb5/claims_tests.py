#!/usr/bin/env python3
# Unix SMB/CIFS implementation.
# Copyright (C) Stefan Metzmacher 2020
# Copyright (C) Catalyst.Net Ltd 2022
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

sys.path.insert(0, 'bin/python')
os.environ['PYTHONUNBUFFERED'] = '1'

import re
import ldb

from samba.dcerpc import claims, krb5pac, security
from samba.ndr import ndr_pack

from samba.tests import DynamicTestCase, env_get_var_value
from samba.tests.krb5 import kcrypto
from samba.tests.krb5.kcrypto import Enctype
from samba.tests.krb5.kdc_base_test import GroupType, KDCBaseTest, Principal
from samba.tests.krb5.raw_testcase import Krb5EncryptionKey, RawKerberosTest
from samba.tests.krb5.rfc4120_constants import (
    AES256_CTS_HMAC_SHA1_96,
    ARCFOUR_HMAC_MD5,
    KRB_TGS_REP,
    NT_PRINCIPAL,
)
import samba.tests.krb5.rfc4120_pyasn1 as krb5_asn1

SidType = RawKerberosTest.SidType

global_asn1_print = False
global_hexdump = False


class UnorderedList(tuple):
    def __eq__(self, other):
        if not isinstance(other, UnorderedList):
            raise AssertionError('unexpected comparison attempt')
        return sorted(self) == sorted(other)

    def __hash__(self):
        return hash(tuple(sorted(self)))


@DynamicTestCase
class ClaimsTests(KDCBaseTest):
    # Placeholder objects that represent accounts undergoing testing.
    user = object()
    mach = object()

    # Constants for group SID attributes.
    default_attrs = security.SE_GROUP_DEFAULT_FLAGS
    resource_attrs = default_attrs | security.SE_GROUP_RESOURCE

    asserted_identity = security.SID_AUTHENTICATION_AUTHORITY_ASSERTED_IDENTITY
    compounded_auth = security.SID_COMPOUNDED_AUTHENTICATION

    @classmethod
    def setUpClass(cls):
        super().setUpClass()

        cls._search_iterator = None

    def setUp(self):
        super().setUp()
        self.do_asn1_print = global_asn1_print
        self.do_hexdump = global_hexdump

    def get_sample_dn(self):
        if self._search_iterator is None:
            samdb = self.get_samdb()
            type(self)._search_iterator = samdb.search_iterator()

        return str(next(self._search_iterator).dn)

    def get_binary_dn(self):
        return 'B:8:01010101:' + self.get_sample_dn()

    def setup_claims(self, all_claims):
        expected_claims = {}
        unexpected_claims = set()

        details = {}
        mod_msg = ldb.Message()
        security_desc = None

        for claim in all_claims:
            # Make a copy to avoid modifying the original.
            claim = dict(claim)

            claim_id = self.get_new_username()

            expected = claim.pop('expected', False)
            expected_values = claim.pop('expected_values', None)
            if not expected:
                self.assertIsNone(expected_values,
                                  'claim not expected, '
                                  'but expected values provided')

            values = claim.pop('values', None)
            if values is not None:
                def get_placeholder(val):
                    if val is self.sample_dn:
                        return self.get_sample_dn()
                    elif val is self.binary_dn:
                        return self.get_binary_dn()
                    else:
                        return val

                def ldb_transform(val):
                    if val is True:
                        return 'TRUE'
                    elif val is False:
                        return 'FALSE'
                    elif isinstance(val, int):
                        return str(val)
                    else:
                        return val

                values_type = type(values)
                values = values_type(map(get_placeholder, values))
                transformed_values = values_type(map(ldb_transform, values))

                attribute = claim['attribute']
                if attribute in details:
                    self.assertEqual(details[attribute], transformed_values,
                                     'conflicting values set for attribute')
                details[attribute] = transformed_values

                readable = claim.pop('readable', True)
                if not readable:
                    if security_desc is None:
                        security_desc = security.descriptor()

                    # Deny all read property access to the attribute.
                    ace = security.ace()
                    ace.type = security.SEC_ACE_TYPE_ACCESS_DENIED_OBJECT
                    ace.access_mask = security.SEC_ADS_READ_PROP
                    ace.trustee = security.dom_sid(security.SID_WORLD)
                    ace.object.flags |= security.SEC_ACE_OBJECT_TYPE_PRESENT
                    ace.object.type = self.get_schema_id_guid_from_attribute(
                        attribute)

                    security_desc.dacl_add(ace)

                if expected_values is None:
                    expected_values = values

            mod_values = claim.pop('mod_values', None)
            if mod_values is not None:
                flag = (ldb.FLAG_MOD_REPLACE
                        if values is not None else ldb.FLAG_MOD_ADD)
                mod_msg[attribute] = ldb.MessageElement(mod_values,
                                                        flag,
                                                        attribute)

            if expected:
                self.assertIsNotNone(expected_values,
                                     'expected claim, but no value(s) set')
                value_type = claim['value_type']

                expected_claims[claim_id] = {
                    'source_type': claims.CLAIMS_SOURCE_TYPE_AD,
                    'type': value_type,
                    'values': expected_values,
                }
            else:
                unexpected_claims.add(claim_id)

            self.create_claim(claim_id, **claim)

        if security_desc is not None:
            self.assertNotIn('nTSecurityDescriptor', details)
            details['nTSecurityDescriptor'] = ndr_pack(security_desc)

        return details, mod_msg, expected_claims, unexpected_claims

    def modify_pac_remove_client_claims(self, pac):
        pac_buffers = pac.buffers
        for pac_buffer in pac_buffers:
            if pac_buffer.type == krb5pac.PAC_TYPE_CLIENT_CLAIMS_INFO:
                pac.num_buffers -= 1
                pac_buffers.remove(pac_buffer)

                break
        else:
            self.fail('expected client claims in PAC')

        pac.buffers = pac_buffers

        return pac

    def remove_client_claims(self, ticket):
        return self.modified_ticket(
            ticket,
            modify_pac_fn=self.modify_pac_remove_client_claims,
            checksum_keys=self.get_krbtgt_checksum_key())

    def remove_client_claims_tgt_from_rodc(self, ticket):
        rodc_krbtgt_creds = self.get_mock_rodc_krbtgt_creds()
        rodc_krbtgt_key = self.TicketDecryptionKey_from_creds(
            rodc_krbtgt_creds)

        checksum_keys = {
            krb5pac.PAC_TYPE_KDC_CHECKSUM: rodc_krbtgt_key
        }

        return self.modified_ticket(
            ticket,
            new_ticket_key=rodc_krbtgt_key,
            modify_pac_fn=self.modify_pac_remove_client_claims,
            checksum_keys=checksum_keys)

    def test_tgs_claims(self):
        self.run_tgs_test(remove_claims=False, to_krbtgt=False)

    def test_tgs_claims_remove_claims(self):
        self.run_tgs_test(remove_claims=True, to_krbtgt=False)

    def test_tgs_claims_to_krbtgt(self):
        self.run_tgs_test(remove_claims=False, to_krbtgt=True)

    def test_tgs_claims_remove_claims_to_krbtgt(self):
        self.run_tgs_test(remove_claims=True, to_krbtgt=True)

    def test_delegation_claims(self):
        self.run_delegation_test(remove_claims=False)

    def test_delegation_claims_remove_claims(self):
        self.run_delegation_test(remove_claims=True)

    def test_rodc_issued_claims_modify(self):
        self.run_rodc_tgs_test(remove_claims=False, delete_claim=False)

    def test_rodc_issued_claims_delete(self):
        self.run_rodc_tgs_test(remove_claims=False, delete_claim=True)

    def test_rodc_issued_claims_remove_claims_modify(self):
        self.run_rodc_tgs_test(remove_claims=True, delete_claim=False)

    def test_rodc_issued_claims_remove_claims_delete(self):
        self.run_rodc_tgs_test(remove_claims=True, delete_claim=True)

    def test_rodc_issued_device_claims_modify(self):
        self.run_device_rodc_tgs_test(remove_claims=False, delete_claim=False)

    def test_rodc_issued_device_claims_delete(self):
        self.run_device_rodc_tgs_test(remove_claims=False, delete_claim=True)

    def test_rodc_issued_device_claims_remove_claims_modify(self):
        self.run_device_rodc_tgs_test(remove_claims=True, delete_claim=False)

    def test_rodc_issued_device_claims_remove_claims_delete(self):
        self.run_device_rodc_tgs_test(remove_claims=True, delete_claim=True)

    # Create a user account with an applicable claim for the 'middleName'
    # attribute. After obtaining a TGT, from which we optionally remove the
    # claims, change the middleName attribute values for the account in the
    # database to a different value. By which we may observe, when examining
    # the reply to our following Kerberos TGS request, whether the claims
    # contained therein are taken directly from the ticket, or obtained fresh
    # from the database.
    def run_tgs_test(self, remove_claims, to_krbtgt):
        samdb = self.get_samdb()
        user_creds, user_dn = self.create_account(samdb,
                                                  self.get_new_username(),
                                                  additional_details={
                                                      'middleName': 'foo',
                                                  })

        claim_id = self.get_new_username()
        self.create_claim(claim_id,
                          enabled=True,
                          attribute='middleName',
                          single_valued=True,
                          source_type='AD',
                          for_classes=['user'],
                          value_type=claims.CLAIM_TYPE_STRING)

        expected_claims = {
            claim_id: {
                'source_type': claims.CLAIMS_SOURCE_TYPE_AD,
                'type': claims.CLAIM_TYPE_STRING,
                'values': ('foo',),
            },
        }

        # Get a TGT for the user.
        tgt = self.get_tgt(user_creds, expect_pac=True,
                           expect_client_claims=True,
                           expected_client_claims=expected_claims)

        if remove_claims:
            tgt = self.remove_client_claims(tgt)

        # Change the value of the attribute used for the claim.
        msg = ldb.Message(ldb.Dn(samdb, user_dn))
        msg['middleName'] = ldb.MessageElement('bar',
                                               ldb.FLAG_MOD_REPLACE,
                                               'middleName')
        samdb.modify(msg)

        if to_krbtgt:
            target_creds = self.get_krbtgt_creds()
            sname = self.get_krbtgt_sname()
        else:
            target_creds = self.get_service_creds()
            sname = None

        # Get a service ticket for the user. The claim value should not have
        # changed, indicating that the client claims are propagated straight
        # through.
        self.get_service_ticket(
            tgt, target_creds,
            sname=sname,
            expect_pac=True,
            expect_client_claims=not remove_claims,
            expected_client_claims=(expected_claims
                                    if not remove_claims else None))

    # Perform a test similar to that preceeding. This time, create both a user
    # and a computer account, each having an applicable claim. After obtaining
    # tickets, from which the claims are optionally removed, change the claim
    # attribute of each account to a different value. Then perform constrained
    # delegation with the user's service ticket, verifying that the user's
    # claims are carried into the resulting ticket.
    def run_delegation_test(self, remove_claims):
        service_creds = self.get_service_creds()
        service_spn = service_creds.get_spn()

        user_name = self.get_new_username()
        mach_name = self.get_new_username()

        samdb = self.get_samdb()
        user_creds, user_dn = self.create_account(
            samdb,
            user_name,
            self.AccountType.USER,
            additional_details={
                'middleName': 'user_old',
            })
        mach_creds, mach_dn = self.create_account(
            samdb,
            mach_name,
            self.AccountType.COMPUTER,
            spn=f'host/{mach_name}',
            additional_details={
                'middleName': 'mach_old',
                'msDS-AllowedToDelegateTo': service_spn,
            })

        claim_id = self.get_new_username()
        self.create_claim(claim_id,
                          enabled=True,
                          attribute='middleName',
                          single_valued=True,
                          source_type='AD',
                          for_classes=['user', 'computer'],
                          value_type=claims.CLAIM_TYPE_STRING)

        options = 'forwardable'
        expected_flags = krb5_asn1.TicketFlags(options)

        expected_claims_user = {
            claim_id: {
                'source_type': claims.CLAIMS_SOURCE_TYPE_AD,
                'type': claims.CLAIM_TYPE_STRING,
                'values': ('user_old',),
            },
        }
        expected_claims_mach = {
            claim_id: {
                'source_type': claims.CLAIMS_SOURCE_TYPE_AD,
                'type': claims.CLAIM_TYPE_STRING,
                'values': ('mach_old',),
            },
        }

        user_tgt = self.get_tgt(user_creds,
                                kdc_options=options,
                                expect_pac=True,
                                expected_flags=expected_flags,
                                expect_client_claims=True,
                                expected_client_claims=expected_claims_user)
        user_ticket = self.get_service_ticket(
            user_tgt,
            mach_creds,
            kdc_options=options,
            expect_pac=True,
            expected_flags=expected_flags,
            expect_client_claims=True,
            expected_client_claims=expected_claims_user)

        mach_tgt = self.get_tgt(mach_creds,
                                expect_pac=True,
                                expect_client_claims=True,
                                expected_client_claims=expected_claims_mach)

        if remove_claims:
            user_ticket = self.remove_client_claims(user_ticket)
            mach_tgt = self.remove_client_claims(mach_tgt)

        # Change the value of the attribute used for the user claim.
        msg = ldb.Message(ldb.Dn(samdb, user_dn))
        msg['middleName'] = ldb.MessageElement('user_new',
                                               ldb.FLAG_MOD_REPLACE,
                                               'middleName')
        samdb.modify(msg)

        # Change the value of the attribute used for the machine claim.
        msg = ldb.Message(ldb.Dn(samdb, mach_dn))
        msg['middleName'] = ldb.MessageElement('mach_new',
                                               ldb.FLAG_MOD_REPLACE,
                                               'middleName')
        samdb.modify(msg)

        additional_tickets = [user_ticket.ticket]
        options = str(krb5_asn1.KDCOptions('cname-in-addl-tkt'))

        user_realm = user_creds.get_realm()
        user_cname = self.PrincipalName_create(name_type=NT_PRINCIPAL,
                                               names=[user_name])

        user_sid = self.get_objectSid(samdb, user_dn)

        mach_realm = mach_creds.get_realm()

        service_name = service_creds.get_username()[:-1]
        service_realm = service_creds.get_realm()
        service_sname = self.PrincipalName_create(name_type=NT_PRINCIPAL,
                                                  names=['host', service_name])
        service_decryption_key = self.TicketDecryptionKey_from_creds(
            service_creds)
        service_etypes = service_creds.tgs_supported_enctypes

        expected_proxy_target = service_creds.get_spn()
        expected_transited_services = [f'host/{mach_name}@{mach_realm}']

        authenticator_subkey = self.RandomKey(Enctype.AES256)

        etypes = (AES256_CTS_HMAC_SHA1_96, ARCFOUR_HMAC_MD5)

        # The user's claims are propagated into the new ticket, while the
        # machine's claims are dispensed with.
        expected_claims = expected_claims_user if not remove_claims else None

        # Perform constrained delegation.
        kdc_exchange_dict = self.tgs_exchange_dict(
            expected_crealm=user_realm,
            expected_cname=user_cname,
            expected_srealm=service_realm,
            expected_sname=service_sname,
            expected_account_name=user_name,
            expected_sid=user_sid,
            expected_supported_etypes=service_etypes,
            ticket_decryption_key=service_decryption_key,
            check_rep_fn=self.generic_check_kdc_rep,
            check_kdc_private_fn=self.generic_check_kdc_private,
            tgt=mach_tgt,
            authenticator_subkey=authenticator_subkey,
            kdc_options=options,
            expected_proxy_target=expected_proxy_target,
            expected_transited_services=expected_transited_services,
            expect_client_claims=not remove_claims,
            expected_client_claims=expected_claims,
            expect_device_claims=False,
            expect_pac=True)

        rep = self._generic_kdc_exchange(kdc_exchange_dict,
                                         cname=None,
                                         realm=service_realm,
                                         sname=service_sname,
                                         etypes=etypes,
                                         additional_tickets=additional_tickets)
        self.check_reply(rep, KRB_TGS_REP)

    def run_rodc_tgs_test(self, remove_claims, delete_claim):
        samdb = self.get_samdb()
        # Create a user account permitted to replicate to the RODC.
        user_creds = self.get_cached_creds(
            account_type=self.AccountType.USER,
            opts={
                # Set the value of the claim attribute.
                'additional_details': (('middleName', 'foo'),),
                'allowed_replication_mock': True,
                'revealed_to_mock_rodc': True,
            },
            use_cache=False)
        user_dn = user_creds.get_dn()

        # Create a claim that applies to the user.
        claim_id = self.get_new_username()
        self.create_claim(claim_id,
                          enabled=True,
                          attribute='middleName',
                          single_valued=True,
                          source_type='AD',
                          for_classes=['user'],
                          value_type=claims.CLAIM_TYPE_STRING)

        expected_claims = {
            claim_id: {
                'source_type': claims.CLAIMS_SOURCE_TYPE_AD,
                'type': claims.CLAIM_TYPE_STRING,
                'values': ('foo',),
            },
        }

        # Get a TGT for the user.
        tgt = self.get_tgt(user_creds, expect_pac=True,
                           expect_client_claims=True,
                           expected_client_claims=expected_claims)

        # Modify the TGT to be issued by an RODC. Optionally remove the client
        # claims.
        if remove_claims:
            tgt = self.remove_client_claims_tgt_from_rodc(tgt)
        else:
            tgt = self.issued_by_rodc(tgt)

        # Modify or delete the value of the attribute used for the claim. Modify
        # our test expectations accordingly.
        msg = ldb.Message(user_dn)
        if delete_claim:
            msg['middleName'] = ldb.MessageElement([],
                                                   ldb.FLAG_MOD_DELETE,
                                                   'middleName')
            expected_claims = None
            unexpected_claims = {claim_id}
        else:
            msg['middleName'] = ldb.MessageElement('bar',
                                                   ldb.FLAG_MOD_REPLACE,
                                                   'middleName')
            expected_claims = {
                claim_id: {
                    'source_type': claims.CLAIMS_SOURCE_TYPE_AD,
                    'type': claims.CLAIM_TYPE_STRING,
                    'values': ('bar',),
                },
            }
            unexpected_claims = None
        samdb.modify(msg)

        target_creds = self.get_service_creds()

        # Get a service ticket for the user. The claim value should have
        # changed, indicating that the client claims have been regenerated or
        # removed, depending on whether the corresponding attribute is still
        # present on the account.
        self.get_service_ticket(
            tgt, target_creds,
            expect_pac=True,
            # Expect the CLIENT_CLAIMS_INFO PAC buffer. It may be empty.
            expect_client_claims=True,
            expected_client_claims=expected_claims,
            unexpected_client_claims=unexpected_claims)

    def run_device_rodc_tgs_test(self, remove_claims, delete_claim):
        samdb = self.get_samdb()

        # Create the user account.
        user_creds = self.get_cached_creds(
            account_type=self.AccountType.USER)
        user_name = user_creds.get_username()

        # Create a machine account permitted to replicate to the RODC.
        mach_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER,
            opts={
                # Set the value of the claim attribute.
                'additional_details': (('middleName', 'foo'),),
                'allowed_replication_mock': True,
                'revealed_to_mock_rodc': True,
            },
            use_cache=False)
        mach_dn = mach_creds.get_dn()

        # Create a claim that applies to the computer.
        claim_id = self.get_new_username()
        self.create_claim(claim_id,
                          enabled=True,
                          attribute='middleName',
                          single_valued=True,
                          source_type='AD',
                          for_classes=['computer'],
                          value_type=claims.CLAIM_TYPE_STRING)

        expected_claims = {
            claim_id: {
                'source_type': claims.CLAIMS_SOURCE_TYPE_AD,
                'type': claims.CLAIM_TYPE_STRING,
                'values': ('foo',),
            },
        }

        # Get a TGT for the user.
        user_tgt = self.get_tgt(user_creds)

        # Get a TGT for the computer.
        mach_tgt = self.get_tgt(mach_creds, expect_pac=True,
                                expect_client_claims=True,
                                expected_client_claims=expected_claims)

        # Modify the computer's TGT to be issued by an RODC. Optionally remove
        # the client claims.
        if remove_claims:
            mach_tgt = self.remove_client_claims_tgt_from_rodc(mach_tgt)
        else:
            mach_tgt = self.issued_by_rodc(mach_tgt)

        # Modify or delete the value of the attribute used for the claim. Modify
        # our test expectations accordingly.
        msg = ldb.Message(mach_dn)
        if delete_claim:
            msg['middleName'] = ldb.MessageElement([],
                                                   ldb.FLAG_MOD_DELETE,
                                                   'middleName')
            expected_claims = None
            unexpected_claims = {claim_id}
        else:
            msg['middleName'] = ldb.MessageElement('bar',
                                                   ldb.FLAG_MOD_REPLACE,
                                                   'middleName')
            expected_claims = {
                claim_id: {
                    'source_type': claims.CLAIMS_SOURCE_TYPE_AD,
                    'type': claims.CLAIM_TYPE_STRING,
                    'values': ('bar',),
                },
            }
            unexpected_claims = None
        samdb.modify(msg)

        subkey = self.RandomKey(user_tgt.session_key.etype)

        armor_subkey = self.RandomKey(subkey.etype)
        explicit_armor_key = self.generate_armor_key(armor_subkey,
                                                     mach_tgt.session_key)
        armor_key = kcrypto.cf2(explicit_armor_key.key,
                                subkey.key,
                                b'explicitarmor',
                                b'tgsarmor')
        armor_key = Krb5EncryptionKey(armor_key, None)

        target_creds = self.get_service_creds()
        target_name = target_creds.get_username()
        if target_name[-1] == '$':
            target_name = target_name[:-1]

        sname = self.PrincipalName_create(name_type=NT_PRINCIPAL,
                                          names=['host', target_name])
        srealm = target_creds.get_realm()

        decryption_key = self.TicketDecryptionKey_from_creds(
            target_creds)

        target_supported_etypes = target_creds.tgs_supported_enctypes

        etypes = (AES256_CTS_HMAC_SHA1_96, ARCFOUR_HMAC_MD5)

        kdc_options = '0'
        pac_options = '1'  # claims support

        # Perform a TGS-REQ for the user. The device claim value should have
        # changed, indicating that the computer's client claims have been
        # regenerated or removed, depending on whether the corresponding
        # attribute is still present on the account.

        kdc_exchange_dict = self.tgs_exchange_dict(
            expected_crealm=user_tgt.crealm,
            expected_cname=user_tgt.cname,
            expected_srealm=srealm,
            expected_sname=sname,
            expected_account_name=user_name,
            ticket_decryption_key=decryption_key,
            generate_fast_fn=self.generate_simple_fast,
            generate_fast_armor_fn=self.generate_ap_req,
            check_rep_fn=self.generic_check_kdc_rep,
            check_kdc_private_fn=self.generic_check_kdc_private,
            tgt=user_tgt,
            armor_key=armor_key,
            armor_tgt=mach_tgt,
            armor_subkey=armor_subkey,
            pac_options=pac_options,
            authenticator_subkey=subkey,
            kdc_options=kdc_options,
            expect_pac=True,
            expected_supported_etypes=target_supported_etypes,
            # Expect the DEVICE_CLAIMS_INFO PAC buffer. It may be empty.
            expect_device_claims=True,
            expected_device_claims=expected_claims,
            unexpected_device_claims=unexpected_claims)

        rep = self._generic_kdc_exchange(kdc_exchange_dict,
                                         cname=None,
                                         realm=srealm,
                                         sname=sname,
                                         etypes=etypes)
        self.check_reply(rep, KRB_TGS_REP)

    @staticmethod
    def freeze(m):
        return frozenset((k, v) for k, v in m.items())

    @classmethod
    def setUpDynamicTestCases(cls):
        FILTER = env_get_var_value('FILTER', allow_missing=True)
        for case in cls.cases:
            name = case.pop('name')
            if FILTER and not re.search(FILTER, name):
                continue
            name = re.sub(r'\W+', '_', name)

            # Run tests making requests both to the krbtgt and to our own
            # account.
            cls.generate_dynamic_test('test_claims', name,
                                      dict(case), False)
            cls.generate_dynamic_test('test_claims', name + '_to_self',
                                      dict(case), True)

        for case in cls.device_claims_cases:
            name = case.pop('test')
            if FILTER and not re.search(FILTER, name):
                continue
            name = re.sub(r'\W+', '_', name)

            cls.generate_dynamic_test('test_device_claims', name,
                                      dict(case))

    def _test_claims_with_args(self, case, to_self):
        account_class = case.pop('class')
        if account_class == 'user':
            account_type = self.AccountType.USER
        elif account_class == 'computer':
            account_type = self.AccountType.COMPUTER
        else:
            self.fail(f'Unknown class "{account_class}"')

        all_claims = case.pop('claims')
        (details, mod_msg,
         expected_claims,
         unexpected_claims) = self.setup_claims(all_claims)
        self.assertFalse(mod_msg,
                         'mid-test modifications not supported in this test')
        creds = self.get_cached_creds(
            account_type=account_type,
            opts={
                'additional_details': self.freeze(details),
            })

        # Whether to specify claims support in PA-PAC-OPTIONS.
        pac_options_claims = case.pop('pac-options:claims-support', None)

        self.assertFalse(case, 'unexpected parameters in testcase')

        if pac_options_claims is None:
            pac_options_claims = True

        if to_self:
            service_creds = self.get_service_creds()
            sname = self.PrincipalName_create(
                name_type=NT_PRINCIPAL,
                names=[service_creds.get_username()])
            ticket_etype = Enctype.RC4
        else:
            service_creds = None
            sname = None
            ticket_etype = None

        if pac_options_claims:
            pac_options = '1'  # claims support
        else:
            pac_options = '0'  # no claims support

        self.get_tgt(creds,
                     sname=sname,
                     target_creds=service_creds,
                     ticket_etype=ticket_etype,
                     pac_options=pac_options,
                     expect_pac=True,
                     expect_client_claims=True,
                     expected_client_claims=expected_claims or None,
                     unexpected_client_claims=unexpected_claims or None)

    sample_dn = object()
    binary_dn = object()
    security_descriptor = (b'\x01\x00\x04\x95\x14\x00\x00\x00\x00\x00\x00\x00'
                           b'\x00\x00\x00\x00$\x00\x00\x00\x01\x02\x00\x00\x00'
                           b'\x00\x00\x05 \x00\x00\x00 \x02\x00\x00\x04\x00'
                           b'\x1c\x00\x01\x00\x00\x00\x00\x1f\x14\x00\xff\x01'
                           b'\x0f\xf0\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00'
                           b'\x00\x00')

    cases = [
        {
            'name': 'no claims',
            'claims': [],
            'class': 'user',
        },
        {
            'name': 'simple AD-sourced claim',
            'claims': [
                {
                    # 2.5.5.12
                    'enabled': True,
                    'attribute': 'carLicense',
                    'single_valued': True,
                    'source_type': 'AD',
                    'for_classes': ['user'],
                    'value_type': claims.CLAIM_TYPE_STRING,
                    'values': ('foo',),
                    'expected': True,
                },
            ],
            'class': 'user',
        },
        {
            'name': 'no claims support in pac options',
            'claims': [
                {
                    # 2.5.5.12
                    'enabled': True,
                    'attribute': 'carLicense',
                    'single_valued': True,
                    'source_type': 'AD',
                    'for_classes': ['user'],
                    'value_type': claims.CLAIM_TYPE_STRING,
                    'values': ('foo',),
                    # We still get claims in the PAC even if we don't specify
                    # claims support in PA-PAC-OPTIONS.
                    'expected': True,
                },
            ],
            'class': 'user',
            'pac-options:claims-support': False,
        },
        {
            'name': 'deny RP',
            'claims': [
                {
                    # 2.5.5.12
                    'enabled': True,
                    'attribute': 'carLicense',
                    'single_valued': True,
                    'source_type': 'AD',
                    'for_classes': ['user'],
                    'value_type': claims.CLAIM_TYPE_STRING,
                    'values': ('foo',),
                    # Deny read access to the attribute. It still shows up in
                    # the claim.
                    'readable': False,
                    'expected': True,
                },
            ],
            'class': 'user',
        },
        {
            # Note: The order of these DNs may differ on Windows.
            'name': 'dn string syntax',
            'claims': [
                {
                    # 2.5.5.1
                    'enabled': True,
                    'attribute': 'msDS-AuthenticatedAtDC',
                    'single_valued': True,
                    'source_type': 'AD',
                    'for_classes': ['user'],
                    'value_type': claims.CLAIM_TYPE_STRING,
                    'values': UnorderedList([sample_dn, sample_dn, sample_dn]),
                    'expected': True,
                },
            ],
            'class': 'user',
        },
        {
            'name': 'dn string syntax, wrong value type',
            'claims': [
                {
                    # 2.5.5.1
                    'enabled': True,
                    'attribute': 'msDS-AuthenticatedAtDC',
                    'single_valued': True,
                    'source_type': 'AD',
                    'for_classes': ['user'],
                    'value_type': claims.CLAIM_TYPE_BOOLEAN,
                    'values': UnorderedList([sample_dn, sample_dn, sample_dn]),
                },
            ],
            'class': 'user',
        },
        {
            'name': 'oid syntax',
            'claims': [
                {
                    # 2.5.5.2
                    'enabled': True,
                    'attribute': 'objectClass',
                    'single_valued': True,
                    'source_type': 'AD',
                    'for_classes': ['user'],
                    'value_type': claims.CLAIM_TYPE_UINT64,
                    'expected_values': [655369, 65543, 65542, 65536],
                    'expected': True,
                },
            ],
            'class': 'user',
        },
        {
            'name': 'oid syntax 2',
            'claims': [
                {
                    # 2.5.5.2
                    'enabled': True,
                    'attribute': 'objectClass',
                    'single_valued': True,
                    'source_type': 'AD',
                    'for_classes': ['computer'],
                    'value_type': claims.CLAIM_TYPE_UINT64,
                    'expected_values': [196638, 655369, 65543, 65542, 65536],
                    'expected': True,
                },
            ],
            'class': 'computer',
        },
        {
            'name': 'oid syntax, wrong value type',
            'claims': [
                {
                    # 2.5.5.2
                    'enabled': True,
                    'attribute': 'objectClass',
                    'single_valued': True,
                    'source_type': 'AD',
                    'for_classes': ['user'],
                    'value_type': claims.CLAIM_TYPE_INT64,
                },
            ],
            'class': 'user',
        },
        {
            'name': 'boolean syntax, true',
            'claims': [
                {
                    # 2.5.5.8
                    'enabled': True,
                    'attribute': 'msTSAllowLogon',
                    'single_valued': True,
                    'source_type': 'AD',
                    'for_classes': ['user'],
                    'value_type': claims.CLAIM_TYPE_BOOLEAN,
                    'values': (True,),
                    'expected': True,
                },
            ],
            'class': 'user',
        },
        {
            'name': 'boolean syntax, false',
            'claims': [
                {
                    # 2.5.5.8
                    'enabled': True,
                    'attribute': 'msTSAllowLogon',
                    'single_valued': True,
                    'source_type': 'AD',
                    'for_classes': ['user'],
                    'value_type': claims.CLAIM_TYPE_BOOLEAN,
                    'values': (False,),
                    'expected': True,
                },
            ],
            'class': 'user',
        },
        {
            'name': 'boolean syntax, wrong value type',
            'claims': [
                {
                    # 2.5.5.8
                    'enabled': True,
                    'attribute': 'msTSAllowLogon',
                    'single_valued': True,
                    'source_type': 'AD',
                    'for_classes': ['user'],
                    'value_type': claims.CLAIM_TYPE_STRING,
                    'values': (True,),
                },
            ],
            'class': 'user',
        },
        {
            # This test fails on Windows, which for an integer syntax claim
            # issues corrupt data shifted four bytes to the right.
            'name': 'integer syntax',
            'claims': [
                {
                    # 2.5.5.9
                    'enabled': True,
                    'attribute': 'localeID',
                    'single_valued': True,
                    'source_type': 'AD',
                    'for_classes': ['user'],
                    'value_type': claims.CLAIM_TYPE_INT64,
                    'values': (3, 42, -999, 1000, 20000),
                    'expected': True,
                },
            ],
            'class': 'user',
        },
        {
            # This test fails on Windows, which for an integer syntax claim
            # issues corrupt data that cannot be NDR unpacked.
            'name': 'integer syntax, duplicate claim',
            'claims': [
                {
                    # 2.5.5.9
                    'enabled': True,
                    'attribute': 'localeID',
                    'single_valued': True,
                    'source_type': 'AD',
                    'for_classes': ['user'],
                    'value_type': claims.CLAIM_TYPE_INT64,
                    'values': (3, 42, -999, 1000, 20000),
                    'expected': True,
                },
            ] * 2,  # Create two integer syntax claims.
            'class': 'user',
        },
        {
            'name': 'integer syntax, wrong value type',
            'claims': [
                {
                    # 2.5.5.9
                    'enabled': True,
                    'attribute': 'localeID',
                    'single_valued': True,
                    'source_type': 'AD',
                    'for_classes': ['user'],
                    'value_type': claims.CLAIM_TYPE_UINT64,
                    'values': (3, 42, -999, 1000),
                },
            ],
            'class': 'user',
        },
        {
            'name': 'security descriptor syntax',
            'claims': [
                {
                    # 2.5.5.15
                    'enabled': True,
                    'attribute': 'msDS-AllowedToActOnBehalfOfOtherIdentity',
                    'single_valued': True,
                    'source_type': 'AD',
                    'for_classes': ['computer'],
                    'value_type': claims.CLAIM_TYPE_STRING,
                    'values': (security_descriptor,),
                    'expected_values': (
                        'O:BAD:PARAI(A;OICINPIOID;CCDCLCSWRPWPDTLOCRSDRCWDWOGAGXGWGR;;;S-1-0-0)',
                    ),
                    'expected': True,
                },
            ],
            'class': 'computer',
        },
        {
            'name': 'security descriptor syntax, wrong value type',
            'claims': [
                {
                    # 2.5.5.15
                    'enabled': True,
                    'attribute': 'msDS-AllowedToActOnBehalfOfOtherIdentity',
                    'single_valued': True,
                    'source_type': 'AD',
                    'for_classes': ['computer'],
                    'value_type': claims.CLAIM_TYPE_UINT64,
                    'values': (security_descriptor,),
                },
            ],
            'class': 'computer',
        },
        {
            'name': 'case insensitive string syntax (invalid)',
            'claims': [
                {
                    # 2.5.5.4
                    'enabled': True,
                    'attribute': 'networkAddress',
                    'single_valued': True,
                    'source_type': 'AD',
                    'for_classes': ['user'],
                    'value_type': claims.CLAIM_TYPE_STRING,
                    'values': ('foo', 'bar'),
                },
            ],
            'class': 'user',
        },
        {
            'name': 'printable string syntax (invalid)',
            'claims': [
                {
                    # 2.5.5.5
                    'enabled': True,
                    'attribute': 'displayNamePrintable',
                    'single_valued': True,
                    'source_type': 'AD',
                    'for_classes': ['user'],
                    'value_type': claims.CLAIM_TYPE_STRING,
                    'values': ('foo',),
                },
            ],
            'class': 'user',
        },
        {
            'name': 'numeric string syntax (invalid)',
            'claims': [
                {
                    # 2.5.5.6
                    'enabled': True,
                    'attribute': 'internationalISDNNumber',
                    'single_valued': True,
                    'source_type': 'AD',
                    'for_classes': ['user'],
                    'value_type': claims.CLAIM_TYPE_STRING,
                    'values': ('foo', 'bar'),
                },
            ],
            'class': 'user',
        },
        {
            'name': 'dn binary syntax (invalid)',
            'claims': [
                {
                    # 2.5.5.7
                    'enabled': True,
                    'attribute': 'msDS-RevealedUsers',
                    'single_valued': True,
                    'source_type': 'AD',
                    'for_classes': ['user'],
                    'value_type': claims.CLAIM_TYPE_STRING,
                    'values': (binary_dn, binary_dn, binary_dn),
                },
            ],
            'class': 'computer',
        },
        {
            'name': 'octet string syntax (invalid)',
            'claims': [
                {
                    # 2.5.5.10
                    'enabled': True,
                    'attribute': 'jpegPhoto',
                    'single_valued': True,
                    'source_type': 'AD',
                    'for_classes': ['user'],
                    'value_type': claims.CLAIM_TYPE_STRING,
                    'values': ('foo', 'bar'),
                },
            ],
            'class': 'user',
        },
        {
            'name': 'utc time syntax (invalid)',
            'claims': [
                {
                    # 2.5.5.11
                    'enabled': True,
                    'attribute': 'msTSExpireDate2',
                    'single_valued': True,
                    'source_type': 'AD',
                    'for_classes': ['user'],
                    'value_type': claims.CLAIM_TYPE_STRING,
                    'values': ('19700101000000.0Z',),
                },
            ],
            'class': 'user',
        },
        {
            'name': 'access point syntax (invalid)',
            'claims': [
                {
                    # 2.5.5.17
                    'enabled': True,
                    'attribute': 'mS-DS-CreatorSID',
                    'single_valued': True,
                    'source_type': 'AD',
                    'for_classes': ['user'],
                    'value_type': claims.CLAIM_TYPE_STRING,
                },
            ],
            'class': 'user',
        },
        {
            'name': 'no value set',
            'claims': [
                {
                    # 2.5.5.12
                    'enabled': True,
                    'attribute': 'carLicense',
                    'single_valued': True,
                    'source_type': 'AD',
                    'for_classes': ['user'],
                    'value_type': claims.CLAIM_TYPE_STRING,
                },
            ],
            'class': 'user',
        },
        {
            'name': 'multi-valued claim',
            'claims': [
                {
                    # 2.5.5.12
                    'enabled': True,
                    'attribute': 'carLicense',
                    'single_valued': True,
                    'source_type': 'AD',
                    'for_classes': ['user'],
                    'value_type': claims.CLAIM_TYPE_STRING,
                    'values': ('foo', 'bar', 'baz'),
                    'expected': True,
                },
            ],
            'class': 'user',
        },
        {
            'name': 'missing attribute',
            'claims': [
                {
                    'enabled': True,
                    'single_valued': True,
                    'source_type': 'AD',
                    'for_classes': ['user'],
                    'value_type': claims.CLAIM_TYPE_STRING,
                },
            ],
            'class': 'user',
        },
        {
            'name': 'invalid attribute',
            'claims': [
                {
                    # 2.5.5.10
                    'enabled': True,
                    'attribute': 'unicodePwd',
                    'single_valued': True,
                    'source_type': 'AD',
                    'for_classes': ['user'],
                    'value_type': claims.CLAIM_TYPE_STRING,
                },
            ],
            'class': 'user',
        },
        {
            'name': 'incorrect value type',
            'claims': [
                {
                    # 2.5.5.12
                    'enabled': True,
                    'attribute': 'carLicense',
                    'single_valued': True,
                    'source_type': 'AD',
                    'for_classes': ['user'],
                    'value_type': claims.CLAIM_TYPE_INT64,
                    'values': ('foo',),
                },
            ],
            'class': 'user',
        },
        {
            'name': 'invalid value type',
            'claims': [
                {
                    # 2.5.5.12
                    'enabled': True,
                    'attribute': 'carLicense',
                    'single_valued': True,
                    'source_type': 'AD',
                    'for_classes': ['user'],
                    'value_type': 0,
                    'values': ('foo',),
                },
            ],
            'class': 'user',
        },
        {
            'name': 'missing value type',
            'claims': [
                {
                    # 2.5.5.12
                    'enabled': True,
                    'attribute': 'carLicense',
                    'single_valued': True,
                    'source_type': 'AD',
                    'for_classes': ['user'],
                    'values': ('foo',),
                },
            ],
            'class': 'user',
        },
        {
            'name': 'string syntax, duplicate claim',
            'claims': [
                {
                    # 2.5.5.12
                    'enabled': True,
                    'attribute': 'carLicense',
                    'single_valued': True,
                    'source_type': 'AD',
                    'for_classes': ['user'],
                    'value_type': claims.CLAIM_TYPE_STRING,
                    'values': ('foo',),
                    'expected': True,
                },
            ] * 2,  # Create two string syntax claims.
            'class': 'user',
        },
        {
            'name': 'multiple claims',
            'claims': [
                {
                    # 2.5.5.12
                    'enabled': True,
                    'attribute': 'carLicense',
                    'single_valued': True,
                    'source_type': 'AD',
                    'for_classes': ['user'],
                    'value_type': claims.CLAIM_TYPE_STRING,
                    'values': ('foo', 'bar', 'baz'),
                    'expected': True,
                },
                {
                    # 2.5.5.8
                    'enabled': True,
                    'attribute': 'msTSAllowLogon',
                    'single_valued': True,
                    'source_type': 'AD',
                    'for_classes': ['user'],
                    'value_type': claims.CLAIM_TYPE_BOOLEAN,
                    'values': (True,),
                    'expected': True,
                },
            ],
            'class': 'user',
        },
        {
            'name': 'case difference for source type',
            'claims': [
                {
                    # 2.5.5.12
                    'enabled': True,
                    'attribute': 'carLicense',
                    'single_valued': True,
                    'source_type': 'ad',
                    'for_classes': ['user'],
                    'value_type': claims.CLAIM_TYPE_STRING,
                    'values': ('foo',),
                    'expected': True,
                },
            ],
            'class': 'user',
        },
        {
            'name': 'unhandled source type',
            'claims': [
                {
                    # 2.5.5.12
                    'enabled': True,
                    'attribute': 'carLicense',
                    'single_valued': True,
                    'source_type': '<unknown>',
                    'for_classes': ['user'],
                    'value_type': claims.CLAIM_TYPE_STRING,
                    'values': ('foo',),
                },
            ],
            'class': 'user',
        },
        {
            'name': 'disabled claim',
            'claims': [
                {
                    # 2.5.5.12
                    'enabled': False,
                    'attribute': 'carLicense',
                    'single_valued': True,
                    'source_type': 'AD',
                    'for_classes': ['user'],
                    'value_type': claims.CLAIM_TYPE_STRING,
                    'values': ('foo',),
                },
            ],
            'class': 'user',
        },
        {
            'name': 'not enabled claim',
            'claims': [
                {
                    # 2.5.5.12
                    'attribute': 'carLicense',
                    'single_valued': True,
                    'source_type': 'AD',
                    'for_classes': ['user'],
                    'value_type': claims.CLAIM_TYPE_STRING,
                    'values': ('foo',),
                },
            ],
            'class': 'user',
        },
        {
            'name': 'not applicable to any class',
            'claims': [
                {
                    # 2.5.5.12
                    'enabled': True,
                    'attribute': 'carLicense',
                    'single_valued': True,
                    'source_type': 'AD',
                    'value_type': claims.CLAIM_TYPE_STRING,
                    'values': ('foo',),
                },
            ],
            'class': 'user',
        },
        {
            'name': 'not applicable to class',
            'claims': [
                {
                    # 2.5.5.12
                    'enabled': True,
                    'attribute': 'carLicense',
                    'single_valued': True,
                    'source_type': 'AD',
                    'for_classes': ['user'],
                    'value_type': claims.CLAIM_TYPE_STRING,
                    'values': ('foo',),
                },
            ],
            'class': 'computer',
        },
        {
            'name': 'applicable to class',
            'claims': [
                {
                    # 2.5.5.12
                    'enabled': True,
                    'attribute': 'carLicense',
                    'single_valued': True,
                    'source_type': 'AD',
                    'for_classes': ['user', 'computer'],
                    'value_type': claims.CLAIM_TYPE_STRING,
                    'values': ('foo',),
                    'expected': True,
                },
            ],
            'class': 'computer',
        },
        {
            'name': 'applicable to base class',
            'claims': [
                {
                    # 2.5.5.12
                    'enabled': True,
                    'attribute': 'carLicense',
                    'single_valued': True,
                    'source_type': 'AD',
                    'for_classes': ['top'],
                    'value_type': claims.CLAIM_TYPE_STRING,
                    'values': ('foo',),
                },
            ],
            'class': 'user',
        },
        {
            'name': 'applicable to base class 2',
            'claims': [
                {
                    # 2.5.5.12
                    'enabled': True,
                    'attribute': 'carLicense',
                    'single_valued': True,
                    'source_type': 'AD',
                    'for_classes': ['organizationalPerson'],
                    'value_type': claims.CLAIM_TYPE_STRING,
                    'values': ('foo',),
                },
            ],
            'class': 'user',
        },
        {
            'name': 'large compressed claim',
            'claims': [
                {
                    # 2.5.5.12
                    'enabled': True,
                    'attribute': 'carLicense',
                    'single_valued': True,
                    'source_type': 'AD',
                    'for_classes': ['user'],
                    'value_type': claims.CLAIM_TYPE_STRING,
                    # a large value that should cause the claim to be
                    # compressed.
                    'values': ('a' * 10000,),
                    'expected': True,
                },
            ],
            'class': 'user',
        },
    ]

    def _test_device_claims_with_args(self, case):
        # The group arrangement for the test.
        group_setup = case.pop('groups')

        # Groups that should be the primary group for the user and machine
        # respectively.
        primary_group = case.pop('primary_group', None)
        mach_primary_group = case.pop('mach:primary_group', None)

        # Whether the TGS-REQ should be directed to the krbtgt.
        tgs_to_krbtgt = case.pop('tgs:to_krbtgt', None)

        # Whether the target server of the TGS-REQ should support compound
        # identity or resource SID compression.
        tgs_compound_id = case.pop('tgs:compound_id', None)
        tgs_compression = case.pop('tgs:compression', None)

        # Optional SIDs to replace those in the machine account PAC prior to a
        # TGS-REQ.
        tgs_mach_sids = case.pop('tgs:mach:sids', None)

        # Optional machine SID to replace that in the PAC prior to a TGS-REQ.
        tgs_mach_sid = case.pop('tgs:mach_sid', None)

        # User flags that may be set or reset in the PAC prior to a TGS-REQ.
        tgs_mach_set_user_flags = case.pop('tgs:mach:set_user_flags', None)
        tgs_mach_reset_user_flags = case.pop('tgs:mach:reset_user_flags', None)

        # The SIDs we expect to see in the PAC after a AS-REQ or a TGS-REQ.
        as_expected = case.pop('as:expected', None)
        as_mach_expected = case.pop('as:mach:expected', None)
        tgs_expected = case.pop('tgs:expected', None)
        tgs_device_expected = case.pop('tgs:device:expected', None)

        # Whether to specify claims support in PA-PAC-OPTIONS.
        pac_options_claims = case.pop('pac-options:claims-support', None)

        all_claims = case.pop('claims')

        # There should be no parameters remaining in the testcase.
        self.assertFalse(case, 'unexpected parameters in testcase')

        if as_expected is None:
            self.assertIsNotNone(tgs_expected,
                                 'no set of expected SIDs is provided')

        if as_mach_expected is None:
            self.assertIsNotNone(tgs_expected,
                                 'no set of expected machine SIDs is provided')

        if tgs_to_krbtgt is None:
            tgs_to_krbtgt = False

        if tgs_compound_id is None and not tgs_to_krbtgt:
            # Assume the service supports compound identity by default.
            tgs_compound_id = True

        if tgs_to_krbtgt:
            self.assertIsNone(tgs_device_expected,
                              'device SIDs are not added for a krbtgt request')

        self.assertIsNotNone(tgs_expected,
                             'no set of expected TGS SIDs is provided')

        if tgs_mach_sid is not None:
            self.assertIsNotNone(tgs_mach_sids,
                                 'specified TGS-REQ mach SID, but no '
                                 'accompanying machine SIDs provided')

        if tgs_mach_set_user_flags is None:
            tgs_mach_set_user_flags = 0
        else:
            self.assertIsNotNone(tgs_mach_sids,
                                 'specified TGS-REQ set user flags, but no '
                                 'accompanying machine SIDs provided')

        if tgs_mach_reset_user_flags is None:
            tgs_mach_reset_user_flags = 0
        else:
            self.assertIsNotNone(tgs_mach_sids,
                                 'specified TGS-REQ reset user flags, but no '
                                 'accompanying machine SIDs provided')

        if pac_options_claims is None:
            pac_options_claims = True

        (details, mod_msg,
         expected_claims,
         unexpected_claims) = self.setup_claims(all_claims)

        samdb = self.get_samdb()

        domain_sid = samdb.get_domain_sid()

        user_creds = self.get_cached_creds(
            account_type=self.AccountType.USER)
        user_dn = user_creds.get_dn()
        user_sid = self.get_objectSid(samdb, user_dn)

        mach_name = self.get_new_username()
        mach_creds, mach_dn_str = self.create_account(
            samdb,
            mach_name,
            account_type=self.AccountType.COMPUTER,
            additional_details=details)
        mach_dn = ldb.Dn(samdb, mach_dn_str)
        mach_sid = self.get_objectSid(samdb, mach_dn)

        user_principal = Principal(user_dn, user_sid)
        mach_principal = Principal(mach_dn, mach_sid)
        preexisting_groups = {
            self.user: user_principal,
            self.mach: mach_principal,
        }
        primary_groups = {}
        if primary_group is not None:
            primary_groups[user_principal] = primary_group
        if mach_primary_group is not None:
            primary_groups[mach_principal] = mach_primary_group
        groups = self.setup_groups(samdb,
                                   preexisting_groups,
                                   group_setup,
                                   primary_groups)
        del group_setup

        tgs_user_sid = user_sid
        tgs_user_domain_sid, tgs_user_rid = tgs_user_sid.rsplit('-', 1)

        if tgs_mach_sid is None:
            tgs_mach_sid = mach_sid
        elif tgs_mach_sid in groups:
            tgs_mach_sid = groups[tgs_mach_sid].sid

        tgs_mach_domain_sid, tgs_mach_rid = tgs_mach_sid.rsplit('-', 1)

        expected_groups = self.map_sids(as_expected, groups,
                                        domain_sid)
        mach_expected_groups = self.map_sids(as_mach_expected, groups,
                                             domain_sid)
        tgs_mach_sids_mapped = self.map_sids(tgs_mach_sids, groups,
                                             tgs_mach_domain_sid)
        tgs_expected_mapped = self.map_sids(tgs_expected, groups,
                                            tgs_user_domain_sid)
        tgs_device_expected_mapped = self.map_sids(tgs_device_expected, groups,
                                                   tgs_mach_domain_sid)

        user_tgt = self.get_tgt(user_creds, expected_groups=expected_groups)

        # Get a TGT for the computer.
        mach_tgt = self.get_tgt(mach_creds, expect_pac=True,
                                expected_groups=mach_expected_groups,
                                expect_client_claims=True,
                                expected_client_claims=expected_claims,
                                unexpected_client_claims=unexpected_claims)

        if tgs_mach_sids is not None:
            # Replace the SIDs in the PAC with the ones provided by the test.
            mach_tgt = self.ticket_with_sids(mach_tgt,
                                             tgs_mach_sids_mapped,
                                             tgs_mach_domain_sid,
                                             tgs_mach_rid,
                                             set_user_flags=tgs_mach_set_user_flags,
                                             reset_user_flags=tgs_mach_reset_user_flags)

        if mod_msg:
            self.assertFalse(tgs_to_krbtgt,
                             'device claims are omitted for a krbtgt request, '
                             'so specifying mod_values is probably a mistake!')

            # Change the value of attributes used for claims.
            mod_msg.dn = mach_dn
            samdb.modify(mod_msg)

        domain_sid = samdb.get_domain_sid()

        subkey = self.RandomKey(user_tgt.session_key.etype)

        armor_subkey = self.RandomKey(subkey.etype)
        explicit_armor_key = self.generate_armor_key(armor_subkey,
                                                     mach_tgt.session_key)
        armor_key = kcrypto.cf2(explicit_armor_key.key,
                                subkey.key,
                                b'explicitarmor',
                                b'tgsarmor')
        armor_key = Krb5EncryptionKey(armor_key, None)

        target_creds, sname = self.get_target(
            to_krbtgt=tgs_to_krbtgt,
            compound_id=tgs_compound_id,
            compression=tgs_compression)
        srealm = target_creds.get_realm()

        decryption_key = self.TicketDecryptionKey_from_creds(
            target_creds)

        etypes = (AES256_CTS_HMAC_SHA1_96, ARCFOUR_HMAC_MD5)

        kdc_options = '0'
        if pac_options_claims:
            pac_options = '1'  # claims support
        else:
            pac_options = '0'  # no claims support

        requester_sid = None
        if tgs_to_krbtgt:
            requester_sid = user_sid

        if tgs_to_krbtgt:
            expected_claims = None
            unexpected_claims = None

        # Get a service ticket for the user, using the computer's TGT as an
        # armor TGT. The claim value should not have changed.

        kdc_exchange_dict = self.tgs_exchange_dict(
            expected_crealm=user_tgt.crealm,
            expected_cname=user_tgt.cname,
            expected_srealm=srealm,
            expected_sname=sname,
            ticket_decryption_key=decryption_key,
            generate_fast_fn=self.generate_simple_fast,
            generate_fast_armor_fn=self.generate_ap_req,
            check_rep_fn=self.generic_check_kdc_rep,
            check_kdc_private_fn=self.generic_check_kdc_private,
            tgt=user_tgt,
            armor_key=armor_key,
            armor_tgt=mach_tgt,
            armor_subkey=armor_subkey,
            pac_options=pac_options,
            authenticator_subkey=subkey,
            kdc_options=kdc_options,
            expect_pac=True,
            expect_pac_attrs=tgs_to_krbtgt,
            expect_pac_attrs_pac_request=tgs_to_krbtgt,
            expected_sid=tgs_user_sid,
            expected_requester_sid=requester_sid,
            expected_domain_sid=tgs_user_domain_sid,
            expected_device_domain_sid=tgs_mach_domain_sid,
            expected_groups=tgs_expected_mapped,
            unexpected_groups=None,
            expect_client_claims=True,
            expected_client_claims=None,
            expect_device_info=not tgs_to_krbtgt,
            expected_device_groups=tgs_device_expected_mapped,
            expect_device_claims=not tgs_to_krbtgt,
            expected_device_claims=expected_claims,
            unexpected_device_claims=unexpected_claims)

        rep = self._generic_kdc_exchange(kdc_exchange_dict,
                                         cname=None,
                                         realm=srealm,
                                         sname=sname,
                                         etypes=etypes)
        self.check_reply(rep, KRB_TGS_REP)

    device_claims_cases = [
        {
            # Make a TGS request containing claims, but omit the Claims Valid
            # SID.
            'test': 'device to service no claims valid sid',
            'groups': {
                # Some groups to test how the device info is generated.
                'foo': (GroupType.DOMAIN_LOCAL, {mach}),
                'bar': (GroupType.DOMAIN_LOCAL, {mach}),
            },
            'claims': [
                {
                    # 2.5.5.10
                    'enabled': True,
                    'attribute': 'middleName',
                    'single_valued': True,
                    'source_type': 'AD',
                    'for_classes': ['computer'],
                    'value_type': claims.CLAIM_TYPE_STRING,
                    'values': ('foo',),
                    'expected': True,
                    'mod_values': ['bar'],
                },
            ],
            'as:expected': {
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.BASE_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
                (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, default_attrs),
            },
            'as:mach:expected': {
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (security.DOMAIN_RID_DOMAIN_MEMBERS, SidType.BASE_SID, default_attrs),
                (security.DOMAIN_RID_DOMAIN_MEMBERS, SidType.PRIMARY_GID, None),
                (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, default_attrs),
            },
            'tgs:mach:sids': {
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (security.DOMAIN_RID_DOMAIN_MEMBERS, SidType.BASE_SID, default_attrs),
                (security.DOMAIN_RID_DOMAIN_MEMBERS, SidType.PRIMARY_GID, None),
                # Omit the Claims Valid SID, and verify that this doesn't
                # affect the propagation of claims into the final ticket.

                # Some extra SIDs to show how they are propagated into the
                # final ticket.
                ('S-1-5-22-1-2-3-4', SidType.EXTRA_SID, default_attrs),
                ('S-1-5-22-1-2-3-5', SidType.EXTRA_SID, default_attrs),
            },
            'tgs:to_krbtgt': False,
            'tgs:expected': {
                (security.SID_AUTHENTICATION_AUTHORITY_ASSERTED_IDENTITY, SidType.EXTRA_SID, default_attrs),
                (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, default_attrs),
                (security.SID_COMPOUNDED_AUTHENTICATION, SidType.EXTRA_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.BASE_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
            },
            'tgs:device:expected': {
                (security.DOMAIN_RID_DOMAIN_MEMBERS, SidType.BASE_SID, default_attrs),
                (security.DOMAIN_RID_DOMAIN_MEMBERS, SidType.PRIMARY_GID, None),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                ('S-1-5-22-1-2-3-4', SidType.EXTRA_SID, default_attrs),
                ('S-1-5-22-1-2-3-5', SidType.EXTRA_SID, default_attrs),
                frozenset([
                    ('foo', SidType.RESOURCE_SID, resource_attrs),
                    ('bar', SidType.RESOURCE_SID, resource_attrs),
                ]),
            },
        },
        {
            # Make a TGS request containing claims to a service that lacks
            # support for compound identity. The claims are still propagated to
            # the final ticket.
            'test': 'device to service no compound id',
            'groups': {
                'foo': (GroupType.DOMAIN_LOCAL, {mach}),
                'bar': (GroupType.DOMAIN_LOCAL, {mach}),
            },
            'claims': [
                {
                    # 2.5.5.10
                    'enabled': True,
                    'attribute': 'middleName',
                    'single_valued': True,
                    'source_type': 'AD',
                    'for_classes': ['computer'],
                    'value_type': claims.CLAIM_TYPE_STRING,
                    'values': ('foo',),
                    'expected': True,
                    'mod_values': ['bar'],
                },
            ],
            'as:expected': {
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.BASE_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
                (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, default_attrs),
            },
            'as:mach:expected': {
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (security.DOMAIN_RID_DOMAIN_MEMBERS, SidType.BASE_SID, default_attrs),
                (security.DOMAIN_RID_DOMAIN_MEMBERS, SidType.PRIMARY_GID, None),
                (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, default_attrs),
            },
            'tgs:to_krbtgt': False,
            # Compound identity is unsupported.
            'tgs:compound_id': False,
            'tgs:expected': {
                (security.SID_AUTHENTICATION_AUTHORITY_ASSERTED_IDENTITY, SidType.EXTRA_SID, default_attrs),
                (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, default_attrs),
                (security.SID_COMPOUNDED_AUTHENTICATION, SidType.EXTRA_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.BASE_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
            },
            'tgs:device:expected': {
                (security.DOMAIN_RID_DOMAIN_MEMBERS, SidType.BASE_SID, default_attrs),
                (security.DOMAIN_RID_DOMAIN_MEMBERS, SidType.PRIMARY_GID, None),
                frozenset([
                    ('foo', SidType.RESOURCE_SID, resource_attrs),
                    ('bar', SidType.RESOURCE_SID, resource_attrs),
                ]),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                frozenset([(security.SID_CLAIMS_VALID, SidType.RESOURCE_SID, default_attrs)]),
            },
        },
        {
            # Make a TGS request containing claims to a service, but don't
            # specify support for claims in PA-PAC-OPTIONS. We still expect the
            # final PAC to contain claims.
            'test': 'device to service no claims support in pac options',
            'groups': {
                'foo': (GroupType.DOMAIN_LOCAL, {mach}),
                'bar': (GroupType.DOMAIN_LOCAL, {mach}),
            },
            'claims': [
                {
                    # 2.5.5.10
                    'enabled': True,
                    'attribute': 'middleName',
                    'single_valued': True,
                    'source_type': 'AD',
                    'for_classes': ['computer'],
                    'value_type': claims.CLAIM_TYPE_STRING,
                    'values': ('foo',),
                    'expected': True,
                    'mod_values': ['bar'],
                },
            ],
            'as:expected': {
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.BASE_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
                (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, default_attrs),
            },
            'as:mach:expected': {
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                (security.DOMAIN_RID_DOMAIN_MEMBERS, SidType.BASE_SID, default_attrs),
                (security.DOMAIN_RID_DOMAIN_MEMBERS, SidType.PRIMARY_GID, None),
                (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, default_attrs),
            },
            'tgs:to_krbtgt': False,
            # Claims are unsupported.
            'pac-options:claims-support': False,
            'tgs:expected': {
                (security.SID_AUTHENTICATION_AUTHORITY_ASSERTED_IDENTITY, SidType.EXTRA_SID, default_attrs),
                (security.SID_CLAIMS_VALID, SidType.EXTRA_SID, default_attrs),
                (security.SID_COMPOUNDED_AUTHENTICATION, SidType.EXTRA_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.BASE_SID, default_attrs),
                (security.DOMAIN_RID_USERS, SidType.PRIMARY_GID, None),
            },
            'tgs:device:expected': {
                (security.DOMAIN_RID_DOMAIN_MEMBERS, SidType.BASE_SID, default_attrs),
                (security.DOMAIN_RID_DOMAIN_MEMBERS, SidType.PRIMARY_GID, None),
                frozenset([
                    ('foo', SidType.RESOURCE_SID, resource_attrs),
                    ('bar', SidType.RESOURCE_SID, resource_attrs),
                ]),
                (asserted_identity, SidType.EXTRA_SID, default_attrs),
                frozenset([(security.SID_CLAIMS_VALID, SidType.RESOURCE_SID, default_attrs)]),
            },
        },
    ]

    def test_auth_silo_claim(self):
        self.run_auth_silo_claim_test()

    def test_auth_silo_claim_unenforced(self):
        # The claim is not present if the silo is unenforced.
        self.run_auth_silo_claim_test(enforced=False,
                                      expect_claim=False)

    def test_auth_silo_claim_not_a_member(self):
        # The claim is not present if the user is not a member of the silo.
        self.run_auth_silo_claim_test(add_to_silo=False,
                                      expect_claim=False)

    def test_auth_silo_claim_unassigned(self):
        # The claim is not present if the user is not assigned to the silo.
        self.run_auth_silo_claim_test(assigned=False,
                                      expect_claim=False)

    def test_auth_silo_claim_assigned_to_wrong_dn(self):
        samdb = self.get_samdb()

        # The claim is not present if the user is assigned to some other DN.
        self.run_auth_silo_claim_test(assigned=self.get_server_dn(samdb),
                                      expect_claim=False)

    def run_auth_silo_claim_test(self, *,
                                 enforced=True,
                                 add_to_silo=True,
                                 assigned=True,
                                 expect_claim=True):
        # Create a new authentication silo.
        silo_id = self.get_new_username()
        silo_dn = self.create_auth_silo(silo_id, enforced=enforced)

        account_options = None
        if assigned is not False:
            if assigned is True:
                assigned = silo_dn

            account_options = {
                'additional_details': self.freeze({
                    # The user is assigned to the authentication silo we just
                    # created, or to some DN specified by a test.
                    'msDS-AssignedAuthNPolicySilo': str(assigned),
                }),
            }

        # Create the user account.
        creds = self.get_cached_creds(
            account_type=self.AccountType.USER,
            opts=account_options)

        if add_to_silo:
            # Add the account to the silo.
            self.add_to_group(str(creds.get_dn()),
                              silo_dn,
                              'msDS-AuthNPolicySiloMembers',
                              expect_attr=False)

        claim_id = self.create_auth_silo_claim_id()

        if expect_claim:
            expected_claims = {
                claim_id: {
                    'source_type': claims.CLAIMS_SOURCE_TYPE_AD,
                    'type': claims.CLAIM_TYPE_STRING,
                    # Expect a claim containing the name of the silo.
                    'values': (silo_id,),
                },
            }
            unexpected_claims = None
        else:
            expected_claims = None
            unexpected_claims = {claim_id}

        # Get a TGT and check whether the claim is present or missing.
        self.get_tgt(creds,
                     expect_pac=True,
                     expect_client_claims=True,
                     expected_client_claims=expected_claims,
                     unexpected_client_claims=unexpected_claims)


if __name__ == '__main__':
    global_asn1_print = False
    global_hexdump = False
    import unittest
    unittest.main()
