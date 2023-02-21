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

from samba.tests import DynamicTestCase, env_get_var_value
from samba.tests.krb5 import kcrypto
from samba.tests.krb5.kcrypto import Enctype
from samba.tests.krb5.kdc_base_test import KDCBaseTest
from samba.tests.krb5.raw_testcase import Krb5EncryptionKey
from samba.tests.krb5.rfc4120_constants import (
    AES256_CTS_HMAC_SHA1_96,
    ARCFOUR_HMAC_MD5,
    KRB_TGS_REP,
    NT_PRINCIPAL,
    NT_SRV_INST,
)
import samba.tests.krb5.rfc4120_pyasn1 as krb5_asn1

global_asn1_print = False
global_hexdump = False


class UnorderedList(list):
    def __eq__(self, other):
        if isinstance(other, UnorderedList):
            return sorted(self) == sorted(other)
        else:
            return False


@DynamicTestCase
class ClaimsTests(KDCBaseTest):
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

        details = ((k, v) for k, v in details.items())

        return details, mod_msg, expected_claims, unexpected_claims

    def remove_client_claims(self, ticket):
        def modify_pac_fn(pac):
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

        return self.modified_ticket(
            ticket,
            modify_pac_fn=modify_pac_fn,
            checksum_keys=self.get_krbtgt_checksum_key())

    def test_delegation_claims(self):
        self.run_delegation_test(remove_claims=False)

    def test_delegation_claims_remove_claims(self):
        self.run_delegation_test(remove_claims=True)

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
                'values': ['user_old'],
            },
        }
        expected_claims_mac = {
            claim_id: {
                'source_type': claims.CLAIMS_SOURCE_TYPE_AD,
                'type': claims.CLAIM_TYPE_STRING,
                'values': ['mach_old'],
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
                                expected_client_claims=expected_claims_mac)

        if remove_claims:
            user_ticket = self.remove_client_claims(user_ticket)
            mach_tgt = self.remove_client_claims(mach_tgt)

        # Change the value of the attributes used for the claim.
        msg = ldb.Message(ldb.Dn(samdb, user_dn))
        msg['middleName'] = ldb.MessageElement('user_new',
                                               ldb.FLAG_MOD_REPLACE,
                                               'middleName')
        samdb.modify(msg)

        # Change the value of the attributes used for the claim.
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

        expected_claims = expected_claims_user if not remove_claims else None

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
            expect_pac=True)

        self._generic_kdc_exchange(kdc_exchange_dict,
                                   cname=None,
                                   realm=service_realm,
                                   sname=service_sname,
                                   etypes=etypes,
                                   additional_tickets=additional_tickets)

    def test_tgs_claims(self):
        self.run_tgs_test(remove_claims=False, to_krbtgt=False)

    def test_tgs_claims_remove_claims(self):
        self.run_tgs_test(remove_claims=True, to_krbtgt=False)

    def test_tgs_claims_to_krbtgt(self):
        self.run_tgs_test(remove_claims=False, to_krbtgt=True)

    def test_tgs_claims_remove_claims_to_krbtgt(self):
        self.run_tgs_test(remove_claims=True, to_krbtgt=True)

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
                'values': ['foo'],
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

        # Get a service ticket for the user. The value should not have changed.
        self.get_service_ticket(
            tgt, target_creds,
            sname=sname,
            expect_pac=True,
            expect_client_claims=not remove_claims,
            expected_client_claims=(expected_claims
                                    if not remove_claims else None))

    def test_device_info(self):
        self._run_device_info_test(to_krbtgt=False)

    def test_device_info_to_krbtgt(self):
        self._run_device_info_test(to_krbtgt=True)

    def _run_device_info_test(self, to_krbtgt):
        user_creds = self.get_cached_creds(
            account_type=self.AccountType.USER)
        user_tgt = self.get_tgt(user_creds)

        mach_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER)
        mach_tgt = self.get_tgt(mach_creds)

        samdb = self.get_samdb()
        expected_sid = self.get_objectSid(samdb, user_creds.get_dn())

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
            to_krbtgt,
            extra_enctypes=security.KERB_ENCTYPE_COMPOUND_IDENTITY_SUPPORTED)
        srealm = target_creds.get_realm()

        decryption_key = self.TicketDecryptionKey_from_creds(
            target_creds)

        etypes = (AES256_CTS_HMAC_SHA1_96, ARCFOUR_HMAC_MD5)

        kdc_options = '0'
        pac_options = '1'  # claims support

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
            expect_pac_attrs=to_krbtgt,
            expect_pac_attrs_pac_request=to_krbtgt,
            expected_sid=expected_sid,
            expect_device_claims=not to_krbtgt,
            expect_device_info=not to_krbtgt)

        rep = self._generic_kdc_exchange(kdc_exchange_dict,
                                         cname=None,
                                         realm=srealm,
                                         sname=sname,
                                         etypes=etypes)
        self.check_reply(rep, KRB_TGS_REP)

    def test_device_claims(self):
        self._run_device_claims_test(to_krbtgt=False)

    def test_device_claims_to_krbtgt(self):
        self._run_device_claims_test(to_krbtgt=True)

    def _run_device_claims_test(self, to_krbtgt):
        user_creds = self.get_cached_creds(
            account_type=self.AccountType.USER)
        user_tgt = self.get_tgt(user_creds)

        samdb = self.get_samdb()
        mach_creds, mach_dn = self.create_account(
            samdb,
            self.get_new_username(),
            account_type=self.AccountType.COMPUTER,
            additional_details={
                'middleName': 'foo',
            })

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
                'values': ['foo'],
            },
        }

        # Get a TGT for the computer.
        mach_tgt = self.get_tgt(mach_creds, expect_pac=True,
                                expect_client_claims=True,
                                expected_client_claims=expected_claims)

        # Change the value of the attribute used for the claim.
        msg = ldb.Message(ldb.Dn(samdb, mach_dn))
        msg['middleName'] = ldb.MessageElement('bar',
                                               ldb.FLAG_MOD_REPLACE,
                                               'middleName')
        samdb.modify(msg)

        # Get a service ticket for the user, using the computer's TGT as an
        # armor TGT. The value should not have changed.

        expected_sid = self.get_objectSid(samdb, user_creds.get_dn())

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
            to_krbtgt,
            extra_enctypes=security.KERB_ENCTYPE_COMPOUND_IDENTITY_SUPPORTED)
        srealm = target_creds.get_realm()

        decryption_key = self.TicketDecryptionKey_from_creds(
            target_creds)

        etypes = (AES256_CTS_HMAC_SHA1_96, ARCFOUR_HMAC_MD5)

        kdc_options = '0'
        pac_options = '1'  # claims support

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
            expect_pac_attrs=to_krbtgt,
            expect_pac_attrs_pac_request=to_krbtgt,
            expected_sid=expected_sid,
            expect_device_info=not to_krbtgt,
            expect_device_claims=not to_krbtgt,
            expected_device_claims=expected_claims if not to_krbtgt else None)

        rep = self._generic_kdc_exchange(kdc_exchange_dict,
                                         cname=None,
                                         realm=srealm,
                                         sname=sname,
                                         etypes=etypes)
        self.check_reply(rep, KRB_TGS_REP)

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

    def _test_claims_with_args(self, case, to_self):
        account_class = case.pop('class')
        if account_class == 'user':
            account_type = self.AccountType.USER
        elif account_class == 'computer':
            account_type = self.AccountType.COMPUTER
        else:
            self.fail(f'Unknown class "{account_class}"')

        all_claims = case.pop('claims')
        (details, _,
         expected_claims,
         unexpected_claims) = self.setup_claims(all_claims)
        creds = self.get_cached_creds(account_type=account_type,
                                      opts={
                                          'additional_details': details,
                                      })

        self.assertFalse(case, 'unexpected parameters in testcase')

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

        self.get_tgt(creds,
                     sname=sname,
                     target_creds=service_creds,
                     ticket_etype=ticket_etype,
                     expect_pac=True,
                     expect_client_claims=True,
                     expected_client_claims=expected_claims or None,
                     unexpected_client_claims=unexpected_claims or None)

    sample_dn = object()
    binary_dn = object()
    security_descriptor = (b'\x01\x00\x04\x80\x14\x00\x00\x00\x00\x00\x00\x00'
                           b'\x00\x00\x00\x00$\x00\x00\x00\x01\x02\x00\x00\x00'
                           b'\x00\x00\x05 \x00\x00\x00 \x02\x00\x00\x04\x00'
                           b'\x1c\x00\x01\x00\x00\x00\x00\x00\x14\x00\xff\x01'
                           b'\x0f\x00\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00'
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
                    'values': ['foo'],
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
                    'values': [True],
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
                    'values': [False],
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
                    'values': [True],
                },
            ],
            'class': 'user',
        },
        {
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
                    'values': [3, 42, -999, 1000, 20000],
                    'expected_values': [3 << 32,
                                        42 << 32,
                                        -999 << 32,
                                        1000 << 32 | 0xffffffff,
                                        20000 << 32],
                    'expected': True,
                },
            ],
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
                    'values': [3, 42, -999, 1000],
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
                    'values': [security_descriptor],
                    'expected_values': ['O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;'
                                        ';;S-1-0-0)'],
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
                    'values': [security_descriptor],
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
                    'values': ['foo', 'bar'],
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
                    'values': ['foo'],
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
                    'values': ['foo', 'bar'],
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
                    'values': [binary_dn, binary_dn, binary_dn],
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
                    'values': ['foo', 'bar'],
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
                    'values': ['19700101000000.0Z'],
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
                    'values': ['foo', 'bar', 'baz'],
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
                    'values': ['foo'],
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
                    'values': ['foo'],
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
                    'values': ['foo'],
                },
            ],
            'class': 'user',
        },
        {
            'name': 'duplicate claim',
            'claims': [
                {
                    # 2.5.5.12
                    'enabled': True,
                    'attribute': 'carLicense',
                    'single_valued': True,
                    'source_type': 'AD',
                    'for_classes': ['user'],
                    'value_type': claims.CLAIM_TYPE_STRING,
                    'values': ['foo'],
                    'expected': True,
                },
                {
                    # 2.5.5.12
                    'enabled': True,
                    'attribute': 'carLicense',
                    'single_valued': True,
                    'source_type': 'AD',
                    'for_classes': ['user'],
                    'value_type': claims.CLAIM_TYPE_STRING,
                    'values': ['foo'],
                    'expected': True,
                },
            ],
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
                    'values': ['foo', 'bar', 'baz'],
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
                    'values': [True],
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
                    'values': ['foo'],
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
                    'values': ['foo'],
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
                    'values': ['foo'],
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
                    'values': ['foo'],
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
                    'values': ['foo'],
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
                    'values': ['foo'],
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
                    'values': ['foo'],
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
                    'values': ['foo'],
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
                    'values': ['foo'],
                },
            ],
            'class': 'user',
        },
    ]


if __name__ == '__main__':
    global_asn1_print = False
    global_hexdump = False
    import unittest
    unittest.main()
