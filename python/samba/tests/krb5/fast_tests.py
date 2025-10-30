#!/usr/bin/env python3
# Unix SMB/CIFS implementation.
# Copyright (C) Stefan Metzmacher 2020
# Copyright (C) 2020 Catalyst.Net Ltd
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

sys.path.insert(0, "bin/python")
os.environ["PYTHONUNBUFFERED"] = "1"

import functools
import collections

import ldb

from samba.dcerpc import krb5pac, security
from samba.tests.krb5.raw_testcase import Krb5EncryptionKey, ZeroedChecksumKey
from samba.tests.krb5.kdc_base_test import KDCBaseTest
from samba.tests.krb5.rfc4120_constants import (
    AD_FX_FAST_ARMOR,
    AD_FX_FAST_USED,
    AES256_CTS_HMAC_SHA1_96,
    ARCFOUR_HMAC_MD5,
    FX_FAST_ARMOR_AP_REQUEST,
    KDC_ERR_BAD_INTEGRITY,
    KDC_ERR_ETYPE_NOSUPP,
    KDC_ERR_GENERIC,
    KDC_ERR_S_PRINCIPAL_UNKNOWN,
    KDC_ERR_MODIFIED,
    KDC_ERR_NOT_US,
    KDC_ERR_POLICY,
    KDC_ERR_PREAUTH_FAILED,
    KDC_ERR_PREAUTH_REQUIRED,
    KDC_ERR_SKEW,
    KDC_ERR_UNKNOWN_CRITICAL_FAST_OPTIONS,
    KRB_AS_REP,
    KRB_TGS_REP,
    KU_TGS_REQ_AUTH_DAT_SESSION,
    KU_TGS_REQ_AUTH_DAT_SUBKEY,
    NT_PRINCIPAL,
    NT_SRV_HST,
    NT_SRV_INST,
    PADATA_FX_COOKIE,
    PADATA_FX_FAST,
    PADATA_REQ_ENC_PA_REP,
)
import samba.tests.krb5.rfc4120_pyasn1 as krb5_asn1
import samba.tests.krb5.kcrypto as kcrypto

global_asn1_print = False
global_hexdump = False


class FAST_Tests(KDCBaseTest):
    def setUp(self):
        super().setUp()
        self.do_asn1_print = global_asn1_print
        self.do_hexdump = global_hexdump

    def test_simple(self):
        self._run_test_sequence([
            {
                'rep_type': KRB_AS_REP,
                'expected_error_mode': KDC_ERR_PREAUTH_REQUIRED,
                'use_fast': False
            },
            {
                'rep_type': KRB_AS_REP,
                'expected_error_mode': 0,
                'use_fast': False,
                'gen_padata_fn': self.generate_enc_timestamp_padata
            }
        ])

    def test_simple_as_req_self(self):
        self._run_test_sequence([
            {
                'rep_type': KRB_AS_REP,
                'expected_error_mode': KDC_ERR_PREAUTH_REQUIRED,
                'use_fast': False,
                'as_req_self': True
            },
            {
                'rep_type': KRB_AS_REP,
                'expected_error_mode': 0,
                'use_fast': False,
                'gen_padata_fn': self.generate_enc_timestamp_padata,
                'as_req_self': True
            }
        ], client_account=self.AccountType.COMPUTER)

    def test_simple_as_req_self_no_auth_data(self):
        self._run_test_sequence(
            [
                {
                    'rep_type': KRB_AS_REP,
                    'expected_error_mode': KDC_ERR_PREAUTH_REQUIRED,
                    'use_fast': False,
                    'as_req_self': True
                },
                {
                    'rep_type': KRB_AS_REP,
                    'expected_error_mode': 0,
                    'use_fast': False,
                    'gen_padata_fn': self.generate_enc_timestamp_padata,
                    'as_req_self': True,
                    'expect_pac': True
                }
            ],
            client_account=self.AccountType.COMPUTER,
            client_opts={'no_auth_data_required': True})

    def test_simple_as_req_self_pac_request_false(self):
        expect_pac = self.always_include_pac
        self._run_test_sequence([
            {
                'rep_type': KRB_AS_REP,
                'expected_error_mode': KDC_ERR_PREAUTH_REQUIRED,
                'use_fast': False,
                'as_req_self': True
            },
            {
                'rep_type': KRB_AS_REP,
                'expected_error_mode': 0,
                'use_fast': False,
                'gen_padata_fn': self.generate_enc_timestamp_padata,
                'as_req_self': True,
                'pac_request': False,
                'expect_pac': expect_pac
            }
        ], client_account=self.AccountType.COMPUTER)

    def test_simple_as_req_self_pac_request_none(self):
        self._run_test_sequence([
            {
                'rep_type': KRB_AS_REP,
                'expected_error_mode': KDC_ERR_PREAUTH_REQUIRED,
                'use_fast': False,
                'as_req_self': True
            },
            {
                'rep_type': KRB_AS_REP,
                'expected_error_mode': 0,
                'use_fast': False,
                'gen_padata_fn': self.generate_enc_timestamp_padata,
                'as_req_self': True,
                'pac_request': None,
                'expect_pac': True
            }
        ], client_account=self.AccountType.COMPUTER)

    def test_simple_as_req_self_pac_request_true(self):
        self._run_test_sequence([
            {
                'rep_type': KRB_AS_REP,
                'expected_error_mode': KDC_ERR_PREAUTH_REQUIRED,
                'use_fast': False,
                'as_req_self': True
            },
            {
                'rep_type': KRB_AS_REP,
                'expected_error_mode': 0,
                'use_fast': False,
                'gen_padata_fn': self.generate_enc_timestamp_padata,
                'as_req_self': True,
                'pac_request': True,
                'expect_pac': True
            }
        ], client_account=self.AccountType.COMPUTER)

    def test_simple_tgs(self):
        self._run_test_sequence([
            {
                'rep_type': KRB_TGS_REP,
                'expected_error_mode': 0,
                'use_fast': False,
                'gen_tgt_fn': self.get_user_tgt
            }
        ])

    def test_fast_rodc_issued_armor(self):
        self._run_test_sequence([
            {
                'rep_type': KRB_AS_REP,
                'expected_error_mode': KDC_ERR_PREAUTH_REQUIRED,
                'use_fast': True,
                'fast_armor': FX_FAST_ARMOR_AP_REQUEST,
                'gen_armor_tgt_fn': self.get_rodc_issued_mach_tgt,
            },
            {
                'rep_type': KRB_AS_REP,
                # Test that RODC-issued armor tickets are permitted.
                'expected_error_mode': 0,
                'use_fast': True,
                'gen_padata_fn': self.generate_enc_challenge_padata,
                'fast_armor': FX_FAST_ARMOR_AP_REQUEST,
                'gen_armor_tgt_fn': self.get_rodc_issued_mach_tgt,
            }
        ],
        armor_opts={
            'allowed_replication_mock': True,
            'revealed_to_mock_rodc': True,
        })

    def test_fast_tgs_rodc_issued_armor(self):
        self._run_test_sequence([
            {
                'rep_type': KRB_TGS_REP,
                # Test that RODC-issued armor tickets are not permitted.
                'expected_error_mode': 0,
                'use_fast': True,
                'gen_tgt_fn': self.get_user_tgt,
                'gen_armor_tgt_fn': self.get_rodc_issued_mach_tgt,
                'fast_armor': FX_FAST_ARMOR_AP_REQUEST,
            }
        ],
        armor_opts={
            'allowed_replication_mock': True,
            'revealed_to_mock_rodc': True,
        })

    def test_simple_enc_pa_rep(self):
        self._run_test_sequence([
            {
                'rep_type': KRB_AS_REP,
                'expected_error_mode': KDC_ERR_PREAUTH_REQUIRED,
                'use_fast': False
            },
            {
                'rep_type': KRB_AS_REP,
                'expected_error_mode': 0,
                'use_fast': False,
                'gen_padata_fn': self.generate_enc_pa_rep_timestamp_padata,
                'expected_flags': 'enc-pa-rep'
            }
        ])

    # Currently we only send PADATA-REQ-ENC-PA-REP for AS-REQ requests.
    def test_simple_tgs_enc_pa_rep(self):
        self._run_test_sequence([
            {
                'rep_type': KRB_TGS_REP,
                'expected_error_mode': 0,
                'use_fast': False,
                'gen_tgt_fn': self.get_user_tgt,
                'gen_padata_fn': self.generate_enc_pa_rep_padata,
                'expected_flags': 'enc-pa-rep'
            }
        ])

    def test_simple_no_sname(self):
        expected_sname = self.get_krbtgt_sname()

        self._run_test_sequence([
            {
                'rep_type': KRB_AS_REP,
                'expected_error_mode': (KDC_ERR_GENERIC, KDC_ERR_S_PRINCIPAL_UNKNOWN),
                'use_fast': False,
                'sname': None,
                'expected_sname': expected_sname,
                'expect_edata': False
            }
        ])

    def test_simple_tgs_no_sname(self):
        expected_sname = self.get_krbtgt_sname()

        self._run_test_sequence([
            {
                'rep_type': KRB_TGS_REP,
                'expected_error_mode': (KDC_ERR_GENERIC, KDC_ERR_S_PRINCIPAL_UNKNOWN),
                'use_fast': False,
                'gen_tgt_fn': self.get_user_tgt,
                'sname': None,
                'expected_sname': expected_sname,
                'expect_edata': False
            }
        ])

    def test_fast_no_sname(self):
        expected_sname = self.get_krbtgt_sname()

        self._run_test_sequence([
            {
                'rep_type': KRB_AS_REP,
                'expected_error_mode': (KDC_ERR_GENERIC,
                                        KDC_ERR_S_PRINCIPAL_UNKNOWN),
                'use_fast': True,
                'fast_armor': FX_FAST_ARMOR_AP_REQUEST,
                'gen_armor_tgt_fn': self.get_mach_tgt,
                'sname': None,
                'expected_sname': expected_sname,
                'strict_edata_checking': False
            }
        ])

    def test_fast_tgs_no_sname(self):
        expected_sname = self.get_krbtgt_sname()

        self._run_test_sequence([
            {
                'rep_type': KRB_TGS_REP,
                'expected_error_mode': (KDC_ERR_GENERIC, KDC_ERR_S_PRINCIPAL_UNKNOWN),
                'use_fast': True,
                'gen_tgt_fn': self.get_user_tgt,
                'fast_armor': None,
                'sname': None,
                'expected_sname': expected_sname,
                'strict_edata_checking': False
            }
        ])

    def test_fast_inner_no_sname(self):
        expected_sname = self.get_krbtgt_sname()

        self._run_test_sequence([
            {
                'rep_type': KRB_AS_REP,
                'expected_error_mode': (KDC_ERR_GENERIC,
                                        KDC_ERR_S_PRINCIPAL_UNKNOWN),
                'use_fast': True,
                'fast_armor': FX_FAST_ARMOR_AP_REQUEST,
                'gen_armor_tgt_fn': self.get_mach_tgt,
                'inner_req': {
                    'sname': None  # should be ignored
                },
                'expected_sname': expected_sname,
                'strict_edata_checking': False
            }
        ])

    def test_fast_tgs_inner_no_sname(self):
        expected_sname = self.get_krbtgt_sname()

        self._run_test_sequence([
            {
                'rep_type': KRB_TGS_REP,
                'expected_error_mode': (KDC_ERR_GENERIC,
                                        KDC_ERR_S_PRINCIPAL_UNKNOWN),
                'use_fast': True,
                'gen_tgt_fn': self.get_user_tgt,
                'fast_armor': None,
                'inner_req': {
                    'sname': None  # should be ignored
                },
                'expected_sname': expected_sname,
                'strict_edata_checking': False
            }
        ])

    def test_simple_tgs_wrong_principal(self):
        self._run_test_sequence([
            {
                'rep_type': KRB_TGS_REP,
                'expected_error_mode': 0,
                'use_fast': False,
                'gen_tgt_fn': self.get_mach_tgt
            }
        ])

    def test_simple_tgs_service_ticket(self):
        self._run_test_sequence([
            {
                'rep_type': KRB_TGS_REP,
                'expected_error_mode': (KDC_ERR_NOT_US,
                                        KDC_ERR_POLICY),
                'use_fast': False,
                'gen_tgt_fn': self.get_user_service_ticket,
                'expect_edata': False
            }
        ])

    def test_simple_tgs_service_ticket_mach(self):
        self._run_test_sequence([
            {
                'rep_type': KRB_TGS_REP,
                'expected_error_mode': (KDC_ERR_NOT_US,
                                        KDC_ERR_POLICY),
                'use_fast': False,
                'gen_tgt_fn': self.get_mach_service_ticket,
                'expect_edata': False
            }
        ])

    def test_fast_no_claims(self):
        self._run_test_sequence([
            {
                'rep_type': KRB_AS_REP,
                'expected_error_mode': KDC_ERR_PREAUTH_REQUIRED,
                'use_fast': True,
                'fast_armor': FX_FAST_ARMOR_AP_REQUEST,
                'gen_armor_tgt_fn': self.get_mach_tgt,
                'pac_options': '0'
            },
            {
                'rep_type': KRB_AS_REP,
                'expected_error_mode': 0,
                'use_fast': True,
                'gen_padata_fn': self.generate_enc_challenge_padata,
                'fast_armor': FX_FAST_ARMOR_AP_REQUEST,
                'gen_armor_tgt_fn': self.get_mach_tgt,
                'pac_options': '0'
            }
        ])

    def test_fast_tgs_no_claims(self):
        self._run_test_sequence([
            {
                'rep_type': KRB_TGS_REP,
                'expected_error_mode': 0,
                'use_fast': True,
                'gen_tgt_fn': self.get_user_tgt,
                'fast_armor': None,
                'pac_options': '0'
            }
        ])

    def test_fast_no_claims_or_canon(self):
        self._run_test_sequence([
            {
                'rep_type': KRB_AS_REP,
                'expected_error_mode': KDC_ERR_PREAUTH_REQUIRED,
                'use_fast': True,
                'fast_armor': FX_FAST_ARMOR_AP_REQUEST,
                'gen_armor_tgt_fn': self.get_mach_tgt,
                'pac_options': '0',
                'kdc_options': '0'
            },
            {
                'rep_type': KRB_AS_REP,
                'expected_error_mode': 0,
                'use_fast': True,
                'gen_padata_fn': self.generate_enc_challenge_padata,
                'fast_armor': FX_FAST_ARMOR_AP_REQUEST,
                'gen_armor_tgt_fn': self.get_mach_tgt,
                'pac_options': '0',
                'kdc_options': '0'
            }
        ])

    def test_fast_tgs_no_claims_or_canon(self):
        self._run_test_sequence([
            {
                'rep_type': KRB_TGS_REP,
                'expected_error_mode': 0,
                'use_fast': True,
                'gen_tgt_fn': self.get_user_tgt,
                'fast_armor': None,
                'pac_options': '0',
                'kdc_options': '0'
            }
        ])

    def test_fast_no_canon(self):
        self._run_test_sequence([
            {
                'rep_type': KRB_AS_REP,
                'expected_error_mode': KDC_ERR_PREAUTH_REQUIRED,
                'use_fast': True,
                'fast_armor': FX_FAST_ARMOR_AP_REQUEST,
                'gen_armor_tgt_fn': self.get_mach_tgt,
                'kdc_options': '0'
            },
            {
                'rep_type': KRB_AS_REP,
                'expected_error_mode': 0,
                'use_fast': True,
                'gen_padata_fn': self.generate_enc_challenge_padata,
                'fast_armor': FX_FAST_ARMOR_AP_REQUEST,
                'gen_armor_tgt_fn': self.get_mach_tgt,
                'kdc_options': '0'
            }
        ])

    def test_fast_tgs_no_canon(self):
        self._run_test_sequence([
            {
                'rep_type': KRB_TGS_REP,
                'expected_error_mode': 0,
                'use_fast': True,
                'gen_tgt_fn': self.get_user_tgt,
                'fast_armor': None,
                'kdc_options': '0'
            }
        ])

    def test_simple_tgs_no_etypes(self):
        self._run_test_sequence([
            {
                'rep_type': KRB_TGS_REP,
                'expected_error_mode': KDC_ERR_ETYPE_NOSUPP,
                'use_fast': False,
                'gen_tgt_fn': self.get_mach_tgt,
                'etypes': (),
                'expect_edata': False
            }
        ])

    def test_fast_tgs_no_etypes(self):
        self._run_test_sequence([
            {
                'rep_type': KRB_TGS_REP,
                'expected_error_mode': KDC_ERR_ETYPE_NOSUPP,
                'use_fast': True,
                'gen_tgt_fn': self.get_mach_tgt,
                'fast_armor': None,
                'etypes': (),
                'strict_edata_checking': False
            }
        ])

    def test_simple_no_etypes(self):
        self._run_test_sequence([
            {
                'rep_type': KRB_AS_REP,
                'expected_error_mode': KDC_ERR_ETYPE_NOSUPP,
                'use_fast': False,
                'etypes': ()
            }
        ])

    def test_simple_fast_no_etypes(self):
        self._run_test_sequence([
            {
                'rep_type': KRB_AS_REP,
                'expected_error_mode': KDC_ERR_ETYPE_NOSUPP,
                'use_fast': True,
                'fast_armor': FX_FAST_ARMOR_AP_REQUEST,
                'gen_armor_tgt_fn': self.get_mach_tgt,
                'etypes': (),
                'strict_edata_checking': False
            }
        ])

    def test_empty_fast(self):
        # Add an empty PA-FX-FAST in the initial AS-REQ. This should get
        # rejected with a Generic error.
        self._run_test_sequence([
            {
                'rep_type': KRB_AS_REP,
                'expected_error_mode': (KDC_ERR_GENERIC,
                                        KDC_ERR_PREAUTH_FAILED),
                'use_fast': True,
                'gen_fast_fn': self.generate_empty_fast,
                'fast_armor': None,
                'gen_armor_tgt_fn': self.get_mach_tgt,
                'expect_edata': False
            }
        ])

    # Expected to fail against Windows - Windows does not produce an error.
    def test_fast_unknown_critical_option(self):
        self._run_test_sequence([
            {
                'rep_type': KRB_AS_REP,
                'expected_error_mode': KDC_ERR_PREAUTH_REQUIRED,
                'use_fast': True,
                'fast_armor': FX_FAST_ARMOR_AP_REQUEST,
                'gen_armor_tgt_fn': self.get_mach_tgt
            },
            {
                'rep_type': KRB_AS_REP,
                'expected_error_mode': KDC_ERR_UNKNOWN_CRITICAL_FAST_OPTIONS,
                'use_fast': True,
                'gen_padata_fn': self.generate_enc_challenge_padata,
                'fast_options': '001',  # unsupported critical option
                'fast_armor': FX_FAST_ARMOR_AP_REQUEST,
                'gen_armor_tgt_fn': self.get_mach_tgt
            }
        ])

    def test_unarmored_as_req(self):
        self._run_test_sequence([
            {
                'rep_type': KRB_AS_REP,
                'expected_error_mode': (KDC_ERR_GENERIC,
                                        KDC_ERR_PREAUTH_FAILED),
                'use_fast': True,
                'fast_armor': None,  # no armor,
                'gen_armor_tgt_fn': self.get_mach_tgt,
                'expect_edata': False
            }
        ])

    def test_fast_invalid_armor_type(self):
        self._run_test_sequence([
            {
                'rep_type': KRB_AS_REP,
                'expected_error_mode': KDC_ERR_PREAUTH_FAILED,
                'use_fast': True,
                'fast_armor': 0,  # invalid armor type
                'gen_armor_tgt_fn': self.get_mach_tgt
            }
        ])

    def test_fast_invalid_armor_type2(self):
        self._run_test_sequence([
            {
                'rep_type': KRB_AS_REP,
                'expected_error_mode': KDC_ERR_PREAUTH_FAILED,
                'use_fast': True,
                'fast_armor': 2,  # invalid armor type
                'gen_armor_tgt_fn': self.get_mach_tgt
            }
        ])

    def test_fast_encrypted_challenge(self):
        self._run_test_sequence([
            {
                'rep_type': KRB_AS_REP,
                'expected_error_mode': KDC_ERR_PREAUTH_REQUIRED,
                'use_fast': True,
                'fast_armor': FX_FAST_ARMOR_AP_REQUEST,
                'gen_armor_tgt_fn': self.get_mach_tgt
            },
            {
                'rep_type': KRB_AS_REP,
                'expected_error_mode': 0,
                'use_fast': True,
                'gen_padata_fn': self.generate_enc_challenge_padata,
                'fast_armor': FX_FAST_ARMOR_AP_REQUEST,
                'gen_armor_tgt_fn': self.get_mach_tgt
            }
        ])

    def test_fast_encrypted_challenge_as_req_self(self):
        self._run_test_sequence([
            {
                'rep_type': KRB_AS_REP,
                'expected_error_mode': KDC_ERR_PREAUTH_REQUIRED,
                'use_fast': True,
                'fast_armor': FX_FAST_ARMOR_AP_REQUEST,
                'gen_armor_tgt_fn': self.get_mach_tgt,
                'as_req_self': True
            },
            {
                'rep_type': KRB_AS_REP,
                'expected_error_mode': 0,
                'use_fast': True,
                'gen_padata_fn': self.generate_enc_challenge_padata,
                'fast_armor': FX_FAST_ARMOR_AP_REQUEST,
                'gen_armor_tgt_fn': self.get_mach_tgt,
                'as_req_self': True
            }
        ], client_account=self.AccountType.COMPUTER)

    def test_fast_encrypted_challenge_wrong_key(self):
        self._run_test_sequence([
            {
                'rep_type': KRB_AS_REP,
                'expected_error_mode': KDC_ERR_PREAUTH_REQUIRED,
                'use_fast': True,
                'fast_armor': FX_FAST_ARMOR_AP_REQUEST,
                'gen_armor_tgt_fn': self.get_mach_tgt
            },
            {
                'rep_type': KRB_AS_REP,
                'expected_error_mode': KDC_ERR_PREAUTH_FAILED,
                'use_fast': True,
                'gen_padata_fn': self.generate_enc_challenge_padata_wrong_key,
                'fast_armor': FX_FAST_ARMOR_AP_REQUEST,
                'gen_armor_tgt_fn': self.get_mach_tgt
            }
        ])

    def test_fast_encrypted_challenge_wrong_key_kdc(self):
        self._run_test_sequence([
            {
                'rep_type': KRB_AS_REP,
                'expected_error_mode': KDC_ERR_PREAUTH_REQUIRED,
                'use_fast': True,
                'fast_armor': FX_FAST_ARMOR_AP_REQUEST,
                'gen_armor_tgt_fn': self.get_mach_tgt
            },
            {
                'rep_type': KRB_AS_REP,
                'expected_error_mode': KDC_ERR_PREAUTH_FAILED,
                'use_fast': True,
                'gen_padata_fn':
                self.generate_enc_challenge_padata_wrong_key_kdc,
                'fast_armor': FX_FAST_ARMOR_AP_REQUEST,
                'gen_armor_tgt_fn': self.get_mach_tgt
            }
        ])

    def test_fast_encrypted_challenge_no_fast(self):
        self._run_test_sequence([
            {
                'rep_type': KRB_AS_REP,
                'expected_error_mode': KDC_ERR_PREAUTH_REQUIRED,
                'use_fast': False
            },
            {
                'rep_type': KRB_AS_REP,
                'expected_error_mode': (KDC_ERR_PREAUTH_FAILED,
                                        KDC_ERR_PREAUTH_REQUIRED),
                'use_fast': False,
                'gen_padata_fn': self.generate_enc_challenge_padata_wrong_key
            }
        ])

    # Expected to fail against Windows - Windows does not produce an error.
    def test_fast_encrypted_challenge_clock_skew(self):
        # The KDC is supposed to confirm that the timestamp is within its
        # current clock skew, and return KRB_APP_ERR_SKEW if it is not (RFC6113
        # 5.4.6). However, this test fails against Windows, which accepts a
        # skewed timestamp in the encrypted challenge.
        self._run_test_sequence([
            {
                'rep_type': KRB_AS_REP,
                'expected_error_mode': KDC_ERR_PREAUTH_REQUIRED,
                'use_fast': True,
                'fast_armor': FX_FAST_ARMOR_AP_REQUEST,
                'gen_armor_tgt_fn': self.get_mach_tgt
            },
            {
                'rep_type': KRB_AS_REP,
                'expected_error_mode': KDC_ERR_SKEW,
                'use_fast': True,
                'gen_padata_fn': functools.partial(
                    self.generate_enc_challenge_padata,
                    skew=10000),
                'fast_armor': FX_FAST_ARMOR_AP_REQUEST,
                'gen_armor_tgt_fn': self.get_mach_tgt
            }
        ])

    def test_fast_invalid_tgt(self):
        # The armor ticket 'sname' field is required to identify the target
        # realm TGS (RFC6113 5.4.1.1). However, this test fails against
        # Windows, which will still accept a service ticket identifying a
        # different server principal.
        self._run_test_sequence([
            {
                'rep_type': KRB_AS_REP,
                'expected_error_mode': (KDC_ERR_POLICY,
                                        KDC_ERR_S_PRINCIPAL_UNKNOWN),
                'use_fast': True,
                'fast_armor': FX_FAST_ARMOR_AP_REQUEST,
                'gen_armor_tgt_fn': self.get_user_service_ticket
                                    # ticket not identifying TGS of current
                                    # realm
            }
        ])

    # Similarly, this test fails against Windows, which accepts a service
    # ticket identifying a different server principal.
    def test_fast_invalid_tgt_mach(self):
        self._run_test_sequence([
            {
                'rep_type': KRB_AS_REP,
                'expected_error_mode': (KDC_ERR_POLICY,
                                        KDC_ERR_S_PRINCIPAL_UNKNOWN),
                'use_fast': True,
                'fast_armor': FX_FAST_ARMOR_AP_REQUEST,
                'gen_armor_tgt_fn': self.get_mach_service_ticket
                                    # ticket not identifying TGS of current
                                    # realm
            }
        ])

    def test_fast_invalid_checksum_tgt(self):
        # The armor ticket 'sname' field is required to identify the target
        # realm TGS (RFC6113 5.4.1.1). However, this test fails against
        # Windows, which will still accept a service ticket identifying a
        # different server principal even if the ticket checksum is invalid.
        self._run_test_sequence([
            {
                'rep_type': KRB_AS_REP,
                'expected_error_mode': (KDC_ERR_POLICY,
                                        KDC_ERR_S_PRINCIPAL_UNKNOWN),
                'use_fast': True,
                'fast_armor': FX_FAST_ARMOR_AP_REQUEST,
                'gen_armor_tgt_fn': self.get_service_ticket_invalid_checksum
            }
        ])

    def test_fast_enc_timestamp(self):
        # Provide ENC-TIMESTAMP as FAST padata when we should be providing
        # ENCRYPTED-CHALLENGE - ensure that we get PREAUTH_REQUIRED.
        self._run_test_sequence([
            {
                'rep_type': KRB_AS_REP,
                'expected_error_mode': KDC_ERR_PREAUTH_REQUIRED,
                'use_fast': True,
                'fast_armor': FX_FAST_ARMOR_AP_REQUEST,
                'gen_armor_tgt_fn': self.get_mach_tgt
            },
            {
                'rep_type': KRB_AS_REP,
                'expected_error_mode': (KDC_ERR_PREAUTH_REQUIRED,
                                        KDC_ERR_POLICY),
                'use_fast': True,
                'gen_padata_fn': self.generate_enc_timestamp_padata,
                'fast_armor': FX_FAST_ARMOR_AP_REQUEST,
                'gen_armor_tgt_fn': self.get_mach_tgt
            }
        ])

    def test_fast(self):
        self._run_test_sequence([
            {
                'rep_type': KRB_AS_REP,
                'expected_error_mode': KDC_ERR_PREAUTH_REQUIRED,
                'use_fast': True,
                'fast_armor': FX_FAST_ARMOR_AP_REQUEST,
                'gen_armor_tgt_fn': self.get_mach_tgt
            },
            {
                'rep_type': KRB_AS_REP,
                'expected_error_mode': 0,
                'use_fast': True,
                'gen_padata_fn': self.generate_enc_challenge_padata,
                'fast_armor': FX_FAST_ARMOR_AP_REQUEST,
                'gen_armor_tgt_fn': self.get_mach_tgt
            }
        ])

    def test_fast_tgs(self):
        self._run_test_sequence([
            {
                'rep_type': KRB_TGS_REP,
                'expected_error_mode': 0,
                'use_fast': True,
                'gen_tgt_fn': self.get_user_tgt,
                'fast_armor': None
            }
        ])

    def test_fast_tgs_armor(self):
        self._run_test_sequence([
            {
                'rep_type': KRB_TGS_REP,
                'expected_error_mode': 0,
                'use_fast': True,
                'gen_tgt_fn': self.get_user_tgt,
                'gen_armor_tgt_fn': self.get_mach_tgt,
                'fast_armor': FX_FAST_ARMOR_AP_REQUEST
            }
        ])

    def test_fast_session_key(self):
        # Ensure that specified APOptions are ignored.
        self._run_test_sequence([
            {
                'rep_type': KRB_AS_REP,
                'expected_error_mode': KDC_ERR_PREAUTH_REQUIRED,
                'use_fast': True,
                'fast_armor': FX_FAST_ARMOR_AP_REQUEST,
                'gen_armor_tgt_fn': self.get_mach_tgt,
                'fast_ap_options': str(krb5_asn1.APOptions('use-session-key'))
            },
            {
                'rep_type': KRB_AS_REP,
                'expected_error_mode': 0,
                'use_fast': True,
                'gen_padata_fn': self.generate_enc_challenge_padata,
                'fast_armor': FX_FAST_ARMOR_AP_REQUEST,
                'gen_armor_tgt_fn': self.get_mach_tgt,
                'fast_ap_options': str(krb5_asn1.APOptions('use-session-key'))
            }
        ])

    def test_fast_tgs_armor_session_key(self):
        # Ensure that specified APOptions are ignored.
        self._run_test_sequence([
            {
                'rep_type': KRB_TGS_REP,
                'expected_error_mode': 0,
                'use_fast': True,
                'gen_tgt_fn': self.get_user_tgt,
                'gen_armor_tgt_fn': self.get_mach_tgt,
                'fast_armor': FX_FAST_ARMOR_AP_REQUEST,
                'fast_ap_options': str(krb5_asn1.APOptions('use-session-key'))
            }
        ])

    def test_fast_enc_pa_rep(self):
        self._run_test_sequence([
            {
                'rep_type': KRB_AS_REP,
                'expected_error_mode': KDC_ERR_PREAUTH_REQUIRED,
                'use_fast': True,
                'fast_armor': FX_FAST_ARMOR_AP_REQUEST,
                'gen_armor_tgt_fn': self.get_mach_tgt,
                'expected_flags': 'enc-pa-rep'
            },
            {
                'rep_type': KRB_AS_REP,
                'expected_error_mode': 0,
                'use_fast': True,
                'gen_padata_fn': self.generate_enc_pa_rep_challenge_padata,
                'fast_armor': FX_FAST_ARMOR_AP_REQUEST,
                'gen_armor_tgt_fn': self.get_mach_tgt,
                'expected_flags': 'enc-pa-rep'
            }
        ])

    # Currently we only send PADATA-REQ-ENC-PA-REP for AS-REQ requests.
    def test_fast_tgs_enc_pa_rep(self):
        self._run_test_sequence([
            {
                'rep_type': KRB_TGS_REP,
                'expected_error_mode': 0,
                'use_fast': True,
                'gen_tgt_fn': self.get_user_tgt,
                'fast_armor': None,
                'gen_padata_fn': self.generate_enc_pa_rep_padata,
                'expected_flags': 'enc-pa-rep'
            }
        ])

    # Currently we only send PADATA-REQ-ENC-PA-REP for AS-REQ requests.
    def test_fast_tgs_armor_enc_pa_rep(self):
        self._run_test_sequence([
            {
                'rep_type': KRB_TGS_REP,
                'expected_error_mode': 0,
                'use_fast': True,
                'gen_tgt_fn': self.get_user_tgt,
                'gen_armor_tgt_fn': self.get_mach_tgt,
                'fast_armor': FX_FAST_ARMOR_AP_REQUEST,
                'gen_padata_fn': self.generate_enc_pa_rep_padata,
                'expected_flags': 'enc-pa-rep'
            }
        ])

    def test_fast_outer_wrong_realm(self):
        self._run_test_sequence([
            {
                'rep_type': KRB_AS_REP,
                'expected_error_mode': KDC_ERR_PREAUTH_REQUIRED,
                'use_fast': True,
                'fast_armor': FX_FAST_ARMOR_AP_REQUEST,
                'gen_armor_tgt_fn': self.get_mach_tgt,
                'outer_req': {
                    'realm': 'TEST'  # should be ignored
                }
            },
            {
                'rep_type': KRB_AS_REP,
                'expected_error_mode': 0,
                'use_fast': True,
                'gen_padata_fn': self.generate_enc_challenge_padata,
                'fast_armor': FX_FAST_ARMOR_AP_REQUEST,
                'gen_armor_tgt_fn': self.get_mach_tgt,
                'outer_req': {
                    'realm': 'TEST'  # should be ignored
                }
            }
        ])

    def test_fast_tgs_outer_wrong_realm(self):
        self._run_test_sequence([
            {
                'rep_type': KRB_TGS_REP,
                'expected_error_mode': 0,
                'use_fast': True,
                'gen_tgt_fn': self.get_user_tgt,
                'fast_armor': None,
                'outer_req': {
                    'realm': 'TEST'  # should be ignored
                }
            }
        ])

    def test_fast_outer_wrong_nonce(self):
        self._run_test_sequence([
            {
                'rep_type': KRB_AS_REP,
                'expected_error_mode': KDC_ERR_PREAUTH_REQUIRED,
                'use_fast': True,
                'fast_armor': FX_FAST_ARMOR_AP_REQUEST,
                'gen_armor_tgt_fn': self.get_mach_tgt,
                'outer_req': {
                    'nonce': '123'  # should be ignored
                }
            },
            {
                'rep_type': KRB_AS_REP,
                'expected_error_mode': 0,
                'use_fast': True,
                'gen_padata_fn': self.generate_enc_challenge_padata,
                'fast_armor': FX_FAST_ARMOR_AP_REQUEST,
                'gen_armor_tgt_fn': self.get_mach_tgt,
                'outer_req': {
                    'nonce': '123'  # should be ignored
                }
            }
        ])

    def test_fast_tgs_outer_wrong_nonce(self):
        self._run_test_sequence([
            {
                'rep_type': KRB_TGS_REP,
                'expected_error_mode': 0,
                'use_fast': True,
                'gen_tgt_fn': self.get_user_tgt,
                'fast_armor': None,
                'outer_req': {
                    'nonce': '123'  # should be ignored
                }
            }
        ])

    def test_fast_outer_wrong_flags(self):
        self._run_test_sequence([
            {
                'rep_type': KRB_AS_REP,
                'expected_error_mode': KDC_ERR_PREAUTH_REQUIRED,
                'use_fast': True,
                'fast_armor': FX_FAST_ARMOR_AP_REQUEST,
                'gen_armor_tgt_fn': self.get_mach_tgt,
                'outer_req': {
                    'kdc-options': '11111111111111111'  # should be ignored
                }
            },
            {
                'rep_type': KRB_AS_REP,
                'expected_error_mode': 0,
                'use_fast': True,
                'gen_padata_fn': self.generate_enc_challenge_padata,
                'fast_armor': FX_FAST_ARMOR_AP_REQUEST,
                'gen_armor_tgt_fn': self.get_mach_tgt,
                'outer_req': {
                    'kdc-options': '11111111111111111'  # should be ignored
                }
            }
        ])

    def test_fast_tgs_outer_wrong_flags(self):
        self._run_test_sequence([
            {
                'rep_type': KRB_TGS_REP,
                'expected_error_mode': 0,
                'use_fast': True,
                'gen_tgt_fn': self.get_user_tgt,
                'fast_armor': None,
                'outer_req': {
                    'kdc-options': '11111111111111111'  # should be ignored
                }
            }
        ])

    def test_fast_outer_no_sname(self):
        self._run_test_sequence([
            {
                'rep_type': KRB_AS_REP,
                'expected_error_mode': KDC_ERR_PREAUTH_REQUIRED,
                'use_fast': True,
                'fast_armor': FX_FAST_ARMOR_AP_REQUEST,
                'gen_armor_tgt_fn': self.get_mach_tgt,
                'outer_req': {
                    'sname': None  # should be ignored
                }
            },
            {
                'rep_type': KRB_AS_REP,
                'expected_error_mode': 0,
                'use_fast': True,
                'gen_padata_fn': self.generate_enc_challenge_padata,
                'fast_armor': FX_FAST_ARMOR_AP_REQUEST,
                'gen_armor_tgt_fn': self.get_mach_tgt,
                'outer_req': {
                    'sname': None  # should be ignored
                }
            }
        ])

    def test_fast_tgs_outer_no_sname(self):
        self._run_test_sequence([
            {
                'rep_type': KRB_TGS_REP,
                'expected_error_mode': 0,
                'use_fast': True,
                'gen_tgt_fn': self.get_user_tgt,
                'fast_armor': None,
                'outer_req': {
                    'sname': None  # should be ignored
                }
            }
        ])

    def test_fast_outer_wrong_till(self):
        self._run_test_sequence([
            {
                'rep_type': KRB_AS_REP,
                'expected_error_mode': KDC_ERR_PREAUTH_REQUIRED,
                'use_fast': True,
                'fast_armor': FX_FAST_ARMOR_AP_REQUEST,
                'gen_armor_tgt_fn': self.get_mach_tgt,
                'outer_req': {
                    'till': '15000101000000Z'  # should be ignored
                }
            },
            {
                'rep_type': KRB_AS_REP,
                'expected_error_mode': 0,
                'use_fast': True,
                'gen_padata_fn': self.generate_enc_challenge_padata,
                'fast_armor': FX_FAST_ARMOR_AP_REQUEST,
                'gen_armor_tgt_fn': self.get_mach_tgt,
                'outer_req': {
                    'till': '15000101000000Z'  # should be ignored
                }
            }
        ])

    def test_fast_tgs_outer_wrong_till(self):
        self._run_test_sequence([
            {
                'rep_type': KRB_TGS_REP,
                'expected_error_mode': 0,
                'use_fast': True,
                'gen_tgt_fn': self.get_user_tgt,
                'fast_armor': None,
                'outer_req': {
                    'till': '15000101000000Z'  # should be ignored
                }
            }
        ])

    def test_fast_authdata_fast_used(self):
        self._run_test_sequence([
            {
                'rep_type': KRB_TGS_REP,
                'expected_error_mode': 0,
                'use_fast': True,
                'gen_authdata_fn': self.generate_fast_used_auth_data,
                'gen_tgt_fn': self.get_user_tgt,
                'fast_armor': None
            }
        ])

    def test_fast_authdata_fast_not_used(self):
        # The AD-fx-fast-used authdata type can be included in the
        # authenticator or the TGT authentication data to indicate that FAST
        # must be used. The KDC must return KRB_APP_ERR_MODIFIED if it receives
        # this authdata type in a request not using FAST (RFC6113 5.4.2).
        self._run_test_sequence([
            # This request works without FAST.
            {
                'rep_type': KRB_TGS_REP,
                'expected_error_mode': 0,
                'use_fast': False,
                'gen_tgt_fn': self.get_user_tgt
            },
            # Add the 'FAST used' auth data and it now fails.
            {
                'rep_type': KRB_TGS_REP,
                'expected_error_mode': (KDC_ERR_MODIFIED,
                                        KDC_ERR_GENERIC),
                'use_fast': False,
                'gen_authdata_fn': self.generate_fast_used_auth_data,
                'gen_tgt_fn': self.get_user_tgt,
                'expect_edata': False
            }
        ])

    def test_fast_ad_fx_fast_armor(self):
        expected_sname = self.get_krbtgt_sname()

        # If the authenticator or TGT authentication data contains the
        # AD-fx-fast-armor authdata type, the KDC must reject the request
        # (RFC6113 5.4.1.1).
        self._run_test_sequence([
            # This request works.
            {
                'rep_type': KRB_TGS_REP,
                'expected_error_mode': 0,
                'use_fast': True,
                'gen_tgt_fn': self.get_user_tgt,
                'fast_armor': None
            },
            # Add the 'FAST armor' auth data and it now fails.
            {
                'rep_type': KRB_TGS_REP,
                'expected_error_mode': (KDC_ERR_GENERIC,
                                        KDC_ERR_BAD_INTEGRITY),
                'use_fast': True,
                'gen_authdata_fn': self.generate_fast_armor_auth_data,
                'gen_tgt_fn': self.get_user_tgt,
                'fast_armor': None,
                'expected_sname': expected_sname,
                'expect_edata': False
            }
        ])

    def test_fast_ad_fx_fast_armor2(self):
        # Show that we can still use the AD-fx-fast-armor authorization data in
        # FAST armor tickets.
        self._run_test_sequence([
            {
                'rep_type': KRB_AS_REP,
                'expected_error_mode': KDC_ERR_PREAUTH_REQUIRED,
                'use_fast': True,
                'fast_armor': FX_FAST_ARMOR_AP_REQUEST,
                'gen_armor_tgt_fn': self.get_mach_tgt
            },
            {
                'rep_type': KRB_AS_REP,
                'expected_error_mode': 0,
                'use_fast': True,
                'gen_padata_fn': self.generate_enc_challenge_padata,
                'gen_authdata_fn': self.generate_fast_armor_auth_data,
                # include the auth data in the FAST armor.
                'fast_armor': FX_FAST_ARMOR_AP_REQUEST,
                'gen_armor_tgt_fn': self.get_mach_tgt
            }
        ])

    def test_fast_ad_fx_fast_armor_ticket(self):
        expected_sname = self.get_krbtgt_sname()

        # If the authenticator or TGT authentication data contains the
        # AD-fx-fast-armor authdata type, the KDC must reject the request
        # (RFC6113 5.4.2).
        self._run_test_sequence([
            # This request works.
            {
                'rep_type': KRB_TGS_REP,
                'expected_error_mode': 0,
                'use_fast': True,
                'gen_tgt_fn': self.get_user_tgt,
                'fast_armor': None
            },
            # Add AD-fx-fast-armor authdata element to user TGT. This request
            # fails.
            {
                'rep_type': KRB_TGS_REP,
                'expected_error_mode': (KDC_ERR_GENERIC,
                                        KDC_ERR_BAD_INTEGRITY),
                'use_fast': True,
                'gen_tgt_fn': self.gen_tgt_fast_armor_auth_data,
                'fast_armor': None,
                'expected_sname': expected_sname,
                'expect_edata': False
            }
        ])

    def test_fast_ad_fx_fast_armor_enc_auth_data(self):
        # If the authenticator or TGT authentication data contains the
        # AD-fx-fast-armor authdata type, the KDC must reject the request
        # (RFC6113 5.4.2). However, the KDC should not reject a request that
        # contains this authdata type in enc-authorization-data.
        self._run_test_sequence([
            # This request works.
            {
                'rep_type': KRB_TGS_REP,
                'expected_error_mode': 0,
                'use_fast': True,
                'gen_tgt_fn': self.get_user_tgt,
                'fast_armor': None
            },
            # Add AD-fx-fast-armor authdata element to
            # enc-authorization-data. This request also works.
            {
                'rep_type': KRB_TGS_REP,
                'expected_error_mode': 0,
                'use_fast': True,
                'gen_enc_authdata_fn': self.generate_fast_armor_auth_data,
                'gen_tgt_fn': self.get_user_tgt,
                'fast_armor': None
            }
        ])

    def test_fast_ad_fx_fast_armor_ticket2(self):
        self._run_test_sequence([
            # Show that we can still use the modified ticket as armor.
            {
                'rep_type': KRB_AS_REP,
                'expected_error_mode': KDC_ERR_PREAUTH_REQUIRED,
                'use_fast': True,
                'fast_armor': FX_FAST_ARMOR_AP_REQUEST,
                'gen_armor_tgt_fn': self.get_mach_tgt
            },
            {
                'rep_type': KRB_AS_REP,
                'expected_error_mode': 0,
                'use_fast': True,
                'gen_padata_fn': self.generate_enc_challenge_padata,
                'fast_armor': FX_FAST_ARMOR_AP_REQUEST,
                'gen_armor_tgt_fn': self.gen_tgt_fast_armor_auth_data
            }
        ])

    def test_fast_tgs_service_ticket(self):
        # Try to use a non-TGT ticket to establish an armor key, which fails
        # (RFC6113 5.4.2).
        self._run_test_sequence([
            {
                'rep_type': KRB_TGS_REP,
                'expected_error_mode': (KDC_ERR_NOT_US,
                                        KDC_ERR_POLICY),
                'use_fast': True,
                'gen_tgt_fn': self.get_user_service_ticket,  # fails
                'fast_armor': None
            }
        ])

    def test_fast_tgs_service_ticket_mach(self):
        self._run_test_sequence([
            {
                'rep_type': KRB_TGS_REP,
                'expected_error_mode': (KDC_ERR_NOT_US,  # fails
                                        KDC_ERR_POLICY),
                'use_fast': True,
                'gen_tgt_fn': self.get_mach_service_ticket,
                'fast_armor': None
            }
        ])

    def test_simple_tgs_no_subkey(self):
        self._run_test_sequence([
            {
                'rep_type': KRB_TGS_REP,
                'expected_error_mode': 0,
                'use_fast': False,
                'gen_tgt_fn': self.get_user_tgt,
                'include_subkey': False
            }
        ])

    def test_fast_tgs_no_subkey(self):
        expected_sname = self.get_krbtgt_sname()

        # Show that omitting the subkey in the TGS-REQ authenticator fails
        # (RFC6113 5.4.2).
        self._run_test_sequence([
            {
                'rep_type': KRB_TGS_REP,
                'expected_error_mode': (KDC_ERR_GENERIC,
                                        KDC_ERR_PREAUTH_FAILED),
                'use_fast': True,
                'gen_tgt_fn': self.get_user_tgt,
                'fast_armor': None,
                'include_subkey': False,
                'expected_sname': expected_sname,
                'expect_edata': False
            }
        ])

    def test_fast_hide_client_names(self):
        self._run_test_sequence([
            {
                'rep_type': KRB_AS_REP,
                'expected_error_mode': KDC_ERR_PREAUTH_REQUIRED,
                'use_fast': True,
                'fast_armor': FX_FAST_ARMOR_AP_REQUEST,
                'gen_armor_tgt_fn': self.get_mach_tgt,
                'fast_options': str(krb5_asn1.FastOptions(
                    'hide-client-names')),
                'expected_anon': True
            },
            {
                'rep_type': KRB_AS_REP,
                'expected_error_mode': 0,
                'use_fast': True,
                'gen_padata_fn': self.generate_enc_challenge_padata,
                'fast_armor': FX_FAST_ARMOR_AP_REQUEST,
                'gen_armor_tgt_fn': self.get_mach_tgt,
                'fast_options': str(krb5_asn1.FastOptions(
                    'hide-client-names')),
                'expected_anon': True
            }
        ])

    def test_fast_tgs_hide_client_names(self):
        self._run_test_sequence([
            {
                'rep_type': KRB_TGS_REP,
                'expected_error_mode': 0,
                'use_fast': True,
                'gen_tgt_fn': self.get_user_tgt,
                'fast_armor': None,
                'fast_options': str(krb5_asn1.FastOptions(
                    'hide-client-names')),
                'expected_anon': True
            }
        ])

    def test_fast_encrypted_challenge_replay(self):
        # The KDC is supposed to check that encrypted challenges are not
        # replays (RFC6113 5.4.6), but timestamps may be reused; an encrypted
        # challenge is only considered a replay if the ciphertext is identical
        # to a previous challenge. Windows does not perform this check.

        self._run_test_sequence([
            {
                'rep_type': KRB_AS_REP,
                'expected_error_mode': KDC_ERR_PREAUTH_REQUIRED,
                'use_fast': True,
                'fast_armor': FX_FAST_ARMOR_AP_REQUEST,
                'gen_armor_tgt_fn': self.get_mach_tgt
            },
            {
                'rep_type': KRB_AS_REP,
                'expected_error_mode': 0,
                'use_fast': True,
                'gen_padata_fn': self.generate_enc_challenge_padata_replay,
                'fast_armor': FX_FAST_ARMOR_AP_REQUEST,
                'gen_armor_tgt_fn': self.get_mach_tgt,
                'repeat': 2
            }
        ])

    def test_fx_cookie_fast(self):
        """Test that the FAST cookie is present and that its value is as
        expected when FAST is used."""
        kdc_exchange_dict = self._run_test_sequence([
            {
                'rep_type': KRB_AS_REP,
                'expected_error_mode': KDC_ERR_PREAUTH_REQUIRED,
                'use_fast': True,
                'fast_armor': FX_FAST_ARMOR_AP_REQUEST,
                'gen_armor_tgt_fn': self.get_mach_tgt
            },
        ])

        cookie = kdc_exchange_dict.get('fast_cookie')
        self.assertEqual(b'Microsoft', cookie)

    def test_fx_cookie_no_fast(self):
        """Test that the FAST cookie is present and that its value is as
        expected when FAST is not used."""
        kdc_exchange_dict = self._run_test_sequence([
            {
                'rep_type': KRB_AS_REP,
                'expected_error_mode': KDC_ERR_PREAUTH_REQUIRED,
                'use_fast': False
            },
        ])

        cookie = kdc_exchange_dict.get('fast_cookie')
        self.assertEqual(b'Microsof\x00', cookie)

    def test_unsolicited_fx_cookie_preauth(self):
        """Test sending an unsolicited FX-COOKIE in an AS-REQ without
        pre-authentication data."""

        # Include a FAST cookie.
        fast_cookie = self.create_fast_cookie('Samba-Test')

        kdc_exchange_dict = self._run_test_sequence([
            {
                'rep_type': KRB_AS_REP,
                'expected_error_mode': KDC_ERR_PREAUTH_REQUIRED,
                'use_fast': True,
                'fast_armor': FX_FAST_ARMOR_AP_REQUEST,
                'gen_armor_tgt_fn': self.get_mach_tgt,
                'fast_cookie': fast_cookie,
            },
        ])

        got_cookie = kdc_exchange_dict.get('fast_cookie')
        self.assertEqual(b'Microsoft', got_cookie)

    def test_unsolicited_fx_cookie_fast(self):
        """Test sending an unsolicited FX-COOKIE in an AS-REQ with
        pre-authentication data."""

        # Include a FAST cookie.
        fast_cookie = self.create_fast_cookie('Samba-Test')

        kdc_exchange_dict = self._run_test_sequence([
            {
                'rep_type': KRB_AS_REP,
                'expected_error_mode': KDC_ERR_PREAUTH_REQUIRED,
                'use_fast': True,
                'fast_armor': FX_FAST_ARMOR_AP_REQUEST,
                'gen_armor_tgt_fn': self.get_mach_tgt,
            },
            {
                'rep_type': KRB_AS_REP,
                'expected_error_mode': 0,
                'use_fast': True,
                'gen_padata_fn': self.generate_enc_challenge_padata,
                'fast_armor': FX_FAST_ARMOR_AP_REQUEST,
                'gen_armor_tgt_fn': self.get_mach_tgt,
                'fast_cookie': fast_cookie,
            }
        ])

        got_cookie = kdc_exchange_dict.get('fast_cookie')
        self.assertIsNone(got_cookie)

    def generate_enc_timestamp_padata(self,
                                      kdc_exchange_dict,
                                      callback_dict,
                                      req_body):
        key = kdc_exchange_dict['preauth_key']

        padata = self.get_enc_timestamp_pa_data_from_key(key)
        return [padata], req_body

    def generate_enc_challenge_padata(self,
                                      kdc_exchange_dict,
                                      callback_dict,
                                      req_body,
                                      skew=0):
        armor_key = kdc_exchange_dict['armor_key']
        key = kdc_exchange_dict['preauth_key']

        client_challenge_key = (
            self.generate_client_challenge_key(armor_key, key))
        padata = self.get_challenge_pa_data(client_challenge_key, skew=skew)
        return [padata], req_body

    def generate_enc_challenge_padata_wrong_key_kdc(self,
                                      kdc_exchange_dict,
                                      callback_dict,
                                      req_body):
        armor_key = kdc_exchange_dict['armor_key']
        key = kdc_exchange_dict['preauth_key']

        kdc_challenge_key = (
            self.generate_kdc_challenge_key(armor_key, key))
        padata = self.get_challenge_pa_data(kdc_challenge_key)
        return [padata], req_body

    def generate_enc_challenge_padata_wrong_key(self,
                                                kdc_exchange_dict,
                                                callback_dict,
                                                req_body):
        key = kdc_exchange_dict['preauth_key']

        padata = self.get_challenge_pa_data(key)
        return [padata], req_body

    def generate_enc_challenge_padata_replay(self,
                                             kdc_exchange_dict,
                                             callback_dict,
                                             req_body):
        padata = callback_dict.get('replay_padata')

        if padata is None:
            armor_key = kdc_exchange_dict['armor_key']
            key = kdc_exchange_dict['preauth_key']

            client_challenge_key = (
                self.generate_client_challenge_key(armor_key, key))
            padata = self.get_challenge_pa_data(client_challenge_key)
            callback_dict['replay_padata'] = padata

        return [padata], req_body

    def generate_empty_fast(self,
                            _kdc_exchange_dict,
                            _callback_dict,
                            _req_body,
                            _fast_padata,
                            _fast_armor,
                            _checksum,
                            _fast_options=''):
        fast_padata = self.PA_DATA_create(PADATA_FX_FAST, b'')

        return fast_padata

    def _run_test_sequence(self, test_sequence,
                           client_account=KDCBaseTest.AccountType.USER,
                           client_opts=None,
                           armor_opts=None):
        if self.strict_checking:
            self.check_kdc_fast_support()

        kdc_options_default = str(krb5_asn1.KDCOptions('forwardable,'
                                                       'canonicalize'))

        client_creds = self.get_cached_creds(account_type=client_account,
                                             opts=client_opts)
        target_creds = self.get_service_creds()
        krbtgt_creds = self.get_krbtgt_creds()

        client_username = client_creds.get_username()
        client_realm = client_creds.get_realm()
        client_cname = self.PrincipalName_create(name_type=NT_PRINCIPAL,
                                                 names=[client_username])

        krbtgt_username = krbtgt_creds.get_username()
        krbtgt_realm = krbtgt_creds.get_realm()
        krbtgt_sname = self.PrincipalName_create(
            name_type=NT_SRV_INST, names=[krbtgt_username, krbtgt_realm])
        krbtgt_decryption_key = self.TicketDecryptionKey_from_creds(
            krbtgt_creds)
        krbtgt_etypes = krbtgt_creds.tgs_supported_enctypes

        target_username = target_creds.get_username()[:-1]
        target_realm = target_creds.get_realm()
        target_service = 'host'
        target_sname = self.PrincipalName_create(
            name_type=NT_SRV_HST, names=[target_service, target_username])
        target_decryption_key = self.TicketDecryptionKey_from_creds(
            target_creds)
        target_etypes = target_creds.tgs_supported_enctypes

        client_decryption_key = self.TicketDecryptionKey_from_creds(
            client_creds)
        client_etypes = client_creds.tgs_supported_enctypes

        fast_cookie = None
        preauth_etype_info2 = None

        for kdc_dict in test_sequence:
            rep_type = kdc_dict.pop('rep_type')
            self.assertIn(rep_type, (KRB_AS_REP, KRB_TGS_REP))

            expected_error_mode = kdc_dict.pop('expected_error_mode')
            if expected_error_mode == 0:
                expected_error_mode = ()
            elif not isinstance(expected_error_mode, collections.abc.Container):
                expected_error_mode = (expected_error_mode,)
            for error in expected_error_mode:
                self.assertIn(error, range(240))

            use_fast = kdc_dict.pop('use_fast')
            self.assertIs(type(use_fast), bool)

            if use_fast:
                self.assertIn('fast_armor', kdc_dict)
                fast_armor_type = kdc_dict.pop('fast_armor')

                if fast_armor_type is not None:
                    self.assertIn('gen_armor_tgt_fn', kdc_dict)
                elif KDC_ERR_GENERIC not in expected_error_mode:
                    self.assertNotIn('gen_armor_tgt_fn', kdc_dict)

                gen_armor_tgt_fn = kdc_dict.pop('gen_armor_tgt_fn', None)
                if gen_armor_tgt_fn is not None:
                    armor_tgt = gen_armor_tgt_fn(armor_opts)
                else:
                    armor_tgt = None

                fast_options = kdc_dict.pop('fast_options', '')
            else:
                fast_armor_type = None
                armor_tgt = None

                self.assertNotIn('fast_options', kdc_dict)
                fast_options = None

            if rep_type == KRB_TGS_REP:
                gen_tgt_fn = kdc_dict.pop('gen_tgt_fn')
                tgt = gen_tgt_fn(opts=client_opts)
            else:
                self.assertNotIn('gen_tgt_fn', kdc_dict)
                tgt = None

            if len(expected_error_mode) != 0:
                check_error_fn = self.generic_check_kdc_error
                check_rep_fn = None
            else:
                check_error_fn = None
                check_rep_fn = self.generic_check_kdc_rep

            etypes = kdc_dict.pop('etypes', (AES256_CTS_HMAC_SHA1_96,
                                             ARCFOUR_HMAC_MD5))

            cname = client_cname if rep_type == KRB_AS_REP else None
            crealm = client_realm

            as_req_self = kdc_dict.pop('as_req_self', False)
            if as_req_self:
                self.assertEqual(KRB_AS_REP, rep_type)

            if 'sname' in kdc_dict:
                sname = kdc_dict.pop('sname')
            else:
                if as_req_self:
                    sname = client_cname
                elif rep_type == KRB_AS_REP:
                    sname = krbtgt_sname
                else:  # KRB_TGS_REP
                    sname = target_sname

            if rep_type == KRB_AS_REP:
                srealm = krbtgt_realm
            else:  # KRB_TGS_REP
                srealm = target_realm

            if rep_type == KRB_TGS_REP:
                tgt_cname = tgt.cname
            else:
                tgt_cname = client_cname

            expect_edata = kdc_dict.pop('expect_edata', None)
            if expect_edata is not None:
                self.assertTrue(expected_error_mode)

            expected_cname = kdc_dict.pop('expected_cname', tgt_cname)
            expected_anon = kdc_dict.pop('expected_anon',
                                         False)
            expected_crealm = kdc_dict.pop('expected_crealm', client_realm)
            expected_sname = kdc_dict.pop('expected_sname', sname)
            expected_srealm = kdc_dict.pop('expected_srealm', srealm)

            expected_salt = client_creds.get_salt()

            authenticator_subkey = self.RandomKey(kcrypto.Enctype.AES256)
            if rep_type == KRB_AS_REP:
                if use_fast:
                    armor_key = self.generate_armor_key(authenticator_subkey,
                                                        armor_tgt.session_key)
                    armor_subkey = authenticator_subkey
                else:
                    armor_key = None
                    armor_subkey = authenticator_subkey
            else:  # KRB_TGS_REP
                if fast_armor_type is not None:
                    armor_subkey = self.RandomKey(kcrypto.Enctype.AES256)
                    explicit_armor_key = self.generate_armor_key(
                        armor_subkey,
                        armor_tgt.session_key)
                    armor_key = kcrypto.cf2(explicit_armor_key.key,
                                            authenticator_subkey.key,
                                            b'explicitarmor',
                                            b'tgsarmor')
                    armor_key = Krb5EncryptionKey(armor_key, None)
                else:
                    armor_key = self.generate_armor_key(authenticator_subkey,
                                                        tgt.session_key)
                    armor_subkey = authenticator_subkey

            if not kdc_dict.pop('include_subkey', True):
                authenticator_subkey = None

            if use_fast:
                generate_fast_fn = kdc_dict.pop('gen_fast_fn', None)
                if generate_fast_fn is None:
                    generate_fast_fn = functools.partial(
                        self.generate_simple_fast,
                        fast_options=fast_options)
            else:
                generate_fast_fn = None

            generate_fast_armor_fn = (
                self.generate_ap_req
                if fast_armor_type is not None
                else None)

            def _generate_padata_copy(_kdc_exchange_dict,
                                      _callback_dict,
                                      req_body,
                                      padata):
                return list(padata), req_body

            pac_request = kdc_dict.pop('pac_request', None)
            expect_pac = kdc_dict.pop('expect_pac', True)

            pac_options = kdc_dict.pop('pac_options', '1')  # claims support

            kdc_options = kdc_dict.pop('kdc_options', kdc_options_default)

            gen_padata_fn = kdc_dict.pop('gen_padata_fn', None)

            if rep_type == KRB_AS_REP and gen_padata_fn is not None:
                self.assertIsNotNone(preauth_etype_info2)

                preauth_key = self.PasswordKey_from_etype_info2(
                    client_creds,
                    preauth_etype_info2[0],
                    client_creds.get_kvno())
            else:
                preauth_key = None

            if use_fast:
                try:
                    fast_cookie = kdc_dict.pop('fast_cookie')
                except KeyError:
                    pass

                generate_fast_padata_fn = gen_padata_fn
                generate_padata_fn = (functools.partial(_generate_padata_copy,
                                                         padata=[fast_cookie])
                                       if fast_cookie is not None else None)
            else:
                generate_fast_padata_fn = None
                generate_padata_fn = gen_padata_fn

            gen_authdata_fn = kdc_dict.pop('gen_authdata_fn', None)
            if gen_authdata_fn is not None:
                auth_data = [gen_authdata_fn()]
            else:
                auth_data = None

            gen_enc_authdata_fn = kdc_dict.pop('gen_enc_authdata_fn', None)
            if gen_enc_authdata_fn is not None:
                enc_auth_data = [gen_enc_authdata_fn()]

                enc_auth_data_key = authenticator_subkey
                enc_auth_data_usage = KU_TGS_REQ_AUTH_DAT_SUBKEY
                if enc_auth_data_key is None:
                    enc_auth_data_key = tgt.session_key
                    enc_auth_data_usage = KU_TGS_REQ_AUTH_DAT_SESSION
            else:
                enc_auth_data = None

                enc_auth_data_key = None
                enc_auth_data_usage = None

            if not use_fast:
                self.assertNotIn('inner_req', kdc_dict)
                self.assertNotIn('outer_req', kdc_dict)
            inner_req = kdc_dict.pop('inner_req', None)
            outer_req = kdc_dict.pop('outer_req', None)

            expected_flags = kdc_dict.pop('expected_flags', None)
            if expected_flags is not None:
                expected_flags = krb5_asn1.TicketFlags(expected_flags)
            unexpected_flags = kdc_dict.pop('unexpected_flags', None)
            if unexpected_flags is not None:
                unexpected_flags = krb5_asn1.TicketFlags(unexpected_flags)

            fast_ap_options = kdc_dict.pop('fast_ap_options', None)

            strict_edata_checking = kdc_dict.pop('strict_edata_checking', True)

            if rep_type == KRB_AS_REP:
                if as_req_self:
                    expected_supported_etypes = client_etypes
                    decryption_key = client_decryption_key
                else:
                    expected_supported_etypes = krbtgt_etypes
                    decryption_key = krbtgt_decryption_key

                kdc_exchange_dict = self.as_exchange_dict(
                    creds=client_creds,
                    expected_crealm=expected_crealm,
                    expected_cname=expected_cname,
                    expected_anon=expected_anon,
                    expected_srealm=expected_srealm,
                    expected_sname=expected_sname,
                    expected_supported_etypes=expected_supported_etypes,
                    expected_flags=expected_flags,
                    unexpected_flags=unexpected_flags,
                    ticket_decryption_key=decryption_key,
                    generate_fast_fn=generate_fast_fn,
                    generate_fast_armor_fn=generate_fast_armor_fn,
                    generate_fast_padata_fn=generate_fast_padata_fn,
                    fast_armor_type=fast_armor_type,
                    generate_padata_fn=generate_padata_fn,
                    check_error_fn=check_error_fn,
                    check_rep_fn=check_rep_fn,
                    check_kdc_private_fn=self.generic_check_kdc_private,
                    callback_dict={},
                    expected_error_mode=expected_error_mode,
                    expected_salt=expected_salt,
                    authenticator_subkey=authenticator_subkey,
                    preauth_key=preauth_key,
                    auth_data=auth_data,
                    armor_key=armor_key,
                    armor_tgt=armor_tgt,
                    armor_subkey=armor_subkey,
                    kdc_options=kdc_options,
                    inner_req=inner_req,
                    outer_req=outer_req,
                    expect_pac=expect_pac,
                    pac_request=pac_request,
                    pac_options=pac_options,
                    fast_ap_options=fast_ap_options,
                    strict_edata_checking=strict_edata_checking,
                    expect_edata=expect_edata)
            else:  # KRB_TGS_REP
                kdc_exchange_dict = self.tgs_exchange_dict(
                    creds=client_creds,
                    expected_crealm=expected_crealm,
                    expected_cname=expected_cname,
                    expected_anon=expected_anon,
                    expected_srealm=expected_srealm,
                    expected_sname=expected_sname,
                    expected_supported_etypes=target_etypes,
                    expected_flags=expected_flags,
                    unexpected_flags=unexpected_flags,
                    ticket_decryption_key=target_decryption_key,
                    generate_fast_fn=generate_fast_fn,
                    generate_fast_armor_fn=generate_fast_armor_fn,
                    generate_fast_padata_fn=generate_fast_padata_fn,
                    fast_armor_type=fast_armor_type,
                    generate_padata_fn=generate_padata_fn,
                    check_error_fn=check_error_fn,
                    check_rep_fn=check_rep_fn,
                    check_kdc_private_fn=self.generic_check_kdc_private,
                    expected_error_mode=expected_error_mode,
                    callback_dict={},
                    tgt=tgt,
                    armor_key=armor_key,
                    armor_tgt=armor_tgt,
                    armor_subkey=armor_subkey,
                    authenticator_subkey=authenticator_subkey,
                    auth_data=auth_data,
                    body_checksum_type=None,
                    kdc_options=kdc_options,
                    inner_req=inner_req,
                    outer_req=outer_req,
                    expect_pac=expect_pac,
                    pac_request=pac_request,
                    pac_options=pac_options,
                    fast_ap_options=fast_ap_options,
                    strict_edata_checking=strict_edata_checking,
                    expect_edata=expect_edata)

            repeat = kdc_dict.pop('repeat', 1)
            for _ in range(repeat):
                rep = self._generic_kdc_exchange(
                    kdc_exchange_dict,
                    cname=cname,
                    realm=crealm,
                    sname=sname,
                    etypes=etypes,
                    EncAuthorizationData=enc_auth_data,
                    EncAuthorizationData_key=enc_auth_data_key,
                    EncAuthorizationData_usage=enc_auth_data_usage)
                if len(expected_error_mode) == 0:
                    self.check_reply(rep, rep_type)

                    fast_cookie = None
                    preauth_etype_info2 = None

                    # Check whether the ticket contains a PAC.
                    ticket = kdc_exchange_dict['rep_ticket_creds']
                    pac = self.get_ticket_pac(ticket, expect_pac=expect_pac)
                    if expect_pac:
                        self.assertIsNotNone(pac)
                    else:
                        self.assertIsNone(pac)
                else:
                    self.check_error_rep(rep, expected_error_mode)

                    if 'fast_cookie' in kdc_exchange_dict:
                        fast_cookie = self.create_fast_cookie(
                            kdc_exchange_dict['fast_cookie'])
                    else:
                        fast_cookie = None

                    if KDC_ERR_PREAUTH_REQUIRED in expected_error_mode:
                        preauth_etype_info2 = (
                            kdc_exchange_dict['preauth_etype_info2'])
                    else:
                        preauth_etype_info2 = None

            # Ensure we used all the parameters given to us.
            self.assertEqual({}, kdc_dict)

        return kdc_exchange_dict

    def generate_enc_pa_rep_padata(self,
                                   kdc_exchange_dict,
                                   callback_dict,
                                   req_body):
        padata = self.PA_DATA_create(PADATA_REQ_ENC_PA_REP, b'')

        return [padata], req_body

    def generate_enc_pa_rep_challenge_padata(self,
                                             kdc_exchange_dict,
                                             callback_dict,
                                             req_body):
        padata, req_body = self.generate_enc_challenge_padata(kdc_exchange_dict,
                                                              callback_dict,
                                                              req_body)

        padata.append(self.PA_DATA_create(PADATA_REQ_ENC_PA_REP, b''))

        return padata, req_body

    def generate_enc_pa_rep_timestamp_padata(self,
                                             kdc_exchange_dict,
                                             callback_dict,
                                             req_body):
        padata, req_body = self.generate_enc_timestamp_padata(kdc_exchange_dict,
                                                              callback_dict,
                                                              req_body)

        padata.append(self.PA_DATA_create(PADATA_REQ_ENC_PA_REP, b''))

        return padata, req_body

    def generate_fast_armor_auth_data(self):
        auth_data = self.AuthorizationData_create(AD_FX_FAST_ARMOR, b'')

        return auth_data

    def generate_fast_used_auth_data(self):
        auth_data = self.AuthorizationData_create(AD_FX_FAST_USED, b'')

        return auth_data

    def gen_tgt_fast_armor_auth_data(self, opts):
        user_tgt = self.get_user_tgt(opts)

        auth_data = self.generate_fast_armor_auth_data()

        def modify_fn(enc_part):
            enc_part['authorization-data'].append(auth_data)

            return enc_part

        checksum_keys = self.get_krbtgt_checksum_key()

        # Use our modified TGT to replace the one in the request.
        return self.modified_ticket(user_tgt,
                                    modify_fn=modify_fn,
                                    checksum_keys=checksum_keys)

    def create_fast_cookie(self, cookie):
        self.assertIsNotNone(cookie)
        if self.strict_checking:
            self.assertNotEqual(0, len(cookie))

        return self.PA_DATA_create(PADATA_FX_COOKIE, cookie)

    def check_kdc_fast_support(self):
        # Check that the KDC supports FAST

        samdb = self.get_samdb()

        krbtgt_rid = security.DOMAIN_RID_KRBTGT
        krbtgt_sid = '%s-%d' % (samdb.get_domain_sid(), krbtgt_rid)

        res = samdb.search(base='<SID=%s>' % krbtgt_sid,
                           scope=ldb.SCOPE_BASE,
                           attrs=['msDS-SupportedEncryptionTypes'])

        krbtgt_etypes = int(res[0]['msDS-SupportedEncryptionTypes'][0])

        self.assertTrue(
            security.KERB_ENCTYPE_FAST_SUPPORTED & krbtgt_etypes)
        self.assertTrue(
            security.KERB_ENCTYPE_COMPOUND_IDENTITY_SUPPORTED & krbtgt_etypes)
        self.assertTrue(
            security.KERB_ENCTYPE_CLAIMS_SUPPORTED & krbtgt_etypes)

    def get_mach_tgt(self, opts):
        if opts is None:
            opts = {}
        mach_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER,
            opts={
                **opts,
                'fast_support': True,
                'claims_support': True,
                'compound_id_support': True,
                'supported_enctypes': (
                    security.KERB_ENCTYPE_RC4_HMAC_MD5 |
                    security.KERB_ENCTYPE_AES256_CTS_HMAC_SHA1_96_SK
                ),
            })
        return self.get_tgt(mach_creds)

    def get_rodc_issued_mach_tgt(self, opts):
        return self.issued_by_rodc(self.get_mach_tgt(opts))

    def get_user_tgt(self, opts):
        user_creds = self.get_cached_creds(
            account_type=self.AccountType.USER,
            opts=opts)
        return self.get_tgt(user_creds)

    def get_user_service_ticket(self, opts):
        user_tgt = self.get_user_tgt(opts)
        service_creds = self.get_service_creds()
        return self.get_service_ticket(user_tgt, service_creds)

    def get_mach_service_ticket(self, opts):
        mach_tgt = self.get_mach_tgt(opts)
        service_creds = self.get_service_creds()
        return self.get_service_ticket(mach_tgt, service_creds)

    def get_service_ticket_invalid_checksum(self, opts):
        ticket = self.get_user_service_ticket(opts)

        krbtgt_creds = self.get_krbtgt_creds()
        krbtgt_key = self.TicketDecryptionKey_from_creds(krbtgt_creds)

        zeroed_key = ZeroedChecksumKey(krbtgt_key.key,
                                       krbtgt_key.kvno)

        server_key = ticket.decryption_key
        checksum_keys = {
            krb5pac.PAC_TYPE_SRV_CHECKSUM: server_key,
            krb5pac.PAC_TYPE_KDC_CHECKSUM: krbtgt_key,
            krb5pac.PAC_TYPE_TICKET_CHECKSUM: zeroed_key,
        }

        return self.modified_ticket(
            ticket,
            checksum_keys=checksum_keys,
            include_checksums={krb5pac.PAC_TYPE_TICKET_CHECKSUM: True})


if __name__ == "__main__":
    global_asn1_print = False
    global_hexdump = False
    import unittest
    unittest.main()
