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

import functools
import os
import sys
import collections

import ldb

from samba.dcerpc import security
from samba.tests.krb5.raw_testcase import Krb5EncryptionKey
from samba.tests.krb5.kdc_base_test import KDCBaseTest
from samba.tests.krb5.rfc4120_constants import (
    AD_FX_FAST_ARMOR,
    AD_FX_FAST_USED,
    AES256_CTS_HMAC_SHA1_96,
    ARCFOUR_HMAC_MD5,
    FX_FAST_ARMOR_AP_REQUEST,
    KDC_ERR_ETYPE_NOSUPP,
    KDC_ERR_GENERIC,
    KDC_ERR_S_PRINCIPAL_UNKNOWN,
    KDC_ERR_NOT_US,
    KDC_ERR_PREAUTH_FAILED,
    KDC_ERR_PREAUTH_REQUIRED,
    KDC_ERR_UNKNOWN_CRITICAL_FAST_OPTIONS,
    KRB_AS_REP,
    KRB_TGS_REP,
    NT_PRINCIPAL,
    NT_SRV_HST,
    NT_SRV_INST,
    PADATA_FX_COOKIE,
    PADATA_FX_FAST,
)
import samba.tests.krb5.rfc4120_pyasn1 as krb5_asn1
import samba.tests.krb5.kcrypto as kcrypto

sys.path.insert(0, "bin/python")
os.environ["PYTHONUNBUFFERED"] = "1"

global_asn1_print = False
global_hexdump = False


class FAST_Tests(KDCBaseTest):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()

        cls.user_tgt = None
        cls.user_service_ticket = None

        cls.mach_tgt = None
        cls.mach_service_ticket = None

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

    def test_simple_tgs(self):
        self._run_test_sequence([
            {
                'rep_type': KRB_TGS_REP,
                'expected_error_mode': 0,
                'use_fast': False,
                'gen_tgt_fn': self.get_user_tgt
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
                'expected_error_mode': KDC_ERR_GENERIC,
                'use_fast': True,
                'fast_armor': FX_FAST_ARMOR_AP_REQUEST,
                'gen_armor_tgt_fn': self.get_mach_tgt,
                'sname': None,
                'expected_sname': expected_sname
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
                'expected_sname': expected_sname
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
                'expected_error_mode': KDC_ERR_NOT_US,
                'use_fast': False,
                'gen_tgt_fn': self.get_user_service_ticket,
                'expect_edata': False
            }
        ])

    def test_simple_tgs_service_ticket_mach(self):
        self._run_test_sequence([
            {
                'rep_type': KRB_TGS_REP,
                'expected_error_mode': KDC_ERR_NOT_US,
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
                'etypes': ()
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
                'etypes': ()
            }
        ])

    def test_empty_fast(self):
        # Add an empty PA-FX-FAST in the initial AS-REQ. This should get
        # rejected with a Generic error.
        self._run_test_sequence([
            {
                'rep_type': KRB_AS_REP,
                'expected_error_mode': KDC_ERR_GENERIC,
                'use_fast': True,
                'gen_fast_fn': self.generate_empty_fast,
                'fast_armor': None,
                'gen_armor_tgt_fn': self.get_mach_tgt,
                'expect_edata': False
            }
        ])

    def test_fast_unknown_critical_option(self):
        self._run_test_sequence([
            {
                'rep_type': KRB_AS_REP,
                'expected_error_mode': KDC_ERR_UNKNOWN_CRITICAL_FAST_OPTIONS,
                'use_fast': True,
                'fast_options': '001',  # unsupported critical option
                'fast_armor': FX_FAST_ARMOR_AP_REQUEST,
                'gen_armor_tgt_fn': self.get_mach_tgt
            }
        ])

    def test_unarmored_as_req(self):
        self._run_test_sequence([
            {
                'rep_type': KRB_AS_REP,
                'expected_error_mode': KDC_ERR_GENERIC,
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

    def test_fast_encrypted_challenge_clock_skew(self):
        # The KDC is supposed to confirm that the timestamp is within its
        # current clock skew, and return KRB_APP_ERR_SKEW if it is not (RFC6113
        # 5.4.6).  However, Windows accepts a skewed timestamp in the encrypted
        # challenge.
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
                'gen_padata_fn': functools.partial(
                    self.generate_enc_challenge_padata,
                    skew=10000),
                'fast_armor': FX_FAST_ARMOR_AP_REQUEST,
                'gen_armor_tgt_fn': self.get_mach_tgt
            }
        ])

    def test_fast_invalid_tgt(self):
        # The armor ticket 'sname' field is required to identify the target
        # realm TGS (RFC6113 5.4.1.1). However, Windows will still accept a
        # service ticket identifying a different server principal.
        self._run_test_sequence([
            {
                'rep_type': KRB_AS_REP,
                'expected_error_mode': KDC_ERR_PREAUTH_REQUIRED,
                'use_fast': True,
                'fast_armor': FX_FAST_ARMOR_AP_REQUEST,
                'gen_armor_tgt_fn': self.get_user_service_ticket
            },
            {
                'rep_type': KRB_AS_REP,
                'expected_error_mode': 0,
                'use_fast': True,
                'gen_padata_fn': self.generate_enc_challenge_padata,
                'fast_armor': FX_FAST_ARMOR_AP_REQUEST,
                'gen_armor_tgt_fn': self.get_user_service_ticket
                                    # ticket not identifying TGS of current
                                    # realm
            }
        ])

    def test_fast_invalid_tgt_mach(self):
        self._run_test_sequence([
            {
                'rep_type': KRB_AS_REP,
                'expected_error_mode': KDC_ERR_PREAUTH_REQUIRED,
                'use_fast': True,
                'fast_armor': FX_FAST_ARMOR_AP_REQUEST,
                'gen_armor_tgt_fn': self.get_mach_service_ticket
            },
            {
                'rep_type': KRB_AS_REP,
                'expected_error_mode': 0,
                'use_fast': True,
                'gen_padata_fn': self.generate_enc_challenge_padata,
                'fast_armor': FX_FAST_ARMOR_AP_REQUEST,
                'gen_armor_tgt_fn': self.get_mach_service_ticket
                                    # ticket not identifying TGS of current
                                    # realm
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
                'expected_error_mode': KDC_ERR_PREAUTH_REQUIRED,
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
                'expected_error_mode': KDC_ERR_GENERIC,
                # should be KRB_APP_ERR_MODIFIED
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
                'expected_error_mode': KDC_ERR_GENERIC,
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
                'expected_error_mode': KDC_ERR_GENERIC,
                'use_fast': True,
                'gen_tgt_fn': self.gen_tgt_fast_armor_auth_data,
                'fast_armor': None,
                'expected_sname': expected_sname,
                'expect_edata': False
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
                'expected_error_mode': KDC_ERR_NOT_US,
                'use_fast': True,
                'gen_tgt_fn': self.get_user_service_ticket,  # fails
                'fast_armor': None
            }
        ])

    def test_fast_tgs_service_ticket_mach(self):
        self._run_test_sequence([
            {
                'rep_type': KRB_TGS_REP,
                'expected_error_mode': KDC_ERR_NOT_US,  # fails
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
                'expected_error_mode': KDC_ERR_GENERIC,
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
                'fast_options': '01',  # hide client names
                'expected_anon': True
            },
            {
                'rep_type': KRB_AS_REP,
                'expected_error_mode': 0,
                'use_fast': True,
                'gen_padata_fn': self.generate_enc_challenge_padata,
                'fast_armor': FX_FAST_ARMOR_AP_REQUEST,
                'gen_armor_tgt_fn': self.get_mach_tgt,
                'fast_options': '01',  # hide client names
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
                'fast_options': '01',  # hide client names
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

    def _run_test_sequence(self, test_sequence):
        if self.strict_checking:
            self.check_kdc_fast_support()

        kdc_options_default = str(krb5_asn1.KDCOptions('forwardable,'
                                                       'renewable,'
                                                       'canonicalize,'
                                                       'renewable-ok'))

        client_creds = self.get_client_creds()
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
                    armor_tgt = gen_armor_tgt_fn()
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
                tgt = gen_tgt_fn()
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

            if 'sname' in kdc_dict:
                sname = kdc_dict.pop('sname')
            else:
                if rep_type == KRB_AS_REP:
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

            if rep_type == KRB_AS_REP:
                kdc_exchange_dict = self.as_exchange_dict(
                    expected_crealm=expected_crealm,
                    expected_cname=expected_cname,
                    expected_anon=expected_anon,
                    expected_srealm=expected_srealm,
                    expected_sname=expected_sname,
                    expected_supported_etypes=krbtgt_etypes,
                    expected_flags=expected_flags,
                    unexpected_flags=unexpected_flags,
                    ticket_decryption_key=krbtgt_decryption_key,
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
                    client_as_etypes=etypes,
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
                    pac_request=True,
                    pac_options=pac_options,
                    expect_edata=expect_edata)
            else:  # KRB_TGS_REP
                kdc_exchange_dict = self.tgs_exchange_dict(
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
                    pac_request=None,
                    pac_options=pac_options,
                    expect_edata=expect_edata)

            repeat = kdc_dict.pop('repeat', 1)
            for _ in range(repeat):
                rep = self._generic_kdc_exchange(kdc_exchange_dict,
                                                 cname=cname,
                                                 realm=crealm,
                                                 sname=sname,
                                                 etypes=etypes)
                if len(expected_error_mode) == 0:
                    self.check_reply(rep, rep_type)

                    fast_cookie = None
                    preauth_etype_info2 = None
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

    def generate_fast_armor_auth_data(self):
        auth_data = self.AuthorizationData_create(AD_FX_FAST_ARMOR, b'')

        return auth_data

    def generate_fast_used_auth_data(self):
        auth_data = self.AuthorizationData_create(AD_FX_FAST_USED, b'')

        return auth_data

    def gen_tgt_fast_armor_auth_data(self):
        user_tgt = self.get_user_tgt()

        auth_data = self.generate_fast_armor_auth_data()

        def modify_fn(enc_part):
            enc_part['authorization-data'].append(auth_data)

            return enc_part

        checksum_keys = self.get_krbtgt_checksum_key()

        # Use our modifed TGT to replace the one in the request.
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

    def get_mach_tgt(self):
        if self.mach_tgt is None:
            mach_creds = self.get_mach_creds()
            type(self).mach_tgt = self.get_tgt(mach_creds)

        return self.mach_tgt

    def get_user_tgt(self):
        if self.user_tgt is None:
            user_creds = self.get_client_creds()
            type(self).user_tgt = self.get_tgt(user_creds)

        return self.user_tgt

    def get_user_service_ticket(self):
        if self.user_service_ticket is None:
            user_tgt = self.get_user_tgt()
            service_creds = self.get_service_creds()
            type(self).user_service_ticket = (
                self.get_service_ticket(user_tgt, service_creds))

        return self.user_service_ticket

    def get_mach_service_ticket(self):
        if self.mach_service_ticket is None:
            mach_tgt = self.get_mach_tgt()
            service_creds = self.get_service_creds()
            type(self).mach_service_ticket = (
                self.get_service_ticket(mach_tgt, service_creds))

        return self.mach_service_ticket


if __name__ == "__main__":
    global_asn1_print = False
    global_hexdump = False
    import unittest
    unittest.main()
