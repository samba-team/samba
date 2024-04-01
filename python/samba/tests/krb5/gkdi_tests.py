#!/usr/bin/env python3
# Unix SMB/CIFS implementation.
# Copyright (C) Catalyst.Net Ltd 2023
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
#

import sys
import os

sys.path.insert(0, "bin/python")
os.environ["PYTHONUNBUFFERED"] = "1"

import secrets

from typing import ClassVar, Optional

from samba.dcerpc import gkdi, misc
from samba.gkdi import (
    Algorithm,
    Gkid,
    KEY_CYCLE_DURATION,
    KEY_LEN_BYTES,
    MAX_CLOCK_SKEW,
    NtTime,
    NtTimeDelta,
    SeedKeyPair,
)
from samba.hresult import HRES_E_INVALIDARG, HRES_NTE_BAD_KEY, HRES_NTE_NO_KEY
from samba.nt_time import timedelta_from_nt_time_delta

from samba.tests.gkdi import GetKeyError, GkdiBaseTest, ROOT_KEY_START_TIME
from samba.tests.krb5.kdc_base_test import KDCBaseTest


class GkdiKdcBaseTest(GkdiBaseTest, KDCBaseTest):
    def new_root_key(self, *args, **kwargs) -> misc.GUID:
        samdb = self.get_samdb()
        domain_dn = self.get_server_dn(samdb)
        return self.create_root_key(samdb, domain_dn, *args, **kwargs)

    def gkdi_conn(self) -> gkdi.gkdi:
        # The seed keys used by Group Managed Service Accounts correspond to the
        # Enterprise DCs SID (S-1-5-9); as such they can be retrieved only by
        # server accounts.
        return self.gkdi_connect(
            self.dc_host,
            self.get_lp(),
            self.get_cached_creds(account_type=self.AccountType.SERVER),
        )

    def check_rpc_get_key(
        self, root_key_id: Optional[misc.GUID], gkid: Gkid
    ) -> SeedKeyPair:
        got_key_pair = self.rpc_get_key(
            self.gkdi_conn(), self.gmsa_sd, root_key_id, gkid
        )
        expected_key_pair = self.get_key(
            self.get_samdb(),
            self.gmsa_sd,
            root_key_id,
            gkid,
            root_key_id_hint=got_key_pair.root_key_id if root_key_id is None else None,
        )
        self.assertEqual(
            got_key_pair.root_key_id,
            expected_key_pair.root_key_id,
            "root key IDs must match",
        )
        self.assertEqual(got_key_pair, expected_key_pair, "key pairs must match")

        return got_key_pair


class GkdiExplicitRootKeyTests(GkdiKdcBaseTest):
    def test_current_l0_idx(self):
        """Request a key with the current L0 index. This index is regularly
        incremented every 427 days or so."""
        root_key_id = self.new_root_key()

        # It actually doesn’t matter what we specify for the L1 and L2 indices.
        # We’ll get the same result regardless — they just cannot specify a key
        # from the future.
        current_gkid = self.current_gkid(self.get_samdb())
        key = self.check_rpc_get_key(root_key_id, current_gkid)

        self.assertEqual(current_gkid, key.gkid)
        self.assertEqual(root_key_id, key.root_key_id)

    def test_previous_l0_idx(self):
        """Request a key with a previous L0 index."""
        root_key_id = self.new_root_key(use_start_time=ROOT_KEY_START_TIME)

        # It actually doesn’t matter what we specify for the L1 and L2 indices.
        # We’ll get the same result regardless.
        previous_l0_idx = self.current_gkid(self.get_samdb()).l0_idx - 1
        key = self.check_rpc_get_key(root_key_id, Gkid(previous_l0_idx, 0, 0))

        # Expect to get an L1 seed key.
        self.assertIsNotNone(key.l1_key)
        self.assertIsNone(key.l2_key)
        self.assertEqual(Gkid(previous_l0_idx, 31, 31), key.gkid)
        self.assertEqual(root_key_id, key.root_key_id)

    def test_algorithm_sha1(self):
        """Test with the SHA1 algorithm."""
        key = self.check_rpc_get_key(
            self.new_root_key(hash_algorithm=Algorithm.SHA1),
            self.current_gkid(self.get_samdb()),
        )
        self.assertIs(Algorithm.SHA1, key.hash_algorithm)

    def test_algorithm_sha256(self):
        """Test with the SHA256 algorithm."""
        key = self.check_rpc_get_key(
            self.new_root_key(hash_algorithm=Algorithm.SHA256),
            self.current_gkid(self.get_samdb()),
        )
        self.assertIs(Algorithm.SHA256, key.hash_algorithm)

    def test_algorithm_sha384(self):
        """Test with the SHA384 algorithm."""
        key = self.check_rpc_get_key(
            self.new_root_key(hash_algorithm=Algorithm.SHA384),
            self.current_gkid(self.get_samdb()),
        )
        self.assertIs(Algorithm.SHA384, key.hash_algorithm)

    def test_algorithm_sha512(self):
        """Test with the SHA512 algorithm."""
        key = self.check_rpc_get_key(
            self.new_root_key(hash_algorithm=Algorithm.SHA512),
            self.current_gkid(self.get_samdb()),
        )
        self.assertIs(Algorithm.SHA512, key.hash_algorithm)

    def test_algorithm_none(self):
        """Test without a specified algorithm."""
        key = self.check_rpc_get_key(
            self.new_root_key(hash_algorithm=None),
            self.current_gkid(self.get_samdb()),
        )
        self.assertIs(Algorithm.SHA256, key.hash_algorithm)

    def test_future_key(self):
        """Try to request a key from the future."""
        root_key_id = self.new_root_key(use_start_time=ROOT_KEY_START_TIME)

        future_gkid = self.current_gkid(
            self.get_samdb(),
            offset=timedelta_from_nt_time_delta(
                NtTimeDelta(KEY_CYCLE_DURATION + MAX_CLOCK_SKEW)
            )
        )

        with self.assertRaises(GetKeyError) as err:
            self.get_key(self.get_samdb(), self.gmsa_sd, root_key_id, future_gkid)

        self.assertEqual(
            HRES_E_INVALIDARG,
            err.exception.args[0],
            "requesting a key from the future should fail with INVALID_PARAMETER",
        )

        with self.assertRaises(GetKeyError) as rpc_err:
            self.rpc_get_key(self.gkdi_conn(), self.gmsa_sd, root_key_id, future_gkid)

        self.assertEqual(
            HRES_E_INVALIDARG,
            rpc_err.exception.args[0],
            "requesting a key from the future should fail with INVALID_PARAMETER",
        )

    def test_root_key_use_start_time_zero(self):
        """Attempt to use a root key with an effective time of zero."""
        root_key_id = self.new_root_key(use_start_time=NtTime(0))

        gkid = self.current_gkid(self.get_samdb())

        with self.assertRaises(GetKeyError) as err:
            self.get_key(self.get_samdb(), self.gmsa_sd, root_key_id, gkid)

        self.assertEqual(
            HRES_NTE_BAD_KEY,
            err.exception.args[0],
            "using a root key with an effective time of zero should fail with BAD_KEY",
        )

        with self.assertRaises(GetKeyError) as rpc_err:
            self.rpc_get_key(self.gkdi_conn(), self.gmsa_sd, root_key_id, gkid)

        self.assertEqual(
            HRES_NTE_BAD_KEY,
            rpc_err.exception.args[0],
            "using a root key with an effective time of zero should fail with BAD_KEY",
        )

    def test_root_key_use_start_time_too_low(self):
        """Attempt to use a root key with an effective time set too low."""
        root_key_id = self.new_root_key(use_start_time=NtTime(ROOT_KEY_START_TIME - 1))

        gkid = self.current_gkid(self.get_samdb())

        with self.assertRaises(GetKeyError) as err:
            self.get_key(self.get_samdb(), self.gmsa_sd, root_key_id, gkid)

        self.assertEqual(
            HRES_E_INVALIDARG,
            err.exception.args[0],
            "using a root key with too low effective time should fail with"
            " INVALID_PARAMETER",
        )

        with self.assertRaises(GetKeyError) as rpc_err:
            self.rpc_get_key(self.gkdi_conn(), self.gmsa_sd, root_key_id, gkid)

        self.assertEqual(
            HRES_E_INVALIDARG,
            rpc_err.exception.args[0],
            "using a root key with too low effective time should fail with"
            " INVALID_PARAMETER",
        )

    def test_before_valid(self):
        """Attempt to use a key before it is valid."""
        gkid = self.current_gkid(self.get_samdb())
        valid_start_time = NtTime(
            gkid.start_nt_time() + KEY_CYCLE_DURATION + MAX_CLOCK_SKEW
        )

        # Using a valid root key is allowed.
        valid_root_key_id = self.new_root_key(use_start_time=valid_start_time)
        self.check_rpc_get_key(valid_root_key_id, gkid)

        # But attempting to use a root key that is not yet valid will result in
        # an INVALID_PARAMETER error.
        invalid_root_key_id = self.new_root_key(use_start_time=valid_start_time + 1)

        with self.assertRaises(GetKeyError) as err:
            self.get_key(self.get_samdb(), self.gmsa_sd, invalid_root_key_id, gkid)

        self.assertEqual(
            HRES_E_INVALIDARG,
            err.exception.args[0],
            "using a key before it is valid should fail with INVALID_PARAMETER",
        )

        with self.assertRaises(GetKeyError) as rpc_err:
            self.rpc_get_key(self.gkdi_conn(), self.gmsa_sd, invalid_root_key_id, gkid)

        self.assertEqual(
            HRES_E_INVALIDARG,
            rpc_err.exception.args[0],
            "using a key before it is valid should fail with INVALID_PARAMETER",
        )

    def test_non_existent_root_key(self):
        """Attempt to use a non‐existent root key."""
        root_key_id = misc.GUID(secrets.token_bytes(16))

        gkid = self.current_gkid(self.get_samdb())

        with self.assertRaises(GetKeyError) as err:
            self.get_key(self.get_samdb(), self.gmsa_sd, root_key_id, gkid)

        self.assertEqual(
            HRES_NTE_NO_KEY,
            err.exception.args[0],
            "using a non‐existent root key should fail with NO_KEY",
        )

        with self.assertRaises(GetKeyError) as rpc_err:
            self.rpc_get_key(self.gkdi_conn(), self.gmsa_sd, root_key_id, gkid)

        self.assertEqual(
            HRES_NTE_NO_KEY,
            rpc_err.exception.args[0],
            "using a non‐existent root key should fail with NO_KEY",
        )

    def test_root_key_wrong_length(self):
        """Attempt to use a root key that is the wrong length."""
        root_key_id = self.new_root_key(data=bytes(KEY_LEN_BYTES // 2))

        gkid = self.current_gkid(self.get_samdb())

        with self.assertRaises(GetKeyError) as err:
            self.get_key(self.get_samdb(), self.gmsa_sd, root_key_id, gkid)

        self.assertEqual(
            HRES_NTE_BAD_KEY,
            err.exception.args[0],
            "using a root key that is the wrong length should fail with BAD_KEY",
        )

        with self.assertRaises(GetKeyError) as rpc_err:
            self.rpc_get_key(self.gkdi_conn(), self.gmsa_sd, root_key_id, gkid)

        self.assertEqual(
            HRES_NTE_BAD_KEY,
            rpc_err.exception.args[0],
            "using a root key that is the wrong length should fail with BAD_KEY",
        )


class GkdiImplicitRootKeyTests(GkdiKdcBaseTest):
    _root_key: ClassVar[misc.GUID]

    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()

        cls._root_key = None

    def setUp(self) -> None:
        super().setUp()

        if self._root_key is None:
            # GKDI requires a root key to operate. Creating a root key here
            # saves creating one before every test.
            #
            # We cannot delete this key after the tests have run, as Windows
            # might have decided to cache it to be used in subsequent runs. It
            # will keep a root key cached even if the corresponding AD object
            # has been deleted, leading to various problems later.
            cls = type(self)
            cls._root_key = self.new_root_key(use_start_time=ROOT_KEY_START_TIME)

    def test_l1_seed_key(self):
        """Request a key and expect to receive an L1 seed key."""
        gkid = Gkid(300, 0, 31)
        key = self.check_rpc_get_key(None, gkid)

        # Expect to get an L1 seed key.
        self.assertIsNotNone(key.l1_key)
        self.assertIsNone(key.l2_key)
        self.assertEqual(gkid, key.gkid)

    def test_l2_seed_key(self):
        """Request a key and expect to receive an L2 seed key."""
        gkid = Gkid(300, 0, 0)
        key = self.check_rpc_get_key(None, gkid)

        # Expect to get an L2 seed key.
        self.assertIsNone(key.l1_key)
        self.assertIsNotNone(key.l2_key)
        self.assertEqual(gkid, key.gkid)

    def test_both_seed_keys(self):
        """Request a key and expect to receive L1 and L2 seed keys."""
        gkid = Gkid(300, 1, 0)
        key = self.check_rpc_get_key(None, gkid)

        # Expect to get both L1 and L2 seed keys.
        self.assertIsNotNone(key.l1_key)
        self.assertIsNotNone(key.l2_key)
        self.assertEqual(gkid, key.gkid)

    def test_both_seed_keys_no_hint(self):
        """Request a key, but don’t specify ‘root_key_id_hint’."""
        gkid = Gkid(300, 1, 0)
        key = self.get_key(
            self.get_samdb(),
            self.gmsa_sd,
            None,
            gkid,
        )

        # Expect to get both L1 and L2 seed keys.
        self.assertIsNotNone(key.l1_key)
        self.assertIsNotNone(key.l2_key)
        self.assertEqual(gkid, key.gkid)

    def test_request_l0_seed_key(self):
        """Attempt to request an L0 seed key."""
        gkid = Gkid.l0_seed_key(300)

        with self.assertRaises(GetKeyError) as err:
            self.get_key(self.get_samdb(), self.gmsa_sd, None, gkid)

        self.assertEqual(
            HRES_E_INVALIDARG,
            err.exception.args[0],
            "requesting an L0 seed key should fail with INVALID_PARAMETER",
        )

        with self.assertRaises(GetKeyError) as rpc_err:
            self.rpc_get_key(self.gkdi_conn(), self.gmsa_sd, None, gkid)

        self.assertEqual(
            HRES_E_INVALIDARG,
            rpc_err.exception.args[0],
            "requesting an L0 seed key should fail with INVALID_PARAMETER",
        )

    def test_request_l1_seed_key(self):
        """Attempt to request an L1 seed key."""
        gkid = Gkid.l1_seed_key(300, 0)

        with self.assertRaises(GetKeyError) as err:
            self.get_key(self.get_samdb(), self.gmsa_sd, None, gkid)

        self.assertEqual(
            HRES_E_INVALIDARG,
            err.exception.args[0],
            "requesting an L1 seed key should fail with INVALID_PARAMETER",
        )

        with self.assertRaises(GetKeyError) as rpc_err:
            self.rpc_get_key(self.gkdi_conn(), self.gmsa_sd, None, gkid)

        self.assertEqual(
            HRES_E_INVALIDARG,
            rpc_err.exception.args[0],
            "requesting an L1 seed key should fail with INVALID_PARAMETER",
        )

    def test_request_default_seed_key(self):
        """Try to make a request with the default GKID."""
        gkid = Gkid.default()

        self.assertRaises(
            NotImplementedError,
            self.get_key,
            self.get_samdb(),
            self.gmsa_sd,
            None,
            gkid,
        )

        self.rpc_get_key(self.gkdi_conn(), self.gmsa_sd, None, gkid)


class GkdiSelfTests(GkdiKdcBaseTest):
    def test_current_l0_idx_l1_seed_key(self):
        """Request a key with the current L0 index, expecting to receive an L1
        seed key."""
        root_key_id = self.new_root_key(
            use_start_time=ROOT_KEY_START_TIME,
            hash_algorithm=Algorithm.SHA512,
            guid=misc.GUID("89f70521-9d66-441f-c314-1b462f9b1052"),
            data=bytes.fromhex(
                "a6ef87dbbbf86b6bbe55750b941f13ca99efe5185e2e2bded5b838d8a0e77647"
                "0537e68cae45a7a0f4b1d6c9bf5494c3f879e172e326557cdbb6a56e8799a722"
            ),
        )

        current_gkid = Gkid(255, 24, 31)
        key = self.get_key(
            self.get_samdb(),
            self.gmsa_sd,
            root_key_id,
            Gkid(255, 2, 5),
            current_time=current_gkid.start_nt_time(),
        )

        # Expect to get an L1 seed key.
        self.assertEqual(current_gkid, key.gkid)
        self.assertEqual(root_key_id, key.root_key_id)
        self.assertEqual(Algorithm.SHA512, key.hash_algorithm)
        self.assertEqual(
            bytes.fromhex(
                "bd538a073490f3cf9451c933025de9b22c97eaddaffa94b379e2b919a4bed147"
                "5bc67f6a9175b139c69204c57d4300a0141ffe34d12ced84614593b1aa13af1c"
            ),
            key.l1_key,
        )
        self.assertIsNone(key.l2_key)

    def test_current_l0_idx_l2_seed_key(self):
        """Request a key with the current L0 index, expecting to receive an L2
        seed key."""
        root_key_id = self.new_root_key(
            use_start_time=ROOT_KEY_START_TIME,
            hash_algorithm=Algorithm.SHA512,
            guid=misc.GUID("1a3d6c30-aa81-cb7f-d3fe-80775d135dfe"),
            data=bytes.fromhex(
                "dfd95be3153a0805c65694e7d284aace5ab0aa493350025eb8dbc6df0b4e9256"
                "fb4cbfbe6237ce3732694e2608760076b67082d39abd3c0fedba1b8873645064"
            ),
        )

        current_gkid = Gkid(321, 0, 12)
        key = self.get_key(
            self.get_samdb(),
            self.gmsa_sd,
            root_key_id,
            Gkid(321, 0, 1),
            current_time=current_gkid.start_nt_time(),
        )

        # Expect to get an L2 seed key.
        self.assertEqual(current_gkid, key.gkid)
        self.assertEqual(root_key_id, key.root_key_id)
        self.assertEqual(Algorithm.SHA512, key.hash_algorithm)
        self.assertIsNone(key.l1_key)
        self.assertEqual(
            bytes.fromhex(
                "bbbd9376cd16c247ed40f5912d1908218c08f0915bae02fe02cbfb3753bde406"
                "f9c553acd95143cf63906a0440e3cf237d2335ae4e4b9cd2d946a71351ebcb7b"
            ),
            key.l2_key,
        )

    def test_current_l0_idx_both_seed_keys(self):
        """Request a key with the current L0 index, expecting to receive L1 and
        L2 seed keys."""
        root_key_id = self.new_root_key(
            use_start_time=ROOT_KEY_START_TIME,
            hash_algorithm=Algorithm.SHA512,
            guid=misc.GUID("09de0b38-c743-7abf-44ea-7a3c3e404314"),
            data=bytes.fromhex(
                "d5912d0eb3bd60e1371b1e525dd83be7fc5baf77018b0dba6bd948b7a98ebe5a"
                "f37674332506a46c52c108a62f2a3e89251ad1bde6d539004679c0658853bb68"
            ),
        )

        current_gkid = Gkid(123, 21, 0)
        key = self.get_key(
            self.get_samdb(),
            self.gmsa_sd,
            root_key_id,
            Gkid(123, 2, 1),
            current_time=current_gkid.start_nt_time(),
        )

        # Expect to get both L1 and L2 seed keys.
        self.assertEqual(current_gkid, key.gkid)
        self.assertEqual(root_key_id, key.root_key_id)
        self.assertEqual(Algorithm.SHA512, key.hash_algorithm)
        self.assertEqual(
            bytes.fromhex(
                "b1f7c5896e7dc791d9c0aaf8ca7dbab8c172a4f8b873db488a3c4cbd0f559b11"
                "52ffba39d4aff2d9e8aada90b27a3c94a5af996f4b8f584a4f37ccab4d505d3d"
            ),
            key.l1_key,
        )
        self.assertEqual(
            bytes.fromhex(
                "133c9bbd20d9227aeb38dfcd3be6bcbfc5983ba37202088ff5c8a70511214506"
                "a69c195a8807cd844bcb955e9569c8e4d197759f28577cc126d15f16a7da4ee0"
            ),
            key.l2_key,
        )

    def test_previous_l0_idx(self):
        """Request a key with a previous L0 index."""
        root_key_id = self.new_root_key(
            use_start_time=ROOT_KEY_START_TIME,
            hash_algorithm=Algorithm.SHA512,
            guid=misc.GUID("27136e8f-e093-6fe3-e57f-1d915b102e1c"),
            data=bytes.fromhex(
                "b41118c60a19cafa5ecf858d1a2a2216527b2daedf386e9d599e42a46add6c7d"
                "c93868619761c880ff3674a77c6e5fbf3434d130a9727bb2cd2a2557bdcfc752"
            ),
        )

        key = self.get_key(
            self.get_samdb(),
            self.gmsa_sd,
            root_key_id,
            Gkid(100, 20, 30),
            current_time=Gkid(101, 2, 3).start_nt_time(),
        )

        # Expect to get an L1 seed key.
        self.assertEqual(Gkid(100, 31, 31), key.gkid)
        self.assertEqual(root_key_id, key.root_key_id)
        self.assertEqual(Algorithm.SHA512, key.hash_algorithm)
        self.assertEqual(
            bytes.fromhex(
                "935cbdc06198eb28fa44b8d8278f51072c4613999236585041ede8e72d02fe95"
                "e3454f046382cbc0a700779b79474dd7e080509d76302d2937407e96e3d3d022"
            ),
            key.l1_key,
        )
        self.assertIsNone(key.l2_key)

    def test_sha1(self):
        """Request a key derived with SHA1."""
        root_key_id = self.new_root_key(
            use_start_time=ROOT_KEY_START_TIME,
            hash_algorithm=Algorithm.SHA1,
            guid=misc.GUID("970abad6-fe55-073a-caf1-b801d3f26bd3"),
            data=bytes.fromhex(
                "3bed03bf0fb7d4013149154f24ca2d59b98db6d588cb1f54eca083855e25eb28"
                "d3562a01adc78c4b70e0b72a59515863e7732b853fba02dd7646e63108441211"
            ),
        )

        current_gkid = Gkid(1, 2, 3)
        key = self.get_key(
            self.get_samdb(),
            self.gmsa_sd,
            root_key_id,
            Gkid(1, 1, 1),
            current_time=current_gkid.start_nt_time(),
        )

        # Expect to get both L1 and L2 seed keys.
        self.assertEqual(current_gkid, key.gkid)
        self.assertEqual(root_key_id, key.root_key_id)
        self.assertEqual(Algorithm.SHA1, key.hash_algorithm)
        self.assertEqual(
            bytes.fromhex(
                "576cb68f2e52eb739f817b488c3590d86f1c2c365f3fc9201d9c7fee7494853d"
                "58746ee13e48f18aa6fa69f7157de3d07de34e13836792b7c088ffb6914a89c2"
            ),
            key.l1_key,
        )
        self.assertEqual(
            bytes.fromhex(
                "3ffb825adaf116b6533207d568a30ed3d3f21c68840941c9456684f9afa11b05"
                "6e0c59391b4d88c495d984c3d680029cc5c594630f34179119c1c5acaae5e90e"
            ),
            key.l2_key,
        )

    def test_sha256(self):
        """Request a key derived with SHA256."""
        root_key_id = self.new_root_key(
            use_start_time=ROOT_KEY_START_TIME,
            hash_algorithm=Algorithm.SHA256,
            guid=misc.GUID("45e26207-ed33-dcd5-925a-518a0deef69e"),
            data=bytes.fromhex(
                "28b5b6503d3c1d24814de781bb7bfce3ef69eed1ce4809372bee2c506270c5f0"
                "b5c6df597472623f256c86daa0991e8a11a1705f21b2cfdc0bb9db4ba23246a2"
            ),
        )

        current_gkid = Gkid(222, 22, 22)
        key = self.get_key(
            self.get_samdb(),
            self.gmsa_sd,
            root_key_id,
            Gkid(222, 11, 0),
            current_time=current_gkid.start_nt_time(),
        )

        # Expect to get both L1 and L2 seed keys.
        self.assertEqual(current_gkid, key.gkid)
        self.assertEqual(root_key_id, key.root_key_id)
        self.assertEqual(Algorithm.SHA256, key.hash_algorithm)
        self.assertEqual(
            bytes.fromhex(
                "57aced6e75f83f3af4f879b38b60f090b42e4bfa022fae3e6fd94280b469b0ec"
                "15d8b853a870b5fbdf28708cce19273b74a573acbe0deda8ef515db4691e2dcb"
            ),
            key.l1_key,
        )
        self.assertEqual(
            bytes.fromhex(
                "752a0879ae2424c0504c7493599f13e588e1bbdc252f83325ad5b1fb91c24c89"
                "01d440f3ff9ffba59fcd65bb975732d9f383dd50b898174bb9393e383d25d540"
            ),
            key.l2_key,
        )

    def test_sha384(self):
        """Request a key derived with SHA384."""
        root_key_id = self.new_root_key(
            use_start_time=ROOT_KEY_START_TIME,
            hash_algorithm=Algorithm.SHA384,
            guid=misc.GUID("66e6d9f7-4924-f3fc-fe34-605634d42ebd"),
            data=bytes.fromhex(
                "23e5ba86cbd88f7b432ee66dbb03bf4eebf401cbfc3df735d4d728b503c87f84"
                "3207c6f6153f190dfe85a86cb8d8b74df13b25305981be8d7e29c96ee54c9630"
            ),
        )

        current_gkid = Gkid(287, 28, 27)
        key = self.get_key(
            self.get_samdb(),
            self.gmsa_sd,
            root_key_id,
            Gkid(287, 8, 7),
            current_time=current_gkid.start_nt_time(),
        )

        # Expect to get both L1 and L2 seed keys.
        self.assertEqual(current_gkid, key.gkid)
        self.assertEqual(root_key_id, key.root_key_id)
        self.assertEqual(Algorithm.SHA384, key.hash_algorithm)
        self.assertEqual(
            bytes.fromhex(
                "fabadd7a9a63df57d6832df7a735aebb6e181888b2eaf301a2e4ff9a70246d38"
                "ab1d2416325bf3eb726a0267bab4bd950c7291f05ea5f17197ece56992af3eb8"
            ),
            key.l1_key,
        )
        self.assertEqual(
            bytes.fromhex(
                "ec1c65634b5694818e1d341da9996db8f2a1ef6a2c776a7126a7ebd18b37a073"
                "afdac44c41b167b14e4b872d485bbb6d7b70964215d0e84a2ff142a9d943f205"
            ),
            key.l2_key,
        )

    def test_derive_key_exact(self):
        """Derive a key at an exact GKID."""
        root_key_id = self.new_root_key(
            use_start_time=ROOT_KEY_START_TIME,
            hash_algorithm=Algorithm.SHA512,
            guid=misc.GUID("d95fb06f-5a9c-1829-e20d-27f3f2ecfbeb"),
            data=bytes.fromhex(
                "489f3531c537774d432d6b97e3bc1f43d2e8c6dc17eb0e4fd9a0870d2f1ebf92"
                "e2496668a8b5bd11aea2d32d0aab716f48fe569f5c9b50ff3f9bf5deaea572fb"
            ),
        )

        gkid = Gkid(333, 22, 11)
        key = self.get_key_exact(
            self.get_samdb(),
            self.gmsa_sd,
            root_key_id,
            gkid,
            current_time=self.current_nt_time(self.get_samdb()),
        )

        self.assertEqual(gkid, key.gkid)
        self.assertEqual(root_key_id, key.root_key_id)
        self.assertEqual(Algorithm.SHA512, key.hash_algorithm)
        self.assertEqual(
            bytes.fromhex(
                "d6ab3b14f4f4c8908aa3464011b39f10a8bfadb9974af90f7d9a9fede2fdc6e5"
                "f68a628ec00f9994a3abd8a52ae9e2db4f68e83648311e9d7765f2535515b5e2"
            ),
            key.key,
        )


if __name__ == "__main__":
    import unittest

    unittest.main()
