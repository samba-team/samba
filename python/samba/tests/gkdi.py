#
# Helper classes for testing the Group Key Distribution Service.
#
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

import datetime
import secrets
from typing import NewType, Optional, Tuple, Union

import ldb

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.kbkdf import CounterLocation, KBKDFHMAC, Mode

from samba import (
    ntstatus,
    NTSTATUSError,
    werror,
)
from samba.credentials import Credentials
from samba.dcerpc import gkdi, misc
from samba.gkdi import (
    Algorithm,
    Gkid,
    GkidType,
    GroupKey,
    KEY_CYCLE_DURATION,
    KEY_LEN_BYTES,
    MAX_CLOCK_SKEW,
    SeedKeyPair,
)
from samba.hresult import (
    HRES_E_INVALIDARG,
    HRES_NTE_BAD_KEY,
    HRES_NTE_NO_KEY,
)
from samba.ndr import ndr_pack, ndr_unpack
from samba.nt_time import (
    datetime_from_nt_time,
    nt_time_from_datetime,
    NtTime,
    NtTimeDelta,
    timedelta_from_nt_time_delta,
)
from samba.param import LoadParm
from samba.samdb import SamDB

from samba.tests import delete_force, TestCase


HResult = NewType("HResult", int)
RootKey = NewType("RootKey", ldb.Message)


ROOT_KEY_START_TIME = NtTime(KEY_CYCLE_DURATION + MAX_CLOCK_SKEW)

DSDB_GMSA_TIME_OPAQUE = "dsdb_gmsa_time_opaque"


class GetKeyError(Exception):
    def __init__(self, status: HResult, message: str):
        super().__init__(status, message)


class GkdiBaseTest(TestCase):
    # This is the NDR‐encoded security descriptor O:SYD:(A;;FRFW;;;S-1-5-9).
    gmsa_sd = (
        b"\x01\x00\x04\x800\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x14\x00\x00\x00\x02\x00\x1c\x00\x01\x00\x00\x00\x00\x00\x14\x00"
        b"\x9f\x01\x12\x00\x01\x01\x00\x00\x00\x00\x00\x05\t\x00\x00\x00"
        b"\x01\x01\x00\x00\x00\x00\x00\x05\x12\x00\x00\x00"
    )

    def set_db_time(self, samdb: SamDB, time: Optional[NtTime]) -> None:
        samdb.set_opaque(DSDB_GMSA_TIME_OPAQUE, time)

    def get_db_time(self, samdb: SamDB) -> Optional[NtTime]:
        return samdb.get_opaque(DSDB_GMSA_TIME_OPAQUE)

    def current_time(
        self, samdb: SamDB, *, offset: Optional[datetime.timedelta] = None
    ) -> datetime.datetime:
        now = self.get_db_time(samdb)
        if now is None:
            current_time = datetime.datetime.now(tz=datetime.timezone.utc)
        else:
            current_time = datetime_from_nt_time(now)

        if offset is not None:
            current_time += offset

        return current_time

    def current_nt_time(
        self, samdb: SamDB, *, offset: Optional[datetime.timedelta] = None
    ) -> NtTime:
        return nt_time_from_datetime(self.current_time(samdb, offset=offset))

    def current_gkid(
        self, samdb: SamDB, *, offset: Optional[datetime.timedelta] = None
    ) -> Gkid:
        return Gkid.from_nt_time(self.current_nt_time(samdb, offset=offset))

    def gkdi_connect(
        self, host: str, lp: LoadParm, server_creds: Credentials
    ) -> gkdi.gkdi:
        try:
            return gkdi.gkdi(f"ncacn_ip_tcp:{host}[seal]", lp, server_creds)
        except NTSTATUSError as err:
            if err.args[0] == ntstatus.NT_STATUS_PORT_UNREACHABLE:
                self.fail(
                    "Try starting the Microsoft Key Distribution Service (KdsSvc).\n"
                    "In PowerShell, run:\n\tStart-Service -Name KdsSvc"
                )

            raise

    def rpc_get_key(
        self,
        conn: gkdi.gkdi,
        target_sd: bytes,
        root_key_id: Optional[misc.GUID],
        gkid: Gkid,
    ) -> SeedKeyPair:
        out_len, out, result = conn.GetKey(
            list(target_sd), root_key_id, gkid.l0_idx, gkid.l1_idx, gkid.l2_idx
        )
        result_code, result_string = result
        if (
            root_key_id is None
            and result_code & 0xFFFF == werror.WERR_TOO_MANY_OPEN_FILES
        ):
            self.fail(
                "The server has given up selecting a root key because there are too"
                " many keys (more than 1000) in the Master Root Keys container. Delete"
                " some root keys and try again."
            )
        if result != (0, None):
            raise GetKeyError(result_code, result_string)
        self.assertEqual(len(out), out_len, "output len mismatch")

        envelope = ndr_unpack(gkdi.GroupKeyEnvelope, bytes(out))

        gkid = Gkid(envelope.l0_index, envelope.l1_index, envelope.l2_index)
        l1_key = bytes(envelope.l1_key) if envelope.l1_key else None
        l2_key = bytes(envelope.l2_key) if envelope.l2_key else None

        hash_algorithm = Algorithm.from_kdf_parameters(bytes(envelope.kdf_parameters))

        root_key_id = envelope.root_key_id

        return SeedKeyPair(l1_key, l2_key, gkid, hash_algorithm, root_key_id)

    def get_root_key_object(
        self, samdb: SamDB, root_key_id: Optional[misc.GUID], gkid: Gkid
    ) -> Tuple[RootKey, misc.GUID]:
        """Return a root key object and its corresponding GUID.

        *root_key_id* specifies the GUID of the root key object to return. It
        can be ``None`` to indicate that the selected key should be the most
        recently created key starting not after the time indicated by *gkid*.

        Bear in mind as that the Microsoft Key Distribution Service caches root
        keys, the most recently created key might not be the one that Windows
        chooses."""

        root_key_attrs = [
            "cn",
            "msKds-CreateTime",
            "msKds-KDFAlgorithmID",
            "msKds-KDFParam",
            "msKds-RootKeyData",
            "msKds-UseStartTime",
            "msKds-Version",
        ]

        gkid_start_nt_time = gkid.start_nt_time()

        exact_key_specified = root_key_id is not None
        if exact_key_specified:
            root_key_dn = self.get_root_key_container_dn(samdb)
            root_key_dn.add_child(f"CN={root_key_id}")

            try:
                root_key_res = samdb.search(
                    root_key_dn, scope=ldb.SCOPE_BASE, attrs=root_key_attrs
                )
            except ldb.LdbError as err:
                if err.args[0] == ldb.ERR_NO_SUCH_OBJECT:
                    raise GetKeyError(HRES_NTE_NO_KEY, "no such root key exists")

                raise

            root_key_object = root_key_res[0]
        else:
            root_keys = samdb.search(
                self.get_root_key_container_dn(samdb),
                scope=ldb.SCOPE_SUBTREE,
                expression=f"(msKds-UseStartTime<={gkid_start_nt_time})",
                attrs=root_key_attrs,
            )
            if not root_keys:
                raise GetKeyError(
                    HRES_NTE_NO_KEY, "no root keys exist at specified time"
                )

            def root_key_create_time(key: RootKey) -> NtTime:
                create_time = key.get("msKds-CreateTime", idx=0)
                if create_time is None:
                    return NtTime(0)

                return NtTime(int(create_time))

            root_key_object = max(root_keys, key=root_key_create_time)

            root_key_cn = root_key_object.get("cn", idx=0)
            self.assertIsNotNone(root_key_cn)
            root_key_id = misc.GUID(root_key_cn)

        data = root_key_object.get("msKds-RootKeyData", idx=0)
        self.assertIsNotNone(data)
        if len(data) != KEY_LEN_BYTES:
            raise GetKeyError(
                HRES_NTE_BAD_KEY, f"root key data must be {KEY_LEN_BYTES} bytes"
            )

        use_start_nt_time = NtTime(
            int(root_key_object.get("msKds-UseStartTime", idx=0))
        )
        if use_start_nt_time == 0:
            raise GetKeyError(HRES_NTE_BAD_KEY, "root key effective time is 0")
        use_start_nt_time = NtTime(
            use_start_nt_time - NtTimeDelta(KEY_CYCLE_DURATION + MAX_CLOCK_SKEW)
        )

        if exact_key_specified and not (0 <= use_start_nt_time <= gkid_start_nt_time):
            raise GetKeyError(HRES_E_INVALIDARG, "root key is not yet valid")

        return root_key_object, root_key_id

    def validate_get_key_request(
        self, gkid: Gkid, current_time: NtTime, root_key_specified: bool
    ) -> None:
        # The key being requested must not be from the future. That said, we
        # allow for a little bit of clock skew so that we can compute the next
        # managed password prior to the expiration of the current one.
        current_gkid = Gkid.from_nt_time(NtTime(current_time + MAX_CLOCK_SKEW))
        if gkid > current_gkid:
            raise GetKeyError(
                HRES_E_INVALIDARG,
                f"invalid request for a key from the future: {gkid} > {current_gkid}",
            )

        gkid_type = gkid.gkid_type()
        if gkid_type is GkidType.DEFAULT:
            derived_from = (
                " derived from the specified root key" if root_key_specified else ""
            )
            raise NotImplementedError(
                f"The latest group key{derived_from} is being requested."
            )

        if gkid_type is not GkidType.L2_SEED_KEY:
            raise GetKeyError(
                HRES_E_INVALIDARG, f"invalid request for {gkid_type.description()}"
            )

    def get_key(
        self,
        samdb: SamDB,
        target_sd: bytes,  # An NDR‐encoded valid security descriptor in self‐relative format.
        root_key_id: Optional[misc.GUID],
        gkid: Gkid,
        *,
        root_key_id_hint: Optional[misc.GUID] = None,
        current_time: Optional[NtTime] = None,
    ) -> SeedKeyPair:
        """Emulate the ISDKey.GetKey() RPC method.

        When passed a NULL root key ID, GetKey() may use a cached root key
        rather than picking the most recently created applicable key as the
        documentation implies. If it’s important to arrive at the same result as
        Windows, pass a GUID in the *root_key_id_hint* parameter to specify a
        particular root key to use."""

        if current_time is None:
            current_time = self.current_nt_time(samdb)

        root_key_specified = root_key_id is not None
        if root_key_specified:
            self.assertIsNone(
                root_key_id_hint, "don’t provide both root key ID parameters"
            )

        self.validate_get_key_request(gkid, current_time, root_key_specified)

        root_key_object, root_key_id = self.get_root_key_object(
            samdb, root_key_id if root_key_specified else root_key_id_hint, gkid
        )

        if root_key_specified:
            current_gkid = Gkid.from_nt_time(current_time)
            if gkid.l0_idx < current_gkid.l0_idx:
                # All of the seed keys with an L0 index less than the current L0
                # index are from the past and thus are safe to return. If the
                # caller has requested a specific seed key with a past L0 index,
                # return the L1 seed key (L0, 31, −1), from which any L1 or L2
                # seed key having that L0 index can be derived.
                l1_gkid = Gkid(gkid.l0_idx, 31, -1)
                seed_key = self.compute_seed_key(
                    target_sd, root_key_id, root_key_object, l1_gkid
                )
                return SeedKeyPair(
                    seed_key.key,
                    None,
                    Gkid(gkid.l0_idx, 31, 31),
                    seed_key.hash_algorithm,
                    root_key_id,
                )

            # All of the previous seed keys with an L0 index equal to the
            # current L0 index can be derived from the current seed key or from
            # the next older L1 seed key.
            gkid = current_gkid

        if gkid.l2_idx == 31:
            # The current seed key, and all previous seed keys with that same L0
            # index, can be derived from the L1 seed key (L0, L1, 31).
            l1_gkid = Gkid(gkid.l0_idx, gkid.l1_idx, -1)
            seed_key = self.compute_seed_key(
                target_sd, root_key_id, root_key_object, l1_gkid
            )
            return SeedKeyPair(
                seed_key.key, None, gkid, seed_key.hash_algorithm, root_key_id
            )

        # Compute the L2 seed key to return.
        seed_key = self.compute_seed_key(target_sd, root_key_id, root_key_object, gkid)

        next_older_seed_key = None
        if gkid.l1_idx != 0:
            # From the current seed key can be derived only those seed keys that
            # share its L1 and L2 indices. To be able to derive previous seed
            # keys with older L1 indices, the caller must be given the next
            # older L1 seed key as well.
            next_older_l1_gkid = Gkid(gkid.l0_idx, gkid.l1_idx - 1, -1)
            next_older_seed_key = self.compute_seed_key(
                target_sd, root_key_id, root_key_object, next_older_l1_gkid
            ).key

        return SeedKeyPair(
            next_older_seed_key,
            seed_key.key,
            gkid,
            seed_key.hash_algorithm,
            root_key_id,
        )

    def get_key_exact(
        self,
        samdb: SamDB,
        target_sd: bytes,  # An NDR‐encoded valid security descriptor in self‐relative format.
        root_key_id: Optional[misc.GUID],
        gkid: Gkid,
        current_time: Optional[NtTime] = None,
    ) -> GroupKey:
        if current_time is None:
            current_time = self.current_nt_time(samdb)

        root_key_specified = root_key_id is not None
        self.validate_get_key_request(gkid, current_time, root_key_specified)

        root_key_object, root_key_id = self.get_root_key_object(
            samdb, root_key_id, gkid
        )

        return self.compute_seed_key(target_sd, root_key_id, root_key_object, gkid)

    def get_root_key_data(self, root_key: RootKey) -> Tuple[bytes, Algorithm]:
        version = root_key.get("msKds-Version", idx=0)
        self.assertEqual(b"1", version)

        algorithm_id = root_key.get("msKds-KDFAlgorithmID", idx=0)
        self.assertEqual(b"SP800_108_CTR_HMAC", algorithm_id)

        hash_algorithm = Algorithm.from_kdf_parameters(
            root_key.get("msKds-KDFParam", idx=0)
        )

        root_key_data = root_key.get("msKds-RootKeyData", idx=0)
        self.assertIsInstance(root_key_data, bytes)

        return root_key_data, hash_algorithm

    def compute_seed_key(
        self,
        target_sd: bytes,
        root_key_id: misc.GUID,
        root_key: RootKey,
        target_gkid: Gkid,
    ) -> GroupKey:
        target_gkid_type = target_gkid.gkid_type()
        self.assertIn(
            target_gkid_type,
            (GkidType.L1_SEED_KEY, GkidType.L2_SEED_KEY),
            f"unexpected attempt to compute {target_gkid_type.description()}",
        )

        root_key_data, algorithm = self.get_root_key_data(root_key)
        root_key_id_bytes = ndr_pack(root_key_id)

        hash_algorithm = algorithm.algorithm()

        # Derive the L0 seed key.
        gkid = Gkid.l0_seed_key(target_gkid.l0_idx)
        key = self.derive_key(root_key_data, root_key_id_bytes, hash_algorithm, gkid)

        # Derive the L1 seed key.

        gkid = gkid.derive_l1_seed_key()
        key = self.derive_key(
            key, root_key_id_bytes, hash_algorithm, gkid, target_sd=target_sd
        )

        while gkid.l1_idx != target_gkid.l1_idx:
            gkid = gkid.derive_l1_seed_key()
            key = self.derive_key(key, root_key_id_bytes, hash_algorithm, gkid)

        # Derive the L2 seed key.
        while gkid != target_gkid:
            gkid = gkid.derive_l2_seed_key()
            key = self.derive_key(key, root_key_id_bytes, hash_algorithm, gkid)

        return GroupKey(key, gkid, algorithm, root_key_id)

    def derive_key(
        self,
        key: bytes,
        root_key_id_bytes: bytes,
        hash_algorithm: hashes.HashAlgorithm,
        gkid: Gkid,
        *,
        target_sd: Optional[bytes] = None,
    ) -> bytes:
        def u32_bytes(n: int) -> bytes:
            return (n & 0xFFFF_FFFF).to_bytes(length=4, byteorder="little")

        context = (
            root_key_id_bytes
            + u32_bytes(gkid.l0_idx)
            + u32_bytes(gkid.l1_idx)
            + u32_bytes(gkid.l2_idx)
        )
        if target_sd is not None:
            context += target_sd
        return self.kdf(hash_algorithm, key, context)

    def kdf(
        self,
        hash_algorithm: hashes.HashAlgorithm,
        key: bytes,
        context: bytes,
        *,
        label="KDS service",
        len_in_bytes=KEY_LEN_BYTES,
    ) -> bytes:
        label = label.encode("utf-16-le") + b"\x00\x00"
        kdf = KBKDFHMAC(
            algorithm=hash_algorithm,
            mode=Mode.CounterMode,
            length=len_in_bytes,
            rlen=4,
            llen=4,
            location=CounterLocation.BeforeFixed,
            label=label,
            context=context,
            fixed=None,
            backend=default_backend(),
        )
        return kdf.derive(key)

    def get_config_dn(self, samdb: SamDB, dn: str) -> ldb.Dn:
        config_dn = samdb.get_config_basedn()
        config_dn.add_child(dn)
        return config_dn

    def get_server_config_dn(self, samdb: SamDB) -> ldb.Dn:
        # [MS-GKDI] has “CN=Sid Key Service” for “CN=Group Key Distribution
        # Service”, and “CN=SID Key Server Configuration” for “CN=Group Key
        # Distribution Service Server Configuration”.
        return self.get_config_dn(
            samdb,
            "CN=Group Key Distribution Service Server Configuration,"
            "CN=Server Configuration,"
            "CN=Group Key Distribution Service,"
            "CN=Services",
        )

    def get_root_key_container_dn(self, samdb: SamDB) -> ldb.Dn:
        # [MS-GKDI] has “CN=Sid Key Service” for “CN=Group Key Distribution Service”.
        return self.get_config_dn(
            samdb,
            "CN=Master Root Keys,CN=Group Key Distribution Service,CN=Services",
        )

    def create_root_key(
        self,
        samdb: SamDB,
        domain_dn: ldb.Dn,
        *,
        use_start_time: Optional[Union[datetime.datetime, NtTime]] = None,
        hash_algorithm: Optional[Algorithm] = Algorithm.SHA512,
        guid: Optional[misc.GUID] = None,
        data: Optional[bytes] = None,
    ) -> misc.GUID:
        # we defer the actual work to the create_root_key() function,
        # which exists so that the samba-tool tests can borrow that
        # function.

        root_key_guid, root_key_dn = create_root_key(
            samdb,
            domain_dn,
            current_nt_time=self.current_nt_time(
                samdb,
                # Allow for clock skew.
                offset=timedelta_from_nt_time_delta(MAX_CLOCK_SKEW),
            ),
            use_start_time=use_start_time,
            hash_algorithm=hash_algorithm,
            guid=guid,
            data=data,
        )

        if guid is not None:
            # A test may request that a root key have a specific GUID so that
            # results may be reproducible. Ensure these keys are cleaned up
            # afterwards.
            self.addCleanup(delete_force, samdb, root_key_dn)
            self.assertEqual(guid, root_key_guid)

        return root_key_guid


def create_root_key(
    samdb: SamDB,
    domain_dn: ldb.Dn,
    *,
    current_nt_time: NtTime,
    use_start_time: Optional[Union[datetime.datetime, NtTime]] = None,
    hash_algorithm: Optional[Algorithm] = Algorithm.SHA512,
    guid: Optional[misc.GUID] = None,
    data: Optional[bytes] = None,
) -> Tuple[misc.GUID, ldb.Dn]:
    # [MS-GKDI] 3.1.4.1.1, “Creating a New Root Key”, states that if the
    # server receives a GetKey request and the root keys container in Active
    # Directory is empty, the server must create a new root key object
    # based on the default Server Configuration object. Additional root keys
    # are to be created based on either the default Server Configuration
    # object or an updated one specifying optional configuration values.

    if guid is None:
        guid = misc.GUID(secrets.token_bytes(16))

    if data is None:
        data = secrets.token_bytes(KEY_LEN_BYTES)

    create_time = current_nt_time

    if use_start_time is None:
        # Root keys created by Windows without the ‘-EffectiveImmediately’
        # parameter have an effective time of exactly ten days in the
        # future, presumably to allow time for replication.
        #
        # Microsoft’s documentation on creating a KDS root key, located at
        # https://learn.microsoft.com/en-us/windows-server/security/group-managed-service-accounts/create-the-key-distribution-services-kds-root-key,
        # claims to the contrary that domain controllers will only wait up
        # to ten hours before allowing Group Managed Service Accounts to be
        # created.
        #
        # The same page includes instructions for creating a root key with
        # an effective time of ten hours in the past (for testing purposes),
        # but I’m not sure why — the KDS will consider a key valid for use
        # immediately after its start time has passed, without bothering to
        # wait ten hours first. In fact, it will consider a key to be valid
        # a full ten hours (plus clock skew) *before* its declared start
        # time — intentional, or (conceivably) the result of an accidental
        # negation?
        current_interval_start_nt_time = Gkid.from_nt_time(
            current_nt_time
        ).start_nt_time()
        use_start_time = NtTime(
            current_interval_start_nt_time + KEY_CYCLE_DURATION + MAX_CLOCK_SKEW
        )

    if isinstance(use_start_time, datetime.datetime):
        use_start_nt_time = nt_time_from_datetime(use_start_time)
    elif isinstance(use_start_time, int):
        use_start_nt_time = use_start_time
    else:
        raise ValueError("use_start_time should be a datetime or int")

    kdf_parameters = None
    if hash_algorithm is not None:
        kdf_parameters = gkdi.KdfParameters()
        kdf_parameters.hash_algorithm = hash_algorithm.value
        kdf_parameters = ndr_pack(kdf_parameters)

    # These are the encoded p and g values, respectively, of the “2048‐bit
    # MODP Group with 256‐bit Prime Order Subgroup” from RFC 5114 section
    # 2.3.
    field_order = (
        b"\x87\xa8\xe6\x1d\xb4\xb6f<\xff\xbb\xd1\x9ce\x19Y\x99\x8c\xee\xf6\x08"
        b"f\r\xd0\xf2],\xee\xd4C^;\x00\xe0\r\xf8\xf1\xd6\x19W\xd4\xfa\xf7\xdfE"
        b"a\xb2\xaa0\x16\xc3\xd9\x114\to\xaa;\xf4)m\x83\x0e\x9a|"
        b" \x9e\x0cd\x97Qz\xbd"
        b'Z\x8a\x9d0k\xcfg\xed\x91\xf9\xe6r[GX\xc0"\xe0\xb1\xefBu\xbf{l[\xfc\x11'
        b"\xd4_\x90\x88\xb9A\xf5N\xb1\xe5\x9b\xb8\xbc9\xa0\xbf\x120\x7f\\O\xdbp\xc5"
        b"\x81\xb2?v\xb6:\xca\xe1\xca\xa6\xb7\x90-RRg5H\x8a\x0e\xf1<m\x9aQ\xbf\xa4\xab"
        b":\xd84w\x96RM\x8e\xf6\xa1g\xb5\xa4\x18%\xd9g\xe1D\xe5\x14\x05d%"
        b"\x1c\xca\xcb\x83\xe6\xb4\x86\xf6\xb3\xca?yqP`&\xc0\xb8W\xf6\x89\x96(V"
        b"\xde\xd4\x01\n\xbd\x0b\xe6!\xc3\xa3\x96\nT\xe7\x10\xc3u\xf2cu\xd7\x01A\x03"
        b"\xa4\xb5C0\xc1\x98\xaf\x12a\x16\xd2'n\x11q_i8w\xfa\xd7\xef\t\xca\xdb\tJ\xe9"
        b"\x1e\x1a\x15\x97"
    )
    generator = (
        b"?\xb3,\x9bs\x13M\x0b.wPf`\xed\xbdHL\xa7\xb1\x8f!\xef T\x07\xf4y:"
        b"\x1a\x0b\xa1%\x10\xdb\xc1Pw\xbeF?\xffO\xedJ\xac\x0b\xb5U\xbe:l\x1b\x0ckG\xb1"
        b"\xbc7s\xbf~\x8cob\x90\x12(\xf8\xc2\x8c\xbb\x18\xa5Z\xe3\x13A\x00\ne"
        b"\x01\x96\xf91\xc7zW\xf2\xdd\xf4c\xe5\xe9\xec\x14Kw}\xe6*\xaa\xb8\xa8b"
        b"\x8a\xc3v\xd2\x82\xd6\xed8d\xe6y\x82B\x8e\xbc\x83\x1d\x144\x8fo/\x91\x93"
        b"\xb5\x04Z\xf2vqd\xe1\xdf\xc9g\xc1\xfb?.U\xa4\xbd\x1b\xff\xe8;\x9c\x80"
        b"\xd0R\xb9\x85\xd1\x82\xea\n\xdb*;s\x13\xd3\xfe\x14\xc8HK\x1e\x05%\x88\xb9"
        b"\xb7\xd2\xbb\xd2\xdf\x01a\x99\xec\xd0n\x15W\xcd\t\x15\xb35;\xbbd\xe0\xec7"
        b"\x7f\xd0(7\r\xf9+R\xc7\x89\x14(\xcd\xc6~\xb6\x18KR=\x1d\xb2F\xc3/c\x07\x84"
        b"\x90\xf0\x0e\xf8\xd6G\xd1H\xd4yTQ^#'\xcf\xef\x98\xc5\x82fKL\x0fl\xc4\x16Y"
    )
    assert len(field_order) == len(generator)

    key_length = len(field_order)

    ffc_dh_parameters = gkdi.FfcDhParameters()
    ffc_dh_parameters.field_order = list(field_order)
    ffc_dh_parameters.generator = list(generator)
    ffc_dh_parameters.key_length = key_length
    ffc_dh_parameters = ndr_pack(ffc_dh_parameters)

    root_key_dn = samdb.get_config_basedn()
    root_key_dn.add_child(
        "CN=Master Root Keys,CN=Group Key Distribution Service,CN=Services"
    )

    root_key_dn.add_child(f"CN={guid}")

    # Avoid deleting root key objects without subsequently restarting the
    # Microsoft Key Distribution Service. This service will keep its root
    # key cached even after the corresponding AD object has been deleted,
    # breaking later tests that try to look up the root key object.

    details = {
        "dn": root_key_dn,
        "objectClass": "msKds-ProvRootKey",
        "msKds-RootKeyData": data,
        "msKds-CreateTime": str(create_time),
        "msKds-UseStartTime": str(use_start_nt_time),
        "msKds-DomainID": str(domain_dn),
        "msKds-Version": "1",  # comes from Server Configuration object.
        "msKds-KDFAlgorithmID": (
            "SP800_108_CTR_HMAC"
        ),  # comes from Server Configuration.
        "msKds-SecretAgreementAlgorithmID": "DH",  # comes from Server Configuration.
        "msKds-SecretAgreementParam": (
            ffc_dh_parameters
        ),  # comes from Server Configuration.
        "msKds-PublicKeyLength": "2048",  # comes from Server Configuration.
        "msKds-PrivateKeyLength": (
            "512"
        ),  # comes from Server Configuration. [MS-GKDI] claims this defaults to ‘256’.
    }
    if kdf_parameters is not None:
        details["msKds-KDFParam"] = kdf_parameters  # comes from Server Configuration.

    samdb.add(details)

    return (guid, root_key_dn)
