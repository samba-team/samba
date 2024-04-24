# Unix SMB/CIFS implementation.
# Copyright (C) Catalyst.Net Ltd 2023
#
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

"""Group Key Distribution Service module"""

from enum import Enum
from functools import total_ordering
from typing import Optional, Tuple

from cryptography.hazmat.primitives import hashes

from samba import _glue
from samba.dcerpc import gkdi, misc
from samba.ndr import ndr_pack, ndr_unpack
from samba.nt_time import NtTime, NtTimeDelta


uint64_max: int = 2**64 - 1

L1_KEY_ITERATION: int = _glue.GKDI_L1_KEY_ITERATION
L2_KEY_ITERATION: int = _glue.GKDI_L2_KEY_ITERATION
KEY_CYCLE_DURATION: NtTimeDelta = _glue.GKDI_KEY_CYCLE_DURATION
MAX_CLOCK_SKEW: NtTimeDelta = _glue.GKDI_MAX_CLOCK_SKEW

KEY_LEN_BYTES = 64


class Algorithm(Enum):
    SHA1 = "SHA1"
    SHA256 = "SHA256"
    SHA384 = "SHA384"
    SHA512 = "SHA512"

    def algorithm(self) -> hashes.HashAlgorithm:
        if self is Algorithm.SHA1:
            return hashes.SHA1()

        if self is Algorithm.SHA256:
            return hashes.SHA256()

        if self is Algorithm.SHA384:
            return hashes.SHA384()

        if self is Algorithm.SHA512:
            return hashes.SHA512()

        raise RuntimeError("unknown hash algorithm {self}")

    def __repr__(self) -> str:
        return str(self)

    @staticmethod
    def from_kdf_parameters(kdf_param: Optional[bytes]) -> "Algorithm":
        if not kdf_param:
            return Algorithm.SHA256  # the default used by Windows.

        kdf_parameters = ndr_unpack(gkdi.KdfParameters, kdf_param)
        return Algorithm(kdf_parameters.hash_algorithm)


class GkidType(Enum):
    DEFAULT = object()
    L0_SEED_KEY = object()
    L1_SEED_KEY = object()
    L2_SEED_KEY = object()

    def description(self) -> str:
        if self is GkidType.DEFAULT:
            return "a default GKID"

        if self is GkidType.L0_SEED_KEY:
            return "an L0 seed key"

        if self is GkidType.L1_SEED_KEY:
            return "an L1 seed key"

        if self is GkidType.L2_SEED_KEY:
            return "an L2 seed key"

        raise RuntimeError("unknown GKID type {self}")


class InvalidDerivation(Exception):
    pass


class UndefinedStartTime(Exception):
    pass


@total_ordering
class Gkid:
    # L2 increments every 10 hours. It rolls over after 320 hours (13 days and 8 hours).
    # L1 increments every 320 hours. It rolls over after 10240 hours (426 days and 16 hours).
    # L0 increments every 10240 hours. It rolls over after 43980465111040 hours (five billion years).

    __slots__ = ["_l0_idx", "_l1_idx", "_l2_idx"]

    max_l0_idx = 0x7FFF_FFFF

    def __init__(self, l0_idx: int, l1_idx: int, l2_idx: int) -> None:
        if not -1 <= l0_idx <= Gkid.max_l0_idx:
            raise ValueError(f"L0 index {l0_idx} out of range")

        if not -1 <= l1_idx < L1_KEY_ITERATION:
            raise ValueError(f"L1 index {l1_idx} out of range")

        if not -1 <= l2_idx < L2_KEY_ITERATION:
            raise ValueError(f"L2 index {l2_idx} out of range")

        if l0_idx == -1 and l1_idx != -1:
            raise ValueError("invalid combination of negative and non‐negative indices")

        if l1_idx == -1 and l2_idx != -1:
            raise ValueError("invalid combination of negative and non‐negative indices")

        self._l0_idx = l0_idx
        self._l1_idx = l1_idx
        self._l2_idx = l2_idx

    @property
    def l0_idx(self) -> int:
        return self._l0_idx

    @property
    def l1_idx(self) -> int:
        return self._l1_idx

    @property
    def l2_idx(self) -> int:
        return self._l2_idx

    def gkid_type(self) -> GkidType:
        if self.l0_idx == -1:
            return GkidType.DEFAULT

        if self.l1_idx == -1:
            return GkidType.L0_SEED_KEY

        if self.l2_idx == -1:
            return GkidType.L1_SEED_KEY

        return GkidType.L2_SEED_KEY

    def wrapped_l1_idx(self) -> int:
        if self.l1_idx == -1:
            return L1_KEY_ITERATION

        return self.l1_idx

    def wrapped_l2_idx(self) -> int:
        if self.l2_idx == -1:
            return L2_KEY_ITERATION

        return self.l2_idx

    def derive_l1_seed_key(self) -> "Gkid":
        gkid_type = self.gkid_type()
        if (
            gkid_type is not GkidType.L0_SEED_KEY
            and gkid_type is not GkidType.L1_SEED_KEY
        ):
            raise InvalidDerivation(
                "Invalid attempt to derive an L1 seed key from"
                f" {gkid_type.description()}"
            )

        if self.l1_idx == 0:
            raise InvalidDerivation("No further derivation of L1 seed keys is possible")

        return Gkid(self.l0_idx, self.wrapped_l1_idx() - 1, self.l2_idx)

    def derive_l2_seed_key(self) -> "Gkid":
        gkid_type = self.gkid_type()
        if (
            gkid_type is not GkidType.L1_SEED_KEY
            and gkid_type is not GkidType.L2_SEED_KEY
        ):
            raise InvalidDerivation(
                f"Attempt to derive an L2 seed key from {gkid_type.description()}"
            )

        if self.l2_idx == 0:
            raise InvalidDerivation("No further derivation of L2 seed keys is possible")

        return Gkid(self.l0_idx, self.l1_idx, self.wrapped_l2_idx() - 1)

    def __str__(self) -> str:
        return f"Gkid({self.l0_idx}, {self.l1_idx}, {self.l2_idx})"

    def __repr__(self) -> str:
        cls = type(self)
        return (
            f"{cls.__qualname__}({repr(self.l0_idx)}, {repr(self.l1_idx)},"
            f" {repr(self.l2_idx)})"
        )

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Gkid):
            return NotImplemented

        return (self.l0_idx, self.l1_idx, self.l2_idx) == (
            other.l0_idx,
            other.l1_idx,
            other.l2_idx,
        )

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, Gkid):
            return NotImplemented

        def as_tuple(gkid: Gkid) -> Tuple[int, int, int]:
            l0_idx, l1_idx, l2_idx = gkid.l0_idx, gkid.l1_idx, gkid.l2_idx

            # DEFAULT is considered less than everything else, so that the
            # lexical ordering requirement in [MS-GKDI] 3.1.4.1.3 (GetKey) makes
            # sense.
            if gkid.gkid_type() is not GkidType.DEFAULT:
                # Use the wrapped indices so that L1 seed keys are considered
                # greater than their children L2 seed keys, and L0 seed keys are
                # considered greater than their children L1 seed keys.
                l1_idx = gkid.wrapped_l1_idx()
                l2_idx = gkid.wrapped_l2_idx()

            return l0_idx, l1_idx, l2_idx

        return as_tuple(self) < as_tuple(other)

    def __hash__(self) -> int:
        return hash((self.l0_idx, self.l1_idx, self.l2_idx))

    @staticmethod
    def default() -> "Gkid":
        return Gkid(-1, -1, -1)

    @staticmethod
    def l0_seed_key(l0_idx: int) -> "Gkid":
        return Gkid(l0_idx, -1, -1)

    @staticmethod
    def l1_seed_key(l0_idx: int, l1_idx: int) -> "Gkid":
        return Gkid(l0_idx, l1_idx, -1)

    @staticmethod
    def from_nt_time(nt_time: NtTime) -> "Gkid":
        l0 = nt_time // (L1_KEY_ITERATION * L2_KEY_ITERATION * KEY_CYCLE_DURATION)
        l1 = (
            nt_time
            % (L1_KEY_ITERATION * L2_KEY_ITERATION * KEY_CYCLE_DURATION)
            // (L2_KEY_ITERATION * KEY_CYCLE_DURATION)
        )
        l2 = nt_time % (L2_KEY_ITERATION * KEY_CYCLE_DURATION) // KEY_CYCLE_DURATION

        return Gkid(l0, l1, l2)

    def start_nt_time(self) -> NtTime:
        gkid_type = self.gkid_type()
        if gkid_type is not GkidType.L2_SEED_KEY:
            raise UndefinedStartTime(
                f"{gkid_type.description()} has no defined start time"
            )

        start_time = NtTime(
            (
                self.l0_idx * L1_KEY_ITERATION * L2_KEY_ITERATION
                + self.l1_idx * L2_KEY_ITERATION
                + self.l2_idx
            )
            * KEY_CYCLE_DURATION
        )

        if not 0 <= start_time <= uint64_max:
            raise OverflowError(f"start time {start_time} out of range")

        return start_time

    def previous(self) -> "Gkid":
        return Gkid.from_nt_time(NtTime(self.start_nt_time() - KEY_CYCLE_DURATION))

    def next(self) -> "Gkid":
        return Gkid.from_nt_time(NtTime(self.start_nt_time() + KEY_CYCLE_DURATION))

    @staticmethod
    def from_key_envelope(env: gkdi.KeyEnvelope) -> "Gkid":
        return Gkid(env.l0_index, env.l1_index, env.l2_index)


class SeedKeyPair:
    __slots__ = ["l1_key", "l2_key", "gkid", "hash_algorithm", "root_key_id"]

    def __init__(
        self,
        l1_key: Optional[bytes],
        l2_key: Optional[bytes],
        gkid: Gkid,
        hash_algorithm: Algorithm,
        root_key_id: misc.GUID,
    ) -> None:
        if l1_key is not None and len(l1_key) != KEY_LEN_BYTES:
            raise ValueError(f"L1 key ({repr(l1_key)}) must be {KEY_LEN_BYTES} bytes")
        if l2_key is not None and len(l2_key) != KEY_LEN_BYTES:
            raise ValueError(f"L2 key ({repr(l2_key)}) must be {KEY_LEN_BYTES} bytes")

        self.l1_key = l1_key
        self.l2_key = l2_key
        self.gkid = gkid
        self.hash_algorithm = hash_algorithm
        self.root_key_id = root_key_id

    def __str__(self) -> str:
        l1_key_hex = None if self.l1_key is None else self.l1_key.hex()
        l2_key_hex = None if self.l2_key is None else self.l2_key.hex()

        return (
            f"SeedKeyPair(L1Key({l1_key_hex}), L2Key({l2_key_hex}), {self.gkid},"
            f" {self.root_key_id}, {self.hash_algorithm})"
        )

    def __repr__(self) -> str:
        cls = type(self)
        return (
            f"{cls.__qualname__}({repr(self.l1_key)}, {repr(self.l2_key)},"
            f" {repr(self.gkid)}, {repr(self.hash_algorithm)},"
            f" {repr(self.root_key_id)})"
        )

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, SeedKeyPair):
            return NotImplemented

        return (
            self.l1_key,
            self.l2_key,
            self.gkid,
            self.hash_algorithm,
            self.root_key_id,
        ) == (
            other.l1_key,
            other.l2_key,
            other.gkid,
            other.hash_algorithm,
            other.root_key_id,
        )

    def __hash__(self) -> int:
        return hash(
            (
                self.l1_key,
                self.l2_key,
                self.gkid,
                self.hash_algorithm,
                ndr_pack(self.root_key_id),
            )
        )


class GroupKey:
    __slots__ = ["gkid", "key", "hash_algorithm", "root_key_id"]

    def __init__(
        self, key: bytes, gkid: Gkid, hash_algorithm: Algorithm, root_key_id: misc.GUID
    ) -> None:
        if key is not None and len(key) != KEY_LEN_BYTES:
            raise ValueError(f"Key ({repr(key)}) must be {KEY_LEN_BYTES} bytes")

        self.key = key
        self.gkid = gkid
        self.hash_algorithm = hash_algorithm
        self.root_key_id = root_key_id

    def __str__(self) -> str:
        return (
            f"GroupKey(Key({self.key.hex()}), {self.gkid}, {self.hash_algorithm},"
            f" {self.root_key_id})"
        )

    def __repr__(self) -> str:
        cls = type(self)
        return (
            f"{cls.__qualname__}({repr(self.key)}, {repr(self.gkid)},"
            f" {repr(self.hash_algorithm)}, {repr(self.root_key_id)})"
        )

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, GroupKey):
            return NotImplemented

        return (self.key, self.gkid, self.hash_algorithm, self.root_key_id) == (
            other.key,
            other.gkid,
            other.hash_algorithm,
            other.root_key_id,
        )

    def __hash__(self) -> int:
        return hash(
            (self.key, self.gkid, self.hash_algorithm, ndr_pack(self.root_key_id))
        )
