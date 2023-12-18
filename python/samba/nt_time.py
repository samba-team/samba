#
# NT Time utility functions.
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

import datetime
from typing import Final, NewType


NtTime = NewType("NtTime", int)
NtTimeDelta = NewType("NtTimeDelta", int)


NT_EPOCH: Final = datetime.datetime(
    1601, 1, 1, 0, 0, 0, 0, tzinfo=datetime.timezone.utc
)
NT_TICKS_PER_μSEC: Final = 10
NT_TICKS_PER_SEC: Final = NT_TICKS_PER_μSEC * 10**6


def _validate_nt_time(nt_time: NtTime) -> None:
    if not isinstance(nt_time, int):
        raise ValueError(f"{nt_time} is not an integer")
    if not 0 <= nt_time < 2**64:
        raise ValueError(f"{nt_time} is out of range")


def nt_time_from_datetime(tm: datetime.datetime) -> NtTime:
    time_since_epoch = tm - NT_EPOCH
    nt_time = NtTime(round(time_since_epoch.total_seconds() * NT_TICKS_PER_SEC))
    _validate_nt_time(nt_time)
    return nt_time


def datetime_from_nt_time(nt_time: NtTime) -> datetime.datetime:
    _validate_nt_time(nt_time)
    time_since_epoch = datetime.timedelta(microseconds=nt_time / NT_TICKS_PER_μSEC)
    return NT_EPOCH + time_since_epoch


def nt_time_delta_from_datetime(dt: datetime.timedelta) -> NtTimeDelta:
    return NtTimeDelta(round(dt.total_seconds() * NT_TICKS_PER_SEC))


def timedelta_from_nt_time_delta(nt_time_delta: NtTimeDelta) -> datetime.timedelta:
    return datetime.timedelta(microseconds=nt_time_delta / NT_TICKS_PER_μSEC)
