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
from typing import NewType, Optional
import re


NtTime = NewType("NtTime", int)
NtTimeDelta = NewType("NtTimeDelta", int)

NT_TIME_MAX = NtTime((1 << 64) - 1)

NT_EPOCH = datetime.datetime(1601, 1, 1, 0, 0, 0, 0, tzinfo=datetime.timezone.utc)
NT_TICKS_PER_μSEC = 10
NT_TICKS_PER_SEC = NT_TICKS_PER_μSEC * 1_000_000


def _validate_nt_time(nt_time: NtTime) -> None:
    if not isinstance(nt_time, int):
        raise ValueError(f"{nt_time} is not an integer")
    if not 0 <= nt_time <= NT_TIME_MAX:
        raise ValueError(f"{nt_time} is out of range")


def nt_time_from_datetime(tm: datetime.datetime) -> NtTime:
    time_since_epoch = tm - NT_EPOCH
    nt_time = NtTime(round(time_since_epoch.total_seconds() * NT_TICKS_PER_SEC))
    _validate_nt_time(nt_time)
    return nt_time


def nt_now() -> NtTime:
    dt = datetime.datetime.now(datetime.timezone.utc)
    return nt_time_from_datetime(dt)


def datetime_from_nt_time(nt_time: NtTime) -> datetime.datetime:
    _validate_nt_time(nt_time)
    time_since_epoch = datetime.timedelta(microseconds=nt_time / NT_TICKS_PER_μSEC)
    return NT_EPOCH + time_since_epoch


def nt_time_delta_from_timedelta(dt: datetime.timedelta) -> NtTimeDelta:
    return NtTimeDelta(round(dt.total_seconds() * NT_TICKS_PER_SEC))


def timedelta_from_nt_time_delta(nt_time_delta: NtTimeDelta) -> datetime.timedelta:
    return datetime.timedelta(microseconds=nt_time_delta / NT_TICKS_PER_μSEC)


def nt_time_from_string(s: str) -> NtTime:
    """Convert a subset of ISO 8601 date/time strings, ldap timestamps,
    and the string 'now' into NT time.

    The ldap format is

       YYYYmmddHHMMSS.0Z

    which is 14 digits followed by the fixed string '.0Z'. This is
    used in LDIF and internally by ldb.

    The ISO format is

    YYYY-mm-dd[*HH[:MM[:SS[.fff[fff]]]][+HH:MM[:SS[.ffffff]]]]

    where the '*' can be any character, and the optional last
    '[+HH:MM[:SS[.ffffff]]]' is a timezone offset (use '+00:00' for
    UTC).
    """
    try:
        if s == "now":
            dt = datetime.datetime.now(datetime.timezone.utc)
        elif re.match(r"^\d{14}\.0Z$", s):
            # "20230127223641.0Z"
            dt = datetime.datetime.strptime(s, "%Y%m%d%H%M%S.0Z")
        else:
            dt = datetime.datetime.fromisoformat(s)
    except ValueError:
        raise ValueError(
            "Expected a date in either "
            "ISO8601 'YYYY-MM-DD HH:MM:SS' format, "
            "LDAP timestamp 'YYYYmmddHHMMSS.0Z', "
            "or the literal string 'now'. "
            f" Got '{s}'."
        )

    if dt.tzinfo is None:
        # This is a cursed timestamp with no timezone info. We have to
        # guess or nt_time_from_datetime() will fail. The best guess
        # is the system timezone, which we can get this way:
        dt = dt.astimezone()

    return nt_time_from_datetime(dt)


def string_from_nt_time(nttime: NtTime, format: Optional[str] = None) -> str:
    """Format an NtTime date as a string.

    If format is not provided, an ISO 8601 string is used.
    """
    dt = datetime_from_nt_time(nttime)

    if format is not None:
        return dt.strftime(format)

    return dt.isoformat()
