# Unix SMB/CIFS implementation. Tests for dsdb_dns module
# Copyright © Catalyst IT 2021
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
from samba.tests import TestCase
from samba import dsdb_dns


def unix2nttime(t):
    # here we reimplement unix_to_nt_time from lib/util/time.c
    if t == -1:
        return t
    if t == (1 << 63) - 1:
        return (1 << 63) - 1
    if t == 0:
        return 0
    t += 11644473600
    t *= 1e7
    return int(t)


def unix2dns_timestamp(t):
    nt = unix2nttime(t)
    if nt < 0:
        # because NTTIME is a uint64_t.
        nt += 1 << 64
    return nt // int(3.6e10)


def timestamp2nttime(ts):
    nt = ts * int(3.6e10)
    if nt >= 1 << 63:
        raise OverflowError("nt time won't fit this")
    return nt


class DsdbDnsTestCase(TestCase):
    def test_unix_to_dns_timestamp(self):
        unixtimes = [1616829393,
                     1,
                     0,
                     -1,
                     1 << 31 - 1]

        for t in unixtimes:
            expected = unix2dns_timestamp(t)
            result = dsdb_dns.unix_to_dns_timestamp(t)
            self.assertEqual(result, expected)

    def test_dns_timestamp_to_nt_time(self):
        timestamps = [16168393,
                      1,
                      0,
                      (1 << 32) - 1,
                      (1 << 63) - 1,
                      int((1 << 63) / 3.6e10),
                      int((1 << 63) / 3.6e10) + 1, # overflows
                      ]

        for t in timestamps:
            overflows = False
            try:
                expected = timestamp2nttime(t)
            except OverflowError:
                overflows = True
            try:
                result = dsdb_dns.dns_timestamp_to_nt_time(t)
            except ValueError:
                self.assertTrue(overflows, f"timestamp {t} should not overflow")
                continue
            self.assertFalse(overflows, f"timestamp {t} should overflow")

            self.assertEqual(result, expected)
