# subunit test cases for Samba string functions.

# Copyright (C) 2003 by Martin Pool <mbp@samba.org>
# Copyright (C) 2011 Andrew Bartlett
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

# XXX: All this code assumes that the Unix character set is UTF-8,
# which is the most common setting.  I guess it would be better to
# force it to that value while running the tests.  I'm not sure of the
# best way to do that yet.
#
# -- mbp
import unicodedata
import samba.tests
from samba import strcasecmp_m, strstr_m


KATAKANA_LETTER_A = unicodedata.lookup("KATAKANA LETTER A")


def signum(a):
    if a < 0:
        return -1
    elif a > 0:
        return +1
    else:
        return 0

class strcasecmp_m_Tests(samba.tests.TestCase):
    """String comparisons in simple ASCII and unicode"""
    def test_strcasecmp_m(self):
        # A, B, strcasecmp(A, B)
        cases = [('hello', 'hello', 0),
                 ('hello', 'goodbye', +1),
                 ('goodbye', 'hello', -1),
                 ('hell', 'hello', -1),
                 ('', '', 0),
                 ('a', '', +1),
                 ('', 'a', -1),
                 ('a', 'A', 0),
                 ('aa', 'aA', 0),
                 ('Aa', 'aa', 0),
                 ('longstring ' * 100, 'longstring ' * 100, 0),
                 ('longstring ' * 100, 'longstring ' * 100 + 'a', -1),
                 ('longstring ' * 100 + 'a', 'longstring ' * 100, +1),
                 (KATAKANA_LETTER_A, KATAKANA_LETTER_A, 0),
                 (KATAKANA_LETTER_A, 'a', 1),
                 ]
        for a, b, expect in cases:
            self.assertEqual(signum(strcasecmp_m(a, b)), expect)


class strstr_m_Tests(samba.tests.TestCase):
    """strstr_m tests in simple ASCII and unicode strings"""

    def test_strstr_m(self):
        # A, B, strstr_m(A, B)
        cases = [('hello', 'hello', 'hello'),
                 ('hello', 'goodbye', None),
                 ('goodbye', 'hello', None),
                 ('hell', 'hello', None),
                 ('hello', 'hell', 'hello'),
                 ('', '', ''),
                 ('a', '', 'a'),
                 ('', 'a', None),
                 ('a', 'A', None),
                 ('aa', 'aA', None),
                 ('Aa', 'aa', None),
                 ('%v foo', '%v', '%v foo'),
                 ('foo %v foo', '%v', '%v foo'),
                 ('foo %v', '%v', '%v'),
                 ('longstring ' * 100, 'longstring ' * 99, 'longstring ' * 100),
                 ('longstring ' * 99, 'longstring ' * 100, None),
                 ('longstring a' * 99, 'longstring ' * 100 + 'a', None),
                 ('longstring ' * 100 + 'a', 'longstring ' * 100, 'longstring ' * 100 + 'a'),
                 (KATAKANA_LETTER_A, KATAKANA_LETTER_A + 'bcd', None),
                 (KATAKANA_LETTER_A + 'bcde', KATAKANA_LETTER_A + 'bcd', KATAKANA_LETTER_A + 'bcde'),
                 ('d' +KATAKANA_LETTER_A + 'bcd', KATAKANA_LETTER_A + 'bcd', KATAKANA_LETTER_A + 'bcd'),
                 ('d' +KATAKANA_LETTER_A + 'bd', KATAKANA_LETTER_A + 'bcd', None),

                 ('e' + KATAKANA_LETTER_A + 'bcdf', KATAKANA_LETTER_A + 'bcd', KATAKANA_LETTER_A + 'bcdf'),
                 (KATAKANA_LETTER_A, KATAKANA_LETTER_A + 'bcd', None),
                 (KATAKANA_LETTER_A * 3, 'a', None),
                 ]
        for a, b, expect in cases:
            self.assertEqual(strstr_m(a, b), expect)
