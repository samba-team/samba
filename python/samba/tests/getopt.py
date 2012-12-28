# Unix SMB/CIFS implementation.
# Copyright (C) Jelmer Vernooij <jelmer@samba.org> 2011
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

"""Tests for option parsing.

"""

import optparse
from samba.getopt import (
    AUTO_USE_KERBEROS,
    DONT_USE_KERBEROS,
    MUST_USE_KERBEROS,
    parse_kerberos_arg,
    )
import samba.tests

class KerberosOptionTests(samba.tests.TestCase):

    def test_parse_true(self):
        self.assertEquals(
            MUST_USE_KERBEROS, parse_kerberos_arg("yes", "--kerberos"))
        self.assertEquals(
            MUST_USE_KERBEROS, parse_kerberos_arg("true", "--kerberos"))
        self.assertEquals(
            MUST_USE_KERBEROS, parse_kerberos_arg("1", "--kerberos"))

    def test_parse_false(self):
        self.assertEquals(
            DONT_USE_KERBEROS, parse_kerberos_arg("no", "--kerberos"))
        self.assertEquals(
            DONT_USE_KERBEROS, parse_kerberos_arg("false", "--kerberos"))
        self.assertEquals(
            DONT_USE_KERBEROS, parse_kerberos_arg("0", "--kerberos"))

    def test_parse_auto(self):
        self.assertEquals(
            AUTO_USE_KERBEROS, parse_kerberos_arg("auto", "--kerberos"))

    def test_parse_invalid(self):
        self.assertRaises(optparse.OptionValueError,
            parse_kerberos_arg, "blah?", "--kerberos")
