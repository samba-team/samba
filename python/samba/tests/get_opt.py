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
    parse_kerberos_arg_legacy,
    parse_kerberos_arg,
)
import samba.tests


class KerberosOptionTests(samba.tests.TestCase):

    def test_legacy_parse_true(self):
        self.assertEqual(
            MUST_USE_KERBEROS, parse_kerberos_arg_legacy("yes", "--kerberos"))
        self.assertEqual(
            MUST_USE_KERBEROS, parse_kerberos_arg_legacy("true", "--kerberos"))
        self.assertEqual(
            MUST_USE_KERBEROS, parse_kerberos_arg_legacy("1", "--kerberos"))

    def test_legacy_parse_false(self):
        self.assertEqual(
            DONT_USE_KERBEROS, parse_kerberos_arg_legacy("no", "--kerberos"))
        self.assertEqual(
            DONT_USE_KERBEROS, parse_kerberos_arg_legacy("false", "--kerberos"))
        self.assertEqual(
            DONT_USE_KERBEROS, parse_kerberos_arg_legacy("0", "--kerberos"))

    def test_legacy_parse_auto(self):
        self.assertEqual(
            AUTO_USE_KERBEROS, parse_kerberos_arg_legacy("auto", "--kerberos"))

    def test_legacy_parse_invalid(self):
        self.assertRaises(optparse.OptionValueError,
                          parse_kerberos_arg_legacy, "blah?", "--kerberos")

    def test_parse_valid(self):
        self.assertEqual(
            MUST_USE_KERBEROS, parse_kerberos_arg("required", "--use-kerberos"))
        self.assertEqual(
            AUTO_USE_KERBEROS, parse_kerberos_arg("desired", "--use-kerberos"))
        self.assertEqual(
            DONT_USE_KERBEROS, parse_kerberos_arg("off", "--use-kerberos"))

    def test_parse_invalid(self):
        self.assertRaises(optparse.OptionValueError,
                          parse_kerberos_arg, "wurst", "--use-kerberos")
