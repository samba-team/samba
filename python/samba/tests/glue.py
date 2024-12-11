# Unix SMB/CIFS implementation.
# Copyright (C) Jelmer Vernooij <jelmer@samba.org> 2007
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

"""Tests for the _glue Python bindings."""

from samba import _glue
from samba import param
import samba.tests


class GlueTests(samba.tests.TestCase):

    def test_generate_random_str(self):
        string = _glue.generate_random_str(10)
        self.assertEqual(type(string), str)
        self.assertEqual(len(string), 10)

    def test_generate_random_password(self):
        password = _glue.generate_random_password(5, 10)
        self.assertEqual(type(password), str)
        self.assertTrue(5 <= len(password) <= 10)

    def test_unix2nttime(self):
        self.assertEqual(_glue.unix2nttime(1), 116444736010000000)

    def test_nttime2unix(self):
        self.assertEqual(_glue.nttime2unix(116444736010000000), 1)

    def test_float2nttime(self):
        self.assertEqual(_glue.float2nttime(1.0), 116444736010000000)
        self.assertEqual(_glue.float2nttime(1611058908.0), 132555325080000000)
        # NTTIME has a resolution of 100ns
        self.assertEqual(_glue.float2nttime(1611058908.1234567), 132555325081234567)
        self.assertEqual(_glue.float2nttime(1611058908.123456789), 132555325081234567)

    def test_nttime2float(self):
        self.assertEqual(_glue.nttime2float(1), -11644473600.0)
        self.assertEqual(_glue.nttime2float(0x7fffffffffffffff), 910692730085.4775)
        self.assertEqual(_glue.nttime2float(0x8000000000000000), 910692730085.4775)
        self.assertEqual(_glue.nttime2float(0xf000000000000000), 910692730085.4775)
        self.assertEqual(_glue.nttime2float(116444736010000000), 1.0)
        self.assertEqual(_glue.nttime2float(132555325080000000), 1611058908.0)
        self.assertEqual(_glue.nttime2float(132555325081234567), 1611058908.1234567)
        # NTTIME_OMIT (0) and NTTIME_FREEZE (UINT64_MAX) map to SAMBA_UTIME_OMIT (1)
        self.assertEqual(_glue.nttime2float(0), 1.0)
        self.assertEqual(_glue.nttime2float(0xffffffffffffffff), 1.0)

    def test_nttime2string(self):
        string = _glue.nttime2string(116444736010000000)
        self.assertEqual(type(string), str)
        self.assertIn('1970', string)

    def test_debug_level(self):
        prev_level = _glue.get_debug_level()
        try:
            self.assertIsNone(_glue.set_debug_level(0))
            self.assertEqual(_glue.get_debug_level(), 0)
            self.assertIsNone(_glue.set_debug_level(5))
            self.assertEqual(_glue.get_debug_level(), 5)
        finally:
            _glue.set_debug_level(prev_level)

    def test_interface_ips(self):
        lp = param.LoadParm()
        ips = _glue.interface_ips(lp)
        self.assertEqual(type(ips), list)

    def test_strcasecmp(self):
        self.assertEqual(_glue.strcasecmp_m('aA', 'Aa'), 0)
        self.assertNotEqual(_glue.strcasecmp_m('ab', 'Aa'), 0)

    def test_strstr_m(self):
        string = 'testing_string_num__one'
        self.assertEqual(_glue.strstr_m(string, '_'), '_string_num__one')
        self.assertEqual(_glue.strstr_m(string, '__'), '__one')
        self.assertEqual(_glue.strstr_m(string, 'ring'), 'ring_num__one')

    def test_crypt(self):
        # We hopefully only use schemes 5 and 6 (sha256 and sha512),
        # which are OK and also quite widely supported according to
        # https://en.wikipedia.org/wiki/Crypt_(C)
        for phrase, setting, expected in [
                ("a", "$5$aaaaaa",
                 "$5$aaaaaa$F4lxguL7mZR7TGlvukPTJIxoRhVmHMZs8ZdH8oDP0.6"),
                # with scheme 5, 5000 rounds is default, so hash is the same as above
                ('a', '$5$rounds=5000$aaaaaa',
                 '$5$rounds=5000$aaaaaa$F4lxguL7mZR7TGlvukPTJIxoRhVmHMZs8ZdH8oDP0.6'),
                ('a',
                 '$5$rounds=4999$aaaaaa',
                 '$5$rounds=4999$aaaaaa$FiP70gtxOJUFLokUJvET06E7jbL6aNmF6Wtv2ddzjY8'),
                ('a', '$5$aaaaab',
                 '$5$aaaaab$e9qR2F833/JyuMu.nkQc9kn184vBWLo0ODqnCe./mj0'),

                ('', '$5$aaaaaa', '$5$aaaaaa$5B4WTdWp5n/v/aNUw2N8RsEitqvlZJEaAKhH/pOkGg4'),

                ("a", "$6$aaaaaa",
                 "$6$aaaaaa$KHs/Ez7X/I5/K.V8FR7kEsx9rOvjXnEDUmGC.dLBWP87XWy.oUEAM7QYcZQRVhiDwGepOF2pKrCVETYLyASh60"),

                ('', '$5$', '$5$$3c2QQ0KjIU1OLtB29cl8Fplc2WN7X89bnoEjaR7tWu.'),

                # scheme 1 (md5) should be supported if not used
                ('a', '$1$aaaaaa',
                 '$1$aaaaaa$MUMWPbGfzrHFCNm7ZHg31.'),

                ('', '$6$',
                 '$6$$/chiBau24cE26QQVW3IfIe68Xu5.JQ4E8Ie7lcRLwqxO5cxGuBhqF2HmTL.zWJ9zjChg3yJYFXeGBQ2y3Ba1d1'),
                (' ',
                 '$6$6',
                 '$6$6$asLnbxf0obyuv3ybNvDE9ZcdwGFkDhLe7uW.wzdOdKCm4/M3vGFKq4Ttk1tBQrOn4wALZ3tj1L8IarIu5i8hR/'),

                # original DES scheme, 12 bits of salt
                ("a", "lalala", "laKGbFzgh./R2"),
                ("a", "lalalaLALALAla", "laKGbFzgh./R2"),
                ("a", "arrgh", "ar7VUiUvDhX2c"),
                ("a", "arrggghhh", "ar7VUiUvDhX2c"),
                ]:
            hash = _glue.crypt(phrase, setting)
            self.assertEqual(hash, expected)

    def test_crypt_bad(self):
        # We can't be too strident in our assertions, because every
        # system allows a different set of algorithms, and some have
        # different ideas of how to parse.
        for phrase, setting, exception in [
                ("a", "$5", ValueError),
                ("a", "$0$", ValueError),
                ("a", None, TypeError),
                (None, "", TypeError),
                ('a', '$66$', ValueError),
                ('a', '$$', ValueError),
                ('a', '*0', ValueError),
                ('a', '*', ValueError),
                ('a', '++', ValueError),
                # this next one is too long, except on Rocky Linux 8.
                #('a' * 10000, '$5$5', ValueError),
                # this is invalid, except on Debian 11.
                # (' ', '$6$ ', ValueError),
                ]:
            with self.assertRaises(exception,
                                   msg=f"crypt({phrase!r}, {setting!r}) didn't fail"):
                _glue.crypt(phrase, setting)
