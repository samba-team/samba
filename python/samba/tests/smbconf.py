# Unix SMB/CIFS implementation.
# Copyright (C) Jelmer Vernooij <jelmer@samba.org> 2007
# Copyright (C) John Mulligan <phlogistonjohn@asynchrono.us> 2022
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

"""
Tests for samba.smbconf module
"""

from samba.samba3 import param as s3param
import samba.tests


class SMBConfTests(samba.tests.TestCase):
    _smbconf = None
    _s3smbconf = None

    @property
    def smbconf(self):
        """Property to access module under test without
        importing it at test module load-time.
        """
        if self._smbconf is not None:
            return self._smbconf

        import samba.smbconf

        self._smbconf = samba.smbconf
        return self._smbconf

    @property
    def s3smbconf(self):
        if self._s3smbconf is not None:
            return self._s3smbconf

        import samba.samba3.smbconf

        self._s3smbconf = samba.samba3.smbconf
        return self._s3smbconf

    @property
    def example_conf_default(self):
        return "./testdata/samba3/smb.conf"

    def setUp(self):
        super().setUp()
        # fetch the configuration in the same style as other test suites
        self.lp_ctx = samba.tests.env_loadparm()
        # apply the configuration to the samba3 configuration
        # (because there are two... and they're independent!)
        # this is needed to make use of the registry
        s3_lp = s3param.get_context()
        s3_lp.load(self.lp_ctx.configfile)

    def test_uninitalized_smbconf(self):
        sconf = self.smbconf.SMBConf()
        self.assertRaises(RuntimeError, sconf.requires_messaging)
        self.assertRaises(RuntimeError, sconf.is_writeable)
        self.assertRaises(RuntimeError, sconf.share_names)
        self.assertRaises(RuntimeError, sconf.get_share, "foo")

    def test_txt_backend_properties(self):
        sconf = self.smbconf.init_txt(self.example_conf_default)
        self.assertFalse(sconf.requires_messaging())
        self.assertFalse(sconf.is_writeable())

    def test_share_names(self):
        sconf = self.smbconf.init_txt(self.example_conf_default)
        names = sconf.share_names()
        self.assertEqual(names, ["global", "cd1", "cd2", "media", "tmp"])

    def test_get_share_cd1(self):
        sconf = self.smbconf.init_txt(self.example_conf_default)
        s1 = sconf.get_share("cd1")
        self.assertEqual(s1, ("cd1", [("path", "/mnt/cd1"), ("public", "yes")]))

    def test_get_share_cd2(self):
        sconf = self.smbconf.init_txt(self.example_conf_default)
        s1 = sconf.get_share("cd2")
        self.assertEqual(s1, ("cd2", [("path", "/mnt/cd2"), ("public", "yes")]))

    def test_get_config(self):
        sconf = self.smbconf.init_txt(self.example_conf_default)
        services = sconf.get_config()
        self.assertEqual(len(services), 5)
        self.assertEqual(
            services[0],
            (
                "global",
                [
                    ("workgroup", "SAMBA"),
                    ("security", "user"),
                    (
                        "passdb backend",
                        "smbpasswd:../testdata/samba3/smbpasswd "
                        "tdbsam:../testdata/samba3/passdb.tdb ldapsam:tdb://samba3.ldb",
                    ),
                    ("debug level", "5"),
                    ("netbios name", "BEDWYR"),
                ],
            ),
        )
        self.assertEqual(
            services[1], ("cd1", [("path", "/mnt/cd1"), ("public", "yes")])
        )

    def test_init_reg(self):
        sconf = self.s3smbconf.init_reg(None)
        self.assertTrue(sconf.is_writeable())

    def test_init_str_reg(self):
        sconf = self.s3smbconf.init("registry:")
        self.assertTrue(sconf.is_writeable())

    def test_init_str_file(self):
        sconf = self.s3smbconf.init(f"file:{self.example_conf_default}")
        self.assertFalse(sconf.is_writeable())

    def test_create_share(self):
        sconf = self.s3smbconf.init_reg(None)
        sconf.create_share("alice")
        sconf.create_share("bob")
        names = sconf.share_names()
        self.assertEqual(names, ["alice", "bob"])
        self.assertRaises(
            self.smbconf.SMBConfError, sconf.create_share, "alice"
        )


if __name__ == "__main__":
    import unittest

    unittest.main()
