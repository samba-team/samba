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
        sconf.drop()
        sconf.create_share("alice")
        sconf.create_share("bob")
        names = sconf.share_names()
        self.assertEqual(names, ["alice", "bob"])
        self.assertRaises(
            self.smbconf.SMBConfError, sconf.create_share, "alice"
        )

    def test_drop_share(self):
        sconf = self.s3smbconf.init_reg(None)
        sconf.drop()
        sconf.create_share("alice")
        sconf.drop()
        names = sconf.share_names()
        self.assertEqual(names, [])

    def test_set_parameter(self):
        sconf = self.s3smbconf.init_reg(None)
        sconf.drop()
        sconf.create_share("foobar")
        sconf.set_parameter("foobar", "path", "/mnt/foobar")
        sconf.set_parameter("foobar", "browseable", "no")

        s1 = sconf.get_share("foobar")
        self.assertEqual(
            s1, ("foobar", [("path", "/mnt/foobar"), ("browseable", "no")])
        )

    def test_set_global_parameter(self):
        sconf = self.s3smbconf.init_reg(None)
        sconf.drop()
        sconf.set_global_parameter("workgroup", "EXAMPLE")
        sconf.set_global_parameter("x:custom", "fake")

        s1 = sconf.get_share("global")
        self.assertEqual(
            s1, ("global", [("workgroup", "EXAMPLE"), ("x:custom", "fake")])
        )

    def test_delete_share(self):
        sconf = self.s3smbconf.init_reg(None)
        sconf.drop()

        sconf.create_share("alice")
        sconf.create_share("bob")
        names = sconf.share_names()
        self.assertEqual(names, ["alice", "bob"])

        sconf.delete_share("alice")
        names = sconf.share_names()
        self.assertEqual(names, ["bob"])

    def test_create_set_share(self):
        sconf = self.s3smbconf.init_reg(None)
        sconf.drop()

        params = [
            ("path", "/mnt/baz"),
            ("browseable", "yes"),
            ("read only", "no"),
        ]
        sconf.create_set_share("baz", params)
        self.assertEqual(sconf.get_share("baz"), ("baz", params))

        self.assertRaises(
            self.smbconf.SMBConfError, sconf.create_set_share, "baz", params
        )
        self.assertRaises(TypeError, sconf.create_set_share, "baz", None)
        self.assertRaises(
            ValueError, sconf.create_set_share, "baz", [None, None]
        )
        self.assertRaises(
            TypeError, sconf.create_set_share, "baz", [("hi", None)]
        )
        self.assertRaises(
            ValueError, sconf.create_set_share, "baz", [("a", "b", "c")]
        )

    def test_delete_parameter(self):
        sconf = self.s3smbconf.init_reg(None)
        sconf.drop()

        params = [
            ("path", "/mnt/baz"),
            ("browseable", "yes"),
            ("read only", "no"),
        ]
        sconf.create_set_share("baz", params)
        self.assertEqual(sconf.get_share("baz"), ("baz", params))

        sconf.delete_parameter("baz", "browseable")
        self.assertEqual(
            sconf.get_share("baz"),
            (
                "baz",
                [
                    ("path", "/mnt/baz"),
                    ("read only", "no"),
                ],
            ),
        )

    def test_delete_global_parameter(self):
        sconf = self.s3smbconf.init_reg(None)
        sconf.drop()
        sconf.set_global_parameter("workgroup", "EXAMPLE")
        sconf.set_global_parameter("client min protocol", "NT1")
        sconf.set_global_parameter("server min protocol", "SMB2")

        s1 = sconf.get_share("global")
        self.assertEqual(
            s1,
            (
                "global",
                [
                    ("workgroup", "EXAMPLE"),
                    ("client min protocol", "NT1"),
                    ("server min protocol", "SMB2"),
                ],
            ),
        )

        sconf.delete_global_parameter("server min protocol")
        sconf.delete_global_parameter("client min protocol")
        s1 = sconf.get_share("global")
        self.assertEqual(s1, ("global", [("workgroup", "EXAMPLE")]))

    def test_transaction_direct(self):
        sconf = self.s3smbconf.init_reg(None)
        sconf.drop()
        sconf.set_global_parameter("workgroup", "EXAMPLE")

        sconf.transaction_start()
        sconf.set_global_parameter("client min protocol", "NT1")
        sconf.set_global_parameter("server min protocol", "SMB2")
        sconf.transaction_cancel()

        s1 = sconf.get_share("global")
        self.assertEqual(s1, ("global", [("workgroup", "EXAMPLE")]))

        sconf.transaction_start()
        sconf.set_global_parameter("client min protocol", "NT1")
        sconf.set_global_parameter("server min protocol", "SMB2")
        sconf.transaction_commit()

        s1 = sconf.get_share("global")
        self.assertEqual(
            s1,
            (
                "global",
                [
                    ("workgroup", "EXAMPLE"),
                    ("client min protocol", "NT1"),
                    ("server min protocol", "SMB2"),
                ],
            ),
        )

    def test_transaction_tryexc(self):
        sconf = self.s3smbconf.init_reg(None)
        sconf.drop()

        def _mkshares(shares):
            sconf.transaction_start()
            try:
                for name, params in shares:
                    sconf.create_set_share(name, params)
                sconf.transaction_commit()
            except Exception:
                sconf.transaction_cancel()
                raise

        _mkshares(
            [
                ("hello", [("path", "/srv/world")]),
                ("goodnight", [("path", "/srv/moon")]),
            ]
        )
        # this call to _mkshares will fail the whole transaction because
        # share name "goodnight" already exists
        self.assertRaises(
            self.smbconf.SMBConfError,
            _mkshares,
            [
                ("mars", [("path", "/srv/mars")]),
                ("goodnight", [("path", "/srv/phobos")]),
            ],
        )

        names = sconf.share_names()
        self.assertEqual(names, ["hello", "goodnight"])

    def test_error_badfile(self):
        with self.assertRaises(self.smbconf.SMBConfError) as raised:
            self.smbconf.init_txt("/foo/bar/baz/_I-dont/.exist/-ok-")
        self.assertEqual(
            self.smbconf.SBC_ERR_BADFILE, raised.exception.error_code)

    def test_error_not_supported(self):
        sconf = self.smbconf.init_txt(self.example_conf_default)
        with self.assertRaises(self.smbconf.SMBConfError) as raised:
            sconf.set_global_parameter("client min protocol", "NT1")
        self.assertEqual(
            self.smbconf.SBC_ERR_NOT_SUPPORTED, raised.exception.error_code)

    def test_error_no_such_service(self):
        sconf = self.smbconf.init_txt(self.example_conf_default)
        with self.assertRaises(self.smbconf.SMBConfError) as raised:
            sconf.get_share("zilch"),
        self.assertEqual(
            self.smbconf.SBC_ERR_NO_SUCH_SERVICE, raised.exception.error_code)



if __name__ == "__main__":
    import unittest

    unittest.main()
