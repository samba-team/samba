# Blackbox tests for DFS (widelink)
#
# Copyright (C) Noel Power noel.power@suse.com
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
from samba.tests import BlackboxTestCase, BlackboxProcessError
from samba.samba3 import param as s3param

from samba.credentials import Credentials

import os

class DfsWidelinkBlockboxTestBase(BlackboxTestCase):

    def setUp(self):
        super().setUp()
        self.lp = s3param.get_context()
        self.server = os.environ["SERVER"]
        self.user = os.environ["USER"]
        self.passwd = os.environ["PASSWORD"]
        self.creds = Credentials()
        self.creds.guess(self.lp)
        self.creds.set_username(self.user)
        self.creds.set_password(self.passwd)
        self.testdir = os.getenv("TESTDIR", "msdfs-share-wl")
        self.share = os.getenv("SHARE", "msdfs-share-wl")
        self.dirpath = os.path.join(os.environ["LOCAL_PATH"],self.testdir)
        # allow a custom teardown function to be defined
        self.cleanup = None
        self.cleanup_args = []

    def tearDown(self):
        try:
            if (self.cleanup):
                self.cleanup(self.cleanup_args)
        except Exception as e:
            print("remote remove failed: %s" % str(e))

    def build_test_cmd(self, cmd, args):
        cmd = [cmd, "-U%s%%%s" % (self.user, self.passwd)]
        cmd.extend(args)
        return cmd

    def test_ci_chdir(self):
        parent_dir = "msdfs-src1"
        dirs = [parent_dir, parent_dir.upper()]
        # try as named dir first then try upper-cased version
        for adir in dirs:
            smbclient_args = self.build_test_cmd("smbclient", ["//%s/%s" % (self.server, self.share), "-c", "cd %s" % (adir)])
            try:
                out_str = self.check_output(smbclient_args)
            except BlackboxProcessError as e:
                print(str(e))
                self.fail(str(e))

    def test_nested_chdir(self):
        parent_dir = "dfshop1"
        child_dir = "dfshop2"
        smbclient_args = self.build_test_cmd("smbclient", ["//%s/%s" % (self.server, self.share), "-c", "cd %s/%s" % (parent_dir,child_dir)])
        try:
            out_str = self.check_output(smbclient_args)
        except BlackboxProcessError as e:
            print(str(e))
            self.fail(str(e))

    def test_enumerate_dfs_link(self):
        smbclient_args = self.build_test_cmd("smbclient", ["//%s/%s" % (self.server, self.share), "-c", "dir"])
        try:
            out_str = self.check_output(smbclient_args)
        except BlackboxProcessError as e:
            print(str(e))
            self.fail(str(e))
        out_str = out_str.decode()
        self.assertIn("msdfs-src1", out_str)
