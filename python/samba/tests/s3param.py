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

"""Tests for samba.samba3.param"""

from samba.samba3 import param as s3param
from samba.tests import TestCaseInTempDir
import os


for p in ["../../../../../testdata/samba3", "../../../../testdata/samba3"]:
    DATADIR = os.path.join(os.path.dirname(__file__), p)
    if os.path.exists(DATADIR):
        break


class ParamTestCase(TestCaseInTempDir):

    def setUp(self):
        super(ParamTestCase, self).setUp()
        os.system("cp -r %s %s" % (DATADIR, self.tempdir))
        datadir = os.path.join(self.tempdir, "samba3")

        self.lp = s3param.get_context()
        self.lp.load(os.path.join(datadir, "smb.conf"))

    def tearDown(self):
        self.lp = []
        os.system("rm -rf %s" % os.path.join(self.tempdir, "samba3"))
        super(ParamTestCase, self).tearDown()

    def test_param(self):
        self.assertEqual("BEDWYR", self.lp.get("netbios name"))
        self.assertEqual("SAMBA", self.lp.get("workgroup"))
        self.assertEqual("USER", self.lp.get("security"))
        self.assertEqual("/mnt/cd1", self.lp.get("path", "cd1"))
