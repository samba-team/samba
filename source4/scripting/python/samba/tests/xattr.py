#!/usr/bin/python

# Unix SMB/CIFS implementation. Tests for xattr manipulation
# Copyright (C) Matthieu Patou <mat@matws.net> 2009
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

import samba.xattr_native, samba.xattr_tdb
from samba.dcerpc import xattr
from samba.ndr import ndr_pack, ndr_unpack
from unittest import TestCase
import random
import os
import tdb

class XattrTests(TestCase):

    def test_set_xattr_native(self):
		if samba.xattr_native.is_xattr_supported():
			random.seed()
			path=os.environ['SELFTEST_PREFIX']
			tempf=os.path.join(path,"pytests"+str(int(100000*random.random())))
			ntacl=xattr.NTACL()
			ntacl.version = 1
			open(tempf, 'w').write("empty")
			samba.xattr_native.wrap_setxattr(tempf,"user.unittests",ndr_pack(ntacl))
			os.unlink(tempf)

    def test_set_and_get_native(self):
		if samba.xattr_native.is_xattr_supported():
			random.seed()
			path=os.environ['SELFTEST_PREFIX']
			tempf=os.path.join(path,"pytests"+str(int(100000*random.random())))
			reftxt="this is a test"
			open(tempf, 'w').write("empty")
			samba.xattr_native.wrap_setxattr(tempf,"user.unittests",reftxt)
			text = samba.xattr_native.wrap_getxattr(tempf,"user.unittests")
			self.assertEquals(text,reftxt)
			os.unlink(tempf)

    def test_set_xattr_tdb(self):
		path=os.environ['SELFTEST_PREFIX']
		eadb=tdb.Tdb(os.path.join(path,"eadb.tdb"), 50000, tdb.DEFAULT, os.O_CREAT|os.O_RDWR)
		random.seed()
		tempf=os.path.join(path,"pytests"+str(int(100000*random.random())))
		ntacl=xattr.NTACL()
		ntacl.version = 1
		open(tempf, 'w').write("empty")
		samba.xattr_tdb.wrap_setxattr(eadb,tempf,"user.unittests",ndr_pack(ntacl))
		os.unlink(tempf)
		os.unlink(os.path.join(path,"eadb.tdb"))

    def test_set_and_get_tdb(self):
		path=os.environ['SELFTEST_PREFIX']
		eadb=tdb.Tdb(os.path.join(path,"eadb.tdb"), 50000, tdb.DEFAULT, os.O_CREAT|os.O_RDWR)
		random.seed()
		tempf=os.path.join(path,"pytests"+str(int(100000*random.random())))
		reftxt="this is a test"
		open(tempf, 'w').write("empty")
		samba.xattr_tdb.wrap_setxattr(eadb,tempf,"user.unittests",reftxt)
		text = samba.xattr_tdb.wrap_getxattr(eadb,tempf,"user.unittests")
		self.assertEquals(text,reftxt)
		os.unlink(tempf)
		os.unlink(os.path.join(path,"eadb.tdb"))


