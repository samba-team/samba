# Unix SMB/CIFS implementation. Tests for SamDB
# Copyright (C) Jelmer Vernooij <jelmer@samba.org> 2008
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

"""Tests for samba.samdb."""

import logging
import os
import shutil

from samba.auth import system_session
from samba.provision import provision
from samba.tests import TestCaseInTempDir
from samba.dsdb import DS_DOMAIN_FUNCTION_2008_R2


class SamDBTestCase(TestCaseInTempDir):
    """Base-class for tests with a Sam Database.

    This is used by the Samba SamDB-tests, but e.g. also by the OpenChange
    provisioning tests (which need a Sam).
    """

    def setUp(self):
        super(SamDBTestCase, self).setUp()
        self.session = system_session()
        logger = logging.getLogger("selftest")
        self.domain = "dsdb"
        self.realm = "dsdb.samba.example.com"
        host_name = "test"
        server_role = "active directory domain controller"
        self.result = provision(logger,
                                self.session, targetdir=self.tempdir,
                                realm=self.realm, domain=self.domain,
                                hostname=host_name,
                                use_ntvfs=True,
                                serverrole=server_role,
                                dns_backend="SAMBA_INTERNAL",
                                dom_for_fun_level=DS_DOMAIN_FUNCTION_2008_R2)
        self.samdb = self.result.samdb
        self.lp = self.result.lp

    def tearDown(self):
        for f in ['names.tdb']:
            os.remove(os.path.join(self.tempdir, f))

        for d in ['etc', 'msg.lock', 'private', 'state', 'bind-dns']:
            shutil.rmtree(os.path.join(self.tempdir, d))

        super(SamDBTestCase, self).tearDown()


class SamDBTests(SamDBTestCase):

    def test_get_domain(self):
        self.assertEqual(self.samdb.domain_dns_name(), self.realm.lower())
        self.assertEqual(self.samdb.domain_netbios_name(), self.domain.upper())
