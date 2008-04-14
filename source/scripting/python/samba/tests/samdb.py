#!/usr/bin/python

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
from auth import system_session
from credentials import Credentials
import os
from samba.provision import setup_samdb
from samba.samdb import SamDB
from samba.tests import cmdline_loadparm, TestCaseInTempDir
import security
from unittest import TestCase
import uuid

class SamDBTestCase(TestCaseInTempDir):
    def setUp(self):
        super(SamDBTestCase, self).setUp()
        invocationid = uuid.random()
        domaindn = "DC=COM,DC=EXAMPLE"
        self.domaindn = domaindn
        configdn = "CN=Configuration," + domaindn
        schemadn = "CN=Schema," + configdn
        domainguid = uuid.random()
        policyguid = uuid.random()
        setup_path = lambda x: os.path.join("setup", x)
        creds = Credentials()
        creds.set_anonymous()
        domainsid = security.random_sid()
        hostguid = uuid.random()
        path = os.path.join(self.tempdir, "samdb.ldb")
        self.samdb = setup_samdb(path, setup_path, system_session(), creds, 
                                 cmdline_loadparm, schemadn, configdn, 
                                 self.domaindn, "example.com", "EXAMPLE.COM", 
                                 "FOO", lambda x: None, "foo", domaindn, 
                                 False, domainsid, "# no aci", domainguid, 
                                 policyguid, "EXAMPLE", True, "secret", 
                                 "secret", "secret", hostguid, invocationid, 
                                 "secret", "domain controller")

    def test_add_foreign(self):
        self.samdb.add_foreign(self.domaindn, "S-1-5-7", "Somedescription")

