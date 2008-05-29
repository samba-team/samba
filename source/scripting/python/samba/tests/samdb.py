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
from samba.auth import system_session
from samba.credentials import Credentials
import os
from samba.provision import setup_samdb, guess_names, setup_templatesdb
from samba.samdb import SamDB
from samba.tests import cmdline_loadparm, TestCaseInTempDir
from samba import security
from unittest import TestCase
import uuid

class SamDBTestCase(TestCaseInTempDir):
    def setUp(self):
        super(SamDBTestCase, self).setUp()
        invocationid = str(uuid.uuid4())
        domaindn = "DC=COM,DC=EXAMPLE"
        self.domaindn = domaindn
        configdn = "CN=Configuration," + domaindn
        schemadn = "CN=Schema," + configdn
        domainguid = str(uuid.uuid4())
        policyguid = str(uuid.uuid4())
        setup_path = lambda x: os.path.join("setup", x)
        creds = Credentials()
        creds.set_anonymous()
        domainsid = security.random_sid()
        hostguid = str(uuid.uuid4())
        path = os.path.join(self.tempdir, "samdb.ldb")
        session_info = system_session()
        names = guess_names(lp=cmdline_loadparm, hostname="foo", 
                            domain="EXAMPLE.COM", dnsdomain="example.com", 
                            serverrole="domain controller", 
                            domaindn=self.domaindn, configdn=configdn, 
                            schemadn=schemadn)
        setup_templatesdb(os.path.join(self.tempdir, "templates.ldb"), 
                          setup_path, session_info=session_info, 
                          credentials=creds, lp=cmdline_loadparm)
        self.samdb = setup_samdb(path, setup_path, session_info, creds, 
                                 cmdline_loadparm, names, 
                                 lambda x: None, domainsid, 
                                 "# no aci", domainguid, 
                                 policyguid, False, "secret", 
                                 "secret", "secret", invocationid, 
                                 "secret", "domain controller")
    def tearDown(self):
        for f in ['templates.ldb', 'schema.ldb', 'configuration.ldb', 
                  'users.ldb', 'samdb.ldb']:
            os.remove(os.path.join(self.tempdir, f))
        super(SamDBTestCase, self).tearDown()

    def test_add_foreign(self):
        self.samdb.add_foreign(self.domaindn, "S-1-5-7", "Somedescription")

