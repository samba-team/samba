# Integration tests for pycredentials
#
# Copyright (C) Catalyst IT Ltd. 2017
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
from samba.tests import TestCase, delete_force
import os

import samba
from samba.auth import system_session
from samba.credentials import (
    Credentials,
)
from samba.dsdb import (
    UF_WORKSTATION_TRUST_ACCOUNT,
    UF_PASSWD_NOTREQD,
    UF_NORMAL_ACCOUNT)
from samba.samdb import SamDB

"""KRB5 Integration tests for pycredentials.

Seperated from py_credentials so as to allow running against just one
environment so we know the server that we add the user on will be our
KDC

"""

MACHINE_NAME = "krb5credstest"


class PyKrb5CredentialsTests(TestCase):

    def setUp(self):
        super(PyKrb5CredentialsTests, self).setUp()

        self.server      = os.environ["SERVER"]
        self.domain      = os.environ["DOMAIN"]
        self.host        = os.environ["SERVER_IP"]
        self.lp          = self.get_loadparm()

        self.credentials = self.get_credentials()

        self.session     = system_session()
        self.ldb = SamDB(url="ldap://%s" % self.host,
                         session_info=self.session,
                         credentials=self.credentials,
                         lp=self.lp)

        self.create_machine_account()

    def tearDown(self):
        super(PyKrb5CredentialsTests, self).tearDown()
        delete_force(self.ldb, self.machine_dn)

    def test_get_named_ccache(self):
        name = "MEMORY:py_creds_machine"
        ccache = self.machine_creds.get_named_ccache(self.lp,
                                                     name)
        self.assertEqual(ccache.get_name(), name)

    def test_get_unnamed_ccache(self):
        ccache = self.machine_creds.get_named_ccache(self.lp)
        self.assertIsNotNone(ccache.get_name())

    def test_set_named_ccache(self):
        ccache = self.machine_creds.get_named_ccache(self.lp)

        creds = Credentials()
        creds.set_named_ccache(ccache.get_name())

        ccache2 = creds.get_named_ccache(self.lp)
        self.assertEqual(ccache.get_name(), ccache2.get_name())

    #
    # Create the machine account
    def create_machine_account(self):
        self.machine_pass = samba.generate_random_password(32, 32)
        self.machine_name = MACHINE_NAME
        self.machine_dn = "cn=%s,%s" % (self.machine_name, self.ldb.domain_dn())

        # remove the account if it exists, this will happen if a previous test
        # run failed
        delete_force(self.ldb, self.machine_dn)
        # get unicode str for both py2 and py3
        pass_unicode = self.machine_pass.encode('utf-8').decode('utf-8')
        utf16pw = u'"{0}"'.format(pass_unicode).encode('utf-16-le')
        self.ldb.add({
            "dn": self.machine_dn,
            "objectclass": "computer",
            "sAMAccountName": "%s$" % self.machine_name,
            "userAccountControl":
                str(UF_WORKSTATION_TRUST_ACCOUNT | UF_PASSWD_NOTREQD),
            "unicodePwd": utf16pw})

        self.machine_creds = Credentials()
        self.machine_creds.guess(self.get_loadparm())
        self.machine_creds.set_password(self.machine_pass)
        self.machine_creds.set_username(self.machine_name + "$")
        self.machine_creds.set_workstation(self.machine_name)
