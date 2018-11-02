# Black box tests verify bug 13653
#
# Copyright (C) Catalyst.Net Ltd'. 2018
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

"""Blackbox test verifying bug 13653

https://bugzilla.samba.org/show_bug.cgi?id=13653


When creating a new user and specifying the local filepath of the sam.ldb DB,
it's possible to create an account that you can't actually login with.

This only happens if the DB is using encrypted secrets and you specify "ldb://"
in the sam.ldb path, e.g. "-H ldb://st/ad_dc/private/sam.ldb".
The user account will be created, but its secrets will not be encrypted.
Attempts to login as the user will then be rejected due to invalid credentials.

We think this may also cause replication/joins to break.

You do get a warning about "No encrypted secrets key file" when this happens,
although the reason behind this message is not obvious. Specifying a "tdb://"
prefix, or not specifying a prefix, works fine.

Example of the problem below using the ad_dc testenv.

addc$ bin/samba-tool user create tdb-user pass12#
      -H tdb://st/ad_dc/private/sam.ldb
User 'tdb-user' created successfully

# HERE: using the "ldb://" prefix generates a warning, but the user is still
# created successfully.

addc$ bin/samba-tool user create ldb-user pass12#
      -H ldb://st/ad_dc/private/sam.ldb
No encrypted secrets key file. Secret attributes will not be encrypted or
decrypted

User 'ldb-user' created successfully

addc$ bin/samba-tool user create noprefix-user pass12#
      -H st/ad_dc/private/sam.ldb
User 'noprefix-user' created successfully

addc$ bin/ldbsearch -H ldap://$SERVER -Utdb-user%pass12# '(cn=tdb-user)' dn
# record 1
dn: CN=tdb-user,CN=Users,DC=addom,DC=samba,DC=example,DC=com

# Referral
ref: ldap://addom.samba.example.com/CN=Configuration,DC=addom,DC=samba,
     DC=example,DC=com

# Referral
ref: ldap://addom.samba.example.com/DC=DomainDnsZones,DC=addom,DC=samba,
     DC=example,DC=com

# Referral
ref: ldap://addom.samba.example.com/DC=ForestDnsZones,DC=addom,DC=samba,
     DC=example,DC=com

# returned 4 records
# 1 entries
# 3 referrals

# HERE: can't login as the user created with "ldb://" prefix

addc$ bin/ldbsearch -H ldap://$SERVER -Uldb-user%pass12# '(cn=ldb-user)' dn
Wrong username or password: kinit for ldb-user@ADDOM.SAMBA.EXAMPLE.COM failed
(Client not found in Kerberos database)

Failed to bind - LDAP error 49 LDAP_INVALID_CREDENTIALS
               -  <8009030C: LdapErr: DSID-0C0904DC,
                    comment: AcceptSecurityContext error, data 54e, v1db1> <>
Failed to connect to 'ldap://addc' with backend
    'ldap': LDAP error 49 LDAP_INVALID_CREDENTIALS
            -  <8009030C: LdapErr: DSID-0C0904DC,
               comment: AcceptSecurityContext error, data 54e, v1db1> <>
Failed to connect to ldap://addc - LDAP error 49 LDAP_INVALID_CREDENTIALS
    -  <8009030C: LdapErr: DSID-0C0904DC,
       comment: AcceptSecurityContext error, data 54e, v1db1> <>
addc$ bin/ldbsearch -H ldap://$SERVER -Unoprefix-user%pass12#
      '(cn=noprefix-user)' dn
# record 1
dn: CN=noprefix-user,CN=Users,DC=addom,DC=samba,DC=example,DC=com

# Referral
ref: ldap://addom.samba.example.com/CN=Configuration,DC=addom,DC=samba,
    DC=example,DC=com

# Referral
ref: ldap://addom.samba.example.com/DC=DomainDnsZones,DC=addom,DC=samba,
     DC=example,DC=com

# Referral
ref: ldap://addom.samba.example.com/DC=ForestDnsZones,DC=addom,DC=samba,
     DC=example,DC=com

# returned 4 records
# 1 entries
# 3 referrals
"""

from samba.tests import (
    BlackboxTestCase,
    BlackboxProcessError,
    delete_force,
    env_loadparm)
from samba.credentials import Credentials
from samba.samdb import SamDB
from samba.auth import system_session
from os import environ


class Bug13653Tests(BlackboxTestCase):

    # Open a local connection to the SamDB
    # and load configuration from the OS environment.
    def setUp(self):
        super(Bug13653Tests, self).setUp()
        self.env = environ["TEST_ENV"]
        self.server = environ["SERVER"]
        self.prefix = environ["PREFIX_ABS"]
        lp = env_loadparm()
        creds = Credentials()
        session = system_session()
        creds.guess(lp)
        self.ldb = SamDB(session_info=session,
                         credentials=creds,
                         lp=lp)

    # Delete the user account created by the test case.
    # The user name is in self.user
    def tearDown(self):
        super(Bug13653Tests, self).tearDown()
        try:
            dn = "CN=%s,CN=Users,%s" % (self.user, self.ldb.domain_dn())
            delete_force(self.ldb, dn)
        except Exception as e:
            # We ignore any exceptions deleting the user in tearDown
            # this allows the known fail mechanism to work for this test
            # so the test can be committed before the fix.
            # otherwise this delete fails with
            #   Error(11)  unpacking encrypted secret, data possibly corrupted
            #   or altered
            pass

    # Delete the user account created by the test case.
    # The user name is in self.user
    def delete_user(self):
        dn = "CN=%s,CN=Users,%s" % (self.user, self.ldb.domain_dn())
        try:
            delete_force(self.ldb, dn)
        except Exception as e:
            self.fail(str(e))

    def _test_scheme(self, scheme):
        """Ensure a user can be created by samba-tool with the supplied scheme
           and that that user can logon."""

        self.delete_user()

        password = self.random_password()
        db_path = "%s/%s/%s/private/sam.ldb" % (scheme, self.prefix, self.env)
        try:
            command =\
                "samba-tool user create %s %s -H %s" % (
                    self.user, password, db_path)
            self.check_run(command)
            command =\
                "bin/ldbsearch -H ldap://%s/ -U%s%%%s '(cn=%s)' dn" % (
                    self.server, self.user, password, self.user)
            self.check_run(command)
        except BlackboxProcessError as e:
            self.fail(str(e))

    def test_tdb_scheme(self):
        """Ensure a user can be created by samba-tool with the "tbd://" scheme
           and that that user can logon."""

        self.user = "TDB_USER"
        self._test_scheme("tdb://")

    def test_mdb_scheme(self):
        """Ensure a user can be created by samba-tool with the "mdb://" scheme
           and that that user can logon.

           NOTE: this test is currently in knownfail.d/encrypted_secrets as
                 sam.ldb is currently a tdb even if the lmdb backend is
                 selected
        """

        self.user = "MDB_USER"
        self._test_scheme("mdb://")

    def test_ldb_scheme(self):
        """Ensure a user can be created by samba-tool with the "ldb://" scheme
           and that that user can logon."""

        self.user = "LDB_USER"
        self._test_scheme("ldb://")
