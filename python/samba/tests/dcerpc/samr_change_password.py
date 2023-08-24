# Unix SMB/CIFS implementation.
#
# Copyright © 2020 Andreas Schneider <asn@samba.org>
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

"""Tests for samba.dcerpc.samr.password"""

import ctypes
import samba.tests

from samba import crypto, generate_random_password, generate_random_bytes, ntstatus
from samba.auth import system_session
from samba.credentials import Credentials
from samba.credentials import SMB_ENCRYPTION_REQUIRED
from samba.dcerpc import samr, security, lsa
from samba.samdb import SamDB
from samba.tests import RpcInterfaceTestCase


class SamrPasswordTests(RpcInterfaceTestCase):
    def setUp(self):
        super(SamrPasswordTests, self).setUp()
        self.open_samdb()

        self.create_user_account(10000)

        self.remote_server = samba.tests.env_get_var_value('SERVER')
        self.remote_domain = samba.tests.env_get_var_value('DOMAIN')
        self.remote_user = samba.tests.env_get_var_value('USERNAME')
        self.remote_password = samba.tests.env_get_var_value('PASSWORD')
        self.remote_binding_string = "ncacn_np:%s[krb5]" % (self.remote_server)

        self.remote_creds = Credentials()
        self.remote_creds.guess(self.lp)
        self.remote_creds.set_username(self.remote_user)
        self.remote_creds.set_password(self.remote_password)

    def tearDown(self):
        super(SamrPasswordTests, self).tearDown()

        samr.Close(self.user_handle)
        samr.Close(self.domain_handle)
        samr.Close(self.handle)

        samba.tests.delete_force(self.samdb, self.user_dn)

    #
    # Open the samba database
    #
    def open_samdb(self):
        self.lp = samba.tests.env_loadparm()

        self.local_creds = Credentials()
        self.local_creds.guess(self.lp)
        self.session = system_session()
        self.samdb = SamDB(session_info=self.session,
                           credentials=self.local_creds,
                           lp=self.lp)

    #
    # Open a SAMR Domain handle
    #
    def open_domain_handle(self):
        self.handle = self.conn.Connect2(None,
                                         security.SEC_FLAG_MAXIMUM_ALLOWED)

        self.domain_sid = self.conn.LookupDomain(self.handle,
                                                 lsa.String(self.remote_domain))

        self.domain_handle = self.conn.OpenDomain(self.handle,
                                                  security.SEC_FLAG_MAXIMUM_ALLOWED,
                                                  self.domain_sid)

    def open_user_handle(self):
        name = lsa.String(self.user_name)

        rids = self.conn.LookupNames(self.domain_handle, [name])

        self.user_handle = self.conn.OpenUser(self.domain_handle,
                                              security.SEC_FLAG_MAXIMUM_ALLOWED,
                                              rids[0].ids[0])
    #
    # Create a test user account
    #
    def create_user_account(self, user_id):
        self.user_name = ("SAMR_USER_%d" % user_id)
        self.user_pass = generate_random_password(32, 32)
        self.user_dn = "cn=%s,cn=users,%s" % (self.user_name, self.samdb.domain_dn())

        samba.tests.delete_force(self.samdb, self.user_dn)

        self.samdb.newuser(self.user_name,
                           self.user_pass,
                           description="Password for " + self.user_name + " is " + self.user_pass,
                           givenname=self.user_name,
                           surname=self.user_name)


    def init_samr_CryptPassword(self, password, session_key):

        def encode_pw_buffer(password):
            data = bytearray([0] * 516)

            p = samba.string_to_byte_array(password.encode('utf-16-le'))
            plen = len(p)

            b = generate_random_bytes(512 - plen)

            i = 512 - plen
            data[0:i] = b
            data[i:i+plen] = p
            data[512:516] = plen.to_bytes(4, byteorder='little')

            return bytes(data)

        # This is a test, so always allow to encrypt using RC4
        try:
            crypto.set_relax_mode()
            encrypted_blob = samba.arcfour_encrypt(session_key, encode_pw_buffer(password))
        finally:
            crypto.set_strict_mode()

        out_blob = samr.CryptPassword()
        out_blob.data = list(encrypted_blob)

        return out_blob


    def test_setUserInfo2_Password(self, password='P@ssw0rd'):
        self.conn = samr.samr(self.remote_binding_string,
                              self.get_loadparm(),
                              self.remote_creds)
        self.open_domain_handle()
        self.open_user_handle()

        password='P@ssw0rd'

        level = 24
        info = samr.UserInfo24()

        info.password_expired = 0
        info.password = self.init_samr_CryptPassword(password, self.conn.session_key)

        # If the server is in FIPS mode, it should reject the password change!
        try:
            self.conn.SetUserInfo2(self.user_handle, level, info)
        except samba.NTSTATUSError as e:
            code = ctypes.c_uint32(e.args[0]).value
            print(code)
            if ((code == ntstatus.NT_STATUS_ACCESS_DENIED) and
                (self.lp.weak_crypto == 'disallowed')):
                pass
            else:
                raise


    def test_setUserInfo2_Password_Encrypted(self, password='P@ssw0rd'):
        self.remote_creds.set_smb_encryption(SMB_ENCRYPTION_REQUIRED)

        self.conn = samr.samr(self.remote_binding_string,
                              self.get_loadparm(),
                              self.remote_creds)
        self.open_domain_handle()
        self.open_user_handle()

        password='P@ssw0rd'

        level = 24
        info = samr.UserInfo24()

        info.password_expired = 0
        info.password = self.init_samr_CryptPassword(password, self.conn.session_key)

        self.conn.SetUserInfo2(self.user_handle, level, info)
