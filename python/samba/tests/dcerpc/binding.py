#
# Unix SMB/CIFS implementation.
# Copyright (c) 2020      Andreas Schneider <asn@samba.org>
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

"""Tests for samba.dcerpc., credentials and binding strings"""

import samba.tests
from samba.tests import RpcInterfaceTestCase, TestCase
from samba.dcerpc import lsa
import samba.dcerpc.security as security
from samba.credentials import Credentials, SMB_ENCRYPTION_REQUIRED, SMB_ENCRYPTION_OFF
from samba import NTSTATUSError

class RpcBindingTests(RpcInterfaceTestCase):
    def setUp(self):
        super(RpcBindingTests, self).setUp()

    def get_user_creds(self):
        c = Credentials()
        c.guess()
        domain = samba.tests.env_get_var_value('DOMAIN')
        username = samba.tests.env_get_var_value('USERNAME')
        password = samba.tests.env_get_var_value('PASSWORD')
        c.set_domain(domain)
        c.set_username(username)
        c.set_password(password)
        return c

    def test_smb3_dcerpc_no_encryption(self):
        creds = self.get_user_creds()
        creds.set_smb_encryption(SMB_ENCRYPTION_OFF)

        lp = self.get_loadparm()
        lp.set('client ipc max protocol', 'SMB3')
        lp.set('client ipc min protocol', 'SMB3')

        binding_string = ("ncacn_np:%s" % (samba.tests.env_get_var_value('SERVER')))
        lsa_conn = lsa.lsarpc(binding_string, lp, creds)
        self.assertFalse(lsa_conn.transport_encrypted())

        objectAttr = lsa.ObjectAttribute()
        objectAttr.sec_qos = lsa.QosInfo()

        pol_handle = lsa_conn.OpenPolicy2('',
                                          objectAttr,
                                          security.SEC_FLAG_MAXIMUM_ALLOWED)
        self.assertIsNotNone(pol_handle)

    def test_smb3_dcerpc_encryption(self):
        creds = self.get_user_creds()
        creds.set_smb_encryption(SMB_ENCRYPTION_REQUIRED)

        lp = self.get_loadparm()
        lp.set('client ipc max protocol', 'SMB3')
        lp.set('client ipc min protocol', 'SMB3')

        binding_string = ("ncacn_np:%s" % (samba.tests.env_get_var_value('SERVER')))
        lsa_conn = lsa.lsarpc(binding_string, lp, creds)
        self.assertTrue(lsa_conn.transport_encrypted())

        objectAttr = lsa.ObjectAttribute()
        objectAttr.sec_qos = lsa.QosInfo()

        pol_handle = lsa_conn.OpenPolicy2('',
                                          objectAttr,
                                          security.SEC_FLAG_MAXIMUM_ALLOWED)
        self.assertIsNotNone(pol_handle)

    def test_smb2_dcerpc_encryption(self):
        creds = self.get_user_creds()
        creds.set_smb_encryption(SMB_ENCRYPTION_REQUIRED)

        lp = self.get_loadparm()
        lp.set('client ipc max protocol', 'SMB2')
        lp.set('client ipc min protocol', 'SMB2')

        binding_string = ("ncacn_np:%s" % (samba.tests.env_get_var_value('SERVER')))
        self.assertRaises(NTSTATUSError, lsa.lsarpc, binding_string, lp, creds)

    def test_smb1_dcerpc_encryption(self):
        creds = self.get_user_creds()
        creds.set_smb_encryption(SMB_ENCRYPTION_REQUIRED)

        lp = self.get_loadparm()
        lp.set('client ipc max protocol', 'NT1')
        lp.set('client ipc min protocol', 'NT1')

        binding_string = ("ncacn_np:%s" % (samba.tests.env_get_var_value('SERVER')))
        self.assertRaises(NTSTATUSError, lsa.lsarpc, binding_string, lp, creds)
