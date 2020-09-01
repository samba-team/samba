# Unix SMB/CIFS implementation.
#
# Copyright (C) Andrew Bartlett 2011
# Copyright (C) Isaac Boukris 2020
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

"""Tests for the CreateTrustedDomainRelax wrapper"""

import os
import samba
from samba.tests import TestCase
from samba.dcerpc import lsa, security, drsblobs
from samba.credentials import Credentials, SMB_ENCRYPTION_REQUIRED, SMB_ENCRYPTION_OFF
from samba.trust_utils import CreateTrustedDomainRelax

class CreateTrustedDomainRelaxTest(TestCase):
    def setUp(self):
        super(CreateTrustedDomainRelaxTest, self).setUp()

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

    def _create_trust_relax(self, smbencrypt=True):
        creds = self.get_user_creds()

        if smbencrypt:
            creds.set_smb_encryption(SMB_ENCRYPTION_REQUIRED)
        else:
            creds.set_smb_encryption(SMB_ENCRYPTION_OFF)

        lp = self.get_loadparm()

        binding_string = ("ncacn_np:%s" % (samba.tests.env_get_var_value('SERVER')))
        lsa_conn = lsa.lsarpc(binding_string, lp, creds)

        if smbencrypt:
            self.assertTrue(lsa_conn.transport_encrypted())
        else:
            self.assertFalse(lsa_conn.transport_encrypted())

        objectAttr = lsa.ObjectAttribute()
        objectAttr.sec_qos = lsa.QosInfo()

        pol_handle = lsa_conn.OpenPolicy2('',
                                          objectAttr,
                                          security.SEC_FLAG_MAXIMUM_ALLOWED)
        self.assertIsNotNone(pol_handle)

        name = lsa.String()
        name.string = "tests.samba.example.com"
        try:
            info = lsa_conn.QueryTrustedDomainInfoByName(pol_handle, name,
                                                         lsa.LSA_TRUSTED_DOMAIN_INFO_FULL_INFO)

            lsa_conn.DeleteTrustedDomain(pol_handle, info.info_ex.sid)
        except RuntimeError:
            pass

        info = lsa.TrustDomainInfoInfoEx()
        info.domain_name.string = name.string
        info.netbios_name.string = "createtrustrelax"
        info.sid = security.dom_sid("S-1-5-21-538490383-3740119673-95748416")
        info.trust_direction = lsa.LSA_TRUST_DIRECTION_INBOUND | lsa.LSA_TRUST_DIRECTION_OUTBOUND
        info.trust_type = lsa.LSA_TRUST_TYPE_UPLEVEL
        info.trust_attributes = lsa.LSA_TRUST_ATTRIBUTE_FOREST_TRANSITIVE

        password_blob = samba.string_to_byte_array("password".encode('utf-16-le'))

        clear_value = drsblobs.AuthInfoClear()
        clear_value.size = len(password_blob)
        clear_value.password = password_blob

        clear_authentication_information = drsblobs.AuthenticationInformation()
        clear_authentication_information.LastUpdateTime = 0
        clear_authentication_information.AuthType = lsa.TRUST_AUTH_TYPE_CLEAR
        clear_authentication_information.AuthInfo = clear_value

        authentication_information_array = drsblobs.AuthenticationInformationArray()
        authentication_information_array.count = 1
        authentication_information_array.array = [clear_authentication_information]

        outgoing = drsblobs.trustAuthInOutBlob()
        outgoing.count = 1
        outgoing.current = authentication_information_array

        trustdom_handle = None
        try:
            trustdom_handle = CreateTrustedDomainRelax(lsa_conn,
                                                       pol_handle,
                                                       info,
                                                       security.SEC_STD_DELETE,
                                                       outgoing,
                                                       outgoing)
        except samba.NTSTATUSError as nt:
            raise AssertionError(nt)
        except OSError as e:
            if smbencrypt:
                raise AssertionError(e)

        if smbencrypt:
            self.assertIsNotNone(trustdom_handle)
            lsa_conn.DeleteTrustedDomain(pol_handle, info.sid)
        else:
            self.assertIsNone(trustdom_handle)

    def test_create_trust_relax_encrypt(self):
        self._create_trust_relax(True)

    def test_create_trust_relax_no_enc(self):
        self._create_trust_relax(False)
