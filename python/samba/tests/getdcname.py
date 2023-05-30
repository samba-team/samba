# Unix SMB/CIFS implementation.
# Copyright (C) Andrew Bartlett <abartlet@samba.org> 2018
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

"""
    Tests GetDCNameEx calls in NETLOGON
"""

from samba import auth
from samba import WERRORError, werror
import samba.tests
import os
from samba.credentials import Credentials
from samba.dcerpc import netlogon, nbt
from samba.dcerpc.misc import GUID
from samba.net import Net

class GetDCNameEx(samba.tests.TestCase):

    def setUp(self):
        self.lp = samba.tests.env_loadparm()
        self.creds = Credentials()

        self.netlogon_conn = None
        self.server = os.environ.get('SERVER')
        self.realm = os.environ.get('REALM')
        self.domain = os.environ.get('DOMAIN')
        self.trust_realm = os.environ.get('TRUST_REALM')
        self.trust_domain = os.environ.get('TRUST_DOMAIN')
        self.trust_server = os.environ.get('TRUST_SERVER')

    def _call_get_dc_name(self, domain=None, domain_guid=None,
                          site_name=None, ex2=False, flags=0):
        if self.netlogon_conn is None:
            self.netlogon_conn = netlogon.netlogon(f"ncacn_ip_tcp:{self.server}",
                                                   self.get_loadparm())

        if ex2:
            return self.netlogon_conn.netr_DsRGetDCNameEx2(self.server,
                                                           None, 0,
                                                           domain,
                                                           domain_guid,
                                                           site_name,
                                                           flags)
        else:
            return self.netlogon_conn.netr_DsRGetDCNameEx(self.server,
                                                          domain,
                                                          domain_guid,
                                                          site_name,
                                                          flags)

    def test_get_dc_ex2(self):
        """Check the most trivial requirements of Ex2 (no domain or site)

        a) The paths are prefixed with two backslashes
        b) The returned domains conform to the format requested
        c) The domain matches our own domain
        """
        response = self._call_get_dc_name(ex2=True)

        self.assertIsNotNone(response.dc_unc)
        self.assertTrue(response.dc_unc.startswith('\\\\'))
        self.assertIsNotNone(response.dc_address)
        self.assertTrue(response.dc_address.startswith('\\\\'))

        self.assertTrue(response.domain_name.lower() ==
                        self.realm.lower() or
                        response.domain_name.lower() ==
                        self.domain.lower())

        response = self._call_get_dc_name(ex2=True,
                                          flags=netlogon.DS_RETURN_DNS_NAME)
        self.assertEqual(response.domain_name.lower(),
                         self.realm.lower())

        response = self._call_get_dc_name(ex2=True,
                                          flags=netlogon.DS_RETURN_FLAT_NAME)
        self.assertEqual(response.domain_name.lower(),
                         self.domain.lower())

    def test_get_dc_over_winbind_ex2(self):
        """Check what happens to Ex2 requests after being forwarded to winbind

        a) The paths must still have the same backslash prefixes
        b) The returned domain does not match our own domain
        c) The domain matches the format requested
        """
        self.assertIsNotNone(self.trust_realm)

        response_trust = self._call_get_dc_name(domain=self.trust_realm,
                                                ex2=True)
        response = self._call_get_dc_name(domain=self.realm,
                                          ex2=True)

        self.assertIsNotNone(response_trust.dc_unc)
        self.assertTrue(response_trust.dc_unc.startswith('\\\\'))
        self.assertIsNotNone(response_trust.dc_address)
        self.assertTrue(response_trust.dc_address.startswith('\\\\'))

        self.assertNotEqual(response_trust.dc_unc,
                            response.dc_unc)
        self.assertNotEqual(response_trust.dc_address,
                            response.dc_address)

        self.assertTrue(response_trust.domain_name.lower() ==
                        self.trust_realm.lower() or
                        response_trust.domain_name.lower() ==
                        self.trust_domain.lower())

        response_trust = self._call_get_dc_name(domain=self.trust_realm,
                                                flags=netlogon.DS_RETURN_DNS_NAME,
                                                ex2=True)
        self.assertEqual(response_trust.domain_name.lower(),
                         self.trust_realm.lower())

        response_trust = self._call_get_dc_name(domain=self.trust_realm,
                                                flags=netlogon.DS_RETURN_FLAT_NAME,
                                                ex2=True)
        self.assertEqual(response_trust.domain_name.lower(),
                         self.trust_domain.lower())

    def test_get_dc_over_winbind(self):
        """Test the standard Ex version (not Ex2)

        Ex calls Ex2 anyways, from now on, just test Ex.
        """
        self.assertIsNotNone(self.trust_realm)

        response_trust = self._call_get_dc_name(domain=self.trust_realm,
                                                flags=netlogon.DS_RETURN_DNS_NAME)

        self.assertIsNotNone(response_trust.dc_unc)
        self.assertTrue(response_trust.dc_unc.startswith('\\\\'))
        self.assertIsNotNone(response_trust.dc_address)
        self.assertTrue(response_trust.dc_address.startswith('\\\\'))

        self.assertEqual(response_trust.domain_name.lower(),
                         self.trust_realm.lower())

    def test_get_dc_over_winbind_with_site(self):
        """Test the standard Ex version (not Ex2)

        We assume that there is a Default-First-Site-Name site.
        """
        if self.trust_realm is None:
            return

        site = 'Default-First-Site-Name'
        response_trust = self._call_get_dc_name(domain=self.trust_realm,
                                                site_name=site,
                                                flags=netlogon.DS_RETURN_DNS_NAME)

        self.assertIsNotNone(response_trust.dc_unc)
        self.assertTrue(response_trust.dc_unc.startswith('\\\\'))
        self.assertIsNotNone(response_trust.dc_address)
        self.assertTrue(response_trust.dc_address.startswith('\\\\'))

        self.assertEqual(response_trust.domain_name.lower(),
                         self.trust_realm.lower())

        self.assertEqual(site.lower(), response_trust.dc_site_name.lower())

    def test_get_dc_over_winbind_invalid_site(self):
        """Test the standard Ex version (not Ex2)

        We assume that there is no Invalid-First-Site-Name site.
        """
        self.assertIsNotNone(self.trust_realm)

        site = 'Invalid-First-Site-Name'
        try:
            response_trust = self._call_get_dc_name(domain=self.trust_realm,
                                                    site_name=site,
                                                    flags=netlogon.DS_RETURN_DNS_NAME,
                                                    ex2=False)
            self.fail("Failed to give the correct error for incorrect site")
        except WERRORError as e:
            enum, estr = e.args
            if enum != werror.WERR_NO_SUCH_DOMAIN:
                self.fail("Failed to detect an invalid site name")

    def test_get_dc_over_winbind_invalid_site_ex2(self):
        """Test the Ex2 version.

        We assume that there is no Invalid-First-Site-Name site.
        """
        self.assertIsNotNone(self.trust_realm)

        site = 'Invalid-First-Site-Name'
        try:
            response_trust = self._call_get_dc_name(domain=self.trust_realm,
                                                    site_name=site,
                                                    flags=netlogon.DS_RETURN_DNS_NAME,
                                                    ex2=True)
            self.fail("Failed to give the correct error for incorrect site")
        except WERRORError as e:
            enum, estr = e.args
            if enum != werror.WERR_NO_SUCH_DOMAIN:
                self.fail("Failed to detect an invalid site name")

    def test_get_dc_over_winbind_empty_string_site(self):
        """Test the standard Ex version (not Ex2)

        We assume that there is a Default-First-Site-Name site.
        """
        self.assertIsNotNone(self.trust_realm)

        site = ''
        try:
            response_trust = self._call_get_dc_name(domain=self.trust_realm,
                                                    site_name=site,
                                                    flags=netlogon.DS_RETURN_DNS_NAME)
        except WERRORError as e:
            self.fail("Unable to get empty string site result: " + str(e))

        self.assertIsNotNone(response_trust.dc_unc)
        self.assertTrue(response_trust.dc_unc.startswith('\\\\'))
        self.assertIsNotNone(response_trust.dc_address)
        self.assertTrue(response_trust.dc_address.startswith('\\\\'))

        self.assertEqual(response_trust.domain_name.lower(),
                         self.trust_realm.lower())

        self.assertIsNotNone(response_trust.dc_site_name)
        self.assertNotEqual('', response_trust.dc_site_name)

    def test_get_dc_over_winbind_netbios(self):
        """Supply a NETBIOS trust domain name."""
        self.assertIsNotNone(self.trust_realm)

        try:
            response_trust = self._call_get_dc_name(domain=self.trust_domain,
                                                    flags=netlogon.DS_RETURN_DNS_NAME,
                                                    ex2=False)
        except WERRORError as e:
            self.fail("Failed to succeed over winbind: " + str(e))

        self.assertIsNotNone(response_trust)
        self.assertEqual(response_trust.domain_name.lower(),
                         self.trust_realm.lower())

    def test_get_dc_over_winbind_with_site_netbios(self):
        """Supply a NETBIOS trust domain name.

        Sporadically fails because NETBIOS queries do not return site name in
        winbind. The site check in NETLOGON will trigger and fail the request.

        Currently marked in flapping...
        """
        self.assertIsNotNone(self.trust_realm)

        site = 'Default-First-Site-Name'
        try:
            response_trust = self._call_get_dc_name(domain=self.trust_domain,
                                                    site_name=site,
                                                    flags=netlogon.DS_RETURN_DNS_NAME,
                                                    ex2=False)
        except WERRORError as e:
            self.fail("get_dc_name (domain=%s,site=%s) over winbind failed: %s"
                      % (self.trust_domain, site, e))

        self.assertIsNotNone(response_trust)
        self.assertEqual(response_trust.domain_name.lower(),
                         self.trust_realm.lower())

        self.assertEqual(site.lower(), response_trust.dc_site_name.lower())

    def test_get_dc_over_winbind_domain_guid(self):
        """Ensure that we do not reject requests supplied with a NULL GUID"""

        self.assertIsNotNone(self.trust_realm)

        null_guid = GUID()
        try:
            response_trust = self._call_get_dc_name(domain=self.trust_realm,
                                                    domain_guid=null_guid,
                                                    flags=netlogon.DS_RETURN_DNS_NAME)
        except WERRORError as e:
            self.fail("Unable to get NULL domain GUID result: " + str(e))

        self.assertIsNotNone(response_trust.dc_unc)
        self.assertTrue(response_trust.dc_unc.startswith('\\\\'))
        self.assertIsNotNone(response_trust.dc_address)
        self.assertTrue(response_trust.dc_address.startswith('\\\\'))

        self.assertEqual(response_trust.domain_name.lower(),
                         self.trust_realm.lower())

    def test_get_dc_with_site(self):
        """Test the standard Ex version (not Ex2)

        We assume that there is a Default-First-Site-Name site.
        """

        site = 'Default-First-Site-Name'
        response = self._call_get_dc_name(domain=self.realm,
                                          site_name=site,
                                          flags=netlogon.DS_RETURN_DNS_NAME)

        self.assertIsNotNone(response.dc_unc)
        self.assertTrue(response.dc_unc.startswith('\\\\'))
        self.assertIsNotNone(response.dc_address)
        self.assertTrue(response.dc_address.startswith('\\\\'))

        self.assertEqual(response.domain_name.lower(),
                         self.realm.lower())

        self.assertEqual(site.lower(), response.dc_site_name.lower())

    def test_get_dc_invalid_site(self):
        """Test the standard Ex version (not Ex2)

        We assume that there is no Invalid-First-Site-Name site.
        """
        self.assertIsNotNone(self.realm)

        site = 'Invalid-First-Site-Name'
        try:
            response = self._call_get_dc_name(domain=self.realm,
                                              site_name=site,
                                              flags=netlogon.DS_RETURN_DNS_NAME,
                                              ex2=False)
            self.fail("Failed to give the correct error for incorrect site")
        except WERRORError as e:
            enum, estr = e.args
            if enum != werror.WERR_NO_SUCH_DOMAIN:
                self.fail("Failed to detect an invalid site name")

    def test_get_dc_invalid_site_ex2(self):
        """Test the Ex2 version

        We assume that there is no Invalid-First-Site-Name site.
        """

        site = 'Invalid-First-Site-Name'
        try:
            response = self._call_get_dc_name(domain=self.realm,
                                              site_name=site,
                                              flags=netlogon.DS_RETURN_DNS_NAME,
                                              ex2=True)
            self.fail("Failed to give the correct error for incorrect site")
        except WERRORError as e:
            enum, estr = e.args
            if enum != werror.WERR_NO_SUCH_DOMAIN:
                self.fail("Failed to detect an invalid site name")

    def test_get_dc_empty_string_site(self):
        """Test the standard Ex version (not Ex2)

        We assume that there is a Default-First-Site-Name site.
        """

        site = ''
        try:
            response = self._call_get_dc_name(domain=self.realm,
                                              site_name=site,
                                              flags=netlogon.DS_RETURN_DNS_NAME)
        except WERRORError as e:
            self.fail("Unable to get empty string site result: " + str(e))

        self.assertIsNotNone(response.dc_unc)
        self.assertTrue(response.dc_unc.startswith('\\\\'))
        self.assertIsNotNone(response.dc_address)
        self.assertTrue(response.dc_address.startswith('\\\\'))

        self.assertEqual(response.domain_name.lower(),
                         self.realm.lower())

        self.assertIsNotNone(response.dc_site_name)
        self.assertNotEqual('', response.dc_site_name)

    def test_get_dc_netbios(self):
        """Supply a NETBIOS domain name."""

        try:
            response = self._call_get_dc_name(domain=self.domain,
                                              flags=netlogon.DS_RETURN_DNS_NAME,
                                              ex2=False)
        except WERRORError as e:
            self.fail("Failed to succeed over winbind: " + str(e))

        self.assertIsNotNone(response)
        self.assertEqual(response.domain_name.lower(),
                         self.realm.lower())

    def test_get_dc_with_site_netbios(self):
        """Supply a NETBIOS domain name."""

        site = 'Default-First-Site-Name'
        try:
            response = self._call_get_dc_name(domain=self.domain,
                                              site_name=site,
                                              flags=netlogon.DS_RETURN_DNS_NAME,
                                              ex2=False)
        except WERRORError as e:
            self.fail("Failed to succeed over winbind: " + str(e))

        self.assertIsNotNone(response)
        self.assertEqual(response.domain_name.lower(),
                         self.realm.lower())

        self.assertEqual(site.lower(), response.dc_site_name.lower())

    def test_get_dc_with_domain_guid(self):
        """Ensure that we do not reject requests supplied with a NULL GUID"""

        null_guid = GUID()
        response = self._call_get_dc_name(domain=self.realm,
                                          domain_guid=null_guid,
                                          flags=netlogon.DS_RETURN_DNS_NAME)

        self.assertIsNotNone(response.dc_unc)
        self.assertTrue(response.dc_unc.startswith('\\\\'))
        self.assertIsNotNone(response.dc_address)
        self.assertTrue(response.dc_address.startswith('\\\\'))

        self.assertEqual(response.domain_name.lower(),
                         self.realm.lower())

    def test_get_dc_with_empty_string_domain(self):
        """Ensure that empty domain resolve to the DC domain"""
        response = self._call_get_dc_name(domain='',
                                          flags=netlogon.DS_RETURN_DNS_NAME)

        self.assertIsNotNone(response.dc_unc)
        self.assertTrue(response.dc_unc.startswith('\\\\'))
        self.assertIsNotNone(response.dc_address)
        self.assertTrue(response.dc_address.startswith('\\\\'))

        self.assertEqual(response.domain_name.lower(),
                         self.realm.lower())

    def test_get_dc_winbind_need_2012r2(self):
        """Test requring that we have a FL2012R2 DC as answer
        """
        self.assertIsNotNone(self.trust_realm)

        try:
            response_trust = self._call_get_dc_name(domain=self.trust_realm,
                                                flags=netlogon.DS_RETURN_DNS_NAME|netlogon.DS_DIRECTORY_SERVICE_9_REQUIRED)
        except WERRORError as e:
            enum, estr = e.args
            self.fail(f"netr_DsRGetDCNameEx failed: {estr}")

        self.assertIsNotNone(response_trust.dc_unc)
        self.assertTrue(response_trust.dc_unc.startswith('\\\\'))
        self.assertIsNotNone(response_trust.dc_address)
        self.assertTrue(response_trust.dc_address.startswith('\\\\'))

        self.assertEqual(response_trust.domain_name.lower(),
                         self.trust_realm.lower())

        # Now check the CLDAP netlogon response matches the above
        dc_ip = response_trust.dc_address[2:]

        net = Net(creds=self.creds, lp=self.lp)
        cldap_netlogon_reply = net.finddc(domain=self.trust_realm, address=dc_ip,
                                          flags=(nbt.NBT_SERVER_LDAP |
                                                 nbt.NBT_SERVER_DS))
        self.assertTrue(cldap_netlogon_reply.server_type & nbt.NBT_SERVER_DS_9)

    def test_get_dc_direct_need_2012r2_but_not_found(self):
        """Test requring that we have a FL2012R2 DC as answer, aginst the FL2008R2 domain

        This test requires that the DC in the FL2008R2 does not claim
        to be 2012R2 capable (off by default in Samba)

        """
        self.assertIsNotNone(self.realm)


        try:
            response = self._call_get_dc_name(domain=self.realm,
                                              flags=netlogon.DS_RETURN_DNS_NAME|netlogon.DS_DIRECTORY_SERVICE_9_REQUIRED)

            self.fail("Failed to detect that requirement for 2012R2 was not met")
        except WERRORError as e:
            enum, estr = e.args
            if enum != werror.WERR_NO_SUCH_DOMAIN:
                self.fail(f"Incorrect error {estr} from GetDcNameEx looking for 2012R2 DC that was not available")

    def test_get_dc_direct_need_web_but_not_found(self):
        """Test requring that we (do not) have a AD Web Services on the DC

        This test requires that the DC does not advertise AD Web Services

        This is used as a test that is easy for a modern windows
        version to fail, as (say) Windows 2022 will succeed for all
        the DS_DIRECTORY_SERVICE_* flags.  Disable AD Web services in
        services.mmc to run this test successfully.

        """
        self.assertIsNotNone(self.realm)


        try:
            response = self._call_get_dc_name(domain=self.realm,
                                              flags=netlogon.DS_RETURN_DNS_NAME|netlogon.DS_WEB_SERVICE_REQUIRED)

            self.fail("Failed to detect that requirement for Web Services was not")
        except WERRORError as e:
            enum, estr = e.args
            if enum != werror.WERR_NO_SUCH_DOMAIN:
                self.fail(f"Incorrect error {estr} from GetDcNameEx looking for AD Web Services enabled DC that should not be available")

        # Now check the CLDAP netlogon response matches the above - that the bit was not set
        net = Net(creds=self.creds, lp=self.lp)
        cldap_netlogon_reply = net.finddc(domain=self.realm,
                                          flags=(nbt.NBT_SERVER_LDAP |
                                                 nbt.NBT_SERVER_DS))
        # We can assert this, even without looking for a particular
        # DC, as if any DC has WEB_SERVICE we would have got it above.
        self.assertFalse(cldap_netlogon_reply.server_type & nbt.NBT_SERVER_ADS_WEB_SERVICE)

    def test_get_dc_winbind_need_web_but_not_found(self):
        """Test requring that we (do not) have a AD Web Services on the trusted DC

        This test requires that the DC does not advertise AD Web Services

        This is used as a test that is easy for a modern windows
        version to fail, as (say) Windows 2022 will succeed for all
        the DS_DIRECTORY_SERVICE_* flags.  Disable AD Web services in
        services.mmc to run this test successfully.

        """
        self.assertIsNotNone(self.trust_realm)


        try:
            response = self._call_get_dc_name(domain=self.trust_realm,
                                              flags=netlogon.DS_RETURN_DNS_NAME|netlogon.DS_WEB_SERVICE_REQUIRED)

            self.fail("Failed to detect that requirement for Web Services was not")
        except WERRORError as e:
            enum, estr = e.args
            if enum != werror.WERR_NO_SUCH_DOMAIN:
                self.fail(f"Incorrect error {estr} from GetDcNameEx looking for AD Web Services enabled DC that should not be available")

        # Now check the CLDAP netlogon response matches the above - that the bit was not set
        net = Net(creds=self.creds, lp=self.lp)
        cldap_netlogon_reply = net.finddc(domain=self.trust_realm,
                                          flags=(nbt.NBT_SERVER_LDAP |
                                                 nbt.NBT_SERVER_DS))
        # We can assert this, even without looking for a particular
        # DC, as if any DC has WEB_SERVICE we would have got it above.
        self.assertFalse(cldap_netlogon_reply.server_type & nbt.NBT_SERVER_ADS_WEB_SERVICE)

    def test_get_dc_direct_need_2012r2(self):
        """Test requring that we have a FL2012R2 DC as answer
        """
        self.assertIsNotNone(self.trust_realm)

        self.netlogon_conn = netlogon.netlogon(f"ncacn_ip_tcp:{self.trust_server}",
                                               self.get_loadparm())

        response_trust = self._call_get_dc_name(domain=self.trust_realm,
                                                flags=netlogon.DS_RETURN_DNS_NAME|netlogon.DS_DIRECTORY_SERVICE_9_REQUIRED)

        self.assertIsNotNone(response_trust.dc_unc)
        self.assertTrue(response_trust.dc_unc.startswith('\\\\'))
        self.assertIsNotNone(response_trust.dc_address)
        self.assertTrue(response_trust.dc_address.startswith('\\\\'))

        self.assertEqual(response_trust.domain_name.lower(),
                         self.trust_realm.lower())

        # Now check the CLDAP netlogon response matches the above
        dc_ip = response_trust.dc_address[2:]

        net = Net(creds=self.creds, lp=self.lp)
        cldap_netlogon_reply = net.finddc(domain=self.trust_realm, address=dc_ip,
                                          flags=(nbt.NBT_SERVER_LDAP |
                                                 nbt.NBT_SERVER_DS))
        self.assertTrue(cldap_netlogon_reply.server_type & nbt.NBT_SERVER_DS_9)

    def test_get_dc_winbind_need_2012r2_but_not_found(self):
        """Test requring that we have a FL2012R2 DC as answer, aginst the FL2008R2 domain

        This test requires that the DC in the FL2008R2 does not claim
        to be 2012R2 capable (off by default in Samba)

        """
        self.assertIsNotNone(self.realm)

        self.netlogon_conn = netlogon.netlogon(f"ncacn_ip_tcp:{self.trust_server}",
                                               self.get_loadparm())


        try:
            response = self._call_get_dc_name(domain=self.realm,
                                              flags=netlogon.DS_RETURN_DNS_NAME|netlogon.DS_DIRECTORY_SERVICE_9_REQUIRED)

            self.fail("Failed to detect requirement for 2012R2 that is not met")
        except WERRORError as e:
            enum, estr = e.args
            if enum != werror.WERR_NO_SUCH_DOMAIN:
                self.fail("Failed to detect requirement for 2012R2 that is not met")

        # Now check the CLDAP netlogon response matches the above - that the DS_9 bit was not set
        net = Net(creds=self.creds, lp=self.lp)
        cldap_netlogon_reply = net.finddc(domain=self.realm,
                                          flags=(nbt.NBT_SERVER_LDAP |
                                                 nbt.NBT_SERVER_DS))
        self.assertFalse(cldap_netlogon_reply.server_type & nbt.NBT_SERVER_DS_9)

    def test_get_dc_winbind_need_2012r2_but_not_found_fallback(self):
        """Test requring that we have a FL2012R2 DC as answer, aginst the
        FL2008R2 domain, then trying for just FL2008R2 (to show caching bugs)

        This test requires that the DC in the FL2008R2 does not claim
        to be 2012R2 capable (off by default in Samba)

        """
        self.assertIsNotNone(self.realm)

        self.netlogon_conn = netlogon.netlogon(f"ncacn_ip_tcp:{self.trust_server}",
                                               self.get_loadparm())


        try:
            response = self._call_get_dc_name(domain=self.realm,
                                              flags=netlogon.DS_RETURN_DNS_NAME|netlogon.DS_DIRECTORY_SERVICE_9_REQUIRED)

            self.fail("Failed to detect requirement for 2012R2 that is not met")
        except WERRORError as e:
            enum, estr = e.args
            if enum != werror.WERR_NO_SUCH_DOMAIN:
                self.fail("Failed to detect requirement for 2012R2 that is not met")

        try:
            response = self._call_get_dc_name(domain=self.realm,
                                              flags=netlogon.DS_RETURN_DNS_NAME|netlogon.DS_DIRECTORY_SERVICE_6_REQUIRED)

        except WERRORError as e:
            enum, estr = e.args
            self.fail("Unexpectedly failed to find 2008 DC")

        dc_ip = response.dc_address[2:]

        net = Net(creds=self.creds, lp=self.lp)
        cldap_netlogon_reply = net.finddc(domain=self.realm, address=dc_ip,
                                          flags=(nbt.NBT_SERVER_LDAP |
                                                 nbt.NBT_SERVER_DS))
        self.assertTrue(cldap_netlogon_reply.server_type & nbt.NBT_SERVER_FULL_SECRET_DOMAIN_6)

    def test_get_dc_direct_need_2012r2_but_not_found_fallback(self):
        """Test requring that we have a FL2012R2 DC as answer, aginst the
        FL2008R2 domain, then trying for just FL2008R2 (to show caching bugs)

        This test requires that the DC in the FL2008R2 does not claim
        to be 2012R2 capable (off by default in Samba)

        """
        self.assertIsNotNone(self.realm)

        self.netlogon_conn = netlogon.netlogon(f"ncacn_ip_tcp:{self.server}",
                                               self.get_loadparm())


        try:
            response = self._call_get_dc_name(domain=self.realm,
                                              flags=netlogon.DS_RETURN_DNS_NAME|netlogon.DS_DIRECTORY_SERVICE_9_REQUIRED)

            self.fail("Failed to detect requirement for 2012R2 that is not met")
        except WERRORError as e:
            enum, estr = e.args
            if enum != werror.WERR_NO_SUCH_DOMAIN:
                self.fail("Failed to detect requirement for 2012R2 that is not met")

        try:
            response = self._call_get_dc_name(domain=self.realm,
                                              flags=netlogon.DS_RETURN_DNS_NAME|netlogon.DS_DIRECTORY_SERVICE_6_REQUIRED)

        except WERRORError as e:
            enum, estr = e.args
            self.fail("Unexpectedly failed to find 2008 DC")

        dc_ip = response.dc_address[2:]

        net = Net(creds=self.creds, lp=self.lp)
        cldap_netlogon_reply = net.finddc(domain=self.realm, address=dc_ip,
                                          flags=(nbt.NBT_SERVER_LDAP |
                                                 nbt.NBT_SERVER_DS))
        self.assertTrue(cldap_netlogon_reply.server_type & nbt.NBT_SERVER_FULL_SECRET_DOMAIN_6)

    # TODO Thorough tests of domain GUID
    #
    # The domain GUID does not seem to be authoritative, and seems to be a
    # fallback case for renamed domains.
