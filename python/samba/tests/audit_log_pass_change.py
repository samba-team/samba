# Tests for SamDb password change audit logging.
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

"""Tests for the SamDb logging of password changes.
"""

import samba.tests
from samba.dcerpc.messaging import MSG_DSDB_PWD_LOG, DSDB_PWD_EVENT_NAME
from samba.samdb import SamDB
from samba.auth import system_session
import os
from samba.tests.audit_log_base import AuditLogTestBase
from samba.tests import delete_force
from samba.net import Net
from ldb import (LdbError,
                 ERR_INSUFFICIENT_ACCESS_RIGHTS,
                 ERR_INVALID_DN_SYNTAX,
                 ERR_NO_SUCH_ATTRIBUTE)
from samba.dcerpc.windows_event_ids import (
    EVT_ID_PASSWORD_CHANGE,
    EVT_ID_PASSWORD_RESET,
    EVT_ID_DIRECTORY_OBJECT_CHANGE
)


USER_NAME = "auditlogtestuser"
USER_PASS = samba.generate_random_password(32, 32)

SECOND_USER_NAME = "auditlogtestuser02"
SECOND_USER_PASS = samba.generate_random_password(32, 32)

MACHINE_NAME = "auditlogtestmachineuser"
MACHINE_PASS = samba.generate_random_password(32, 32)


class AuditLogPassChangeTests(AuditLogTestBase):

    def setUp(self):
        self.message_type = MSG_DSDB_PWD_LOG
        self.event_type = DSDB_PWD_EVENT_NAME
        super().setUp()

        self.server_ip = os.environ["SERVER_IP"]

        host = "ldap://%s" % os.environ["SERVER"]
        self.ldb = SamDB(url=host,
                         session_info=system_session(),
                         credentials=self.get_credentials(),
                         lp=self.get_loadparm())
        self.server = os.environ["SERVER"]

        # Gets back the basedn
        self.base_dn = self.ldb.domain_dn()

        # Get the old "dSHeuristics" if it was set
        dsheuristics = self.ldb.get_dsheuristics()

        # Set the "dSHeuristics" to activate the correct "userPassword"
        # behaviour
        self.ldb.set_dsheuristics("000000001")

        # Reset the "dSHeuristics" as they were before
        self.addCleanup(self.ldb.set_dsheuristics, dsheuristics)

        # Get the old "minPwdAge"
        minPwdAge = self.ldb.get_minPwdAge()

        # Set it temporarily to "0"
        self.ldb.set_minPwdAge("0")
        self.base_dn = self.ldb.domain_dn()

        # Reset the "minPwdAge" as it was before
        self.addCleanup(self.ldb.set_minPwdAge, minPwdAge)

        # (Re)adds the test user USER_NAME with password USER_PASS
        delete_force(self.ldb, "cn=" + USER_NAME + ",cn=users," + self.base_dn)
        delete_force(
            self.ldb,
            "cn=" + SECOND_USER_NAME + ",cn=users," + self.base_dn)
        self.ldb.add({
            "dn": "cn=" + USER_NAME + ",cn=users," + self.base_dn,
            "objectclass": "user",
            "sAMAccountName": USER_NAME,
            "userPassword": USER_PASS
        })

        # (Re)adds the test user MACHINE_NAME with password MACHINE_PASS
        delete_force(
            self.ldb,
            "cn=" + MACHINE_NAME + ",cn=users," + self.base_dn)
        self.ldb.add({
            "dn": "cn=" + MACHINE_NAME + ",cn=users," + self.base_dn,
            "objectclass": "computer",
            "sAMAccountName": MACHINE_NAME,
            "userPassword": MACHINE_PASS
        })

    #
    # Discard the messages from the setup code
    #
    def discardSetupMessages(self, dn):
        self.waitForMessages(1, dn=dn)
        self.discardMessages()

    def test_net_change_password(self):

        dn = "CN=" + USER_NAME + ",CN=Users," + self.base_dn
        self.discardSetupMessages(dn)

        creds = self.insta_creds(template=self.get_credentials())

        lp = self.get_loadparm()
        net = Net(creds, lp, server=self.server)
        password = "newPassword!!42"

        net.change_password(newpassword=password,
                            username=USER_NAME,
                            oldpassword=USER_PASS)

        messages = self.waitForMessages(1, net, dn)
        print("Received %d messages" % len(messages))
        self.assertEqual(1,
                          len(messages),
                          "Did not receive the expected number of messages")
        audit = messages[0]["passwordChange"]
        self.assertEqual(EVT_ID_PASSWORD_CHANGE, audit["eventId"])
        self.assertEqual("Change", audit["action"])
        self.assertEqual(dn, audit["dn"])
        self.assertRegex(audit["remoteAddress"],
                         self.remoteAddress)
        session_id = self.get_session()
        self.assertEqual(session_id, audit["sessionId"])
        service_description = self.get_service_description()
        self.assertEqual(service_description, "DCE/RPC")
        self.assertTrue(self.is_guid(audit["transactionId"]))

    def test_net_set_password_user_without_permission(self):

        dn = "CN=" + USER_NAME + ",CN=Users," + self.base_dn
        self.discardSetupMessages(dn)

        self.ldb.newuser(SECOND_USER_NAME, SECOND_USER_PASS)

        #
        # Get the password reset from the user add
        #
        dn = "CN=" + SECOND_USER_NAME + ",CN=Users," + self.base_dn
        messages = self.waitForMessages(1, dn=dn)
        print("Received %d messages" % len(messages))
        self.assertEqual(1,
                          len(messages),
                          "Did not receive the expected number of messages")

        audit = messages[0]["passwordChange"]
        self.assertEqual(EVT_ID_PASSWORD_RESET, audit["eventId"])
        self.assertEqual("Reset", audit["action"])
        self.assertEqual(dn, audit["dn"])
        self.assertRegex(audit["remoteAddress"],
                         self.remoteAddress)
        session_id = self.get_session()
        self.assertEqual(session_id, audit["sessionId"])
        service_description = self.get_service_description()
        self.assertEqual(service_description, "LDAP")
        self.assertTrue(self.is_guid(audit["transactionId"]))
        self.assertEqual(0, audit["statusCode"])
        self.assertEqual("Success", audit["status"])
        self.discardMessages()

        creds = self.insta_creds(
            template=self.get_credentials(),
            username=SECOND_USER_NAME,
            userpass=SECOND_USER_PASS,
            kerberos_state=None)

        lp = self.get_loadparm()
        net = Net(creds, lp, server=self.server)
        password = "newPassword!!42"
        domain = lp.get("workgroup")

        try:
            net.set_password(newpassword=password,
                             account_name=USER_NAME,
                             domain_name=domain)
            self.fail("Expected exception not thrown")
        except Exception:
            pass

        dn = "CN=" + USER_NAME + ",CN=Users," + self.base_dn
        messages = self.waitForMessages(1, net, dn=dn)
        print("Received %d messages" % len(messages))
        self.assertEqual(1,
                          len(messages),
                          "Did not receive the expected number of messages")

        audit = messages[0]["passwordChange"]
        self.assertEqual(EVT_ID_PASSWORD_RESET, audit["eventId"])
        self.assertEqual("Reset", audit["action"])
        self.assertEqual(dn, audit["dn"])
        self.assertRegex(audit["remoteAddress"],
                         self.remoteAddress)
        session_id = self.get_session()
        self.assertEqual(session_id, audit["sessionId"])
        service_description = self.get_service_description()
        self.assertEqual(service_description, "DCE/RPC")
        self.assertTrue(self.is_guid(audit["transactionId"]))
        self.assertEqual(ERR_INSUFFICIENT_ACCESS_RIGHTS, audit["statusCode"])
        self.assertEqual("insufficient access rights", audit["status"])

    def test_net_set_password(self):

        dn = "CN=" + USER_NAME + ",CN=Users," + self.base_dn
        self.discardSetupMessages(dn)

        creds = self.insta_creds(template=self.get_credentials())

        lp = self.get_loadparm()
        net = Net(creds, lp, server=self.server)
        password = "newPassword!!42"
        domain = lp.get("workgroup")

        net.set_password(newpassword=password,
                         account_name=USER_NAME,
                         domain_name=domain)

        dn = "CN=" + USER_NAME + ",CN=Users," + self.base_dn
        messages = self.waitForMessages(1, net, dn)
        print("Received %d messages" % len(messages))
        self.assertEqual(1,
                          len(messages),
                          "Did not receive the expected number of messages")

        audit = messages[0]["passwordChange"]
        self.assertEqual(EVT_ID_PASSWORD_RESET, audit["eventId"])
        self.assertEqual("Reset", audit["action"])
        self.assertEqual(dn, audit["dn"])
        self.assertRegex(audit["remoteAddress"],
                         self.remoteAddress)
        session_id = self.get_session()
        self.assertEqual(session_id, audit["sessionId"])
        service_description = self.get_service_description()
        self.assertEqual(service_description, "DCE/RPC")
        session_id = self.get_session()
        self.assertEqual(session_id, audit["sessionId"])
        self.assertTrue(self.is_guid(audit["transactionId"]))

    def test_ldap_change_password(self):

        dn = "cn=" + USER_NAME + ",cn=users," + self.base_dn
        self.discardSetupMessages(dn)

        new_password = samba.generate_random_password(32, 32)
        self.ldb.modify_ldif(
            "dn: " + dn + "\n" +
            "changetype: modify\n" +
            "delete: userPassword\n" +
            "userPassword: " + USER_PASS + "\n" +
            "add: userPassword\n" +
            "userPassword: " + new_password + "\n")

        messages = self.waitForMessages(1, dn=dn)
        print("Received %d messages" % len(messages))
        self.assertEqual(1,
                          len(messages),
                          "Did not receive the expected number of messages")

        audit = messages[0]["passwordChange"]
        self.assertEqual(EVT_ID_PASSWORD_CHANGE, audit["eventId"])
        self.assertEqual("Change", audit["action"])
        self.assertEqual(dn, audit["dn"])
        self.assertRegex(audit["remoteAddress"],
                         self.remoteAddress)
        self.assertTrue(self.is_guid(audit["sessionId"]))
        session_id = self.get_session()
        self.assertEqual(session_id, audit["sessionId"])
        service_description = self.get_service_description()
        self.assertEqual(service_description, "LDAP")
        self.assertTrue(self.is_guid(audit["transactionId"]))

    def test_ldap_replace_password(self):

        dn = "cn=" + USER_NAME + ",cn=users," + self.base_dn
        self.discardSetupMessages(dn)

        new_password = samba.generate_random_password(32, 32)
        self.ldb.modify_ldif(
            "dn: " + dn + "\n" +
            "changetype: modify\n" +
            "replace: userPassword\n" +
            "userPassword: " + new_password + "\n")

        messages = self.waitForMessages(1, dn=dn)
        print("Received %d messages" % len(messages))
        self.assertEqual(1,
                          len(messages),
                          "Did not receive the expected number of messages")

        audit = messages[0]["passwordChange"]
        self.assertEqual(EVT_ID_PASSWORD_RESET, audit["eventId"])
        self.assertEqual("Reset", audit["action"])
        self.assertEqual(dn, audit["dn"])
        self.assertRegex(audit["remoteAddress"],
                         self.remoteAddress)
        self.assertTrue(self.is_guid(audit["sessionId"]))
        session_id = self.get_session()
        self.assertEqual(session_id, audit["sessionId"])
        service_description = self.get_service_description()
        self.assertEqual(service_description, "LDAP")
        self.assertTrue(self.is_guid(audit["transactionId"]))

    def test_ldap_add_user(self):

        # The setup code adds a user, so we check for the password event
        # generated by it.
        dn = "cn=" + USER_NAME + ",cn=users," + self.base_dn
        messages = self.waitForMessages(1, dn=dn)
        print("Received %d messages" % len(messages))
        self.assertEqual(1,
                          len(messages),
                          "Did not receive the expected number of messages")

        #
        # The first message should be the reset from the Setup code.
        #
        audit = messages[0]["passwordChange"]
        self.assertEqual(EVT_ID_PASSWORD_RESET, audit["eventId"])
        self.assertEqual("Reset", audit["action"])
        self.assertEqual(dn, audit["dn"])
        self.assertRegex(audit["remoteAddress"],
                         self.remoteAddress)
        session_id = self.get_session()
        self.assertEqual(session_id, audit["sessionId"])
        service_description = self.get_service_description()
        self.assertEqual(service_description, "LDAP")
        self.assertTrue(self.is_guid(audit["sessionId"]))
        self.assertTrue(self.is_guid(audit["transactionId"]))


    # These are some valid BinaryDN prefixes for
    # msDS-KeyCredentialLink values.
    kcl_prefixes = [
        ("B:772:000200002000012849ABF23C432F5428756A641827A6CD2E4A4F40"
         "9F4DE57BA152B7C2F31E46EC200002A5499B70EC0FBEF4BCB78AF3878D08"
         "2B2D43527BBAA230462707947C128BAF4226010330820122300D06092A86"
         "4886F70D01010105000382010F003082010A02820101009A16283EA51D94"
         "11FD54C73615D90E4B3B8DAF152D699A79C3B217DDBA7787DE419E3E31E6"
         "012088FD9B4EC0EA9199E91EBE2F99F48A4E7084D819CF76C67C58F5050E"
         "E5428B09676CA475EADFAD91FBEF2835820BE4CDE3F3A3B33DB6A0C75956"
         "47CA8489566EBCF6B748DC637EC2D34D255E008DAF93F3DC77478B7526DE"
         "5A6B4638FC50A622233C2BBA935A0E2BBA6DDCE32D539E57AD12FAA7BA33"
         "1C92D32E54E05290132E66D25476458FDDFBF4940DA97F19B63C30EFE0EF"
         "1F77A2751CD8EAA7EF6DFA54FF0B3500D9E66A1ECC9D435FF0206EA27047"
         "8A37CD9F949EB6CA82925A138C5852C5C763AD6EA60003FCE5C7D486382B"
         "8E347B8CF6645F449902030100010100040108000900CB9A52E817DC01:"),

        ("B:772:00020000200001E251886DDA8335FA6A9B311F1FE4ABCDA7C04F05"
         "33668BA7B143760C675703BB200002E324A0CCE2393C603686A0C7828B53"
         "77A9B5E8C639131F657C3CEB39EDED7D4F26010330820122300D06092A86"
         "4886F70D01010105000382010F003082010A0282010100A5DF595B4E0F36"
         "9A4EF8CD5A2F6AF9322460C14175DDB7DE5F3A494A7591EC1096A5150800"
         "F80401F7D8739C8900165035E231E85AA0E39A9C75BE760764BCDC82A4CB"
         "955D84AFA47A8CACC35BAB6775478BF214A81726263D79CAA1623EA60DAB"
         "2C61CAE29905FE4A89467736F47ADCA27170DBC77F5A82E28075E4D44FB9"
         "76FFF5400B1AFC21B57C52718864253D57E780DEF8F40C990D30FB253831"
         "BC95B01EEFFB312E52F7B773CFB1FF9E48A40B9C82E6B176464087C862F5"
         "EA1D38809CF6454A8F169B993FFA857D1D928E4488EB13C947EE847D30F1"
         "7CF1FAA85DE6AFD07ED82504C024E0CEA5B47E02515E57C3258963E80137"
         "15EB0D3B126067A79F02030100010100040108000900CB9A52E817DC01:"),

        ("B:772:0002000020000118ADEEC2CBCC63FCA44F332CAE39275E12CB881F"
         "68B582ED2F3982718832126120000269F60B033A8697DB69835A356C9263"
         "1CF87FDE6E448F3426285B3978E85C385C26010330820122300D06092A86"
         "4886F70D01010105000382010F003082010A0282010100CADFE83AC8FCE1"
         "B7A999AE162DC6BD6CC53D686E6F0CB866AFADCF64F736249E2CB4F438E2"
         "78B636C4151C540BC4677821E66E6D88E6875A6B9B4F473D41C1C05376A4"
         "F929076E515698F076F1F1BBEB25AAE062C9973D6436E3E4B48F74B5C0A5"
         "B1FAD5026B8AB9E021849FFF8D18E54643C5F5FB57590BDC1CBC747C53CE"
         "A696D5379EE3678E8AE015E2AE4AEA5B79F03E953D415986197F00D876E1"
         "D23A28CC944901FCE5A902C9671CC46D7AA7F349F4F80CEF74FF035AEAEE"
         "30D6FD8F907B08C9A23031B9E44AC84A4010BFA06A468D94B034DDF202A7"
         "1B20663864703AC8205CE7C60B5FC18253C94CB8389381E05DB70B08BCCC"
         "EE58A5E81BA2FE18AD02030100010100040108000980613353E817DC01:"),
    ]

    def test_ldap_key_credential_link(self):
        """Test logging of msDS-KeyCredentialLink public key changes.
        """
        # The restrictions on msDS-KeyCredentialLink changes work
        # different from those on the password attributes. We don't
        # care about dsHeuristics, minPwdAge, etc, but we do care
        # about things like GUID_DRS_DS_VALIDATED_WRITE_COMPUTER and
        # ACLs.
        #
        # To avoid all the set-up cost of making a fresh DB and user,
        # we use sub-tests in this test.
        #
        # See source4/dsdb/tests/pythpn/key_credential_link.py for
        # deeper tests of the restrictions on setting this attribute.

        dn = f"cn={USER_NAME},cn=users,{self.base_dn}"
        self.discardSetupMessages(dn)

        kcls = [f"{x}{dn}" for x in self.kcl_prefixes]
        session_id = self.get_session()
        service_description = self.get_service_description()
        self.assertEqual(service_description, "LDAP")

        self._test_ldap_authentication_information(
            "msDS-keyCredentialLink", kcls)

        transactions_seen = set()

        with self.subTest("add bad KCL DN value"):
            self.ldb.modify_ldif(
                f"dn: {dn}\n"
                "changetype: modify\n"
                "replace: msDS-keyCredentialLink\n"
                f"msDS-keyCredentialLink: B:4:f1ea:{dn}\n")
            messages = self.waitForMessages(1, dn=dn)
            self.discardMessages()
            audit = messages[0]["passwordChange"]
            self.assertEqual(EVT_ID_DIRECTORY_OBJECT_CHANGE, audit["eventId"])
            self.assertEqual("Public key change", audit["action"])
            self.assertEqual(dn, audit["dn"])
            self.assertIn(self.remoteAddress, audit["remoteAddress"])
            self.assertEqual(session_id, audit["sessionId"])
            self.assertEqual(0, audit["statusCode"])
            transactions_seen.add(audit["transactionId"])

        with self.subTest("add a second DN value"):
            # should this fail?
            self.ldb.modify_ldif(
                f"dn: {dn}\n"
                "changetype: modify\n"
                "add: msDS-keyCredentialLink\n"
                f"msDS-keyCredentialLink: B:4:f1ee:{dn}\n")
            messages = self.waitForMessages(1, dn=dn)
            self.discardMessages()
            audit = messages[0]["passwordChange"]
            self.assertEqual(EVT_ID_DIRECTORY_OBJECT_CHANGE, audit["eventId"])
            self.assertEqual("Public key change", audit["action"])
            self.assertEqual(dn, audit["dn"])
            self.assertIn(self.remoteAddress, audit["remoteAddress"])
            self.assertEqual(session_id, audit["sessionId"])
            self.assertEqual(0, audit["statusCode"])
            transactions_seen.add(audit["transactionId"])

        # these should all have been separate transactions
        with self.subTest("check transactions"):
            self.assertEqual(len(transactions_seen), 2)
            for t in transactions_seen:
                self.assertTrue(self.is_guid(t))

        with self.subTest("add bad Binary DN value"):
            for bad_dn in ('B:6:f1ea:{dn}', 'flea', dn):
                with self.assertRaises(LdbError) as e:
                    self.ldb.modify_ldif(
                        f"dn: {dn}\n"
                        "changetype: modify\n"
                        "replace: msDS-keyCredentialLink\n"
                        f"msDS-keyCredentialLink: {bad_dn}\n")
                self.assertEqual(e.exception.args[0], ERR_INVALID_DN_SYNTAX)
            # no messages from those the 3 bad DNs
            # because DN syntax check comes first
            messages = self.waitForMessages(1, dn=dn)
            self.assertEqual(0, len(messages))


    def test_ldap_altSecurityIdentities(self):
        """Test logging of altSecurityIdentities changes.
        """
        values = [
            "X509:<SKI>123456789123",
            "X509:<S>SubjectName<I>IssuerName",
            "X509:<I>IssuerName<SR>123456789123"
        ]
        self._test_ldap_authentication_information(
            "altSecurityIdentities", values)


    def test_ldap_service_principal_name(self):
        """Test logging of servicePrincipalName changes.
        """
        values = [
            "HOST/principal1",
            "HOST/principal2",
            "HOST/Principla3"
        ]
        self._test_ldap_authentication_information(
            "servicePrincipalName", values)


    def test_ldap_dns_host_name(self):
        """Test logging of dNSHostName changes.
        """
        values = [
            "host1.test.samba.org",
            "host2.test.samba.org",
            "host3.test.samba.org"
        ]
        self._test_ldap_authentication_information(
            "dNSHostName", values, user=MACHINE_NAME)

    def test_ldap_msDS_AdditionalDnsHostName(self):
        """Test logging of msDS-AdditionalDnsHostName changes.
        """
        values = [
            "host1.test.samba.org",
            "host2.test.samba.org",
            "host3.test.samba.org"
        ]
        self._test_ldap_authentication_information(
            "msDS-AdditionalDnsHostName", values, user=MACHINE_NAME)

    def _test_ldap_authentication_information(
            self,
            attribute,
            values,
            user=USER_NAME ):
        """Test logging of authentication information changes.
        """
        #
        # To avoid all the set-up cost of making a fresh DB and user,
        # we use sub-tests in this test.
        #

        dn = f"cn={user},cn=users,{self.base_dn}"
        self.discardSetupMessages(dn)

        session_id = self.get_session()
        service_description = self.get_service_description()
        self.assertEqual(service_description, "LDAP")
        transactions_seen = set()

        with self.subTest("initial setup"):
            self.ldb.modify_ldif(
                f"dn: {dn}\n"
                "changetype: modify\n"
                f"add: {attribute}\n"
                f"{attribute}: {values[0]}\n")
            messages = self.waitForMessages(1, dn=dn)
            print("Received %d messages" % len(messages))
            self.assertEqual(1, len(messages))
            audit = messages[0]["passwordChange"]
            self.assertEqual(EVT_ID_DIRECTORY_OBJECT_CHANGE, audit["eventId"])
            self.assertEqual("Public key change", audit["action"])
            self.assertEqual(dn, audit["dn"])
            self.assertIn(self.remoteAddress, audit["remoteAddress"])
            self.assertEqual(session_id, audit["sessionId"])
            transactions_seen.add(audit["transactionId"])
            self.assertEqual(0, audit["statusCode"])
            self.discardMessages()

        with self.subTest("replace"):
            self.ldb.modify_ldif(
                f"dn: {dn}\n"
                "changetype: modify\n"
                f"replace: {attribute}\n"
                f"{attribute}: {values[1]}\n")
            messages = self.waitForMessages(1, dn=dn)
            print("Received %d messages" % len(messages))
            self.assertEqual(1, len(messages))
            audit = messages[0]["passwordChange"]
            self.assertEqual(EVT_ID_DIRECTORY_OBJECT_CHANGE, audit["eventId"])
            self.assertEqual("Public key change", audit["action"])
            self.assertEqual(dn, audit["dn"])
            self.assertIn(self.remoteAddress, audit["remoteAddress"])
            self.assertTrue(self.is_guid(audit["sessionId"]))
            transactions_seen.add(audit["transactionId"])
            self.discardMessages()

        with self.subTest("constrained replace"):
            self.ldb.modify_ldif(
                f"dn: {dn}\n"
                "changetype: modify\n"
                f"delete: {attribute}\n"
                f"{attribute}: {values[1]}\n"
                f"add: {attribute}\n"
                f"{attribute}: {values[2]}\n")
            messages = self.waitForMessages(1, dn=dn)
            print("Received %d messages" % len(messages))
            self.assertEqual(1, len(messages))
            audit = messages[0]["passwordChange"]
            self.assertEqual(EVT_ID_DIRECTORY_OBJECT_CHANGE, audit["eventId"])
            self.assertEqual("Public key change", audit["action"])
            self.assertEqual(dn, audit["dn"])
            self.assertIn(self.remoteAddress, audit["remoteAddress"])
            self.assertEqual(session_id, audit["sessionId"])
            self.assertEqual(0, audit["statusCode"])
            transactions_seen.add(audit["transactionId"])
            self.discardMessages()

        with self.subTest("identical replace"):
            # replacing the value with itself still sends the message.
            self.ldb.modify_ldif(
                f"dn: {dn}\n"
                "changetype: modify\n"
                f"replace: {attribute}\n"
                f"{attribute}: {values[2]}\n")
            messages = self.waitForMessages(1, dn=dn)
            print("Received %d messages" % len(messages))
            self.assertEqual(1, len(messages))
            audit = messages[0]["passwordChange"]
            self.assertEqual(EVT_ID_DIRECTORY_OBJECT_CHANGE, audit["eventId"])
            self.assertEqual("Public key change", audit["action"])
            self.assertEqual(dn, audit["dn"])
            self.assertIn(self.remoteAddress, audit["remoteAddress"])
            self.assertEqual(session_id, audit["sessionId"])
            self.assertEqual(0, audit["statusCode"])
            transactions_seen.add(audit["transactionId"])
            self.discardMessages()

        with self.subTest("replace authentication information AND password"):
            # there should be two messages
            self.ldb.modify_ldif(
                f"dn: {dn}\n"
                "changetype: modify\n"
                f"replace:{attribute}\n"
                f"{attribute}: {values[0]}\n"
                "replace: userPassword\n"
                "userPassword: gruffalo3.\n")
            messages = self.waitForMessages(2, dn=dn)
            self.assertEqual(2, len(messages))
            pwd_audit = messages[0]["passwordChange"]
            kcl_audit = messages[1]["passwordChange"]
            # we send the password message first, but we don't need to
            # depend on that.
            if pwd_audit["eventId"] == EVT_ID_DIRECTORY_OBJECT_CHANGE:
                kcl_audit, pwd_audit = pwd_audit, kcl_audit
            del audit
            self.assertEqual(EVT_ID_DIRECTORY_OBJECT_CHANGE, kcl_audit["eventId"])
            self.assertEqual(EVT_ID_PASSWORD_RESET, pwd_audit["eventId"])
            self.assertEqual("Public key change", kcl_audit["action"])
            self.assertEqual("Reset", pwd_audit["action"])
            # if we delete the action and eventId, the rest of
            # structures should be the same (sessionId, transactionId,
            # version, etc). Timestamps are in the outer message.
            del pwd_audit["eventId"]
            del pwd_audit["action"]
            del kcl_audit["eventId"]
            del kcl_audit["action"]
            # replacing an authentication information value with itself
            # still sends the message.
            self.assertEqual(kcl_audit, pwd_audit)
            transactions_seen.add(pwd_audit["transactionId"])
            self.discardMessages()

        with self.subTest("delete"):
            self.ldb.modify_ldif(
                f"dn: {dn}\n"
                "changetype: modify\n"
                f"delete: {attribute}\n"
                f"{attribute}: {values[0]}\n")
            messages = self.waitForMessages(1, dn=dn)
            print("Received %d messages" % len(messages))
            self.assertEqual(1, len(messages))
            audit = messages[0]["passwordChange"]
            self.assertEqual(EVT_ID_DIRECTORY_OBJECT_CHANGE, audit["eventId"])
            self.assertEqual("Public key change", audit["action"])
            self.assertEqual(dn, audit["dn"])
            self.assertIn(self.remoteAddress, audit["remoteAddress"])
            self.assertEqual(session_id, audit["sessionId"])
            self.assertEqual(0, audit["statusCode"])
            transactions_seen.add(audit["transactionId"])
            self.discardMessages()

        with self.subTest("delete that which does not exist"):
            # still sends a message
            with self.assertRaises(LdbError) as e:
                self.ldb.modify_ldif(
                    f"dn: {dn}\n"
                    "changetype: modify\n"
                    f"delete: {attribute}\n"
                    f"{attribute}: {values[2]}\n")
            self.assertEqual(e.exception.args[0], ERR_NO_SUCH_ATTRIBUTE)
            messages = self.waitForMessages(1, dn=dn)
            print("Received %d messages" % len(messages))
            # We still get the message on a failed attempt
            self.assertEqual(1, len(messages))
            audit = messages[0]["passwordChange"]
            self.assertEqual(EVT_ID_DIRECTORY_OBJECT_CHANGE, audit["eventId"])
            self.assertEqual("Public key change", audit["action"])
            self.assertEqual(dn, audit["dn"])
            self.assertIn(self.remoteAddress, audit["remoteAddress"])
            self.assertEqual(session_id, audit["sessionId"])
            transactions_seen.add(audit["transactionId"])
            self.discardMessages()
            with self.subTest("check status code"):
                self.assertEqual(ERR_NO_SUCH_ATTRIBUTE, audit["statusCode"])
                self.assertEqual("No such attribute", audit["status"])

        # these should all have been separate transactions
        with self.subTest("check transactions"):
            self.assertEqual(len(transactions_seen), 7)
            for t in transactions_seen:
                self.assertTrue(self.is_guid(t))

