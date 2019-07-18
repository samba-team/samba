# Unit and integration tests for traffic_packet.py
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

import os
import shutil
import tempfile


from samba.auth import system_session

from samba.credentials import MUST_USE_KERBEROS, DONT_USE_KERBEROS
from samba.emulate import traffic_packets as p
from samba.emulate import traffic
from samba.emulate.traffic import Packet

from samba.samdb import SamDB
import samba.tests
from samba import sd_utils


class TrafficEmulatorPacketTests(samba.tests.TestCase):
    def setUp(self):
        super(TrafficEmulatorPacketTests, self).setUp()
        self.server      = os.environ["SERVER"]
        self.domain      = os.environ["DOMAIN"]
        self.host        = os.environ["SERVER_IP"]
        self.lp          = self.get_loadparm()
        self.session     = system_session()
        self.credentials = self.get_credentials()

        self.ldb = SamDB(url="ldap://%s" % self.host,
                         session_info=self.session,
                         credentials=self.credentials,
                         lp=self.lp)
        self.domain_sid = self.ldb.get_domain_sid()

        traffic.clean_up_accounts(self.ldb, 1)
        self.tempdir = tempfile.mkdtemp(prefix="traffic_packet_test_")
        self.context = traffic.ReplayContext(server=self.server,
                                             lp=self.lp,
                                             creds=self.credentials,
                                             tempdir=self.tempdir,
                                             ou=traffic.ou_name(self.ldb, 1),
                                             domain_sid=self.domain_sid,
                                             total_conversations=3,
                                             instance_id=1)

        self.conversation = traffic.Conversation()
        self.conversation.conversation_id = 1
        self.machinename = "STGM-1-1"
        self.machinepass = samba.generate_random_password(32, 32)
        self.username    = "STGU-1-1"
        self.userpass    = samba.generate_random_password(32, 32)
        account = traffic.ConversationAccounts(
            self.machinename,
            self.machinepass,
            self.username,
            self.userpass)

        traffic.create_ou(self.ldb, 1)
        traffic.create_machine_account(self.ldb,
                                       1,
                                       self.machinename,
                                       self.machinepass)
        traffic.create_user_account(self.ldb,
                                    1,
                                    self.username,
                                    self.userpass)

        self.context.generate_process_local_config(account, self.conversation)

        # grant user write permission to do things like write account SPN
        sdutils = sd_utils.SDUtils(self.ldb)
        mod = "(A;;WP;;;PS)"
        sdutils.dacl_add_ace(self.context.user_dn, mod)

    def tearDown(self):
        super(TrafficEmulatorPacketTests, self).tearDown()
        traffic.clean_up_accounts(self.ldb, 1)
        del self.ldb
        shutil.rmtree(self.tempdir)

    def test_packet_cldap_03(self):
        packet = Packet.from_line(
            "0.0\t11\t1\t2\t1\tcldap\t3\tsearchRequest\t")
        self.assertTrue(p.packet_cldap_3(packet,
                                         self.conversation,
                                         self. context))

    def test_packet_cldap_05(self):
        packet = Packet.from_line(
            "0.0\t11\t1\t1\t2\tcldap\t5\tsearchResDone\t")
        self.assertFalse(p.packet_cldap_5(packet,
                                          self.conversation,
                                          self. context))

    def test_packet_dcerpc_00(self):
        packet = Packet.from_line("0.0\t11\t1\t2\t1\tdcerpc\t0\tRequest\t")
        self.assertFalse(p.packet_dcerpc_0(packet,
                                           self.conversation,
                                           self. context))

    def test_packet_dcerpc_02(self):
        packet = Packet.from_line("0.0\t11\t1\t1\t2\tdcerpc\t2\tResponse\t")
        self.assertFalse(p.packet_dcerpc_2(packet,
                                           self.conversation,
                                           self. context))

    def test_packet_dcerpc_03(self):
        packet = Packet.from_line("0.0\t11\t1\t1\t2\tdcerpc\t3\t\t")
        self.assertFalse(p.packet_dcerpc_3(packet,
                                           self.conversation,
                                           self. context))

    def test_packet_dcerpc_11(self):
        packet = Packet.from_line("0.0\t11\t1\t2\t1\tdcerpc\t11\tBind\t")
        self.assertFalse(p.packet_dcerpc_11(packet,
                                            self.conversation,
                                            self. context))

    def test_packet_dcerpc_13(self):
        packet = Packet.from_line("0.0\t11\t1\t2\t1\tdcerpc\t13\t\t")
        self.assertFalse(p.packet_dcerpc_13(packet,
                                            self.conversation,
                                            self. context))

    def test_packet_dcerpc_14(self):
        packet = Packet.from_line(
            "0.0\t11\t1\t2\t1\tdcerpc\t14\tAlter_context\t")
        self.assertFalse(p.packet_dcerpc_14(packet,
                                            self.conversation,
                                            self. context))

    def test_packet_dcerpc_15(self):
        packet = Packet.from_line(
            "0.0\t11\t1\t1\t2\tdcerpc\t15\tAlter_context_resp\t")
        # Set user_creds MUST_USE_KERBEROS to suppress the warning message.
        self.context.user_creds.set_kerberos_state(MUST_USE_KERBEROS)
        self.assertFalse(p.packet_dcerpc_15(packet,
                                            self.conversation,
                                            self. context))

    def test_packet_dcerpc_16(self):
        packet = Packet.from_line(
            "0.0\t11\t1\t1\t2\tdcerpc\t16\tAUTH3\t")
        self.assertFalse(p.packet_dcerpc_16(packet,
                                            self.conversation,
                                            self. context))

    def test_packet_dns_01(self):
        packet = Packet.from_line(
            "0.0\t11\t1\t1\t2\tdns\t1\tresponse\t")
        self.assertFalse(p.packet_dns_1(packet,
                                        self.conversation,
                                        self. context))

    def test_packet_drsuapi_00(self):
        packet = Packet.from_line(
            "0.0\t06\t1\t1\t2\tdrsuapi\t0\tDsBind\t")
        self.assertTrue(p.packet_drsuapi_0(packet,
                                           self.conversation,
                                           self. context))

    def test_packet_drsuapi_01(self):
        packet = Packet.from_line(
            "0.0\t06\t1\t1\t2\tdrsuapi\t1\tDsUnBind\t")
        self.assertTrue(p.packet_drsuapi_1(packet,
                                           self.conversation,
                                           self. context))

    def test_packet_drsuapi_02(self):
        packet = Packet.from_line(
            "0.0\t06\t1\t1\t2\tdrsuapi\t2\tDsReplicaSync\t")
        self.assertFalse(p.packet_drsuapi_2(packet,
                                            self.conversation,
                                            self. context))

    def test_packet_drsuapi_03(self):
        packet = Packet.from_line(
            "0.0\t06\t1\t1\t2\tdrsuapi\t3\tDsGetNCChanges\t")
        self.assertFalse(p.packet_drsuapi_3(packet,
                                            self.conversation,
                                            self. context))

    def test_packet_drsuapi_04(self):
        packet = Packet.from_line(
            "0.0\t06\t1\t1\t2\tdrsuapi\t4\tDsReplicaUpdateRefs\t")
        self.assertFalse(p.packet_drsuapi_4(packet,
                                            self.conversation,
                                            self. context))

    def test_packet_drsuapi_12(self):
        packet = Packet.from_line(
            "0.0\t06\t1\t1\t2\tdrsuapi\t12\tDsCrackNames\t")
        self.assertTrue(p.packet_drsuapi_12(packet,
                                            self.conversation,
                                            self. context))

    def test_packet_drsuapi_13(self):
        packet = Packet.from_line(
            "0.0\t06\t1\t1\t2\tdrsuapi\t13\tDsWriteAccountSpn\t")
        self.assertTrue(p.packet_drsuapi_13(packet,
                                            self.conversation,
                                            self. context))

    def test_packet_epm_03(self):
        packet = Packet.from_line(
            "0.0\t06\t1\t1\t2\tepm\t3\tMap\t")
        self.assertFalse(p.packet_epm_3(packet,
                                        self.conversation,
                                        self. context))

    def test_packet_kerberos(self):
        """Kerberos packets are not generated, but are used as a hint to
        favour kerberos.
        """
        packet = Packet.from_line(
            "0.0\t11\t1\t1\t2\tkerberos\t\t\t")
        self.assertFalse(p.packet_kerberos_(packet,
                                            self.conversation,
                                            self. context))
        self.assertEqual(MUST_USE_KERBEROS,
                         self.context.user_creds.get_kerberos_state())
        self.assertEqual(MUST_USE_KERBEROS,
                         self.context.user_creds_bad.get_kerberos_state())
        self.assertEqual(MUST_USE_KERBEROS,
                         self.context.machine_creds.get_kerberos_state())
        self.assertEqual(MUST_USE_KERBEROS,
                         self.context.machine_creds_bad.get_kerberos_state())
        self.assertEqual(MUST_USE_KERBEROS,
                         self.context.creds.get_kerberos_state())

        # Need to restore kerberos creds on the admin creds otherwise
        # subsequent tests fail
        self.credentials.set_kerberos_state(DONT_USE_KERBEROS)

    def test_packet_ldap(self):
        packet = Packet.from_line(
            "0.0\t06\t1\t1\t2\tldap\t\t*** Unknown ***\t")
        self.assertFalse(p.packet_ldap_(packet,
                                        self.conversation,
                                        self. context))

    def test_packet_ldap_00_sasl(self):
        packet = Packet.from_line(
            "0.0\t06\t1\t2\t1\tldap\t0\tbindRequest"
            "\t\t\t\t\t3\tsasl\t1.3.6.1.5.5.2")
        self.assertTrue(p.packet_ldap_0(packet,
                                        self.conversation,
                                        self. context))

    def test_packet_ldap_00_simple(self):
        packet = Packet.from_line(
            "0.0\t06\t1\t2\t1\tldap\t0\tbindRequest"
            "\t\t\t\t\t0\tsimple\t")
        self.assertTrue(p.packet_ldap_0(packet,
                                        self.conversation,
                                        self. context))

    def test_packet_ldap_01(self):
        packet = Packet.from_line(
            "0.0\t06\t1\t1\t2\tldap\t1\tbindResponse\t")
        self.assertFalse(p.packet_ldap_1(packet,
                                         self.conversation,
                                         self. context))

    def test_packet_ldap_02(self):
        packet = Packet.from_line(
            "0.0\t06\t1\t2\t1\tldap\t2\tunbindRequest\t")
        self.assertFalse(p.packet_ldap_2(packet,
                                         self.conversation,
                                         self. context))

    def test_packet_ldap_03(self):
        packet = Packet.from_line(
            "0.0\t06\t1\t2\t1\tldap\t3\tsearchRequest"
            "\t2\tDC,DC\t\tcn\t\t\t")
        self.assertTrue(p.packet_ldap_3(packet,
                                        self.conversation,
                                        self. context))

    def test_packet_ldap_04(self):
        packet = Packet.from_line(
            "0.0\t06\t1\t1\t2\tldap\t4\tsearchResEntry\t")
        self.assertFalse(p.packet_ldap_4(packet,
                                         self.conversation,
                                         self. context))

    def test_packet_ldap_05(self):
        packet = Packet.from_line(
            "0.0\t06\t1\t1\t2\tldap\t5\tsearchResDone\t")
        self.assertFalse(p.packet_ldap_5(packet,
                                         self.conversation,
                                         self. context))

    def test_packet_ldap_06(self):
        packet = Packet.from_line(
            "0.0\t06\t1\t2\t1\tldap\t6\tmodifyRequest\t"
            "\t\t\t\t0\tadd")
        self.assertFalse(p.packet_ldap_6(packet,
                                         self.conversation,
                                         self. context))

    def test_packet_ldap_07(self):
        packet = Packet.from_line(
            "0.0\t06\t1\t1\t2\tldap\t7\tmodifyResponse\t")
        self.assertFalse(p.packet_ldap_7(packet,
                                         self.conversation,
                                         self. context))

    def test_packet_ldap_08(self):
        packet = Packet.from_line(
            "0.0\t06\t1\t2\t1\tldap\t8\taddRequest\t")
        self.assertFalse(p.packet_ldap_8(packet,
                                         self.conversation,
                                         self. context))

    def test_packet_ldap_09(self):
        packet = Packet.from_line(
            "0.0\t06\t1\t1\t2\tldap\t9\taddResponse\t")
        self.assertFalse(p.packet_ldap_9(packet,
                                         self.conversation,
                                         self. context))

    def test_packet_ldap_16(self):
        packet = Packet.from_line(
            "0.0\t06\t1\t2\t1\tldap\t16\tabandonRequest\t")
        self.assertFalse(p.packet_ldap_16(packet,
                                          self.conversation,
                                          self. context))

    def test_packet_lsarpc_00(self):
        packet = Packet.from_line(
            "0.0\t06\t1\t2\t1\tlsarpc\t0\tlsa_Close\t")
        self.assertFalse(p.packet_lsarpc_1(packet,
                                           self.conversation,
                                           self. context))

    def test_packet_lsarpc_01(self):
        packet = Packet.from_line(
            "0.0\t06\t1\t2\t1\tlsarpc\t1\tlsa_Delete\t")
        self.assertFalse(p.packet_lsarpc_1(packet,
                                           self.conversation,
                                           self. context))

    def test_packet_lsarpc_02(self):
        packet = Packet.from_line(
            "0.0\t06\t1\t2\t1\tlsarpc\t2\tlsa_EnumeratePrivileges\t")
        self.assertFalse(p.packet_lsarpc_2(packet,
                                           self.conversation,
                                           self. context))

    def test_packet_lsarpc_03(self):
        packet = Packet.from_line(
            "0.0\t06\t1\t2\t1\tlsarpc\t3\tlsa_QuerySecurityObject\t")
        self.assertFalse(p.packet_lsarpc_3(packet,
                                           self.conversation,
                                           self. context))

    def test_packet_lsarpc_04(self):
        packet = Packet.from_line(
            "0.0\t06\t1\t2\t1\tlsarpc\t4\tlsa_SetSecurityObject\t")
        self.assertFalse(p.packet_lsarpc_4(packet,
                                           self.conversation,
                                           self. context))

    def test_packet_lsarpc_05(self):
        packet = Packet.from_line(
            "0.0\t06\t1\t2\t1\tlsarpc\t5\tlsa_ChangePassword\t")
        self.assertFalse(p.packet_lsarpc_5(packet,
                                           self.conversation,
                                           self. context))

    def test_packet_lsarpc_06(self):
        packet = Packet.from_line(
            "0.0\t06\t1\t2\t1\tlsarpc\t6\tlsa_OpenPolicy\t")
        self.assertFalse(p.packet_lsarpc_6(packet,
                                           self.conversation,
                                           self. context))

    def test_packet_lsarpc_14(self):
        packet = Packet.from_line(
            "0.0\t06\t1\t2\t1\tlsarpc\t14\tlsa_LookupNames\t")
        self.assertTrue(p.packet_lsarpc_14(packet,
                                           self.conversation,
                                           self. context))

    def test_packet_lsarpc_15(self):
        packet = Packet.from_line(
            "0.0\t06\t1\t2\t1\tlsarpc\t15\tlsa_LookupSids\t")
        self.assertTrue(p.packet_lsarpc_15(packet,
                                           self.conversation,
                                           self. context))

    def test_packet_lsarpc_39(self):
        packet = Packet.from_line(
            "0.0\t06\t1\t2\t1\tlsarpc\t39\tlsa_QueryTrustedDomainInfoBySid\t")
        self.assertTrue(p.packet_lsarpc_39(packet,
                                           self.conversation,
                                           self. context))

    def test_packet_lsarpc_40(self):
        packet = Packet.from_line(
            "0.0\t06\t1\t2\t1\tlsarpc\t40\tlsa_SetTrustedDomainInfo\t")
        self.assertFalse(p.packet_lsarpc_40(packet,
                                            self.conversation,
                                            self. context))

    def test_packet_lsarpc_43(self):
        packet = Packet.from_line(
            "0.0\t06\t1\t2\t1\tlsarpc\t43\tlsa_StorePrivateData\t")
        self.assertFalse(p.packet_lsarpc_43(packet,
                                            self.conversation,
                                            self. context))

    def test_packet_lsarpc_44(self):
        packet = Packet.from_line(
            "0.0\t06\t1\t2\t1\tlsarpc\t44\tlsa_RetrievePrivateData\t")
        self.assertFalse(p.packet_lsarpc_44(packet,
                                            self.conversation,
                                            self. context))

    def test_packet_lsarpc_68(self):
        packet = Packet.from_line(
            "0.0\t06\t1\t2\t1\tlsarpc\t68\tlsa_LookupNames3\t")
        self.assertFalse(p.packet_lsarpc_68(packet,
                                            self.conversation,
                                            self. context))

    def test_packet_lsarpc_76(self):
        packet = Packet.from_line(
            "0.0\t06\t1\t2\t1\tlsarpc\t76\tlsa_LookupSids3\t")
        self.assertTrue(p.packet_lsarpc_76(packet,
                                           self.conversation,
                                           self. context))

    def test_packet_lsarpc_77(self):
        packet = Packet.from_line(
            "0.0\t06\t1\t2\t1\tlsarpc\t77\tlsa_LookupNames4\t")
        self.assertTrue(p.packet_lsarpc_77(packet,
                                           self.conversation,
                                           self. context))

    def test_packet_nbns_00(self):
        packet = Packet.from_line(
            "0.0\t06\t1\t2\t1\tnbns\t0\tquery\t")
        self.assertTrue(p.packet_nbns_0(packet,
                                        self.conversation,
                                        self. context))

    def test_packet_nbns_01(self):
        packet = Packet.from_line(
            "0.0\t06\t1\t1\t2\tnbns\t1\tresponse\t")
        self.assertTrue(p.packet_nbns_0(packet,
                                        self.conversation,
                                        self. context))

    def test_packet_rpc_netlogon_00(self):
        packet = Packet.from_line(
            "0.0\t06\t1\t2\t1\trpc_netlogon\t0\tNetrLogonUasLogon\t")
        self.assertFalse(p.packet_rpc_netlogon_0(packet,
                                                 self.conversation,
                                                 self. context))

    def test_packet_rpc_netlogon_01(self):
        packet = Packet.from_line(
            "0.0\t06\t1\t2\t1\trpc_netlogon\t1\tNetrLogonUasLogoff\t")
        self.assertFalse(p.packet_rpc_netlogon_1(packet,
                                                 self.conversation,
                                                 self. context))

    def test_packet_rpc_netlogon_04(self):
        packet = Packet.from_line(
            "0.0\t06\t1\t2\t1\trpc_netlogon\t4\tNetrServerReqChallenge\t")
        self.assertFalse(p.packet_rpc_netlogon_4(packet,
                                                 self.conversation,
                                                 self. context))

    def test_packet_rpc_netlogon_14(self):
        packet = Packet.from_line(
            "0.0\t06\t1\t2\t1\trpc_netlogon\t14\tNetrLogonControl2\t")
        self.assertFalse(p.packet_rpc_netlogon_14(packet,
                                                  self.conversation,
                                                  self. context))

    def test_packet_rpc_netlogon_15(self):
        packet = Packet.from_line(
            "0.0\t06\t1\t2\t1\trpc_netlogon\t15\tNetrServerAuthenticate2\t")
        self.assertFalse(p.packet_rpc_netlogon_15(packet,
                                                  self.conversation,
                                                  self. context))

    def test_packet_rpc_netlogon_21(self):
        packet = Packet.from_line(
            "0.0\t06\t1\t2\t1\trpc_netlogon\t21\tNetrLogonDummyRoutine1\t")
        self.assertFalse(p.packet_rpc_netlogon_21(packet,
                                                  self.conversation,
                                                  self. context))

    def test_packet_rpc_netlogon_26(self):
        packet = Packet.from_line(
            "0.0\t06\t1\t2\t1\trpc_netlogon\t26\tNetrServerAuthenticate3\t")
        self.assertFalse(p.packet_rpc_netlogon_26(packet,
                                                  self.conversation,
                                                  self. context))

    def test_packet_rpc_netlogon_29(self):
        packet = Packet.from_line(
            "0.0\t06\t1\t2\t1\trpc_netlogon\t29\tNetrLogonGetDomainInfo\t")
        self.assertTrue(p.packet_rpc_netlogon_29(packet,
                                                 self.conversation,
                                                 self. context))

    def test_packet_rpc_netlogon_30(self):
        packet = Packet.from_line(
            "0.0\t06\t1\t2\t1\trpc_netlogon\t30\tNetrServerPasswordSet2\t")
        self.assertTrue(p.packet_rpc_netlogon_30(packet,
                                                 self.conversation,
                                                 self. context))

    def test_packet_rpc_netlogon_34(self):
        packet = Packet.from_line(
            "0.0\t06\t1\t2\t1\trpc_netlogon\t34\tDsrGetDcNameEx2\t")
        self.assertFalse(p.packet_rpc_netlogon_34(packet,
                                                  self.conversation,
                                                  self. context))

    def test_packet_rpc_netlogon_39(self):
        packet = Packet.from_line(
            "0.0\t06\t1\t2\t1\trpc_netlogon\t39\tNetrLogonSamLogonEx\t")
        self.assertTrue(p.packet_rpc_netlogon_39(packet,
                                                 self.conversation,
                                                 self. context))

    def test_packet_rpc_netlogon_40(self):
        packet = Packet.from_line(
            "0.0\t06\t1\t2\t1\trpc_netlogon\t40\tDsrEnumerateDomainTrusts\t")
        self.assertTrue(p.packet_rpc_netlogon_40(packet,
                                                 self.conversation,
                                                 self. context))

    def test_packet_rpc_netlogon_45(self):
        packet = Packet.from_line(
            "0.0\t06\t1\t2\t1\trpc_netlogon\t45\tNetrLogonSamLogonWithFlags\t")
        self.assertTrue(p.packet_rpc_netlogon_45(packet,
                                                 self.conversation,
                                                 self. context))

    def test_packet_samr_00(self):
        packet = Packet.from_line(
            "0.0\t06\t1\t2\t1\tsamr\t0\tConnect\t")
        self.assertTrue(p.packet_samr_0(packet,
                                        self.conversation,
                                        self. context))

    def test_packet_samr_01(self):
        packet = Packet.from_line(
            "0.0\t06\t1\t2\t1\tsamr\t1\tClose\t")
        self.assertTrue(p.packet_samr_1(packet,
                                        self.conversation,
                                        self. context))

    def test_packet_samr_03(self):
        packet = Packet.from_line(
            "0.0\t06\t1\t2\t1\tsamr\t3\tQuerySecurity\t")
        self.assertTrue(p.packet_samr_3(packet,
                                        self.conversation,
                                        self. context))

    def test_packet_samr_05(self):
        packet = Packet.from_line(
            "0.0\t06\t1\t2\t1\tsamr\t5\tLookupDomain\t")
        self.assertTrue(p.packet_samr_5(packet,
                                        self.conversation,
                                        self. context))

    def test_packet_samr_06(self):
        packet = Packet.from_line(
            "0.0\t06\t1\t2\t1\tsamr\t6\tEnumDomains\t")
        self.assertTrue(p.packet_samr_6(packet,
                                        self.conversation,
                                        self. context))

    def test_packet_samr_07(self):
        packet = Packet.from_line(
            "0.0\t06\t1\t2\t1\tsamr\t7\tOpenDomain\t")
        self.assertTrue(p.packet_samr_7(packet,
                                        self.conversation,
                                        self. context))

    def test_packet_samr_08(self):
        packet = Packet.from_line(
            "0.0\t06\t1\t2\t1\tsamr\t8\tQueryDomainInfo'\t")
        self.assertTrue(p.packet_samr_8(packet,
                                        self.conversation,
                                        self. context))

    def test_packet_samr_14(self):
        packet = Packet.from_line(
            "0.0\t06\t1\t2\t1\tsamr\t14\tCreateDomAlias\t")
        self.assertFalse(p.packet_samr_14(packet,
                                          self.conversation,
                                          self. context))

    def test_packet_samr_15(self):
        packet = Packet.from_line(
            "0.0\t06\t1\t2\t1\tsamr\t15\tEnumDomainAliases\t")
        self.assertTrue(p.packet_samr_15(packet,
                                         self.conversation,
                                         self. context))

    def test_packet_samr_16(self):
        packet = Packet.from_line(
            "0.0\t06\t1\t2\t1\tsamr\t16\tGetAliasMembership\t")
        self.assertTrue(p.packet_samr_16(packet,
                                         self.conversation,
                                         self. context))

    def test_packet_samr_17(self):
        packet = Packet.from_line(
            "0.0\t06\t1\t2\t1\tsamr\t17\tLookupNames\t")
        self.assertTrue(p.packet_samr_17(packet,
                                         self.conversation,
                                         self. context))

    def test_packet_samr_18(self):
        packet = Packet.from_line(
            "0.0\t06\t1\t2\t1\tsamr\t18\tLookupRids\t")
        self.assertTrue(p.packet_samr_18(packet,
                                         self.conversation,
                                         self. context))

    def test_packet_samr_19(self):
        packet = Packet.from_line(
            "0.0\t06\t1\t2\t1\tsamr\t19\tOpenGroup\t")
        self.assertTrue(p.packet_samr_19(packet,
                                         self.conversation,
                                         self. context))

    def test_packet_samr_25(self):
        packet = Packet.from_line(
            "0.0\t06\t1\t2\t1\tsamr\t25\tQueryGroupMember\t")
        self.assertTrue(p.packet_samr_25(packet,
                                         self.conversation,
                                         self. context))

    def test_packet_samr_34(self):
        packet = Packet.from_line(
            "0.0\t06\t1\t2\t1\tsamr\t34\tOpenUser\t")
        self.assertTrue(p.packet_samr_34(packet,
                                         self.conversation,
                                         self. context))

    def test_packet_samr_36(self):
        packet = Packet.from_line(
            "0.0\t06\t1\t2\t1\tsamr\t36\tQueryUserInfo\t")
        self.assertTrue(p.packet_samr_36(packet,
                                         self.conversation,
                                         self. context))

    def test_packet_samr_37(self):
        packet = Packet.from_line(
            "0.0\t06\t1\t2\t1\tsamr\t37\tSetUserInfo\t")
        self.assertFalse(p.packet_samr_37(packet,
                                          self.conversation,
                                          self. context))

    def test_packet_samr_39(self):
        packet = Packet.from_line(
            "0.0\t06\t1\t2\t1\tsamr\t39\tGetGroupsForUser\t")
        self.assertTrue(p.packet_samr_39(packet,
                                         self.conversation,
                                         self. context))

    def test_packet_samr_40(self):
        packet = Packet.from_line(
            "0.0\t06\t1\t2\t1\tsamr\t40\tQueryDisplayInfo\t")
        self.assertFalse(p.packet_samr_40(packet,
                                          self.conversation,
                                          self. context))

    def test_packet_samr_44(self):
        packet = Packet.from_line(
            "0.0\t06\t1\t2\t1\tsamr\t44\tGetUserPwInfo\t")
        self.assertFalse(p.packet_samr_44(packet,
                                          self.conversation,
                                          self. context))

    def test_packet_samr_57(self):
        packet = Packet.from_line(
            "0.0\t06\t1\t2\t1\tsamr\t57\tConnect2\t")
        self.assertTrue(p.packet_samr_57(packet,
                                         self.conversation,
                                         self. context))

    def test_packet_samr_64(self):
        packet = Packet.from_line(
            "0.0\t06\t1\t2\t1\tsamr\t64\tConnect5\t")
        self.assertTrue(p.packet_samr_64(packet,
                                         self.conversation,
                                         self. context))

    def test_packet_samr_68(self):
        packet = Packet.from_line(
            "0.0\t06\t1\t2\t1\tsamr\t68\t\t")
        self.assertFalse(p.packet_samr_68(packet,
                                          self.conversation,
                                          self. context))

    def test_packet_srvsvc_16(self):
        packet = Packet.from_line(
            "0.0\t06\t1\t2\t1\tsrvsvc\t16\tNetShareGetInfo\t")
        self.assertTrue(p.packet_srvsvc_16(packet,
                                           self.conversation,
                                           self. context))

    def test_packet_srvsvc_21(self):
        packet = Packet.from_line(
            "0.0\t06\t1\t2\t1\tsrvsvc\t21\tNetSrvGetInfo\t")
        self.assertTrue(p.packet_srvsvc_21(packet,
                                           self.conversation,
                                           self. context))
