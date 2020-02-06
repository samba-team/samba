#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# test tokengroups attribute against internal token calculation

from __future__ import print_function
import optparse
import sys
import os

sys.path.insert(0, "bin/python")
import samba

from samba.tests.subunitrun import SubunitOptions, TestProgram

import samba.getopt as options

from samba.auth import system_session
from samba import ldb, dsdb
from samba.samdb import SamDB
from samba.auth import AuthContext
from samba.ndr import ndr_unpack
from samba import gensec
from samba.credentials import Credentials, DONT_USE_KERBEROS
from samba.dsdb import GTYPE_SECURITY_GLOBAL_GROUP, GTYPE_SECURITY_UNIVERSAL_GROUP
import samba.tests
from samba.tests import delete_force
from samba.dcerpc import samr, security
from samba.auth import AUTH_SESSION_INFO_DEFAULT_GROUPS, AUTH_SESSION_INFO_AUTHENTICATED, AUTH_SESSION_INFO_SIMPLE_PRIVILEGES, AUTH_SESSION_INFO_NTLM


parser = optparse.OptionParser("token_group.py [options] <host>")
sambaopts = options.SambaOptions(parser)
parser.add_option_group(sambaopts)
parser.add_option_group(options.VersionOptions(parser))
# use command line creds if available
credopts = options.CredentialsOptions(parser)
parser.add_option_group(credopts)
subunitopts = SubunitOptions(parser)
parser.add_option_group(subunitopts)
opts, args = parser.parse_args()

if len(args) < 1:
    parser.print_usage()
    sys.exit(1)

url = args[0]

lp = sambaopts.get_loadparm()
creds = credopts.get_credentials(lp)
creds.set_gensec_features(creds.get_gensec_features() | gensec.FEATURE_SEAL)


def closure(vSet, wSet, aSet):
    for edge in aSet:
        start, end = edge
        if start in wSet:
            if end not in wSet and end in vSet:
                wSet.add(end)
                closure(vSet, wSet, aSet)


class StaticTokenTest(samba.tests.TestCase):

    def setUp(self):
        super(StaticTokenTest, self).setUp()
        self.ldb = SamDB(url, credentials=creds, session_info=system_session(lp), lp=lp)
        self.base_dn = self.ldb.domain_dn()

        res = self.ldb.search("", scope=ldb.SCOPE_BASE, attrs=["tokenGroups"])
        self.assertEqual(len(res), 1)

        self.user_sid_dn = "<SID=%s>" % str(ndr_unpack(samba.dcerpc.security.dom_sid, res[0]["tokenGroups"][0]))

        session_info_flags = (AUTH_SESSION_INFO_DEFAULT_GROUPS |
                              AUTH_SESSION_INFO_AUTHENTICATED |
                              AUTH_SESSION_INFO_SIMPLE_PRIVILEGES)
        if creds.get_kerberos_state() == DONT_USE_KERBEROS:
            session_info_flags |= AUTH_SESSION_INFO_NTLM

        session = samba.auth.user_session(self.ldb, lp_ctx=lp, dn=self.user_sid_dn,
                                          session_info_flags=session_info_flags)

        token = session.security_token
        self.user_sids = []
        for s in token.sids:
            self.user_sids.append(str(s))

    def test_rootDSE_tokenGroups(self):
        """Testing rootDSE tokengroups against internal calculation"""
        if not url.startswith("ldap"):
            self.fail(msg="This test is only valid on ldap")

        res = self.ldb.search("", scope=ldb.SCOPE_BASE, attrs=["tokenGroups"])
        self.assertEqual(len(res), 1)

        print("Getting tokenGroups from rootDSE")
        tokengroups = []
        for sid in res[0]['tokenGroups']:
            tokengroups.append(str(ndr_unpack(samba.dcerpc.security.dom_sid, sid)))

        sidset1 = set(tokengroups)
        sidset2 = set(self.user_sids)
        if len(sidset1.difference(sidset2)):
            print("token sids don't match")
            print("tokengroups: %s" % tokengroups)
            print("calculated : %s" % self.user_sids)
            print("difference : %s" % sidset1.difference(sidset2))
            self.fail(msg="calculated groups don't match against rootDSE tokenGroups")

    def test_dn_tokenGroups(self):
        print("Getting tokenGroups from user DN")
        res = self.ldb.search(self.user_sid_dn, scope=ldb.SCOPE_BASE, attrs=["tokenGroups"])
        self.assertEqual(len(res), 1)

        dn_tokengroups = []
        for sid in res[0]['tokenGroups']:
            dn_tokengroups.append(str(ndr_unpack(samba.dcerpc.security.dom_sid, sid)))

        sidset1 = set(dn_tokengroups)
        sidset2 = set(self.user_sids)
        if len(sidset1.difference(sidset2)):
            print("token sids don't match")
            print("difference : %s" % sidset1.difference(sidset2))
            self.fail(msg="calculated groups don't match against user DN tokenGroups")

    def test_pac_groups(self):
        if creds.get_kerberos_state() == DONT_USE_KERBEROS:
            self.skipTest("Kerberos disabled, skipping PAC test")

        settings = {}
        settings["lp_ctx"] = lp
        settings["target_hostname"] = lp.get("netbios name")

        gensec_client = gensec.Security.start_client(settings)
        gensec_client.set_credentials(creds)
        gensec_client.want_feature(gensec.FEATURE_SEAL)
        gensec_client.start_mech_by_sasl_name("GSSAPI")

        auth_context = AuthContext(lp_ctx=lp, ldb=self.ldb, methods=[])

        gensec_server = gensec.Security.start_server(settings, auth_context)
        machine_creds = Credentials()
        machine_creds.guess(lp)
        machine_creds.set_machine_account(lp)
        gensec_server.set_credentials(machine_creds)

        gensec_server.want_feature(gensec.FEATURE_SEAL)
        gensec_server.start_mech_by_sasl_name("GSSAPI")

        client_finished = False
        server_finished = False
        server_to_client = b""

        # Run the actual call loop.
        while client_finished == False and server_finished == False:
            if not client_finished:
                print("running client gensec_update")
                (client_finished, client_to_server) = gensec_client.update(server_to_client)
            if not server_finished:
                print("running server gensec_update")
                (server_finished, server_to_client) = gensec_server.update(client_to_server)

        session = gensec_server.session_info()

        token = session.security_token
        pac_sids = []
        for s in token.sids:
            pac_sids.append(str(s))

        sidset1 = set(pac_sids)
        sidset2 = set(self.user_sids)
        if len(sidset1.difference(sidset2)):
            print("token sids don't match")
            print("difference : %s" % sidset1.difference(sidset2))
            self.fail(msg="calculated groups don't match against user PAC tokenGroups")


class DynamicTokenTest(samba.tests.TestCase):

    def get_creds(self, target_username, target_password):
        creds_tmp = Credentials()
        creds_tmp.set_username(target_username)
        creds_tmp.set_password(target_password)
        creds_tmp.set_domain(creds.get_domain())
        creds_tmp.set_realm(creds.get_realm())
        creds_tmp.set_workstation(creds.get_workstation())
        creds_tmp.set_gensec_features(creds_tmp.get_gensec_features()
                                      | gensec.FEATURE_SEAL)
        return creds_tmp

    def get_ldb_connection(self, target_username, target_password):
        creds_tmp = self.get_creds(target_username, target_password)
        ldb_target = SamDB(url=url, credentials=creds_tmp, lp=lp)
        return ldb_target

    def setUp(self):
        super(DynamicTokenTest, self).setUp()
        self.admin_ldb = SamDB(url, credentials=creds, session_info=system_session(lp), lp=lp)

        self.base_dn = self.admin_ldb.domain_dn()

        self.test_user = "tokengroups_user1"
        self.test_user_pass = "samba123@"
        self.admin_ldb.newuser(self.test_user, self.test_user_pass)
        self.test_group0 = "tokengroups_group0"
        self.admin_ldb.newgroup(self.test_group0, grouptype=dsdb.GTYPE_SECURITY_DOMAIN_LOCAL_GROUP)
        res = self.admin_ldb.search(base="cn=%s,cn=users,%s" % (self.test_group0, self.base_dn),
                                    attrs=["objectSid"], scope=ldb.SCOPE_BASE)
        self.test_group0_sid = ndr_unpack(samba.dcerpc.security.dom_sid, res[0]["objectSid"][0])

        self.admin_ldb.add_remove_group_members(self.test_group0, [self.test_user],
                                                add_members_operation=True)

        self.test_group1 = "tokengroups_group1"
        self.admin_ldb.newgroup(self.test_group1, grouptype=dsdb.GTYPE_SECURITY_GLOBAL_GROUP)
        res = self.admin_ldb.search(base="cn=%s,cn=users,%s" % (self.test_group1, self.base_dn),
                                    attrs=["objectSid"], scope=ldb.SCOPE_BASE)
        self.test_group1_sid = ndr_unpack(samba.dcerpc.security.dom_sid, res[0]["objectSid"][0])

        self.admin_ldb.add_remove_group_members(self.test_group1, [self.test_user],
                                                add_members_operation=True)

        self.test_group2 = "tokengroups_group2"
        self.admin_ldb.newgroup(self.test_group2, grouptype=dsdb.GTYPE_SECURITY_UNIVERSAL_GROUP)

        res = self.admin_ldb.search(base="cn=%s,cn=users,%s" % (self.test_group2, self.base_dn),
                                    attrs=["objectSid"], scope=ldb.SCOPE_BASE)
        self.test_group2_sid = ndr_unpack(samba.dcerpc.security.dom_sid, res[0]["objectSid"][0])

        self.admin_ldb.add_remove_group_members(self.test_group2, [self.test_user],
                                                add_members_operation=True)

        self.test_group3 = "tokengroups_group3"
        self.admin_ldb.newgroup(self.test_group3, grouptype=dsdb.GTYPE_SECURITY_UNIVERSAL_GROUP)

        res = self.admin_ldb.search(base="cn=%s,cn=users,%s" % (self.test_group3, self.base_dn),
                                    attrs=["objectSid"], scope=ldb.SCOPE_BASE)
        self.test_group3_sid = ndr_unpack(samba.dcerpc.security.dom_sid, res[0]["objectSid"][0])

        self.admin_ldb.add_remove_group_members(self.test_group3, [self.test_group1],
                                                add_members_operation=True)

        self.test_group4 = "tokengroups_group4"
        self.admin_ldb.newgroup(self.test_group4, grouptype=dsdb.GTYPE_SECURITY_UNIVERSAL_GROUP)

        res = self.admin_ldb.search(base="cn=%s,cn=users,%s" % (self.test_group4, self.base_dn),
                                    attrs=["objectSid"], scope=ldb.SCOPE_BASE)
        self.test_group4_sid = ndr_unpack(samba.dcerpc.security.dom_sid, res[0]["objectSid"][0])

        self.admin_ldb.add_remove_group_members(self.test_group4, [self.test_group3],
                                                add_members_operation=True)

        self.test_group5 = "tokengroups_group5"
        self.admin_ldb.newgroup(self.test_group5, grouptype=dsdb.GTYPE_SECURITY_DOMAIN_LOCAL_GROUP)

        res = self.admin_ldb.search(base="cn=%s,cn=users,%s" % (self.test_group5, self.base_dn),
                                    attrs=["objectSid"], scope=ldb.SCOPE_BASE)
        self.test_group5_sid = ndr_unpack(samba.dcerpc.security.dom_sid, res[0]["objectSid"][0])

        self.admin_ldb.add_remove_group_members(self.test_group5, [self.test_group4],
                                                add_members_operation=True)

        self.test_group6 = "tokengroups_group6"
        self.admin_ldb.newgroup(self.test_group6, grouptype=dsdb.GTYPE_SECURITY_DOMAIN_LOCAL_GROUP)

        res = self.admin_ldb.search(base="cn=%s,cn=users,%s" % (self.test_group6, self.base_dn),
                                    attrs=["objectSid"], scope=ldb.SCOPE_BASE)
        self.test_group6_sid = ndr_unpack(samba.dcerpc.security.dom_sid, res[0]["objectSid"][0])

        self.admin_ldb.add_remove_group_members(self.test_group6, [self.test_user],
                                                add_members_operation=True)

        self.ldb = self.get_ldb_connection(self.test_user, self.test_user_pass)

        res = self.ldb.search("", scope=ldb.SCOPE_BASE, attrs=["tokenGroups"])
        self.assertEqual(len(res), 1)

        self.user_sid = ndr_unpack(samba.dcerpc.security.dom_sid, res[0]["tokenGroups"][0])
        self.user_sid_dn = "<SID=%s>" % str(self.user_sid)

        res = self.ldb.search(self.user_sid_dn, scope=ldb.SCOPE_BASE, attrs=[])
        self.assertEqual(len(res), 1)

        self.test_user_dn = res[0].dn

        session_info_flags = (AUTH_SESSION_INFO_DEFAULT_GROUPS |
                              AUTH_SESSION_INFO_AUTHENTICATED |
                              AUTH_SESSION_INFO_SIMPLE_PRIVILEGES)

        if creds.get_kerberos_state() == DONT_USE_KERBEROS:
            session_info_flags |= AUTH_SESSION_INFO_NTLM

        session = samba.auth.user_session(self.ldb, lp_ctx=lp, dn=self.user_sid_dn,
                                          session_info_flags=session_info_flags)

        token = session.security_token
        self.user_sids = []
        for s in token.sids:
            self.user_sids.append(str(s))

    def tearDown(self):
        super(DynamicTokenTest, self).tearDown()
        delete_force(self.admin_ldb, "CN=%s,%s,%s" %
                     (self.test_user, "cn=users", self.base_dn))
        delete_force(self.admin_ldb, "CN=%s,%s,%s" %
                     (self.test_group0, "cn=users", self.base_dn))
        delete_force(self.admin_ldb, "CN=%s,%s,%s" %
                     (self.test_group1, "cn=users", self.base_dn))
        delete_force(self.admin_ldb, "CN=%s,%s,%s" %
                     (self.test_group2, "cn=users", self.base_dn))
        delete_force(self.admin_ldb, "CN=%s,%s,%s" %
                     (self.test_group3, "cn=users", self.base_dn))
        delete_force(self.admin_ldb, "CN=%s,%s,%s" %
                     (self.test_group4, "cn=users", self.base_dn))
        delete_force(self.admin_ldb, "CN=%s,%s,%s" %
                     (self.test_group5, "cn=users", self.base_dn))
        delete_force(self.admin_ldb, "CN=%s,%s,%s" %
                     (self.test_group6, "cn=users", self.base_dn))

    def test_rootDSE_tokenGroups(self):
        """Testing rootDSE tokengroups against internal calculation"""
        if not url.startswith("ldap"):
            self.fail(msg="This test is only valid on ldap")

        res = self.ldb.search("", scope=ldb.SCOPE_BASE, attrs=["tokenGroups"])
        self.assertEqual(len(res), 1)

        print("Getting tokenGroups from rootDSE")
        tokengroups = []
        for sid in res[0]['tokenGroups']:
            tokengroups.append(str(ndr_unpack(samba.dcerpc.security.dom_sid, sid)))

        sidset1 = set(tokengroups)
        sidset2 = set(self.user_sids)
        if len(sidset1.difference(sidset2)):
            print("token sids don't match")
            print("tokengroups: %s" % tokengroups)
            print("calculated : %s" % self.user_sids)
            print("difference : %s" % sidset1.difference(sidset2))
            self.fail(msg="calculated groups don't match against rootDSE tokenGroups")

    def test_dn_tokenGroups(self):
        print("Getting tokenGroups from user DN")
        res = self.ldb.search(self.user_sid_dn, scope=ldb.SCOPE_BASE, attrs=["tokenGroups"])
        self.assertEqual(len(res), 1)

        dn_tokengroups = []
        for sid in res[0]['tokenGroups']:
            dn_tokengroups.append(str(ndr_unpack(samba.dcerpc.security.dom_sid, sid)))

        sidset1 = set(dn_tokengroups)
        sidset2 = set(self.user_sids)

        # The SIDs on the DN do not include the NTLM authentication SID
        sidset2.discard(samba.dcerpc.security.SID_NT_NTLM_AUTHENTICATION)

        if len(sidset1.difference(sidset2)):
            print("token sids don't match")
            print("difference : %s" % sidset1.difference(sidset2))
            self.fail(msg="calculated groups don't match against user DN tokenGroups")

    def test_pac_groups(self):
        settings = {}
        settings["lp_ctx"] = lp
        settings["target_hostname"] = lp.get("netbios name")

        gensec_client = gensec.Security.start_client(settings)
        gensec_client.set_credentials(self.get_creds(self.test_user, self.test_user_pass))
        gensec_client.want_feature(gensec.FEATURE_SEAL)
        gensec_client.start_mech_by_sasl_name("GSSAPI")

        auth_context = AuthContext(lp_ctx=lp, ldb=self.ldb, methods=[])

        gensec_server = gensec.Security.start_server(settings, auth_context)
        machine_creds = Credentials()
        machine_creds.guess(lp)
        machine_creds.set_machine_account(lp)
        gensec_server.set_credentials(machine_creds)

        gensec_server.want_feature(gensec.FEATURE_SEAL)
        gensec_server.start_mech_by_sasl_name("GSSAPI")

        client_finished = False
        server_finished = False
        server_to_client = b""

        # Run the actual call loop.
        while client_finished == False and server_finished == False:
            if not client_finished:
                print("running client gensec_update")
                (client_finished, client_to_server) = gensec_client.update(server_to_client)
            if not server_finished:
                print("running server gensec_update")
                (server_finished, server_to_client) = gensec_server.update(client_to_server)

        session = gensec_server.session_info()

        token = session.security_token
        pac_sids = []
        for s in token.sids:
            pac_sids.append(str(s))

        sidset1 = set(pac_sids)
        sidset2 = set(self.user_sids)
        if len(sidset1.difference(sidset2)):
            print("token sids don't match")
            print("difference : %s" % sidset1.difference(sidset2))
            self.fail(msg="calculated groups don't match against user PAC tokenGroups")

    def test_tokenGroups_manual(self):
        # Manually run the tokenGroups algorithm from MS-ADTS 3.1.1.4.5.19 and MS-DRSR 4.1.8.3
        # and compare the result
        res = self.admin_ldb.search(base=self.base_dn, scope=ldb.SCOPE_SUBTREE,
                                    expression="(|(objectclass=user)(objectclass=group))",
                                    attrs=["memberOf"])
        aSet = set()
        aSetR = set()
        vSet = set()
        for obj in res:
            if "memberOf" in obj:
                for dn in obj["memberOf"]:
                    first = obj.dn.get_casefold()
                    second = ldb.Dn(self.admin_ldb, dn.decode('utf8')).get_casefold()
                    aSet.add((first, second))
                    aSetR.add((second, first))
                    vSet.add(first)
                    vSet.add(second)

        res = self.admin_ldb.search(base=self.base_dn, scope=ldb.SCOPE_SUBTREE,
                                    expression="(objectclass=user)",
                                    attrs=["primaryGroupID"])
        for obj in res:
            if "primaryGroupID" in obj:
                sid = "%s-%d" % (self.admin_ldb.get_domain_sid(), int(obj["primaryGroupID"][0]))
                res2 = self.admin_ldb.search(base="<SID=%s>" % sid, scope=ldb.SCOPE_BASE,
                                             attrs=[])
                first = obj.dn.get_casefold()
                second = res2[0].dn.get_casefold()

                aSet.add((first, second))
                aSetR.add((second, first))
                vSet.add(first)
                vSet.add(second)

        wSet = set()
        wSet.add(self.test_user_dn.get_casefold())
        closure(vSet, wSet, aSet)
        wSet.remove(self.test_user_dn.get_casefold())

        tokenGroupsSet = set()

        res = self.ldb.search(self.user_sid_dn, scope=ldb.SCOPE_BASE, attrs=["tokenGroups"])
        self.assertEqual(len(res), 1)

        dn_tokengroups = []
        for sid in res[0]['tokenGroups']:
            sid = ndr_unpack(samba.dcerpc.security.dom_sid, sid)
            res3 = self.admin_ldb.search(base="<SID=%s>" % sid, scope=ldb.SCOPE_BASE,
                                         attrs=[])
            tokenGroupsSet.add(res3[0].dn.get_casefold())

        if len(wSet.difference(tokenGroupsSet)):
            self.fail(msg="additional calculated: %s" % wSet.difference(tokenGroupsSet))

        if len(tokenGroupsSet.difference(wSet)):
            self.fail(msg="additional tokenGroups: %s" % tokenGroupsSet.difference(wSet))

    def filtered_closure(self, wSet, filter_grouptype):
        res = self.admin_ldb.search(base=self.base_dn, scope=ldb.SCOPE_SUBTREE,
                                    expression="(|(objectclass=user)(objectclass=group))",
                                    attrs=["memberOf"])
        aSet = set()
        aSetR = set()
        vSet = set()
        for obj in res:
            vSet.add(obj.dn.get_casefold())
            if "memberOf" in obj:
                for dn in obj["memberOf"]:
                    first = obj.dn.get_casefold()
                    second = ldb.Dn(self.admin_ldb, dn.decode('utf8')).get_casefold()
                    aSet.add((first, second))
                    aSetR.add((second, first))
                    vSet.add(first)
                    vSet.add(second)

        res = self.admin_ldb.search(base=self.base_dn, scope=ldb.SCOPE_SUBTREE,
                                    expression="(objectclass=user)",
                                    attrs=["primaryGroupID"])
        for obj in res:
            if "primaryGroupID" in obj:
                sid = "%s-%d" % (self.admin_ldb.get_domain_sid(), int(obj["primaryGroupID"][0]))
                res2 = self.admin_ldb.search(base="<SID=%s>" % sid, scope=ldb.SCOPE_BASE,
                                             attrs=[])
                first = obj.dn.get_casefold()
                second = res2[0].dn.get_casefold()

                aSet.add((first, second))
                aSetR.add((second, first))
                vSet.add(first)
                vSet.add(second)

        uSet = set()
        for v in vSet:
            res_group = self.admin_ldb.search(base=v, scope=ldb.SCOPE_BASE,
                                              attrs=["groupType"],
                                              expression="objectClass=group")
            if len(res_group) == 1:
                if hex(int(res_group[0]["groupType"][0]) & 0x00000000FFFFFFFF) == hex(filter_grouptype):
                    uSet.add(v)
            else:
                uSet.add(v)

        closure(uSet, wSet, aSet)

    def test_tokenGroupsGlobalAndUniversal_manual(self):
        # Manually run the tokenGroups algorithm from MS-ADTS 3.1.1.4.5.19 and MS-DRSR 4.1.8.3
        # and compare the result

        # The variable names come from MS-ADTS May 15, 2014

        S = set()
        S.add(self.test_user_dn.get_casefold())

        self.filtered_closure(S, GTYPE_SECURITY_GLOBAL_GROUP)

        T = set()
        # Not really a SID, we do this on DNs...
        for sid in S:
            X = set()
            X.add(sid)
            self.filtered_closure(X, GTYPE_SECURITY_UNIVERSAL_GROUP)

            T = T.union(X)

        T.remove(self.test_user_dn.get_casefold())

        tokenGroupsSet = set()

        res = self.ldb.search(self.user_sid_dn, scope=ldb.SCOPE_BASE, attrs=["tokenGroupsGlobalAndUniversal"])
        self.assertEqual(len(res), 1)

        dn_tokengroups = []
        for sid in res[0]['tokenGroupsGlobalAndUniversal']:
            sid = ndr_unpack(samba.dcerpc.security.dom_sid, sid)
            res3 = self.admin_ldb.search(base="<SID=%s>" % sid, scope=ldb.SCOPE_BASE,
                                         attrs=[])
            tokenGroupsSet.add(res3[0].dn.get_casefold())

        if len(T.difference(tokenGroupsSet)):
            self.fail(msg="additional calculated: %s" % T.difference(tokenGroupsSet))

        if len(tokenGroupsSet.difference(T)):
            self.fail(msg="additional tokenGroupsGlobalAndUniversal: %s" % tokenGroupsSet.difference(T))

    def test_samr_GetGroupsForUser(self):
        # Confirm that we get the correct results against SAMR also
        if not url.startswith("ldap://"):
            self.fail(msg="This test is only valid on ldap (so we an find the hostname and use SAMR)")
        host = url.split("://")[1]
        (domain_sid, user_rid) = self.user_sid.split()
        samr_conn = samba.dcerpc.samr.samr("ncacn_ip_tcp:%s[seal]" % host, lp, creds)
        samr_handle = samr_conn.Connect2(None, security.SEC_FLAG_MAXIMUM_ALLOWED)
        samr_domain = samr_conn.OpenDomain(samr_handle, security.SEC_FLAG_MAXIMUM_ALLOWED,
                                           domain_sid)
        user_handle = samr_conn.OpenUser(samr_domain, security.SEC_FLAG_MAXIMUM_ALLOWED, user_rid)
        rids = samr_conn.GetGroupsForUser(user_handle)
        samr_dns = set()
        for rid in rids.rids:
            self.assertEqual(rid.attributes, security.SE_GROUP_MANDATORY | security.SE_GROUP_ENABLED_BY_DEFAULT | security.SE_GROUP_ENABLED)
            sid = "%s-%d" % (domain_sid, rid.rid)
            res = self.admin_ldb.search(base="<SID=%s>" % sid, scope=ldb.SCOPE_BASE,
                                        attrs=[])
            samr_dns.add(res[0].dn.get_casefold())

        user_info = samr_conn.QueryUserInfo(user_handle, 1)
        self.assertEqual(rids.rids[0].rid, user_info.primary_gid)

        tokenGroupsSet = set()
        res = self.ldb.search(self.user_sid_dn, scope=ldb.SCOPE_BASE, attrs=["tokenGroupsGlobalAndUniversal"])
        for sid in res[0]['tokenGroupsGlobalAndUniversal']:
            sid = ndr_unpack(samba.dcerpc.security.dom_sid, sid)
            res3 = self.admin_ldb.search(base="<SID=%s>" % sid, scope=ldb.SCOPE_BASE,
                                         attrs=[],
                                         expression="(&(|(grouptype=%d)(grouptype=%d))(objectclass=group))"
                                         % (GTYPE_SECURITY_GLOBAL_GROUP, GTYPE_SECURITY_UNIVERSAL_GROUP))
            if len(res) == 1:
                tokenGroupsSet.add(res3[0].dn.get_casefold())

        if len(samr_dns.difference(tokenGroupsSet)):
            self.fail(msg="additional samr_GetUserGroups over tokenGroups: %s" % samr_dns.difference(tokenGroupsSet))

        memberOf = set()
        # Add the primary group
        primary_group_sid = "%s-%d" % (domain_sid, user_info.primary_gid)
        res2 = self.admin_ldb.search(base="<SID=%s>" % sid, scope=ldb.SCOPE_BASE,
                                     attrs=[])

        memberOf.add(res2[0].dn.get_casefold())
        res = self.ldb.search(self.user_sid_dn, scope=ldb.SCOPE_BASE, attrs=["memberOf"])
        for dn in res[0]['memberOf']:
            res3 = self.admin_ldb.search(base=dn, scope=ldb.SCOPE_BASE,
                                         attrs=[],
                                         expression="(&(|(grouptype=%d)(grouptype=%d))(objectclass=group))"
                                         % (GTYPE_SECURITY_GLOBAL_GROUP, GTYPE_SECURITY_UNIVERSAL_GROUP))
            if len(res3) == 1:
                memberOf.add(res3[0].dn.get_casefold())

        if len(memberOf.difference(samr_dns)):
            self.fail(msg="additional memberOf over samr_GetUserGroups: %s" % memberOf.difference(samr_dns))

        if len(samr_dns.difference(memberOf)):
            self.fail(msg="additional samr_GetUserGroups over memberOf: %s" % samr_dns.difference(memberOf))

        S = set()
        S.add(self.test_user_dn.get_casefold())

        self.filtered_closure(S, GTYPE_SECURITY_GLOBAL_GROUP)
        self.filtered_closure(S, GTYPE_SECURITY_UNIVERSAL_GROUP)

        # Now remove the user DN and primary group
        S.remove(self.test_user_dn.get_casefold())

        if len(samr_dns.difference(S)):
            self.fail(msg="additional samr_GetUserGroups over filtered_closure: %s" % samr_dns.difference(S))

    def test_samr_GetGroupsForUser_nomember(self):
        # Confirm that we get the correct results against SAMR also
        if not url.startswith("ldap://"):
            self.fail(msg="This test is only valid on ldap (so we an find the hostname and use SAMR)")
        host = url.split("://")[1]

        test_user = "tokengroups_user2"
        self.admin_ldb.newuser(test_user, self.test_user_pass)
        res = self.admin_ldb.search(base="cn=%s,cn=users,%s" % (test_user, self.base_dn),
                                    attrs=["objectSid"], scope=ldb.SCOPE_BASE)
        user_sid = ndr_unpack(samba.dcerpc.security.dom_sid, res[0]["objectSid"][0])

        (domain_sid, user_rid) = user_sid.split()
        samr_conn = samba.dcerpc.samr.samr("ncacn_ip_tcp:%s[seal]" % host, lp, creds)
        samr_handle = samr_conn.Connect2(None, security.SEC_FLAG_MAXIMUM_ALLOWED)
        samr_domain = samr_conn.OpenDomain(samr_handle, security.SEC_FLAG_MAXIMUM_ALLOWED,
                                           domain_sid)
        user_handle = samr_conn.OpenUser(samr_domain, security.SEC_FLAG_MAXIMUM_ALLOWED, user_rid)
        rids = samr_conn.GetGroupsForUser(user_handle)
        user_info = samr_conn.QueryUserInfo(user_handle, 1)
        delete_force(self.admin_ldb, "CN=%s,%s,%s" %
                     (test_user, "cn=users", self.base_dn))
        self.assertEqual(len(rids.rids), 1)
        self.assertEqual(rids.rids[0].rid, user_info.primary_gid)


if "://" not in url:
    if os.path.isfile(url):
        url = "tdb://%s" % url
    else:
        url = "ldap://%s" % url

TestProgram(module=__name__, opts=subunitopts)
