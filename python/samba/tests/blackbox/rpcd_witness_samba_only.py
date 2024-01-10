#!/usr/bin/env python3
# Unix SMB/CIFS implementation.
#
# Copyright © 2024 Stefan Metzmacher <metze@samba.org>
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

import sys
import os

sys.path.insert(0, "bin/python")
os.environ["PYTHONUNBUFFERED"] = "1"

import json

import samba.tests
from samba.credentials import Credentials
from samba.ndr import ndr_print
from samba.dcerpc import witness
from samba.tests import DynamicTestCase, BlackboxTestCase
from samba.common import get_string
from samba import werror, WERRORError

@DynamicTestCase
class RpcdWitnessSambaTests(BlackboxTestCase):
    @classmethod
    def setUpDynamicTestCases(cls):
        cls.num_nodes = int(samba.tests.env_get_var_value('NUM_NODES'))

        def _define_tests(idx1, idx2, ndr64=False):
            cls._define_GetInterfaceList_test(idx1, idx2, ndr64)
            if idx1 == 0 and idx2 != -1:
                cls._define_ResourceChangeCTDB_tests(idx1, idx2, ndr64)

        for idx1 in range(0, cls.num_nodes):
            _define_tests(idx1, -1, ndr64=False)
            _define_tests(idx1, -1, ndr64=True)
            for idx2 in range(0, cls.num_nodes):
                _define_tests(idx1, idx2, ndr64=False)
                _define_tests(idx1, idx2, ndr64=True)

    def setUp(self):
        super().setUp()

        # ctdb/tests/local_daemons.sh doesn't like CTDB_SOCKET to be set already
        # and it doesn't need CTDB_BASE, so we stash them away
        self.saved_CTDB_SOCKET = samba.tests.env_get_var_value('CTDB_SOCKET',
                                                               allow_missing=True)
        if self.saved_CTDB_SOCKET is not None:
            del os.environ["CTDB_SOCKET"]
        self.saved_CTDB_BASE = samba.tests.env_get_var_value('CTDB_BASE',
                                                             allow_missing=True)
        if self.saved_CTDB_BASE is not None:
            del os.environ["CTDB_BASE"]

        self.disabled_idx = -1

        # set this to True in order to get verbose output
        self.verbose = False

        self.ctdb_prefix = samba.tests.env_get_var_value('CTDB_PREFIX')

        self.cluster_share = samba.tests.env_get_var_value('CLUSTER_SHARE')

        self.lp = self.get_loadparm(s3=True)
        self.remote_domain = samba.tests.env_get_var_value('DOMAIN')
        self.remote_user = samba.tests.env_get_var_value('USERNAME')
        self.remote_password = samba.tests.env_get_var_value('PASSWORD')
        self.remote_creds = Credentials()
        self.remote_creds.guess(self.lp)
        self.remote_creds.set_username(self.remote_user)
        self.remote_creds.set_domain(self.remote_domain)
        self.remote_creds.set_password(self.remote_password)

        self.server_hostname = samba.tests.env_get_var_value('SERVER_HOSTNAME')
        self.interface_group_name = samba.tests.env_get_var_value('INTERFACE_GROUP_NAME')

        common_binding_args = "spnego,sign,target_hostname=%s" % (
            self.server_hostname)
        if self.verbose:
            common_binding_args += ",print"

        common_binding_args32 = common_binding_args
        common_binding_args64 = common_binding_args + ",ndr64"

        self.nodes = []
        for node_idx in range(0, self.num_nodes):
            node = {}

            name_var = 'CTDB_SERVER_NAME_NODE%u' % node_idx
            node["name"] = samba.tests.env_get_var_value(name_var)

            ip_var = 'CTDB_IFACE_IP_NODE%u' % node_idx
            node["ip"] = samba.tests.env_get_var_value(ip_var)

            node["binding_string32"] = "ncacn_ip_tcp:%s[%s]" % (
                    node["ip"], common_binding_args32)
            node["binding_string64"] = "ncacn_ip_tcp:%s[%s]" % (
                    node["ip"], common_binding_args64)
            self.nodes.append(node)

    def tearDown(self):
        if self.disabled_idx != -1:
            self.enable_node(self.disabled_idx)

        if self.saved_CTDB_SOCKET is not None:
            os.environ["CTDB_SOCKET"] = self.saved_CTDB_SOCKET
            self.saved_CTDB_SOCKET = None
        if self.saved_CTDB_BASE is not None:
            os.environ["CTDB_BASE"] = self.saved_CTDB_BASE
            self.saved_CTDB_BASE = None

        super().tearDown()

    def call_onnode(self, nodes, cmd):
        COMMAND = "ctdb/tests/local_daemons.sh"

        argv = "%s '%s' onnode %s '%s'" % (COMMAND, self.ctdb_prefix, nodes, cmd)

        try:
            if self.verbose:
                print("Calling: %s" % argv)
            out = self.check_output(argv)
        except samba.tests.BlackboxProcessError as e:
            self.fail("Error calling [%s]: %s" % (argv, e))

        out_str = get_string(out)
        return out_str

    def dump_ctdb_status_all(self):
        for node_idx in range(0, self.num_nodes):
            print("%s" % self.call_onnode(str(node_idx), "ctdb status"))

    def disable_node(self, node_idx, dump_status=False):
        if dump_status:
            self.dump_ctdb_status_all()

        self.assertEqual(self.disabled_idx, -1)
        self.call_onnode(str(node_idx), "ctdb disable")
        self.disabled_idx = node_idx

        if dump_status:
            self.dump_ctdb_status_all()

    def enable_node(self, node_idx, dump_status=False):
        if dump_status:
            self.dump_ctdb_status_all()

        self.assertEqual(self.disabled_idx, node_idx)
        self.call_onnode(str(node_idx), "ctdb enable")
        self.disabled_idx = -1

        if dump_status:
            self.dump_ctdb_status_all()

    @classmethod
    def _define_GetInterfaceList_test(cls, conn_idx, disable_idx, ndr64=False):
        if disable_idx != -1:
            disable_name = "%u_disabled" % disable_idx
        else:
            disable_name = "all_enabled"

        if ndr64:
            ndr_name = "NDR64"
        else:
            ndr_name = "NDR32"

        name = "Node%u_%s_%s" % (conn_idx, disable_name, ndr_name)
        args = {
            'conn_idx': conn_idx,
            'disable_idx': disable_idx,
            'ndr64': ndr64,
        }
        cls.generate_dynamic_test('test_GetInterfaceList', name, args)

    def _test_GetInterfaceList_with_args(self, args):
        conn_idx = args.pop('conn_idx')
        disable_idx = args.pop('disable_idx')
        ndr64 = args.pop('ndr64')
        self.assertEqual(len(args.keys()), 0)

        conn_node = self.nodes[conn_idx]
        if ndr64:
            binding_string = conn_node["binding_string64"]
        else:
            binding_string = conn_node["binding_string32"]

        if disable_idx != -1:
            self.disable_node(disable_idx)

        conn = witness.witness(binding_string, self.lp, self.remote_creds)
        interface_list = conn.GetInterfaceList()

        if disable_idx != -1:
            self.enable_node(disable_idx)

        self.assertIsNotNone(interface_list)
        self.assertEqual(interface_list.num_interfaces, len(self.nodes))
        for idx in range(0, interface_list.num_interfaces):
            iface = interface_list.interfaces[idx]
            node = self.nodes[idx]

            expected_flags = 0
            expected_flags |= witness.WITNESS_INFO_IPv4_VALID
            if conn_idx != idx:
                expected_flags |= witness.WITNESS_INFO_WITNESS_IF

            if disable_idx == idx:
                expected_state = witness.WITNESS_STATE_UNAVAILABLE
            else:
                expected_state = witness.WITNESS_STATE_AVAILABLE

            self.assertIsNotNone(iface.group_name)
            self.assertEqual(iface.group_name, self.interface_group_name)

            self.assertEqual(iface.version, witness.WITNESS_V2)
            self.assertEqual(iface.state, expected_state)

            self.assertIsNotNone(iface.ipv4)
            self.assertEqual(iface.ipv4, node["ip"])

            self.assertIsNotNone(iface.ipv6)
            self.assertEqual(iface.ipv6,
                    "0000:0000:0000:0000:0000:0000:0000:0000")

            self.assertEqual(iface.flags, expected_flags)

    def assertResourceChanges(self, response, expected_resource_changes):
        self.assertIsNotNone(response)
        self.assertEqual(response.type,
                witness.WITNESS_NOTIFY_RESOURCE_CHANGE)
        self.assertEqual(response.num, len(expected_resource_changes))
        self.assertEqual(len(response.messages), len(expected_resource_changes))
        for ri in range(0, len(expected_resource_changes)):
            expected_resource_change = expected_resource_changes[ri]
            resource_change = response.messages[ri]
            self.assertIsNotNone(resource_change)

            expected_type = witness.WITNESS_RESOURCE_STATE_UNAVAILABLE
            expected_type = expected_resource_change.get('type', expected_type)

            expected_name = expected_resource_change.get('name')

            self.assertEqual(resource_change.type, expected_type)
            self.assertIsNotNone(resource_change.name)
            self.assertEqual(resource_change.name, expected_name)

    def assertResourceChange(self, response, expected_type, expected_name):
        expected_resource_change = {
            'type': expected_type,
            'name': expected_name,
        }
        expected_resource_changes = [expected_resource_change]
        self.assertResourceChanges(response, expected_resource_changes)

    @classmethod
    def _define_ResourceChangeCTDB_tests(cls, conn_idx, monitor_idx, ndr64=False):
        if ndr64:
            ndr_name = "NDR64"
        else:
            ndr_name = "NDR32"

        name_suffix = "WNode%u_RNode%u_%s" % (conn_idx, monitor_idx, ndr_name)
        base_args = {
            'conn_idx': conn_idx,
            'monitor_idx': monitor_idx,
            'ndr64': ndr64,
        }

        name = "v1_disabled_after_%s" % name_suffix
        args = base_args.copy()
        args['reg_v1'] = True
        args['disable_after_reg'] = True
        args['explicit_unregister'] = False
        cls.generate_dynamic_test('test_ResourceChangeCTDB', name, args)

        name = "v1_disabled_after_enabled_after_%s" % name_suffix
        args = base_args.copy()
        args['reg_v1'] = True
        args['disable_after_reg'] = True
        args['enable_after_reg'] = True
        args['explicit_unregister'] = False
        cls.generate_dynamic_test('test_ResourceChangeCTDB', name, args)

        name = "v2_disabled_before_enable_after_%s" % name_suffix
        args = base_args.copy()
        args['disable_before_reg'] = True
        args['enable_after_reg'] = True
        args['wait_for_timeout'] = True
        args['timeout'] = 6
        cls.generate_dynamic_test('test_ResourceChangeCTDB', name, args)

        name = "v2_disabled_after_%s" % name_suffix
        args = base_args.copy()
        args['disable_after_reg'] = True
        args['wait_for_not_found'] = True
        args['explicit_unregister'] = False
        cls.generate_dynamic_test('test_ResourceChangeCTDB', name, args)

        name = "v2_disabled_after_enabled_after_%s" % name_suffix
        args = base_args.copy()
        args['disable_after_reg'] = True
        args['enable_after_reg'] = True
        args['wait_for_not_found'] = True
        args['explicit_unregister'] = False
        cls.generate_dynamic_test('test_ResourceChangeCTDB', name, args)

        name = "share_v2_disabled_before_enable_after_%s" % name_suffix
        args = base_args.copy()
        args['share_reg'] = True
        args['disable_before_reg'] = True
        args['enable_after_reg'] = True
        cls.generate_dynamic_test('test_ResourceChangeCTDB', name, args)

        name = "share_v2_disabled_after_%s" % name_suffix
        args = base_args.copy()
        args['share_reg'] = True
        args['disable_after_reg'] = True
        args['explicit_unregister'] = False
        cls.generate_dynamic_test('test_ResourceChangeCTDB', name, args)

        name = "share_v2_disabled_after_enabled_after_%s" % name_suffix
        args = base_args.copy()
        args['share_reg'] = True
        args['disable_after_reg'] = True
        args['enable_after_reg'] = True
        args['explicit_unregister'] = False
        cls.generate_dynamic_test('test_ResourceChangeCTDB', name, args)

    def _test_ResourceChangeCTDB_with_args(self, args):
        conn_idx = args.pop('conn_idx')
        monitor_idx = args.pop('monitor_idx')
        ndr64 = args.pop('ndr64')
        timeout = int(args.pop('timeout', 15))
        reg_v1 = args.pop('reg_v1', False)
        share_reg = args.pop('share_reg', False)
        disable_before_reg = args.pop('disable_before_reg', False)
        disable_after_reg = args.pop('disable_after_reg', False)
        enable_after_reg = args.pop('enable_after_reg', False)
        explicit_unregister = args.pop('explicit_unregister', True)
        wait_for_not_found = args.pop('wait_for_not_found', False)
        wait_for_timeout = args.pop('wait_for_timeout', False)
        self.assertEqual(len(args.keys()), 0)

        conn_node = self.nodes[conn_idx]
        if ndr64:
            binding_string = conn_node["binding_string64"]
        else:
            binding_string = conn_node["binding_string32"]
        monitor_node = self.nodes[monitor_idx]

        computer_name = "test-rpcd-witness-samba-only-client-computer"

        conn = witness.witness(binding_string, self.lp, self.remote_creds)

        if disable_before_reg:
            self.assertFalse(disable_after_reg)
            self.disable_node(monitor_idx)

        if reg_v1:
            self.assertFalse(wait_for_timeout)
            self.assertFalse(share_reg)

            reg_context = conn.Register(witness.WITNESS_V1,
                                        self.server_hostname,
                                        monitor_node["ip"],
                                        computer_name)
        else:
            if share_reg:
                share_name = self.cluster_share
            else:
                share_name = None

            reg_context = conn.RegisterEx(witness.WITNESS_V2,
                                          self.server_hostname,
                                          share_name,
                                          monitor_node["ip"],
                                          computer_name,
                                          witness.WITNESS_REGISTER_NONE,
                                          timeout)

        if disable_after_reg:
            self.assertFalse(disable_before_reg)
            self.disable_node(monitor_idx)

        if enable_after_reg:
            self.enable_node(monitor_idx)

        if disable_after_reg:
            response_unavailable = conn.AsyncNotify(reg_context)
            self.assertResourceChange(response_unavailable,
                                      witness.WITNESS_RESOURCE_STATE_UNAVAILABLE,
                                      monitor_node["ip"])

        if enable_after_reg:
            response_available = conn.AsyncNotify(reg_context)
            self.assertResourceChange(response_available,
                                      witness.WITNESS_RESOURCE_STATE_AVAILABLE,
                                      monitor_node["ip"])

        if wait_for_timeout:
            self.assertFalse(wait_for_not_found)
            self.assertFalse(disable_after_reg)
            try:
                _ = conn.AsyncNotify(reg_context)
                self.fail()
            except WERRORError as e:
                (num, string) = e.args
                if num != werror.WERR_TIMEOUT:
                    raise

        if wait_for_not_found:
            self.assertFalse(wait_for_timeout)
            self.assertTrue(disable_after_reg)
            self.assertFalse(explicit_unregister)
            try:
                _ = conn.AsyncNotify(reg_context)
                self.fail()
            except WERRORError as e:
                (num, string) = e.args
                if num != werror.WERR_NOT_FOUND:
                    raise

        if not explicit_unregister:
            return

        conn.UnRegister(reg_context)

        try:
            _ = conn.AsyncNotify(reg_context)
            self.fail()
        except WERRORError as e:
            (num, string) = e.args
            if num != werror.WERR_NOT_FOUND:
                raise

        try:
            conn.UnRegister(reg_context)
            self.fail()
        except WERRORError as e:
            (num, string) = e.args
            if num != werror.WERR_NOT_FOUND:
                raise

if __name__ == "__main__":
    import unittest
    unittest.main()
