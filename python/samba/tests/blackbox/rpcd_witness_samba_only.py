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

        self.all_registrations = None

    def tearDown(self):
        self.destroy_all_registrations()

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

    def call_net_witness_subcmd(self, subcmd,
                                as_json=False,
                                registration=None,
                                net_name=None,
                                share_name=None,
                                ip_address=None,
                                client_computer=None):
        COMMAND = "UID_WRAPPER_ROOT=1 bin/net witness"

        argv = "%s %s" % (COMMAND, subcmd)
        if as_json:
            argv += " --json"

        if registration is not None:
            argv += " --witness-registration='%s'" % (
                    registration.uuid)

        if net_name is not None:
            argv += " --witness-net-name='%s'" % (net_name)

        if share_name is not None:
            argv += " --witness-share-name='%s'" % (share_name)

        if ip_address is not None:
            argv += " --witness-ip-address='%s'" % (ip_address)

        if client_computer is not None:
            argv += " --witness-client-computer-name='%s'" % (client_computer)

        try:
            if self.verbose:
                print("Calling: %s" % argv)
            out = self.check_output(argv)
        except samba.tests.BlackboxProcessError as e:
            self.fail("Error calling [%s]: %s" % (argv, e))

        out_str = get_string(out)
        if not as_json:
            return out_str

        json_out = json.loads(out_str)
        return json_out

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

    def prepare_all_registrations(self):
        self.assertIsNone(self.all_registrations)

        regs = []
        for node_idx in range(0, self.num_nodes):
            node = self.nodes[node_idx]
            for ndr64 in [False, True]:
                if ndr64:
                    binding_string = node["binding_string64"]
                    ndr_name = "NDR64"
                else:
                    binding_string = node["binding_string32"]
                    ndr_name = "NDR32"

                conn = witness.witness(binding_string, self.lp, self.remote_creds)
                conn_ip = node["ip"]

                net_name = self.server_hostname
                ip_address = node["ip"]
                share_name = self.cluster_share
                computer_name = "test-net-witness-list-%s-%s" % (
                        node_idx, ndr_name)
                flags = witness.WITNESS_REGISTER_NONE
                timeout = 15

                reg_version = witness.WITNESS_V1
                reg = {
                    'node_idx': node_idx,
                    'ndr64': ndr64,
                    'binding_string': binding_string,
                    'conn_ip': conn_ip,
                    'version': reg_version,
                    'net_name': net_name,
                    'share_name': None,
                    'ip_address': ip_address,
                    'computer_name': computer_name,
                    'flags': 0,
                    'timeout': 0,
                    'conn': conn,
                    'context': None,
                }
                regs.append(reg)

                reg_version = witness.WITNESS_V2
                reg = {
                    'node_idx': node_idx,
                    'ndr64': ndr64,
                    'binding_string': binding_string,
                    'conn_ip': conn_ip,
                    'version': reg_version,
                    'net_name': net_name,
                    'share_name': None,
                    'ip_address': ip_address,
                    'computer_name': computer_name,
                    'flags': flags,
                    'timeout': timeout,
                    'conn': conn,
                    'context': None,
                }
                regs.append(reg)

                reg = {
                    'node_idx': node_idx,
                    'ndr64': ndr64,
                    'binding_string': binding_string,
                    'conn_ip': conn_ip,
                    'version': reg_version,
                    'net_name': net_name,
                    'share_name': share_name,
                    'ip_address': ip_address,
                    'computer_name': computer_name,
                    'flags': flags,
                    'timeout': timeout,
                    'conn': conn,
                    'context': None,
                }
                regs.append(reg)

        self.all_registrations = regs
        return regs

    def close_all_registrations(self):
        self.assertIsNotNone(self.all_registrations)

        for reg in self.all_registrations:
            conn = reg['conn']
            reg_context = reg['context']
            if reg_context is not None:
                conn.UnRegister(reg_context)
                reg_context = None
            reg['context'] = reg_context

    def open_all_registrations(self):
        self.assertIsNotNone(self.all_registrations)

        for reg in self.all_registrations:
            conn = reg['conn']
            reg_context = reg['context']
            self.assertIsNone(reg_context)

            reg_version = reg['version']
            if reg_version == witness.WITNESS_V1:
                reg_context = conn.Register(reg_version,
                                            reg['net_name'],
                                            reg['ip_address'],
                                            reg['computer_name'])
            elif reg_version == witness.WITNESS_V2:
                reg_context = conn.RegisterEx(reg_version,
                                              reg['net_name'],
                                              reg['share_name'],
                                              reg['ip_address'],
                                              reg['computer_name'],
                                              reg['flags'],
                                              reg['timeout'])
            self.assertIsNotNone(reg_context)
            reg['context'] = reg_context

    def destroy_all_registrations(self):
        if self.all_registrations is None:
            return

        for reg in self.all_registrations:
            conn = reg['conn']
            reg_context = reg['context']
            if reg_context is not None:
                conn.UnRegister(reg_context)
                reg_context = None
            reg['context'] = reg_context
            conn = None
            reg['conn'] = conn

        self.all_registrations = None

    def assertJsonReg(self, json_reg, reg):
        self.assertEqual(json_reg['version'], "0x%08x" % reg['version'])
        self.assertEqual(json_reg['net_name'], reg['net_name'])
        if reg['share_name']:
            self.assertEqual(json_reg['share_name'], reg['share_name'])
        else:
            self.assertIsNone(json_reg['share_name'])
        self.assertEqual(json_reg['client_computer_name'], reg['computer_name'])

        self.assertIn('flags', json_reg)
        json_flags = json_reg['flags']
        if reg['flags'] & witness.WITNESS_REGISTER_IP_NOTIFICATION:
            expected_ip_notifaction = True
        else:
            expected_ip_notifaction = False
        self.assertEqual(json_flags['WITNESS_REGISTER_IP_NOTIFICATION'],
                         expected_ip_notifaction)
        self.assertEqual(json_flags['int'], reg['flags'])
        self.assertEqual(json_flags['hex'], "0x%08x" % reg['flags'])
        self.assertEqual(len(json_flags.keys()), 3)

        self.assertEqual(json_reg['timeout'], reg['timeout'])

        self.assertIn('context_handle', json_reg)
        json_context = json_reg['context_handle']
        self.assertEqual(json_context['uuid'], str(reg['context'].uuid))
        self.assertEqual(json_context['handle_type'], reg['context'].handle_type)
        self.assertEqual(len(json_context.keys()), 2)

        self.assertIn('server_id', json_reg)
        json_server_id = json_reg['server_id']
        self.assertIn('pid', json_server_id)
        self.assertIn('task_id', json_server_id)
        self.assertEqual(json_server_id['vnn'], reg['node_idx'])
        self.assertIn('unique_id', json_server_id)
        self.assertEqual(len(json_server_id.keys()), 4)

        self.assertIn('auth', json_reg)
        json_auth = json_reg['auth']
        self.assertEqual(json_auth['account_name'], self.remote_user)
        self.assertEqual(json_auth['domain_name'], self.remote_domain)
        self.assertIn('account_sid', json_auth)
        self.assertEqual(len(json_auth.keys()), 3)

        self.assertIn('connection', json_reg)
        json_conn = json_reg['connection']
        self.assertIn('local_address', json_conn)
        self.assertIn(reg['conn_ip'], json_conn['local_address'])
        self.assertIn('remote_address', json_conn)
        self.assertEqual(len(json_conn.keys()), 2)

        self.assertIn('registration_time', json_reg)

        self.assertEqual(len(json_reg.keys()), 12)

    def max_common_prefix(self, strings):
        if len(strings) == 0:
            return ""

        def string_match_len(s1, s2):
            idx = 0
            for i in range(0, min(len(s1), len(s2))):
                c1 = s1[i:i+1]
                c2 = s2[i:i+1]
                if c1 != c2:
                    break
                idx = i
            return idx

        prefix = None
        for s in strings:
            if prefix is None:
                prefix = s
                continue
            l = string_match_len(prefix, s)
            prefix = prefix[0:l+1]

        return prefix

    def check_net_witness_output(self,
                                 cmd,
                                 regs,
                                 registration_idx=None,
                                 net_name=None,
                                 share_name=None,
                                 ip_address=None,
                                 client_computer=None):
        self.open_all_registrations()
        if registration_idx is not None:
            registration = regs[registration_idx]['context']
            self.assertIsNotNone(registration)
        else:
            registration = None

        plain_res = self.call_net_witness_subcmd(cmd,
                                                 registration=registration,
                                                 net_name=net_name,
                                                 share_name=share_name,
                                                 ip_address=ip_address,
                                                 client_computer=client_computer)
        if self.verbose:
            print("%s" % plain_res)
        plain_lines = plain_res.splitlines()

        num_headlines = 2
        self.assertEqual(len(plain_lines), num_headlines+len(regs))
        plain_lines = plain_lines[num_headlines:]
        self.assertEqual(len(plain_lines), len(regs))

        for reg in regs:
            reg_uuid = reg['context'].uuid

            expected_line = "%-36s " % reg_uuid
            expected_line += "%-20s " % reg['net_name']
            if reg['share_name']:
                expected_share = reg['share_name']
            else:
                expected_share = "''"
            expected_line += "%-15s " % expected_share
            expected_line += "%-20s " % reg['ip_address']
            expected_line += "%s" % reg['computer_name']

            line = None
            for l in plain_lines:
                if not l.startswith(str(reg_uuid)):
                    continue
                self.assertIsNone(line)
                line = l
                self.assertEqual(line, expected_line)
            self.assertIsNotNone(line)

        self.close_all_registrations()

        self.open_all_registrations()
        if registration_idx is not None:
            registration = regs[registration_idx]['context']
            self.assertIsNotNone(registration)
        else:
            registration = None

        json_res = self.call_net_witness_subcmd(cmd,
                                                as_json=True,
                                                registration=registration,
                                                net_name=net_name,
                                                share_name=share_name,
                                                ip_address=ip_address,
                                                client_computer=client_computer)

        num_filters = 0
        if registration:
            num_filters += 1
        if net_name:
            num_filters += 1
        if share_name:
            num_filters += 1
        if ip_address:
            num_filters += 1
        if client_computer:
            num_filters += 1

        num_toplevel = 2

        self.assertIn('filters', json_res);
        self.assertIn('registrations', json_res);
        self.assertEqual(len(json_res.keys()), num_toplevel)

        json_filters = json_res['filters']
        self.assertEqual(len(json_filters.keys()), num_filters)

        if registration:
            self.assertEqual(json_filters['--witness-registration'],
                             str(registration.uuid))
        if net_name:
            self.assertEqual(json_filters['--witness-net-name'],
                             net_name)
        if share_name:
            self.assertEqual(json_filters['--witness-share-name'],
                             share_name)
        if ip_address:
            self.assertEqual(json_filters['--witness-ip-address'],
                             ip_address)
        if client_computer:
            self.assertEqual(json_filters['--witness-client-computer-name'],
                             client_computer)

        json_regs = json_res['registrations']
        self.assertEqual(len(json_regs.keys()), len(regs))

        for reg in regs:
            reg_uuid = reg['context'].uuid

            self.assertIn(str(reg_uuid), json_regs)
            json_reg = json_regs[str(reg_uuid)]
            self.assertJsonReg(json_reg, reg)

        self.close_all_registrations()

    def check_combinations(self, check_func, only_shares=False):
        all_regs = self.prepare_all_registrations()

        share_name_regs = {}
        all_share_name_regs = []
        no_share_name_regs = []
        for reg in all_regs:
            if reg['share_name'] is not None:
                if reg['share_name'] not in share_name_regs:
                    share_name_regs[reg['share_name']] = []
                share_name_regs[reg['share_name']].append(reg)
                all_share_name_regs.append(reg)
            else:
                no_share_name_regs.append(reg)

        ip_address_regs = {}
        computer_name_regs = {}
        for reg in all_regs:
            if reg['ip_address'] not in ip_address_regs:
                ip_address_regs[reg['ip_address']] = []
            ip_address_regs[reg['ip_address']].append(reg)

            if reg['computer_name'] not in computer_name_regs:
                computer_name_regs[reg['computer_name']] = []
            computer_name_regs[reg['computer_name']].append(reg)

        all_share_names = '|'.join(share_name_regs.keys())
        common_share_name = self.max_common_prefix(share_name_regs.keys())
        all_ip_addresses = '|'.join(ip_address_regs.keys())
        common_ip_address = self.max_common_prefix(ip_address_regs.keys())
        all_computer_names = '|'.join(computer_name_regs.keys())
        common_computer_name = self.max_common_prefix(computer_name_regs.keys())

        check_func(all_regs)
        check_func(all_regs,
                   net_name=self.server_hostname)
        check_func(all_regs,
                   ip_address=all_ip_addresses)
        check_func(all_regs,
                   client_computer=all_computer_names)
        check_func(all_regs,
                   net_name=self.server_hostname,
                   ip_address=all_ip_addresses,
                   client_computer=all_computer_names)
        check_func(all_regs,
                   net_name='.*',
                   share_name='.*',
                   ip_address='.*',
                   client_computer='.*')
        check_func(all_regs,
                   share_name='^$|%s.*' % common_share_name,
                   ip_address='%s.*' % common_ip_address,
                   client_computer='%s.*' % common_computer_name)
        check_func(all_share_name_regs,
                   share_name=all_share_names)
        check_func(all_share_name_regs,
                   share_name='%s.*' % common_share_name)
        check_func(no_share_name_regs,
                   share_name='^$')

        for share_name in share_name_regs.keys():
            regs = share_name_regs[share_name]
            check_func(regs, share_name=share_name)

        for ip_address in ip_address_regs.keys():
            regs = ip_address_regs[ip_address]
            check_func(regs, ip_address=ip_address)

        for computer_name in computer_name_regs.keys():
            regs = computer_name_regs[computer_name]
            check_func(regs, client_computer=computer_name)

        for reg in all_regs:
            regs = [reg]
            check_func(regs,
                       registration_idx=0)
            check_func(regs,
                       registration_idx=0,
                       net_name=reg['net_name'],
                       share_name=reg['share_name'],
                       ip_address=reg['ip_address'],
                       client_computer=reg['computer_name'])

    def test_net_witness_list(self):
        def check_list(regs,
                       registration_idx=None,
                       net_name=None,
                       share_name=None,
                       ip_address=None,
                       client_computer=None):
            return self.check_net_witness_output('list',
                                                 regs,
                                                 registration_idx=registration_idx,
                                                 net_name=net_name,
                                                 share_name=share_name,
                                                 ip_address=ip_address,
                                                 client_computer=client_computer)

        self.check_combinations(check_list)

if __name__ == "__main__":
    import unittest
    unittest.main()
