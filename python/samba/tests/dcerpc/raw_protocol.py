#!/usr/bin/env python
# Unix SMB/CIFS implementation.
# Copyright (C) Stefan Metzmacher 2014,2015
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

import samba.dcerpc.dcerpc as dcerpc
import samba.dcerpc.base as base
import samba.dcerpc.misc as misc
import samba.dcerpc.epmapper
import samba.dcerpc.mgmt
import samba.dcerpc.netlogon
import struct
from samba import gensec
from samba.tests import RawDCERPCTest

global_ndr_print = False
global_hexdump = False

class TestDCERPC_BIND(RawDCERPCTest):

    def setUp(self):
        super(TestDCERPC_BIND, self).setUp()
        self.do_ndr_print = global_ndr_print
        self.do_hexdump = global_hexdump

    def _test_no_auth_request_bind_pfc_flags(self, req_pfc_flags, rep_pfc_flags):
        ndr32 = base.transfer_syntax_ndr()

        tsf1_list = [ndr32]
        ctx1 = dcerpc.ctx_list()
        ctx1.context_id = 1
        ctx1.num_transfer_syntaxes = len(tsf1_list)
        ctx1.abstract_syntax = samba.dcerpc.mgmt.abstract_syntax()
        ctx1.transfer_syntaxes = tsf1_list

        req = self.generate_bind(call_id=0, pfc_flags=req_pfc_flags, ctx_list=[ctx1])
        self.send_pdu(req)
        rep = self.recv_pdu()
        self.verify_pdu(rep, dcerpc.DCERPC_PKT_BIND_ACK, req.call_id,
                        pfc_flags=rep_pfc_flags, auth_length=0)
        self.assertEquals(rep.u.max_xmit_frag, req.u.max_xmit_frag)
        self.assertEquals(rep.u.max_recv_frag, req.u.max_recv_frag)
        self.assertNotEquals(rep.u.assoc_group_id, req.u.assoc_group_id)
        self.assertEquals(rep.u.secondary_address_size, 4)
        self.assertEquals(rep.u.secondary_address, "%d" % self.tcp_port)
        self.assertEquals(len(rep.u._pad1), 2)
        # sometimes windows sends random bytes
        # self.assertEquals(rep.u._pad1, '\0' * 2)
        self.assertEquals(rep.u.num_results, 1)
        self.assertEquals(rep.u.ctx_list[0].result,
                dcerpc.DCERPC_BIND_ACK_RESULT_ACCEPTANCE)
        self.assertEquals(rep.u.ctx_list[0].reason,
                dcerpc.DCERPC_BIND_ACK_REASON_NOT_SPECIFIED)
        self.assertNDRSyntaxEquals(rep.u.ctx_list[0].syntax, ndr32)
        self.assertEquals(rep.u.auth_info, '\0' * 0)

        # And now try a request
        req = self.generate_request(call_id = 1,
                                    context_id=ctx1.context_id,
                                    opnum=0,
                                    stub="")
        self.send_pdu(req)
        rep = self.recv_pdu()
        self.verify_pdu(rep, dcerpc.DCERPC_PKT_RESPONSE, req.call_id,
                        auth_length=0)
        self.assertNotEquals(rep.u.alloc_hint, 0)
        self.assertEquals(rep.u.context_id, req.u.context_id)
        self.assertEquals(rep.u.cancel_count, 0)
        self.assertGreaterEqual(len(rep.u.stub_and_verifier), rep.u.alloc_hint)

    def _test_no_auth_request_alter_pfc_flags(self, req_pfc_flags, rep_pfc_flags):
        ndr32 = base.transfer_syntax_ndr()

        tsf1_list = [ndr32]
        ctx1 = dcerpc.ctx_list()
        ctx1.context_id = 1
        ctx1.num_transfer_syntaxes = len(tsf1_list)
        ctx1.abstract_syntax = samba.dcerpc.mgmt.abstract_syntax()
        ctx1.transfer_syntaxes = tsf1_list

        req = self.generate_bind(call_id=0, ctx_list=[ctx1])
        self.send_pdu(req)
        rep = self.recv_pdu()
        self.verify_pdu(rep, dcerpc.DCERPC_PKT_BIND_ACK, req.call_id,
                        auth_length=0)
        self.assertEquals(rep.u.max_xmit_frag, req.u.max_xmit_frag)
        self.assertEquals(rep.u.max_recv_frag, req.u.max_recv_frag)
        self.assertNotEquals(rep.u.assoc_group_id, req.u.assoc_group_id)
        self.assertEquals(rep.u.secondary_address_size, 4)
        self.assertEquals(rep.u.secondary_address, "%d" % self.tcp_port)
        self.assertEquals(len(rep.u._pad1), 2)
        # sometimes windows sends random bytes
        # self.assertEquals(rep.u._pad1, '\0' * 2)
        self.assertEquals(rep.u.num_results, 1)
        self.assertEquals(rep.u.ctx_list[0].result,
                dcerpc.DCERPC_BIND_ACK_RESULT_ACCEPTANCE)
        self.assertEquals(rep.u.ctx_list[0].reason,
                dcerpc.DCERPC_BIND_ACK_REASON_NOT_SPECIFIED)
        self.assertNDRSyntaxEquals(rep.u.ctx_list[0].syntax, ndr32)
        self.assertEquals(rep.u.auth_info, '\0' * 0)

        # And now try a alter context
        req = self.generate_alter(call_id=0, pfc_flags=req_pfc_flags, ctx_list=[ctx1])
        self.send_pdu(req)
        rep = self.recv_pdu()
        self.verify_pdu(rep, dcerpc.DCERPC_PKT_ALTER_RESP, req.call_id,
                        pfc_flags=rep_pfc_flags, auth_length=0)
        self.assertEquals(rep.u.max_xmit_frag, req.u.max_xmit_frag)
        self.assertEquals(rep.u.max_recv_frag, req.u.max_recv_frag)
        self.assertNotEquals(rep.u.assoc_group_id, req.u.assoc_group_id)
        self.assertEquals(rep.u.secondary_address_size, 0)
        self.assertEquals(rep.u.secondary_address, "")
        self.assertEquals(len(rep.u._pad1), 2)
        # sometimes windows sends random bytes
        # self.assertEquals(rep.u._pad1, '\0' * 2)
        self.assertEquals(rep.u.num_results, 1)
        self.assertEquals(rep.u.ctx_list[0].result,
                dcerpc.DCERPC_BIND_ACK_RESULT_ACCEPTANCE)
        self.assertEquals(rep.u.ctx_list[0].reason,
                dcerpc.DCERPC_BIND_ACK_REASON_NOT_SPECIFIED)
        self.assertNDRSyntaxEquals(rep.u.ctx_list[0].syntax, ndr32)
        self.assertEquals(rep.u.auth_info, '\0' * 0)

        # And now try a request
        req = self.generate_request(call_id = 1,
                                    context_id=ctx1.context_id,
                                    opnum=0,
                                    stub="")
        self.send_pdu(req)
        rep = self.recv_pdu()
        self.verify_pdu(rep, dcerpc.DCERPC_PKT_RESPONSE, req.call_id,
                        auth_length=0)
        self.assertNotEquals(rep.u.alloc_hint, 0)
        self.assertEquals(rep.u.context_id, req.u.context_id)
        self.assertEquals(rep.u.cancel_count, 0)
        self.assertGreaterEqual(len(rep.u.stub_and_verifier), rep.u.alloc_hint)

    def test_no_auth_request(self):
        return self._test_no_auth_request_bind_pfc_flags(
                                        req_pfc_flags=0 |
                                        dcerpc.DCERPC_PFC_FLAG_FIRST |
                                        dcerpc.DCERPC_PFC_FLAG_LAST,
                                        rep_pfc_flags=0 |
                                        dcerpc.DCERPC_PFC_FLAG_FIRST |
                                        dcerpc.DCERPC_PFC_FLAG_LAST)

    def test_no_auth_request_bind_pfc_00(self):
        return self._test_no_auth_request_bind_pfc_flags(
                                        req_pfc_flags=0 |
                                        0,
                                        rep_pfc_flags=0 |
                                        dcerpc.DCERPC_PFC_FLAG_FIRST |
                                        dcerpc.DCERPC_PFC_FLAG_LAST)

    def test_no_auth_request_bind_pfc_FIRST(self):
        return self._test_no_auth_request_bind_pfc_flags(
                                        req_pfc_flags=0 |
                                        dcerpc.DCERPC_PFC_FLAG_FIRST |
                                        0,
                                        rep_pfc_flags=0 |
                                        dcerpc.DCERPC_PFC_FLAG_FIRST |
                                        dcerpc.DCERPC_PFC_FLAG_LAST)

    def test_no_auth_request_bind_pfc_LAST(self):
        return self._test_no_auth_request_bind_pfc_flags(
                                        req_pfc_flags=0 |
                                        dcerpc.DCERPC_PFC_FLAG_LAST |
                                        0,
                                        rep_pfc_flags=0 |
                                        dcerpc.DCERPC_PFC_FLAG_FIRST |
                                        dcerpc.DCERPC_PFC_FLAG_LAST)

    # TODO: doesn't announce DCERPC_PFC_FLAG_SUPPORT_HEADER_SIGN
    # without authentication
    def _test_no_auth_request_bind_pfc_HDR_SIGNING(self):
        return self._test_no_auth_request_bind_pfc_flags(
                                        req_pfc_flags=0 |
                                        dcerpc.DCERPC_PFC_FLAG_SUPPORT_HEADER_SIGN |
                                        0,
                                        rep_pfc_flags=0 |
                                        dcerpc.DCERPC_PFC_FLAG_FIRST |
                                        dcerpc.DCERPC_PFC_FLAG_LAST |
                                        dcerpc.DCERPC_PFC_FLAG_SUPPORT_HEADER_SIGN)

    def test_no_auth_request_bind_pfc_08(self):
        return self._test_no_auth_request_bind_pfc_flags(
                                        req_pfc_flags=0 |
                                        8 |
                                        0,
                                        rep_pfc_flags=0 |
                                        dcerpc.DCERPC_PFC_FLAG_FIRST |
                                        dcerpc.DCERPC_PFC_FLAG_LAST)

    def test_no_auth_request_bind_pfc_CONC_MPX(self):
        return self._test_no_auth_request_bind_pfc_flags(
                                        req_pfc_flags=0 |
                                        dcerpc.DCERPC_PFC_FLAG_CONC_MPX |
                                        0,
                                        rep_pfc_flags=0 |
                                        dcerpc.DCERPC_PFC_FLAG_FIRST |
                                        dcerpc.DCERPC_PFC_FLAG_LAST |
                                        dcerpc.DCERPC_PFC_FLAG_CONC_MPX)

    def test_no_auth_request_bind_pfc_DID_NOT_EXECUTE(self):
        return self._test_no_auth_request_bind_pfc_flags(
                                        req_pfc_flags=0 |
                                        dcerpc.DCERPC_PFC_FLAG_DID_NOT_EXECUTE |
                                        0,
                                        rep_pfc_flags=0 |
                                        dcerpc.DCERPC_PFC_FLAG_FIRST |
                                        dcerpc.DCERPC_PFC_FLAG_LAST)

    def test_no_auth_request_bind_pfc_MAYBE(self):
        return self._test_no_auth_request_bind_pfc_flags(
                                        req_pfc_flags=0 |
                                        dcerpc.DCERPC_PFC_FLAG_MAYBE |
                                        0,
                                        rep_pfc_flags=0 |
                                        dcerpc.DCERPC_PFC_FLAG_FIRST |
                                        dcerpc.DCERPC_PFC_FLAG_LAST)

    def test_no_auth_request_bind_pfc_OBJECT_UUID(self):
        return self._test_no_auth_request_bind_pfc_flags(
                                        req_pfc_flags=0 |
                                        dcerpc.DCERPC_PFC_FLAG_OBJECT_UUID |
                                        0,
                                        rep_pfc_flags=0 |
                                        dcerpc.DCERPC_PFC_FLAG_FIRST |
                                        dcerpc.DCERPC_PFC_FLAG_LAST)

    # TODO: doesn't announce DCERPC_PFC_FLAG_SUPPORT_HEADER_SIGN
    # without authentication
    # TODO: doesn't announce DCERPC_PFC_FLAG_CONC_MPX
    # by default
    def _test_no_auth_request_bind_pfc_ff(self):
        return self._test_no_auth_request_bind_pfc_flags(
                                        req_pfc_flags=0 |
                                        0xff |
                                        0,
                                        rep_pfc_flags=0 |
                                        dcerpc.DCERPC_PFC_FLAG_FIRST |
                                        dcerpc.DCERPC_PFC_FLAG_LAST |
                                        dcerpc.DCERPC_PFC_FLAG_SUPPORT_HEADER_SIGN |
                                        dcerpc.DCERPC_PFC_FLAG_CONC_MPX)

    def test_no_auth_request_alter_pfc_00(self):
        return self._test_no_auth_request_alter_pfc_flags(
                                        req_pfc_flags=0 |
                                        0,
                                        rep_pfc_flags=0 |
                                        dcerpc.DCERPC_PFC_FLAG_FIRST |
                                        dcerpc.DCERPC_PFC_FLAG_LAST)

    def test_no_auth_request_alter_pfc_FIRST(self):
        return self._test_no_auth_request_alter_pfc_flags(
                                        req_pfc_flags=0 |
                                        dcerpc.DCERPC_PFC_FLAG_FIRST |
                                        0,
                                        rep_pfc_flags=0 |
                                        dcerpc.DCERPC_PFC_FLAG_FIRST |
                                        dcerpc.DCERPC_PFC_FLAG_LAST)

    def test_no_auth_request_alter_pfc_LAST(self):
        return self._test_no_auth_request_alter_pfc_flags(
                                        req_pfc_flags=0 |
                                        dcerpc.DCERPC_PFC_FLAG_LAST |
                                        0,
                                        rep_pfc_flags=0 |
                                        dcerpc.DCERPC_PFC_FLAG_FIRST |
                                        dcerpc.DCERPC_PFC_FLAG_LAST)

    # TODO: doesn't announce DCERPC_PFC_FLAG_SUPPORT_HEADER_SIGN
    # without authentication
    def _test_no_auth_request_alter_pfc_HDR_SIGNING(self):
        return self._test_no_auth_request_alter_pfc_flags(
                                        req_pfc_flags=0 |
                                        dcerpc.DCERPC_PFC_FLAG_SUPPORT_HEADER_SIGN |
                                        0,
                                        rep_pfc_flags=0 |
                                        dcerpc.DCERPC_PFC_FLAG_FIRST |
                                        dcerpc.DCERPC_PFC_FLAG_LAST |
                                        dcerpc.DCERPC_PFC_FLAG_SUPPORT_HEADER_SIGN)

    def test_no_auth_request_alter_pfc_08(self):
        return self._test_no_auth_request_alter_pfc_flags(
                                        req_pfc_flags=0 |
                                        8 |
                                        0,
                                        rep_pfc_flags=0 |
                                        dcerpc.DCERPC_PFC_FLAG_FIRST |
                                        dcerpc.DCERPC_PFC_FLAG_LAST)

    def test_no_auth_request_alter_pfc_CONC_MPX(self):
        return self._test_no_auth_request_alter_pfc_flags(
                                        req_pfc_flags=0 |
                                        dcerpc.DCERPC_PFC_FLAG_CONC_MPX |
                                        0,
                                        rep_pfc_flags=0 |
                                        dcerpc.DCERPC_PFC_FLAG_FIRST |
                                        dcerpc.DCERPC_PFC_FLAG_LAST)

    def test_no_auth_request_alter_pfc_DID_NOT_EXECUTE(self):
        return self._test_no_auth_request_alter_pfc_flags(
                                        req_pfc_flags=0 |
                                        dcerpc.DCERPC_PFC_FLAG_DID_NOT_EXECUTE |
                                        0,
                                        rep_pfc_flags=0 |
                                        dcerpc.DCERPC_PFC_FLAG_FIRST |
                                        dcerpc.DCERPC_PFC_FLAG_LAST)

    def test_no_auth_request_alter_pfc_MAYBE(self):
        return self._test_no_auth_request_alter_pfc_flags(
                                        req_pfc_flags=0 |
                                        dcerpc.DCERPC_PFC_FLAG_MAYBE |
                                        0,
                                        rep_pfc_flags=0 |
                                        dcerpc.DCERPC_PFC_FLAG_FIRST |
                                        dcerpc.DCERPC_PFC_FLAG_LAST)

    def test_no_auth_request_alter_pfc_OBJECT_UUID(self):
        return self._test_no_auth_request_alter_pfc_flags(
                                        req_pfc_flags=0 |
                                        dcerpc.DCERPC_PFC_FLAG_OBJECT_UUID |
                                        0,
                                        rep_pfc_flags=0 |
                                        dcerpc.DCERPC_PFC_FLAG_FIRST |
                                        dcerpc.DCERPC_PFC_FLAG_LAST)

    # TODO: doesn't announce DCERPC_PFC_FLAG_SUPPORT_HEADER_SIGN
    # without authentication
    def _test_no_auth_request_alter_pfc_ff(self):
        return self._test_no_auth_request_alter_pfc_flags(
                                        req_pfc_flags=0 |
                                        0xff |
                                        0,
                                        rep_pfc_flags=0 |
                                        dcerpc.DCERPC_PFC_FLAG_FIRST |
                                        dcerpc.DCERPC_PFC_FLAG_LAST |
                                        dcerpc.DCERPC_PFC_FLAG_SUPPORT_HEADER_SIGN)

    def test_no_auth_no_ctx(self):
        # send an useless bind
        req = self.generate_bind(call_id=0)
        self.send_pdu(req)
        rep = self.recv_pdu()
        self.verify_pdu(rep, dcerpc.DCERPC_PKT_BIND_NAK, req.call_id,
                        auth_length=0)
        self.assertEquals(rep.u.reject_reason,
                dcerpc.DCERPC_BIND_NAK_REASON_NOT_SPECIFIED)
        self.assertEquals(rep.u.num_versions, 1)
        self.assertEquals(rep.u.versions[0].rpc_vers, req.rpc_vers)
        self.assertEquals(rep.u.versions[0].rpc_vers_minor, req.rpc_vers_minor)
        self.assertEquals(len(rep.u._pad), 3)
        self.assertEquals(rep.u._pad, '\0' * 3)

    def test_invalid_auth_noctx(self):
        req = self.generate_bind(call_id=0)
        req.auth_length = dcerpc.DCERPC_AUTH_TRAILER_LENGTH
        self.send_pdu(req)
        rep = self.recv_pdu()
        self.verify_pdu(rep, dcerpc.DCERPC_PKT_BIND_NAK, req.call_id,
                        auth_length=0)
        self.assertEquals(rep.u.reject_reason,
                dcerpc.DCERPC_BIND_NAK_REASON_PROTOCOL_VERSION_NOT_SUPPORTED)
        self.assertEquals(rep.u.num_versions, 1)
        self.assertEquals(rep.u.versions[0].rpc_vers, req.rpc_vers)
        self.assertEquals(rep.u.versions[0].rpc_vers_minor, req.rpc_vers_minor)
        self.assertEquals(len(rep.u._pad), 3)
        self.assertEquals(rep.u._pad, '\0' * 3)

    def test_no_auth_valid_valid_request(self):
        ndr32 = base.transfer_syntax_ndr()

        tsf1_list = [ndr32]
        ctx1 = dcerpc.ctx_list()
        ctx1.context_id = 1
        ctx1.num_transfer_syntaxes = len(tsf1_list)
        ctx1.abstract_syntax = samba.dcerpc.mgmt.abstract_syntax()
        ctx1.transfer_syntaxes = tsf1_list

        req = self.generate_bind(call_id=0, ctx_list=[ctx1])
        self.send_pdu(req)
        rep = self.recv_pdu()
        self.verify_pdu(rep, dcerpc.DCERPC_PKT_BIND_ACK, req.call_id,
                        auth_length=0)
        self.assertEquals(rep.u.max_xmit_frag, req.u.max_xmit_frag)
        self.assertEquals(rep.u.max_recv_frag, req.u.max_recv_frag)
        self.assertNotEquals(rep.u.assoc_group_id, req.u.assoc_group_id)
        self.assertEquals(rep.u.secondary_address_size, 4)
        self.assertEquals(rep.u.secondary_address, "%d" % self.tcp_port)
        self.assertEquals(len(rep.u._pad1), 2)
        self.assertEquals(rep.u._pad1, '\0' * 2)
        self.assertEquals(rep.u.num_results, 1)
        self.assertEquals(rep.u.ctx_list[0].result,
                dcerpc.DCERPC_BIND_ACK_RESULT_ACCEPTANCE)
        self.assertEquals(rep.u.ctx_list[0].reason,
                dcerpc.DCERPC_BIND_ACK_REASON_NOT_SPECIFIED)
        self.assertNDRSyntaxEquals(rep.u.ctx_list[0].syntax, ndr32)
        self.assertEquals(rep.u.auth_info, '\0' * 0)

        # Send a bind again
        tsf2_list = [ndr32]
        ctx2 = dcerpc.ctx_list()
        ctx2.context_id = 2
        ctx2.num_transfer_syntaxes = len(tsf2_list)
        ctx2.abstract_syntax = samba.dcerpc.mgmt.abstract_syntax()
        ctx2.transfer_syntaxes = tsf2_list

        req = self.generate_bind(call_id=1, ctx_list=[ctx2])
        self.send_pdu(req)
        rep = self.recv_pdu()
        self.verify_pdu(rep, dcerpc.DCERPC_PKT_BIND_NAK, req.call_id,
                        auth_length=0)
        self.assertEquals(rep.u.reject_reason,
                dcerpc.DCERPC_BIND_NAK_REASON_NOT_SPECIFIED)
        self.assertEquals(rep.u.num_versions, 1)
        self.assertEquals(rep.u.versions[0].rpc_vers, req.rpc_vers)
        self.assertEquals(rep.u.versions[0].rpc_vers_minor, req.rpc_vers_minor)
        self.assertEquals(len(rep.u._pad), 3)
        self.assertEquals(rep.u._pad, '\0' * 3)

        # wait for a disconnect
        rep = self.recv_pdu()
        self.assertIsNone(rep)
        self.assertNotConnected()

    def test_no_auth_invalid_valid_request(self):
        # send an useless bind
        req = self.generate_bind(call_id=0)
        self.send_pdu(req)
        rep = self.recv_pdu()
        self.verify_pdu(rep, dcerpc.DCERPC_PKT_BIND_NAK, req.call_id,
                        auth_length=0)
        self.assertEquals(rep.u.reject_reason,
                dcerpc.DCERPC_BIND_NAK_REASON_NOT_SPECIFIED)
        self.assertEquals(rep.u.num_versions, 1)
        self.assertEquals(rep.u.versions[0].rpc_vers, req.rpc_vers)
        self.assertEquals(rep.u.versions[0].rpc_vers_minor, req.rpc_vers_minor)
        self.assertEquals(len(rep.u._pad), 3)
        self.assertEquals(rep.u._pad, '\0' * 3)

        # wait for a disconnect
        rep = self.recv_pdu()
        self.assertIsNone(rep)
        self.assertNotConnected()

    def test_alter_no_auth_no_ctx(self):
        ndr32 = base.transfer_syntax_ndr()

        tsf1_list = [ndr32]
        ctx1 = dcerpc.ctx_list()
        ctx1.context_id = 1
        ctx1.num_transfer_syntaxes = len(tsf1_list)
        ctx1.abstract_syntax = samba.dcerpc.mgmt.abstract_syntax()
        ctx1.transfer_syntaxes = tsf1_list

        req = self.generate_bind(call_id=0, ctx_list=[ctx1])
        self.send_pdu(req)
        rep = self.recv_pdu()
        self.verify_pdu(rep, dcerpc.DCERPC_PKT_BIND_ACK, req.call_id,
                        auth_length=0)
        self.assertEquals(rep.u.max_xmit_frag, req.u.max_xmit_frag)
        self.assertEquals(rep.u.max_recv_frag, req.u.max_recv_frag)
        self.assertNotEquals(rep.u.assoc_group_id, req.u.assoc_group_id)
        self.assertEquals(rep.u.secondary_address_size, 4)
        self.assertEquals(rep.u.secondary_address, "%d" % self.tcp_port)
        self.assertEquals(len(rep.u._pad1), 2)
        self.assertEquals(rep.u._pad1, '\0' * 2)
        self.assertEquals(rep.u.num_results, 1)
        self.assertEquals(rep.u.ctx_list[0].result,
                dcerpc.DCERPC_BIND_ACK_RESULT_ACCEPTANCE)
        self.assertEquals(rep.u.ctx_list[0].reason,
                dcerpc.DCERPC_BIND_ACK_REASON_NOT_SPECIFIED)
        self.assertNDRSyntaxEquals(rep.u.ctx_list[0].syntax, ndr32)
        self.assertEquals(rep.u.auth_info, '\0' * 0)

        # Send a alter
        req = self.generate_alter(call_id=1, ctx_list=[])
        self.send_pdu(req)
        rep = self.recv_pdu()
        self.verify_pdu(rep, dcerpc.DCERPC_PKT_FAULT, req.call_id,
                        pfc_flags=req.pfc_flags |
                        dcerpc.DCERPC_PFC_FLAG_DID_NOT_EXECUTE,
                        auth_length=0)
        self.assertNotEquals(rep.u.alloc_hint, 0)
        self.assertEquals(rep.u.context_id, 0)
        self.assertEquals(rep.u.cancel_count, 0)
        self.assertEquals(rep.u.flags, 0)
        self.assertEquals(rep.u.status, dcerpc.DCERPC_NCA_S_PROTO_ERROR)
        self.assertEquals(rep.u.reserved, 0)
        self.assertEquals(len(rep.u.error_and_verifier), 0)

        # wait for a disconnect
        rep = self.recv_pdu()
        self.assertIsNone(rep)
        self.assertNotConnected()

    def test_no_auth_presentation_ctx_valid1(self):
        ndr32 = base.transfer_syntax_ndr()

        zero_syntax = misc.ndr_syntax_id()

        tsf1_list = [zero_syntax, ndr32]
        ctx1 = dcerpc.ctx_list()
        ctx1.context_id = 1
        ctx1.num_transfer_syntaxes = len(tsf1_list)
        ctx1.abstract_syntax = samba.dcerpc.mgmt.abstract_syntax()
        ctx1.transfer_syntaxes = tsf1_list

        req = self.generate_bind(call_id=0, ctx_list=[ctx1])
        self.send_pdu(req)
        rep = self.recv_pdu()
        self.verify_pdu(rep, dcerpc.DCERPC_PKT_BIND_ACK, req.call_id,
                        auth_length=0)
        self.assertEquals(rep.u.max_xmit_frag, req.u.max_xmit_frag)
        self.assertEquals(rep.u.max_recv_frag, req.u.max_recv_frag)
        self.assertNotEquals(rep.u.assoc_group_id, req.u.assoc_group_id)
        self.assertEquals(rep.u.secondary_address_size, 4)
        self.assertEquals(rep.u.secondary_address, "%d" % self.tcp_port)
        self.assertEquals(len(rep.u._pad1), 2)
        self.assertEquals(rep.u._pad1, '\0' * 2)
        self.assertEquals(rep.u.num_results, 1)
        self.assertEquals(rep.u.ctx_list[0].result,
                dcerpc.DCERPC_BIND_ACK_RESULT_ACCEPTANCE)
        self.assertEquals(rep.u.ctx_list[0].reason,
                dcerpc.DCERPC_BIND_ACK_REASON_NOT_SPECIFIED)
        self.assertNDRSyntaxEquals(rep.u.ctx_list[0].syntax, ndr32)
        self.assertEquals(rep.u.auth_info, '\0' * 0)

        # Send a alter
        req = self.generate_alter(call_id=1, ctx_list=[ctx1])
        self.send_pdu(req)
        rep = self.recv_pdu()
        self.verify_pdu(rep, dcerpc.DCERPC_PKT_ALTER_RESP, req.call_id,
                        auth_length=0)
        self.assertEquals(rep.u.max_xmit_frag, req.u.max_xmit_frag)
        self.assertEquals(rep.u.max_recv_frag, req.u.max_recv_frag)
        self.assertNotEquals(rep.u.assoc_group_id, req.u.assoc_group_id)
        self.assertEquals(rep.u.secondary_address_size, 0)
        self.assertEquals(len(rep.u._pad1), 2)
        #self.assertEquals(rep.u._pad1, '\0' * 2)
        self.assertEquals(rep.u.num_results, 1)
        self.assertEquals(rep.u.ctx_list[0].result,
                dcerpc.DCERPC_BIND_ACK_RESULT_ACCEPTANCE)
        self.assertEquals(rep.u.ctx_list[0].reason,
                dcerpc.DCERPC_BIND_ACK_REASON_NOT_SPECIFIED)
        self.assertNDRSyntaxEquals(rep.u.ctx_list[0].syntax, ndr32)
        self.assertEquals(rep.u.auth_info, '\0' * 0)

        req = self.generate_request(call_id = 2,
                                    context_id=ctx1.context_id,
                                    opnum=0xffff,
                                    stub="")
        self.send_pdu(req)
        rep = self.recv_pdu()
        self.verify_pdu(rep, dcerpc.DCERPC_PKT_FAULT, req.call_id,
                        pfc_flags=req.pfc_flags |
                        dcerpc.DCERPC_PFC_FLAG_DID_NOT_EXECUTE,
                        auth_length=0)
        self.assertNotEquals(rep.u.alloc_hint, 0)
        self.assertEquals(rep.u.context_id, ctx1.context_id)
        self.assertEquals(rep.u.cancel_count, 0)
        self.assertEquals(rep.u.flags, 0)
        self.assertEquals(rep.u.status, dcerpc.DCERPC_NCA_S_OP_RNG_ERROR)
        self.assertEquals(rep.u.reserved, 0)
        self.assertEquals(len(rep.u.error_and_verifier), 0)

    def test_no_auth_presentation_ctx_invalid1(self):
        ndr32 = base.transfer_syntax_ndr()

        zero_syntax = misc.ndr_syntax_id()

        tsf1_list = [ndr32]
        ctx1 = dcerpc.ctx_list()
        ctx1.context_id = 1
        ctx1.num_transfer_syntaxes = len(tsf1_list)
        ctx1.abstract_syntax = ndr32
        ctx1.transfer_syntaxes = tsf1_list

        req = self.generate_bind(call_id=0, ctx_list=[ctx1])
        self.send_pdu(req)
        rep = self.recv_pdu()
        self.verify_pdu(rep, dcerpc.DCERPC_PKT_BIND_ACK, req.call_id,
                        auth_length=0)
        self.assertEquals(rep.u.max_xmit_frag, req.u.max_xmit_frag)
        self.assertEquals(rep.u.max_recv_frag, req.u.max_recv_frag)
        self.assertNotEquals(rep.u.assoc_group_id, req.u.assoc_group_id)
        self.assertEquals(rep.u.secondary_address_size, 4)
        self.assertEquals(rep.u.secondary_address, "%d" % self.tcp_port)
        self.assertEquals(len(rep.u._pad1), 2)
        self.assertEquals(rep.u._pad1, '\0' * 2)
        self.assertEquals(rep.u.num_results, 1)
        self.assertEquals(rep.u.ctx_list[0].result,
                dcerpc.DCERPC_BIND_ACK_RESULT_PROVIDER_REJECTION)
        self.assertEquals(rep.u.ctx_list[0].reason,
                dcerpc.DCERPC_BIND_ACK_REASON_ABSTRACT_SYNTAX_NOT_SUPPORTED)
        self.assertNDRSyntaxEquals(rep.u.ctx_list[0].syntax, zero_syntax)
        self.assertEquals(rep.u.auth_info, '\0' * 0)

        # Send a alter
        req = self.generate_alter(call_id=1, ctx_list=[ctx1])
        self.send_pdu(req)
        rep = self.recv_pdu()
        self.verify_pdu(rep, dcerpc.DCERPC_PKT_ALTER_RESP, req.call_id,
                        auth_length=0)
        self.assertEquals(rep.u.max_xmit_frag, req.u.max_xmit_frag)
        self.assertEquals(rep.u.max_recv_frag, req.u.max_recv_frag)
        self.assertNotEquals(rep.u.assoc_group_id, req.u.assoc_group_id)
        self.assertEquals(rep.u.secondary_address_size, 0)
        self.assertEquals(len(rep.u._pad1), 2)
        #self.assertEquals(rep.u._pad1, '\0' * 2)
        self.assertEquals(rep.u.num_results, 1)
        self.assertEquals(rep.u.ctx_list[0].result,
                dcerpc.DCERPC_BIND_ACK_RESULT_PROVIDER_REJECTION)
        self.assertEquals(rep.u.ctx_list[0].reason,
                dcerpc.DCERPC_BIND_ACK_REASON_ABSTRACT_SYNTAX_NOT_SUPPORTED)
        self.assertNDRSyntaxEquals(rep.u.ctx_list[0].syntax, zero_syntax)
        self.assertEquals(rep.u.auth_info, '\0' * 0)

        req = self.generate_request(call_id = 2,
                                    context_id=12345,
                                    opnum=0,
                                    stub="")
        self.send_pdu(req)
        rep = self.recv_pdu()
        self.verify_pdu(rep, dcerpc.DCERPC_PKT_FAULT, req.call_id,
                        pfc_flags=req.pfc_flags |
                        dcerpc.DCERPC_PFC_FLAG_DID_NOT_EXECUTE,
                        auth_length=0)
        self.assertNotEquals(rep.u.alloc_hint, 0)
        self.assertEquals(rep.u.context_id, 0)
        self.assertEquals(rep.u.cancel_count, 0)
        self.assertEquals(rep.u.flags, 0)
        self.assertEquals(rep.u.status, dcerpc.DCERPC_NCA_S_UNKNOWN_IF)
        self.assertEquals(rep.u.reserved, 0)
        self.assertEquals(len(rep.u.error_and_verifier), 0)

        # Send a alter again to prove the connection is still alive
        req = self.generate_alter(call_id=3, ctx_list=[ctx1])
        self.send_pdu(req)
        rep = self.recv_pdu()
        self.verify_pdu(rep, dcerpc.DCERPC_PKT_ALTER_RESP, req.call_id,
                        auth_length=0)
        self.assertEquals(rep.u.max_xmit_frag, req.u.max_xmit_frag)
        self.assertEquals(rep.u.max_recv_frag, req.u.max_recv_frag)
        self.assertNotEquals(rep.u.assoc_group_id, req.u.assoc_group_id)
        self.assertEquals(rep.u.secondary_address_size, 0)
        self.assertEquals(len(rep.u._pad1), 2)
        #self.assertEquals(rep.u._pad1, '\0' * 2)
        self.assertEquals(rep.u.num_results, 1)
        self.assertEquals(rep.u.ctx_list[0].result,
                dcerpc.DCERPC_BIND_ACK_RESULT_PROVIDER_REJECTION)
        self.assertEquals(rep.u.ctx_list[0].reason,
                dcerpc.DCERPC_BIND_ACK_REASON_ABSTRACT_SYNTAX_NOT_SUPPORTED)
        self.assertNDRSyntaxEquals(rep.u.ctx_list[0].syntax, zero_syntax)
        self.assertEquals(rep.u.auth_info, '\0' * 0)

    def test_no_auth_presentation_ctx_invalid2(self):
        ndr32 = base.transfer_syntax_ndr()

        zero_syntax = misc.ndr_syntax_id()

        tsf1a_list = []
        ctx1a = dcerpc.ctx_list()
        ctx1a.context_id = 1
        ctx1a.num_transfer_syntaxes = len(tsf1a_list)
        ctx1a.abstract_syntax = samba.dcerpc.mgmt.abstract_syntax()
        ctx1a.transfer_syntaxes = tsf1a_list

        req = self.generate_bind(call_id=0, ctx_list=[ctx1a])
        self.send_pdu(req)
        rep = self.recv_pdu()
        self.verify_pdu(rep, dcerpc.DCERPC_PKT_BIND_NAK, req.call_id,
                        auth_length=0)
        self.assertEquals(rep.u.reject_reason,
                dcerpc.DCERPC_BIND_NAK_REASON_NOT_SPECIFIED)
        self.assertEquals(rep.u.num_versions, 1)
        self.assertEquals(rep.u.versions[0].rpc_vers, req.rpc_vers)
        self.assertEquals(rep.u.versions[0].rpc_vers_minor, req.rpc_vers_minor)
        self.assertEquals(len(rep.u._pad), 3)
        self.assertEquals(rep.u._pad, '\0' * 3)

        # wait for a disconnect
        rep = self.recv_pdu()
        self.assertIsNone(rep)
        self.assertNotConnected()

    def test_no_auth_presentation_ctx_invalid3(self):
        ndr32 = base.transfer_syntax_ndr()

        zero_syntax = misc.ndr_syntax_id()

        tsf1a_list = [zero_syntax, ndr32, ndr32, ndr32]
        ctx1a = dcerpc.ctx_list()
        ctx1a.context_id = 1
        ctx1a.num_transfer_syntaxes = len(tsf1a_list)
        ctx1a.abstract_syntax = samba.dcerpc.mgmt.abstract_syntax()
        ctx1a.transfer_syntaxes = tsf1a_list

        req = self.generate_bind(call_id=0, ctx_list=[ctx1a])
        self.send_pdu(req)
        rep = self.recv_pdu()
        self.verify_pdu(rep, dcerpc.DCERPC_PKT_BIND_ACK, req.call_id,
                        auth_length=0)
        self.assertEquals(rep.u.max_xmit_frag, req.u.max_xmit_frag)
        self.assertEquals(rep.u.max_recv_frag, req.u.max_recv_frag)
        self.assertNotEquals(rep.u.assoc_group_id, req.u.assoc_group_id)
        self.assertEquals(rep.u.secondary_address_size, 4)
        self.assertEquals(rep.u.secondary_address, "%d" % self.tcp_port)
        self.assertEquals(len(rep.u._pad1), 2)
        self.assertEquals(rep.u._pad1, '\0' * 2)
        self.assertEquals(rep.u.num_results, 1)
        self.assertEquals(rep.u.ctx_list[0].result,
                dcerpc.DCERPC_BIND_ACK_RESULT_ACCEPTANCE)
        self.assertEquals(rep.u.ctx_list[0].reason,
                dcerpc.DCERPC_BIND_ACK_REASON_NOT_SPECIFIED)
        self.assertNDRSyntaxEquals(rep.u.ctx_list[0].syntax, ndr32)
        self.assertEquals(rep.u.auth_info, '\0' * 0)

        tsf1b_list = []
        ctx1b = dcerpc.ctx_list()
        ctx1b.context_id = 1
        ctx1b.num_transfer_syntaxes = len(tsf1b_list)
        ctx1b.abstract_syntax = samba.dcerpc.mgmt.abstract_syntax()
        ctx1b.transfer_syntaxes = tsf1b_list

        # Send a alter
        req = self.generate_alter(call_id=1, ctx_list=[ctx1b])
        self.send_pdu(req)
        rep = self.recv_pdu()
        self.verify_pdu(rep, dcerpc.DCERPC_PKT_FAULT, req.call_id,
                        pfc_flags=req.pfc_flags |
                        dcerpc.DCERPC_PFC_FLAG_DID_NOT_EXECUTE,
                        auth_length=0)
        self.assertNotEquals(rep.u.alloc_hint, 0)
        self.assertEquals(rep.u.context_id, 0)
        self.assertEquals(rep.u.cancel_count, 0)
        self.assertEquals(rep.u.flags, 0)
        self.assertEquals(rep.u.status, dcerpc.DCERPC_NCA_S_PROTO_ERROR)
        self.assertEquals(rep.u.reserved, 0)
        self.assertEquals(len(rep.u.error_and_verifier), 0)

        # wait for a disconnect
        rep = self.recv_pdu()
        self.assertIsNone(rep)
        self.assertNotConnected()

    def test_no_auth_presentation_ctx_invalid4(self):
        ndr32 = base.transfer_syntax_ndr()
        ndr64 = base.transfer_syntax_ndr64()

        zero_syntax = misc.ndr_syntax_id()

        tsf1a_list = [zero_syntax, ndr32, ndr32, ndr32]
        ctx1a = dcerpc.ctx_list()
        ctx1a.context_id = 1
        ctx1a.num_transfer_syntaxes = len(tsf1a_list)
        ctx1a.abstract_syntax = samba.dcerpc.mgmt.abstract_syntax()
        ctx1a.transfer_syntaxes = tsf1a_list

        req = self.generate_bind(call_id=0, ctx_list=[ctx1a])
        self.send_pdu(req)
        rep = self.recv_pdu()
        self.verify_pdu(rep, dcerpc.DCERPC_PKT_BIND_ACK, req.call_id,
                        auth_length=0)
        self.assertEquals(rep.u.max_xmit_frag, req.u.max_xmit_frag)
        self.assertEquals(rep.u.max_recv_frag, req.u.max_recv_frag)
        self.assertNotEquals(rep.u.assoc_group_id, req.u.assoc_group_id)
        self.assertEquals(rep.u.secondary_address_size, 4)
        self.assertEquals(rep.u.secondary_address, "%d" % self.tcp_port)
        self.assertEquals(len(rep.u._pad1), 2)
        self.assertEquals(rep.u._pad1, '\0' * 2)
        self.assertEquals(rep.u.num_results, 1)
        self.assertEquals(rep.u.ctx_list[0].result,
                dcerpc.DCERPC_BIND_ACK_RESULT_ACCEPTANCE)
        self.assertEquals(rep.u.ctx_list[0].reason,
                dcerpc.DCERPC_BIND_ACK_REASON_NOT_SPECIFIED)
        self.assertNDRSyntaxEquals(rep.u.ctx_list[0].syntax, ndr32)
        self.assertEquals(rep.u.auth_info, '\0' * 0)

        # With a known but wrong syntax we get a protocol error
        # see test_no_auth_presentation_ctx_valid2
        tsf1b_list = [zero_syntax,samba.dcerpc.epmapper.abstract_syntax(),ndr64]
        ctx1b = dcerpc.ctx_list()
        ctx1b.context_id = 1
        ctx1b.num_transfer_syntaxes = len(tsf1b_list)
        ctx1b.abstract_syntax = samba.dcerpc.mgmt.abstract_syntax()
        ctx1b.transfer_syntaxes = tsf1b_list

        # Send a alter
        req = self.generate_alter(call_id=1, ctx_list=[ctx1b])
        self.send_pdu(req)
        rep = self.recv_pdu()
        self.verify_pdu(rep, dcerpc.DCERPC_PKT_FAULT, req.call_id,
                        pfc_flags=req.pfc_flags |
                        dcerpc.DCERPC_PFC_FLAG_DID_NOT_EXECUTE,
                        auth_length=0)
        self.assertNotEquals(rep.u.alloc_hint, 0)
        self.assertEquals(rep.u.context_id, 0)
        self.assertEquals(rep.u.cancel_count, 0)
        self.assertEquals(rep.u.flags, 0)
        self.assertEquals(rep.u.status, dcerpc.DCERPC_NCA_S_PROTO_ERROR)
        self.assertEquals(rep.u.reserved, 0)
        self.assertEquals(len(rep.u.error_and_verifier), 0)

        # wait for a disconnect
        rep = self.recv_pdu()
        self.assertIsNone(rep)
        self.assertNotConnected()

    def test_no_auth_presentation_ctx_valid2(self):
        ndr32 = base.transfer_syntax_ndr()

        zero_syntax = misc.ndr_syntax_id()

        tsf1a_list = [zero_syntax, ndr32, ndr32, ndr32]
        ctx1a = dcerpc.ctx_list()
        ctx1a.context_id = 1
        ctx1a.num_transfer_syntaxes = len(tsf1a_list)
        ctx1a.abstract_syntax = samba.dcerpc.mgmt.abstract_syntax()
        ctx1a.transfer_syntaxes = tsf1a_list

        req = self.generate_bind(call_id=0, ctx_list=[ctx1a])
        self.send_pdu(req)
        rep = self.recv_pdu()
        self.verify_pdu(rep, dcerpc.DCERPC_PKT_BIND_ACK, req.call_id,
                        auth_length=0)
        self.assertEquals(rep.u.max_xmit_frag, req.u.max_xmit_frag)
        self.assertEquals(rep.u.max_recv_frag, req.u.max_recv_frag)
        self.assertNotEquals(rep.u.assoc_group_id, req.u.assoc_group_id)
        self.assertEquals(rep.u.secondary_address_size, 4)
        self.assertEquals(rep.u.secondary_address, "%d" % self.tcp_port)
        self.assertEquals(len(rep.u._pad1), 2)
        self.assertEquals(rep.u._pad1, '\0' * 2)
        self.assertEquals(rep.u.num_results, 1)
        self.assertEquals(rep.u.ctx_list[0].result,
                dcerpc.DCERPC_BIND_ACK_RESULT_ACCEPTANCE)
        self.assertEquals(rep.u.ctx_list[0].reason,
                dcerpc.DCERPC_BIND_ACK_REASON_NOT_SPECIFIED)
        self.assertNDRSyntaxEquals(rep.u.ctx_list[0].syntax, ndr32)
        self.assertEquals(rep.u.auth_info, '\0' * 0)

        # With a unknown but wrong syntaxes we get NO protocol error
        # see test_no_auth_presentation_ctx_invalid4
        tsf1b_list = [zero_syntax,samba.dcerpc.epmapper.abstract_syntax()]
        ctx1b = dcerpc.ctx_list()
        ctx1b.context_id = 1
        ctx1b.num_transfer_syntaxes = len(tsf1b_list)
        ctx1b.abstract_syntax = samba.dcerpc.mgmt.abstract_syntax()
        ctx1b.transfer_syntaxes = tsf1b_list

        # Send a alter
        req = self.generate_alter(call_id=1, ctx_list=[ctx1b])
        self.send_pdu(req)
        rep = self.recv_pdu()
        self.verify_pdu(rep, dcerpc.DCERPC_PKT_ALTER_RESP, req.call_id,
                        auth_length=0)
        self.assertEquals(rep.u.max_xmit_frag, req.u.max_xmit_frag)
        self.assertEquals(rep.u.max_recv_frag, req.u.max_recv_frag)
        self.assertNotEquals(rep.u.assoc_group_id, req.u.assoc_group_id)
        self.assertEquals(rep.u.secondary_address_size, 0)
        self.assertEquals(len(rep.u._pad1), 2)
        #self.assertEquals(rep.u._pad1, '\0' * 2)
        self.assertEquals(rep.u.num_results, 1)
        self.assertEquals(rep.u.ctx_list[0].result,
                dcerpc.DCERPC_BIND_ACK_RESULT_PROVIDER_REJECTION)
        self.assertEquals(rep.u.ctx_list[0].reason,
                dcerpc.DCERPC_BIND_ACK_REASON_TRANSFER_SYNTAXES_NOT_SUPPORTED)
        self.assertNDRSyntaxEquals(rep.u.ctx_list[0].syntax, zero_syntax)
        self.assertEquals(rep.u.auth_info, '\0' * 0)

        req = self.generate_request(call_id = 2,
                                    context_id=ctx1a.context_id,
                                    opnum=0xffff,
                                    stub="")
        self.send_pdu(req)
        rep = self.recv_pdu()
        self.verify_pdu(rep, dcerpc.DCERPC_PKT_FAULT, req.call_id,
                        pfc_flags=req.pfc_flags |
                        dcerpc.DCERPC_PFC_FLAG_DID_NOT_EXECUTE,
                        auth_length=0)
        self.assertNotEquals(rep.u.alloc_hint, 0)
        self.assertEquals(rep.u.context_id, ctx1a.context_id)
        self.assertEquals(rep.u.cancel_count, 0)
        self.assertEquals(rep.u.flags, 0)
        self.assertEquals(rep.u.status, dcerpc.DCERPC_NCA_S_OP_RNG_ERROR)
        self.assertEquals(rep.u.reserved, 0)
        self.assertEquals(len(rep.u.error_and_verifier), 0)

    def test_no_auth_presentation_ctx_no_ndr64(self):
        ndr32 = base.transfer_syntax_ndr()
        zero_syntax = misc.ndr_syntax_id()

        tsfZ_list = [zero_syntax]
        ctxZ = dcerpc.ctx_list()
        ctxZ.context_id = 54321
        ctxZ.num_transfer_syntaxes = len(tsfZ_list)
        ctxZ.abstract_syntax = zero_syntax
        ctxZ.transfer_syntaxes = tsfZ_list

        req = self.generate_bind(call_id=0, ctx_list=[ctxZ])
        self.send_pdu(req)
        rep = self.recv_pdu()
        self.verify_pdu(rep, dcerpc.DCERPC_PKT_BIND_ACK, req.call_id,
                        auth_length=0)
        self.assertEquals(rep.u.max_xmit_frag, req.u.max_xmit_frag)
        self.assertEquals(rep.u.max_recv_frag, req.u.max_recv_frag)
        self.assertNotEquals(rep.u.assoc_group_id, req.u.assoc_group_id)
        self.assertEquals(rep.u.secondary_address_size, 4)
        self.assertEquals(rep.u.secondary_address, "%d" % self.tcp_port)
        self.assertEquals(len(rep.u._pad1), 2)
        self.assertEquals(rep.u._pad1, '\0' * 2)
        self.assertEquals(rep.u.num_results, 1)
        self.assertEquals(rep.u.ctx_list[0].result,
                dcerpc.DCERPC_BIND_ACK_RESULT_PROVIDER_REJECTION)
        self.assertEquals(rep.u.ctx_list[0].reason,
                dcerpc.DCERPC_BIND_ACK_REASON_ABSTRACT_SYNTAX_NOT_SUPPORTED)
        self.assertNDRSyntaxEquals(rep.u.ctx_list[0].syntax, zero_syntax)
        self.assertEquals(rep.u.auth_info, '\0' * 0)

        tsf0_list = [ndr32]
        ctx0 = dcerpc.ctx_list()
        ctx0.context_id = 0
        ctx0.num_transfer_syntaxes = len(tsf0_list)
        ctx0.abstract_syntax = samba.dcerpc.mgmt.abstract_syntax()
        ctx0.transfer_syntaxes = tsf0_list

        req = self.generate_alter(call_id=0, ctx_list=[ctx0])
        self.send_pdu(req)
        rep = self.recv_pdu()
        self.verify_pdu(rep, dcerpc.DCERPC_PKT_ALTER_RESP, req.call_id,
                        auth_length=0)
        self.assertEquals(rep.u.max_xmit_frag, req.u.max_xmit_frag)
        self.assertEquals(rep.u.max_recv_frag, req.u.max_recv_frag)
        self.assertNotEquals(rep.u.assoc_group_id, req.u.assoc_group_id)
        self.assertEquals(rep.u.secondary_address_size, 0)
        self.assertEquals(len(rep.u._pad1), 2)
        #self.assertEquals(rep.u._pad1, '\0' * 2)
        self.assertEquals(rep.u.num_results, 1)
        self.assertEquals(rep.u.ctx_list[0].result,
                dcerpc.DCERPC_BIND_ACK_RESULT_ACCEPTANCE)
        self.assertEquals(rep.u.ctx_list[0].reason,
                dcerpc.DCERPC_BIND_ACK_REASON_NOT_SPECIFIED)
        self.assertNDRSyntaxEquals(rep.u.ctx_list[0].syntax, ndr32)
        self.assertEquals(rep.u.auth_info, '\0' * 0)

        req = self.generate_request(call_id = 1,
                                    context_id=ctx0.context_id,
                                    opnum=0,
                                    stub="")
        self.send_pdu(req)
        rep = self.recv_pdu()
        self.verify_pdu(rep, dcerpc.DCERPC_PKT_RESPONSE, req.call_id,
                        auth_length=0)
        self.assertNotEquals(rep.u.alloc_hint, 0)
        self.assertEquals(rep.u.context_id, req.u.context_id)
        self.assertEquals(rep.u.cancel_count, 0)
        self.assertGreaterEqual(len(rep.u.stub_and_verifier), rep.u.alloc_hint)

        tsf1_list = [zero_syntax,ndr32]
        ctx1 = dcerpc.ctx_list()
        ctx1.context_id = 1
        ctx1.num_transfer_syntaxes = len(tsf1_list)
        ctx1.abstract_syntax = samba.dcerpc.mgmt.abstract_syntax()
        ctx1.transfer_syntaxes = tsf1_list

        req = self.generate_alter(call_id=1, ctx_list=[ctx1])
        self.send_pdu(req)
        rep = self.recv_pdu()
        self.verify_pdu(rep, dcerpc.DCERPC_PKT_ALTER_RESP, req.call_id,
                        auth_length=0)
        self.assertEquals(rep.u.max_xmit_frag, req.u.max_xmit_frag)
        self.assertEquals(rep.u.max_recv_frag, req.u.max_recv_frag)
        self.assertNotEquals(rep.u.assoc_group_id, req.u.assoc_group_id)
        self.assertEquals(rep.u.secondary_address_size, 0)
        self.assertEquals(len(rep.u._pad1), 2)
        #self.assertEquals(rep.u._pad1, '\0' * 2)
        self.assertEquals(rep.u.num_results, 1)
        self.assertEquals(rep.u.ctx_list[0].result,
                dcerpc.DCERPC_BIND_ACK_RESULT_ACCEPTANCE)
        self.assertEquals(rep.u.ctx_list[0].reason,
                dcerpc.DCERPC_BIND_ACK_REASON_NOT_SPECIFIED)
        self.assertNDRSyntaxEquals(rep.u.ctx_list[0].syntax, ndr32)
        self.assertEquals(rep.u.auth_info, '\0' * 0)

        req = self.generate_request(call_id = 1,
                                    context_id=ctx1.context_id,
                                    opnum=0,
                                    stub="")
        self.send_pdu(req)
        rep = self.recv_pdu()
        self.verify_pdu(rep, dcerpc.DCERPC_PKT_RESPONSE, req.call_id,
                        auth_length=0)
        self.assertNotEquals(rep.u.alloc_hint, 0)
        self.assertEquals(rep.u.context_id, req.u.context_id)
        self.assertEquals(rep.u.cancel_count, 0)
        self.assertGreaterEqual(len(rep.u.stub_and_verifier), rep.u.alloc_hint)

        tsf2_list = [ndr32,ndr32]
        ctx2 = dcerpc.ctx_list()
        ctx2.context_id = 2
        ctx2.num_transfer_syntaxes = len(tsf2_list)
        ctx2.abstract_syntax = samba.dcerpc.mgmt.abstract_syntax()
        ctx2.transfer_syntaxes = tsf2_list

        req = self.generate_alter(call_id=2, ctx_list=[ctx2])
        self.send_pdu(req)
        rep = self.recv_pdu()
        self.verify_pdu(rep, dcerpc.DCERPC_PKT_ALTER_RESP, req.call_id,
                        auth_length=0)
        self.assertEquals(rep.u.max_xmit_frag, req.u.max_xmit_frag)
        self.assertEquals(rep.u.max_recv_frag, req.u.max_recv_frag)
        self.assertNotEquals(rep.u.assoc_group_id, req.u.assoc_group_id)
        self.assertEquals(rep.u.secondary_address_size, 0)
        self.assertEquals(len(rep.u._pad1), 2)
        #self.assertEquals(rep.u._pad1, '\0' * 2)
        self.assertEquals(rep.u.num_results, 1)
        self.assertEquals(rep.u.ctx_list[0].result,
                dcerpc.DCERPC_BIND_ACK_RESULT_ACCEPTANCE)
        self.assertEquals(rep.u.ctx_list[0].reason,
                dcerpc.DCERPC_BIND_ACK_REASON_NOT_SPECIFIED)
        self.assertNDRSyntaxEquals(rep.u.ctx_list[0].syntax, ndr32)
        self.assertEquals(rep.u.auth_info, '\0' * 0)

        req = self.generate_request(call_id = 1,
                                    context_id=ctx2.context_id,
                                    opnum=0,
                                    stub="")
        self.send_pdu(req)
        rep = self.recv_pdu()
        self.verify_pdu(rep, dcerpc.DCERPC_PKT_RESPONSE, req.call_id,
                        auth_length=0)
        self.assertNotEquals(rep.u.alloc_hint, 0)
        self.assertEquals(rep.u.context_id, req.u.context_id)
        self.assertEquals(rep.u.cancel_count, 0)
        self.assertGreaterEqual(len(rep.u.stub_and_verifier), rep.u.alloc_hint)

        tsf3_list = [ndr32]
        ctx3 = dcerpc.ctx_list()
        ctx3.context_id = 3
        ctx3.num_transfer_syntaxes = len(tsf3_list)
        ctx3.abstract_syntax = samba.dcerpc.mgmt.abstract_syntax()
        ctx3.transfer_syntaxes = tsf3_list

        tsf4_list = [ndr32]
        ctx4 = dcerpc.ctx_list()
        ctx4.context_id = 4
        ctx4.num_transfer_syntaxes = len(tsf4_list)
        ctx4.abstract_syntax = samba.dcerpc.mgmt.abstract_syntax()
        ctx4.transfer_syntaxes = tsf4_list

        req = self.generate_alter(call_id=34, ctx_list=[ctx3,ctx4])
        self.send_pdu(req)
        rep = self.recv_pdu()
        self.verify_pdu(rep, dcerpc.DCERPC_PKT_ALTER_RESP, req.call_id,
                        auth_length=0)
        self.assertEquals(rep.u.max_xmit_frag, req.u.max_xmit_frag)
        self.assertEquals(rep.u.max_recv_frag, req.u.max_recv_frag)
        self.assertNotEquals(rep.u.assoc_group_id, req.u.assoc_group_id)
        self.assertEquals(rep.u.secondary_address_size, 0)
        self.assertEquals(len(rep.u._pad1), 2)
        #self.assertEquals(rep.u._pad1, '\0' * 2)
        self.assertEquals(rep.u.num_results, 2)
        self.assertEquals(rep.u.ctx_list[0].result,
                dcerpc.DCERPC_BIND_ACK_RESULT_ACCEPTANCE)
        self.assertEquals(rep.u.ctx_list[0].reason,
                dcerpc.DCERPC_BIND_ACK_REASON_NOT_SPECIFIED)
        self.assertNDRSyntaxEquals(rep.u.ctx_list[0].syntax, ndr32)
        self.assertEquals(rep.u.ctx_list[1].result,
                dcerpc.DCERPC_BIND_ACK_RESULT_PROVIDER_REJECTION)
        self.assertEquals(rep.u.ctx_list[1].reason,
                dcerpc.DCERPC_BIND_ACK_REASON_TRANSFER_SYNTAXES_NOT_SUPPORTED)
        self.assertNDRSyntaxEquals(rep.u.ctx_list[1].syntax, zero_syntax)
        self.assertEquals(rep.u.auth_info, '\0' * 0)

        req = self.generate_request(call_id = 1,
                                    context_id=ctx3.context_id,
                                    opnum=0,
                                    stub="")
        self.send_pdu(req)
        rep = self.recv_pdu()
        self.verify_pdu(rep, dcerpc.DCERPC_PKT_RESPONSE, req.call_id,
                        auth_length=0)
        self.assertNotEquals(rep.u.alloc_hint, 0)
        self.assertEquals(rep.u.context_id, req.u.context_id)
        self.assertEquals(rep.u.cancel_count, 0)
        self.assertGreaterEqual(len(rep.u.stub_and_verifier), rep.u.alloc_hint)

        req = self.generate_alter(call_id=43, ctx_list=[ctx4,ctx3])
        self.send_pdu(req)
        rep = self.recv_pdu()
        self.verify_pdu(rep, dcerpc.DCERPC_PKT_ALTER_RESP, req.call_id,
                        auth_length=0)
        self.assertEquals(rep.u.max_xmit_frag, req.u.max_xmit_frag)
        self.assertEquals(rep.u.max_recv_frag, req.u.max_recv_frag)
        self.assertNotEquals(rep.u.assoc_group_id, req.u.assoc_group_id)
        self.assertEquals(rep.u.secondary_address_size, 0)
        self.assertEquals(len(rep.u._pad1), 2)
        #self.assertEquals(rep.u._pad1, '\0' * 2)
        self.assertEquals(rep.u.num_results, 2)
        self.assertEquals(rep.u.ctx_list[0].result,
                dcerpc.DCERPC_BIND_ACK_RESULT_ACCEPTANCE)
        self.assertEquals(rep.u.ctx_list[0].reason,
                dcerpc.DCERPC_BIND_ACK_REASON_NOT_SPECIFIED)
        self.assertNDRSyntaxEquals(rep.u.ctx_list[0].syntax, ndr32)
        self.assertEquals(rep.u.ctx_list[1].result,
                dcerpc.DCERPC_BIND_ACK_RESULT_PROVIDER_REJECTION)
        self.assertEquals(rep.u.ctx_list[1].reason,
                dcerpc.DCERPC_BIND_ACK_REASON_TRANSFER_SYNTAXES_NOT_SUPPORTED)
        self.assertNDRSyntaxEquals(rep.u.ctx_list[1].syntax, zero_syntax)
        self.assertEquals(rep.u.auth_info, '\0' * 0)

        req = self.generate_request(call_id = 1,
                                    context_id=ctx4.context_id,
                                    opnum=0,
                                    stub="")
        self.send_pdu(req)
        rep = self.recv_pdu()
        self.verify_pdu(rep, dcerpc.DCERPC_PKT_RESPONSE, req.call_id,
                        auth_length=0)
        self.assertNotEquals(rep.u.alloc_hint, 0)
        self.assertEquals(rep.u.context_id, req.u.context_id)
        self.assertEquals(rep.u.cancel_count, 0)
        self.assertGreaterEqual(len(rep.u.stub_and_verifier), rep.u.alloc_hint)

        req = self.generate_request(call_id = 1,
                                    context_id=ctx3.context_id,
                                    opnum=0,
                                    stub="")
        self.send_pdu(req)
        rep = self.recv_pdu()
        self.verify_pdu(rep, dcerpc.DCERPC_PKT_RESPONSE, req.call_id,
                        auth_length=0)
        self.assertNotEquals(rep.u.alloc_hint, 0)
        self.assertEquals(rep.u.context_id, req.u.context_id)
        self.assertEquals(rep.u.cancel_count, 0)
        self.assertGreaterEqual(len(rep.u.stub_and_verifier), rep.u.alloc_hint)

        req = self.generate_alter(call_id=44, ctx_list=[ctx4,ctx4])
        self.send_pdu(req)
        rep = self.recv_pdu()
        self.verify_pdu(rep, dcerpc.DCERPC_PKT_ALTER_RESP, req.call_id,
                        auth_length=0)
        self.assertEquals(rep.u.max_xmit_frag, req.u.max_xmit_frag)
        self.assertEquals(rep.u.max_recv_frag, req.u.max_recv_frag)
        self.assertNotEquals(rep.u.assoc_group_id, req.u.assoc_group_id)
        self.assertEquals(rep.u.secondary_address_size, 0)
        self.assertEquals(len(rep.u._pad1), 2)
        #self.assertEquals(rep.u._pad1, '\0' * 2)
        self.assertEquals(rep.u.num_results, 2)
        self.assertEquals(rep.u.ctx_list[0].result,
                dcerpc.DCERPC_BIND_ACK_RESULT_ACCEPTANCE)
        self.assertEquals(rep.u.ctx_list[0].reason,
                dcerpc.DCERPC_BIND_ACK_REASON_NOT_SPECIFIED)
        self.assertNDRSyntaxEquals(rep.u.ctx_list[0].syntax, ndr32)
        self.assertEquals(rep.u.ctx_list[1].result,
                dcerpc.DCERPC_BIND_ACK_RESULT_PROVIDER_REJECTION)
        self.assertEquals(rep.u.ctx_list[1].reason,
                dcerpc.DCERPC_BIND_ACK_REASON_TRANSFER_SYNTAXES_NOT_SUPPORTED)
        self.assertNDRSyntaxEquals(rep.u.ctx_list[1].syntax, zero_syntax)
        self.assertEquals(rep.u.auth_info, '\0' * 0)

        req = self.generate_request(call_id = 1,
                                    context_id=ctx4.context_id,
                                    opnum=0,
                                    stub="")
        self.send_pdu(req)
        rep = self.recv_pdu()
        self.verify_pdu(rep, dcerpc.DCERPC_PKT_RESPONSE, req.call_id,
                        auth_length=0)
        self.assertNotEquals(rep.u.alloc_hint, 0)
        self.assertEquals(rep.u.context_id, req.u.context_id)
        self.assertEquals(rep.u.cancel_count, 0)
        self.assertGreaterEqual(len(rep.u.stub_and_verifier), rep.u.alloc_hint)

        req = self.generate_request(call_id = 1,
                                    context_id=ctx3.context_id,
                                    opnum=0,
                                    stub="")
        self.send_pdu(req)
        rep = self.recv_pdu()
        self.verify_pdu(rep, dcerpc.DCERPC_PKT_RESPONSE, req.call_id,
                        auth_length=0)
        self.assertNotEquals(rep.u.alloc_hint, 0)
        self.assertEquals(rep.u.context_id, req.u.context_id)
        self.assertEquals(rep.u.cancel_count, 0)
        self.assertGreaterEqual(len(rep.u.stub_and_verifier), rep.u.alloc_hint)

        tsf5mgmt_list = [ndr32]
        ctx5mgmt = dcerpc.ctx_list()
        ctx5mgmt.context_id = 5
        ctx5mgmt.num_transfer_syntaxes = len(tsf5mgmt_list)
        ctx5mgmt.abstract_syntax = samba.dcerpc.mgmt.abstract_syntax()
        ctx5mgmt.transfer_syntaxes = tsf5mgmt_list

        tsf5epm_list = [ndr32]
        ctx5epm = dcerpc.ctx_list()
        ctx5epm.context_id = 5
        ctx5epm.num_transfer_syntaxes = len(tsf5epm_list)
        ctx5epm.abstract_syntax = samba.dcerpc.mgmt.abstract_syntax()
        ctx5epm.transfer_syntaxes = tsf5epm_list

        req = self.generate_alter(call_id=55, ctx_list=[ctx5mgmt,ctx5epm])
        self.send_pdu(req)
        rep = self.recv_pdu()
        self.verify_pdu(rep, dcerpc.DCERPC_PKT_ALTER_RESP, req.call_id,
                        auth_length=0)
        self.assertEquals(rep.u.max_xmit_frag, req.u.max_xmit_frag)
        self.assertEquals(rep.u.max_recv_frag, req.u.max_recv_frag)
        self.assertNotEquals(rep.u.assoc_group_id, req.u.assoc_group_id)
        self.assertEquals(rep.u.secondary_address_size, 0)
        self.assertEquals(len(rep.u._pad1), 2)
        #self.assertEquals(rep.u._pad1, '\0' * 2)
        self.assertEquals(rep.u.num_results, 2)
        self.assertEquals(rep.u.ctx_list[0].result,
                dcerpc.DCERPC_BIND_ACK_RESULT_ACCEPTANCE)
        self.assertEquals(rep.u.ctx_list[0].reason,
                dcerpc.DCERPC_BIND_ACK_REASON_NOT_SPECIFIED)
        self.assertNDRSyntaxEquals(rep.u.ctx_list[0].syntax, ndr32)
        self.assertEquals(rep.u.ctx_list[1].result,
                dcerpc.DCERPC_BIND_ACK_RESULT_PROVIDER_REJECTION)
        self.assertEquals(rep.u.ctx_list[1].reason,
                dcerpc.DCERPC_BIND_ACK_REASON_TRANSFER_SYNTAXES_NOT_SUPPORTED)
        self.assertNDRSyntaxEquals(rep.u.ctx_list[1].syntax, zero_syntax)
        self.assertEquals(rep.u.auth_info, '\0' * 0)

        req = self.generate_request(call_id = 1,
                                    context_id=ctx5mgmt.context_id,
                                    opnum=0,
                                    stub="")
        self.send_pdu(req)
        rep = self.recv_pdu()
        self.verify_pdu(rep, dcerpc.DCERPC_PKT_RESPONSE, req.call_id,
                        auth_length=0)
        self.assertNotEquals(rep.u.alloc_hint, 0)
        self.assertEquals(rep.u.context_id, req.u.context_id)
        self.assertEquals(rep.u.cancel_count, 0)
        self.assertGreaterEqual(len(rep.u.stub_and_verifier), rep.u.alloc_hint)

        req = self.generate_alter(call_id=55, ctx_list=[ctx5mgmt,ctx5epm])
        self.send_pdu(req)
        rep = self.recv_pdu()
        self.verify_pdu(rep, dcerpc.DCERPC_PKT_ALTER_RESP, req.call_id,
                        auth_length=0)
        self.assertEquals(rep.u.max_xmit_frag, req.u.max_xmit_frag)
        self.assertEquals(rep.u.max_recv_frag, req.u.max_recv_frag)
        self.assertNotEquals(rep.u.assoc_group_id, req.u.assoc_group_id)
        self.assertEquals(rep.u.secondary_address_size, 0)
        self.assertEquals(len(rep.u._pad1), 2)
        #self.assertEquals(rep.u._pad1, '\0' * 2)
        self.assertEquals(rep.u.num_results, 2)
        self.assertEquals(rep.u.ctx_list[0].result,
                dcerpc.DCERPC_BIND_ACK_RESULT_ACCEPTANCE)
        self.assertEquals(rep.u.ctx_list[0].reason,
                dcerpc.DCERPC_BIND_ACK_REASON_NOT_SPECIFIED)
        self.assertNDRSyntaxEquals(rep.u.ctx_list[0].syntax, ndr32)
        self.assertEquals(rep.u.ctx_list[1].result,
                dcerpc.DCERPC_BIND_ACK_RESULT_PROVIDER_REJECTION)
        self.assertEquals(rep.u.ctx_list[1].reason,
                dcerpc.DCERPC_BIND_ACK_REASON_TRANSFER_SYNTAXES_NOT_SUPPORTED)
        self.assertNDRSyntaxEquals(rep.u.ctx_list[1].syntax, zero_syntax)
        self.assertEquals(rep.u.auth_info, '\0' * 0)

        req = self.generate_request(call_id = 1,
                                    context_id=ctx5mgmt.context_id,
                                    opnum=0,
                                    stub="")
        self.send_pdu(req)
        rep = self.recv_pdu()
        self.verify_pdu(rep, dcerpc.DCERPC_PKT_RESPONSE, req.call_id,
                        auth_length=0)
        self.assertNotEquals(rep.u.alloc_hint, 0)
        self.assertEquals(rep.u.context_id, req.u.context_id)
        self.assertEquals(rep.u.cancel_count, 0)
        self.assertGreaterEqual(len(rep.u.stub_and_verifier), rep.u.alloc_hint)

    def test_no_auth_bind_time_none_simple(self):
        features = 0
        btf = base.bind_time_features_syntax(features)

        zero_syntax = misc.ndr_syntax_id()

        tsf1_list = [btf]
        ctx1 = dcerpc.ctx_list()
        ctx1.context_id = 1
        ctx1.num_transfer_syntaxes = len(tsf1_list)
        ctx1.abstract_syntax = zero_syntax
        ctx1.transfer_syntaxes = tsf1_list

        req = self.generate_bind(call_id=0, ctx_list=[ctx1])
        self.send_pdu(req)
        rep = self.recv_pdu()
        self.verify_pdu(rep, dcerpc.DCERPC_PKT_BIND_ACK, req.call_id,
                        auth_length=0)
        self.assertEquals(rep.u.max_xmit_frag, req.u.max_xmit_frag)
        self.assertEquals(rep.u.max_recv_frag, req.u.max_recv_frag)
        self.assertNotEquals(rep.u.assoc_group_id, req.u.assoc_group_id)
        self.assertEquals(rep.u.secondary_address_size, 4)
        self.assertEquals(rep.u.secondary_address, "%d" % self.tcp_port)
        self.assertEquals(len(rep.u._pad1), 2)
        self.assertEquals(rep.u._pad1, '\0' * 2)
        self.assertEquals(rep.u.num_results, 1)
        self.assertEquals(rep.u.ctx_list[0].result,
                dcerpc.DCERPC_BIND_ACK_RESULT_NEGOTIATE_ACK)
        self.assertEquals(rep.u.ctx_list[0].reason, features)
        self.assertNDRSyntaxEquals(rep.u.ctx_list[0].syntax, zero_syntax)
        self.assertEquals(rep.u.auth_info, '\0' * 0)

    def test_no_auth_bind_time_none_ignore_additional(self):
        features1 = 0
        btf1 = base.bind_time_features_syntax(features1)

        features2 =  dcerpc.DCERPC_BIND_TIME_KEEP_CONNECTION_ON_ORPHAN
        features2 |= dcerpc.DCERPC_BIND_TIME_SECURITY_CONTEXT_MULTIPLEXING
        btf2 = base.bind_time_features_syntax(features2)

        zero_syntax = misc.ndr_syntax_id()
        ndr64 = base.transfer_syntax_ndr64()

        tsf1_list = [btf1,btf2,zero_syntax]
        ctx1 = dcerpc.ctx_list()
        ctx1.context_id = 1
        ctx1.num_transfer_syntaxes = len(tsf1_list)
        ctx1.abstract_syntax = ndr64
        ctx1.transfer_syntaxes = tsf1_list

        req = self.generate_bind(call_id=0, ctx_list=[ctx1])
        self.send_pdu(req)
        rep = self.recv_pdu()
        self.verify_pdu(rep, dcerpc.DCERPC_PKT_BIND_ACK, req.call_id,
                        auth_length=0)
        self.assertEquals(rep.u.max_xmit_frag, req.u.max_xmit_frag)
        self.assertEquals(rep.u.max_recv_frag, req.u.max_recv_frag)
        self.assertNotEquals(rep.u.assoc_group_id, req.u.assoc_group_id)
        self.assertEquals(rep.u.secondary_address_size, 4)
        self.assertEquals(rep.u.secondary_address, "%d" % self.tcp_port)
        self.assertEquals(len(rep.u._pad1), 2)
        self.assertEquals(rep.u._pad1, '\0' * 2)
        self.assertEquals(rep.u.num_results, 1)
        self.assertEquals(rep.u.ctx_list[0].result,
                dcerpc.DCERPC_BIND_ACK_RESULT_NEGOTIATE_ACK)
        self.assertEquals(rep.u.ctx_list[0].reason, features1)
        self.assertNDRSyntaxEquals(rep.u.ctx_list[0].syntax, zero_syntax)
        self.assertEquals(rep.u.auth_info, '\0' * 0)

    def test_no_auth_bind_time_only_first(self):
        features1 = dcerpc.DCERPC_BIND_TIME_KEEP_CONNECTION_ON_ORPHAN
        btf1 = base.bind_time_features_syntax(features1)

        features2 = dcerpc.DCERPC_BIND_TIME_SECURITY_CONTEXT_MULTIPLEXING
        btf2 = base.bind_time_features_syntax(features2)

        zero_syntax = misc.ndr_syntax_id()

        tsf1_list = [zero_syntax,btf1,btf2,zero_syntax]
        ctx1 = dcerpc.ctx_list()
        ctx1.context_id = 1
        ctx1.num_transfer_syntaxes = len(tsf1_list)
        ctx1.abstract_syntax = zero_syntax
        ctx1.transfer_syntaxes = tsf1_list

        req = self.generate_bind(call_id=0, ctx_list=[ctx1])
        self.send_pdu(req)
        rep = self.recv_pdu()
        self.verify_pdu(rep, dcerpc.DCERPC_PKT_BIND_ACK, req.call_id,
                        auth_length=0)
        self.assertEquals(rep.u.max_xmit_frag, req.u.max_xmit_frag)
        self.assertEquals(rep.u.max_recv_frag, req.u.max_recv_frag)
        self.assertNotEquals(rep.u.assoc_group_id, req.u.assoc_group_id)
        self.assertEquals(rep.u.secondary_address_size, 4)
        self.assertEquals(rep.u.secondary_address, "%d" % self.tcp_port)
        self.assertEquals(len(rep.u._pad1), 2)
        self.assertEquals(rep.u._pad1, '\0' * 2)
        self.assertEquals(rep.u.num_results, 1)
        self.assertEquals(rep.u.ctx_list[0].result,
                dcerpc.DCERPC_BIND_ACK_RESULT_PROVIDER_REJECTION)
        self.assertEquals(rep.u.ctx_list[0].reason,
                dcerpc.DCERPC_BIND_ACK_REASON_ABSTRACT_SYNTAX_NOT_SUPPORTED)
        self.assertNDRSyntaxEquals(rep.u.ctx_list[0].syntax, zero_syntax)
        self.assertEquals(rep.u.auth_info, '\0' * 0)

    def test_no_auth_bind_time_twice(self):
        features1 = dcerpc.DCERPC_BIND_TIME_KEEP_CONNECTION_ON_ORPHAN
        btf1 = base.bind_time_features_syntax(features1)

        features2 = dcerpc.DCERPC_BIND_TIME_SECURITY_CONTEXT_MULTIPLEXING
        btf2 = base.bind_time_features_syntax(features2)

        zero_syntax = misc.ndr_syntax_id()

        tsf1_list = [btf1]
        ctx1 = dcerpc.ctx_list()
        ctx1.context_id = 1
        ctx1.num_transfer_syntaxes = len(tsf1_list)
        ctx1.abstract_syntax = zero_syntax
        ctx1.transfer_syntaxes = tsf1_list

        tsf2_list = [btf2]
        ctx2 = dcerpc.ctx_list()
        ctx2.context_id = 2
        ctx2.num_transfer_syntaxes = len(tsf2_list)
        ctx2.abstract_syntax = zero_syntax
        ctx2.transfer_syntaxes = tsf2_list

        req = self.generate_bind(call_id=0, ctx_list=[ctx1,ctx2])
        self.send_pdu(req)
        rep = self.recv_pdu()
        self.verify_pdu(rep, dcerpc.DCERPC_PKT_BIND_NAK, req.call_id,
                        auth_length=0)
        self.assertEquals(rep.u.reject_reason,
                dcerpc.DCERPC_BIND_NAK_REASON_NOT_SPECIFIED)
        self.assertEquals(rep.u.num_versions, 1)
        self.assertEquals(rep.u.versions[0].rpc_vers, req.rpc_vers)
        self.assertEquals(rep.u.versions[0].rpc_vers_minor, req.rpc_vers_minor)
        self.assertEquals(len(rep.u._pad), 3)
        self.assertEquals(rep.u._pad, '\0' * 3)

        # wait for a disconnect
        rep = self.recv_pdu()
        self.assertIsNone(rep)
        self.assertNotConnected()

    def test_no_auth_bind_time_keep_on_orphan_simple(self):
        features = dcerpc.DCERPC_BIND_TIME_KEEP_CONNECTION_ON_ORPHAN
        btf = base.bind_time_features_syntax(features)

        zero_syntax = misc.ndr_syntax_id()

        tsf1_list = [btf]
        ctx1 = dcerpc.ctx_list()
        ctx1.context_id = 1
        ctx1.num_transfer_syntaxes = len(tsf1_list)
        ctx1.abstract_syntax = zero_syntax
        ctx1.transfer_syntaxes = tsf1_list

        req = self.generate_bind(call_id=0, ctx_list=[ctx1])
        self.send_pdu(req)
        rep = self.recv_pdu()
        self.verify_pdu(rep, dcerpc.DCERPC_PKT_BIND_ACK, req.call_id,
                        auth_length=0)
        self.assertEquals(rep.u.max_xmit_frag, req.u.max_xmit_frag)
        self.assertEquals(rep.u.max_recv_frag, req.u.max_recv_frag)
        self.assertNotEquals(rep.u.assoc_group_id, req.u.assoc_group_id)
        self.assertEquals(rep.u.secondary_address_size, 4)
        self.assertEquals(rep.u.secondary_address, "%d" % self.tcp_port)
        self.assertEquals(len(rep.u._pad1), 2)
        self.assertEquals(rep.u._pad1, '\0' * 2)
        self.assertEquals(rep.u.num_results, 1)
        self.assertEquals(rep.u.ctx_list[0].result,
                dcerpc.DCERPC_BIND_ACK_RESULT_NEGOTIATE_ACK)
        self.assertEquals(rep.u.ctx_list[0].reason, features)
        self.assertNDRSyntaxEquals(rep.u.ctx_list[0].syntax, zero_syntax)
        self.assertEquals(rep.u.auth_info, '\0' * 0)

    def test_no_auth_bind_time_keep_on_orphan_ignore_additional(self):
        features1 = dcerpc.DCERPC_BIND_TIME_KEEP_CONNECTION_ON_ORPHAN
        btf1 = base.bind_time_features_syntax(features1)

        features2 = dcerpc.DCERPC_BIND_TIME_SECURITY_CONTEXT_MULTIPLEXING
        btf2 = base.bind_time_features_syntax(features2)

        zero_syntax = misc.ndr_syntax_id()
        ndr64 = base.transfer_syntax_ndr64()

        tsf1_list = [btf1,btf2,zero_syntax]
        ctx1 = dcerpc.ctx_list()
        ctx1.context_id = 1
        ctx1.num_transfer_syntaxes = len(tsf1_list)
        ctx1.abstract_syntax = ndr64
        ctx1.transfer_syntaxes = tsf1_list

        req = self.generate_bind(call_id=0, ctx_list=[ctx1])
        self.send_pdu(req)
        rep = self.recv_pdu()
        self.verify_pdu(rep, dcerpc.DCERPC_PKT_BIND_ACK, req.call_id,
                        auth_length=0)
        self.assertEquals(rep.u.max_xmit_frag, req.u.max_xmit_frag)
        self.assertEquals(rep.u.max_recv_frag, req.u.max_recv_frag)
        self.assertNotEquals(rep.u.assoc_group_id, req.u.assoc_group_id)
        self.assertEquals(rep.u.secondary_address_size, 4)
        self.assertEquals(rep.u.secondary_address, "%d" % self.tcp_port)
        self.assertEquals(len(rep.u._pad1), 2)
        self.assertEquals(rep.u._pad1, '\0' * 2)
        self.assertEquals(rep.u.num_results, 1)
        self.assertEquals(rep.u.ctx_list[0].result,
                dcerpc.DCERPC_BIND_ACK_RESULT_NEGOTIATE_ACK)
        self.assertEquals(rep.u.ctx_list[0].reason, features1)
        self.assertNDRSyntaxEquals(rep.u.ctx_list[0].syntax, zero_syntax)
        self.assertEquals(rep.u.auth_info, '\0' * 0)

    def _test_auth_type_level_bind_nak(self, auth_type, auth_level, creds=None,
                                   reason=dcerpc.DCERPC_BIND_NAK_REASON_INVALID_AUTH_TYPE):
        ndr32 = base.transfer_syntax_ndr()

        tsf1_list = [ndr32]
        ctx1 = dcerpc.ctx_list()
        ctx1.context_id = 1
        ctx1.num_transfer_syntaxes = len(tsf1_list)
        ctx1.abstract_syntax = samba.dcerpc.mgmt.abstract_syntax()
        ctx1.transfer_syntaxes = tsf1_list
        ctx_list = [ctx1]

        auth_context_id = 0

        if creds is not None:
            # We always start with DCERPC_AUTH_LEVEL_INTEGRITY
            auth_context = self.get_auth_context_creds(creds,
                                auth_type=auth_type,
                                auth_level=auth_level,
                                auth_context_id=auth_context_id,
                                g_auth_level=dcerpc.DCERPC_AUTH_LEVEL_INTEGRITY)
            from_server = ""
            (finished, to_server) = auth_context["gensec"].update(from_server)
            self.assertFalse(finished)

            auth_info = self.generate_auth(auth_type=auth_context["auth_type"],
                                           auth_level=auth_context["auth_level"],
                                           auth_context_id=auth_context["auth_context_id"],
                                           auth_blob=to_server)
        else:
            to_server = "none"
            auth_info = self.generate_auth(auth_type=auth_type,
                                           auth_level=auth_level,
                                           auth_context_id=auth_context_id,
                                           auth_blob=to_server)

        req = self.generate_bind(call_id=0,
                                 ctx_list=ctx_list,
                                 auth_info=auth_info)
        self.send_pdu(req)
        rep = self.recv_pdu()
        self.verify_pdu(rep, dcerpc.DCERPC_PKT_BIND_NAK, req.call_id,
                        auth_length=0)
        self.assertEquals(rep.u.reject_reason, reason)
        self.assertEquals(rep.u.num_versions, 1)
        self.assertEquals(rep.u.versions[0].rpc_vers, req.rpc_vers)
        self.assertEquals(rep.u.versions[0].rpc_vers_minor, req.rpc_vers_minor)
        self.assertEquals(len(rep.u._pad), 3)
        self.assertEquals(rep.u._pad, '\0' * 3)

        # wait for a disconnect
        rep = self.recv_pdu()
        self.assertIsNone(rep)
        self.assertNotConnected()

    def _test_auth_none_level_bind(self, auth_level,
                                   reason=dcerpc.DCERPC_BIND_NAK_REASON_INVALID_AUTH_TYPE):
        return self._test_auth_type_level_bind_nak(auth_type=dcerpc.DCERPC_AUTH_LEVEL_NONE,
                                               auth_level=auth_level, reason=reason)

    def test_auth_none_none_bind(self):
        return self._test_auth_none_level_bind(dcerpc.DCERPC_AUTH_LEVEL_NONE,
                            reason=dcerpc.DCERPC_BIND_NAK_REASON_NOT_SPECIFIED)

    def test_auth_none_connect_bind(self):
        return self._test_auth_none_level_bind(dcerpc.DCERPC_AUTH_LEVEL_CONNECT)

    def test_auth_none_call_bind(self):
        return self._test_auth_none_level_bind(dcerpc.DCERPC_AUTH_LEVEL_CALL)

    def test_auth_none_packet_bind(self):
        return self._test_auth_none_level_bind(dcerpc.DCERPC_AUTH_LEVEL_PACKET)

    def test_auth_none_integrity_bind(self):
        return self._test_auth_none_level_bind(dcerpc.DCERPC_AUTH_LEVEL_INTEGRITY)

    def test_auth_none_privacy_bind(self):
        return self._test_auth_none_level_bind(dcerpc.DCERPC_AUTH_LEVEL_PRIVACY)

    def test_auth_none_0_bind(self):
        return self._test_auth_none_level_bind(0,
                            reason=dcerpc.DCERPC_BIND_NAK_REASON_NOT_SPECIFIED)

    def test_auth_none_7_bind(self):
        return self._test_auth_none_level_bind(7,
                            reason=dcerpc.DCERPC_BIND_NAK_REASON_NOT_SPECIFIED)

    def test_auth_none_255_bind(self):
        return self._test_auth_none_level_bind(255,
                            reason=dcerpc.DCERPC_BIND_NAK_REASON_NOT_SPECIFIED)

    def _test_auth_none_level_request(self, auth_level):
        ndr32 = base.transfer_syntax_ndr()

        tsf1_list = [ndr32]
        ctx1 = dcerpc.ctx_list()
        ctx1.context_id = 1
        ctx1.num_transfer_syntaxes = len(tsf1_list)
        ctx1.abstract_syntax = samba.dcerpc.mgmt.abstract_syntax()
        ctx1.transfer_syntaxes = tsf1_list
        ctx_list = [ctx1]

        auth_type = dcerpc.DCERPC_AUTH_TYPE_NONE
        auth_context_id = 0

        req = self.generate_bind(call_id=0,
                                 ctx_list=ctx_list)

        self.send_pdu(req)
        rep = self.recv_pdu()
        self.verify_pdu(rep, dcerpc.DCERPC_PKT_BIND_ACK, req.call_id)
        self.assertEquals(rep.u.max_xmit_frag, req.u.max_xmit_frag)
        self.assertEquals(rep.u.max_recv_frag, req.u.max_recv_frag)
        self.assertNotEquals(rep.u.assoc_group_id, req.u.assoc_group_id)
        self.assertEquals(rep.u.secondary_address_size, 4)
        self.assertEquals(rep.u.secondary_address, "%d" % self.tcp_port)
        self.assertEquals(len(rep.u._pad1), 2)
        self.assertEquals(rep.u._pad1, '\0' * 2)
        self.assertEquals(rep.u.num_results, 1)
        self.assertEquals(rep.u.ctx_list[0].result,
                dcerpc.DCERPC_BIND_ACK_RESULT_ACCEPTANCE)
        self.assertEquals(rep.u.ctx_list[0].reason,
                dcerpc.DCERPC_BIND_ACK_REASON_NOT_SPECIFIED)
        self.assertNDRSyntaxEquals(rep.u.ctx_list[0].syntax, ndr32)
        self.assertEquals(len(rep.u.auth_info), 0)

        # And now try a request without auth_info
        req = self.generate_request(call_id = 2,
                                    context_id=ctx1.context_id,
                                    opnum=0,
                                    stub="")
        self.send_pdu(req)
        rep = self.recv_pdu()
        self.verify_pdu(rep, dcerpc.DCERPC_PKT_RESPONSE, req.call_id,
                        auth_length=0)
        self.assertNotEquals(rep.u.alloc_hint, 0)
        self.assertEquals(rep.u.context_id, req.u.context_id)
        self.assertEquals(rep.u.cancel_count, 0)
        self.assertGreaterEqual(len(rep.u.stub_and_verifier), rep.u.alloc_hint)

        auth_info = self.generate_auth(auth_type=auth_type,
                                       auth_level=auth_level,
                                       auth_context_id=auth_context_id,
                                       auth_blob="none")

        req = self.generate_request(call_id = 3,
                                    context_id=ctx1.context_id,
                                    opnum=0,
                                    stub="",
                                    auth_info=auth_info)
        self.send_pdu(req)
        rep = self.recv_pdu()
        # We get a fault back
        self.verify_pdu(rep, dcerpc.DCERPC_PKT_FAULT, req.call_id,
                        auth_length=0)
        self.assertNotEquals(rep.u.alloc_hint, 0)
        self.assertEquals(rep.u.context_id, req.u.context_id)
        self.assertEquals(rep.u.cancel_count, 0)
        self.assertEquals(rep.u.flags, 0)
        self.assertEquals(rep.u.status, dcerpc.DCERPC_FAULT_ACCESS_DENIED)
        self.assertEquals(rep.u.reserved, 0)
        self.assertEquals(len(rep.u.error_and_verifier), 0)

        # wait for a disconnect
        rep = self.recv_pdu()
        self.assertIsNone(rep)
        self.assertNotConnected()

    def test_auth_none_none_request(self):
        return self._test_auth_none_level_request(dcerpc.DCERPC_AUTH_LEVEL_NONE)

    def test_auth_none_connect_request(self):
        return self._test_auth_none_level_request(dcerpc.DCERPC_AUTH_LEVEL_CONNECT)

    def test_auth_none_call_request(self):
        return self._test_auth_none_level_request(dcerpc.DCERPC_AUTH_LEVEL_CALL)

    def _test_neg_xmit_check_values(self,
                                    req_xmit=None,
                                    req_recv=None,
                                    rep_both=None,
                                    alter_xmit=None,
                                    alter_recv=None):
        ndr32 = base.transfer_syntax_ndr()

        tsf1_list = [ndr32]
        ctx1 = dcerpc.ctx_list()
        ctx1.context_id = 1
        ctx1.num_transfer_syntaxes = len(tsf1_list)
        ctx1.abstract_syntax = samba.dcerpc.mgmt.abstract_syntax()
        ctx1.transfer_syntaxes = tsf1_list

        req = self.generate_bind(call_id=0,
                                 max_xmit_frag=req_xmit,
                                 max_recv_frag=req_recv,
                                 ctx_list=[ctx1])
        self.send_pdu(req)
        rep = self.recv_pdu()
        self.verify_pdu(rep, dcerpc.DCERPC_PKT_BIND_ACK, req.call_id,
                        auth_length=0)
        self.assertEquals(rep.u.max_xmit_frag, rep_both)
        self.assertEquals(rep.u.max_recv_frag, rep_both)
        self.assertNotEquals(rep.u.assoc_group_id, req.u.assoc_group_id)
        self.assertEquals(rep.u.secondary_address_size, 4)
        self.assertEquals(rep.u.secondary_address, "%d" % self.tcp_port)
        self.assertEquals(len(rep.u._pad1), 2)
        self.assertEquals(rep.u._pad1, '\0' * 2)
        self.assertEquals(rep.u.num_results, 1)
        self.assertEquals(rep.u.ctx_list[0].result,
                dcerpc.DCERPC_BIND_ACK_RESULT_ACCEPTANCE)
        self.assertEquals(rep.u.ctx_list[0].reason,
                dcerpc.DCERPC_BIND_ACK_REASON_NOT_SPECIFIED)
        self.assertNDRSyntaxEquals(rep.u.ctx_list[0].syntax, ndr32)
        self.assertEquals(rep.u.auth_info, '\0' * 0)

        assoc_group_id = rep.u.assoc_group_id
        if alter_xmit is None:
            alter_xmit = rep_both - 8
        if alter_recv is None:
            alter_recv = rep_both - 8

        # max_{xmit,recv}_frag and assoc_group_id are completely
        # ignored in alter_context requests
        req = self.generate_alter(call_id=1,
                                  max_xmit_frag=alter_xmit,
                                  max_recv_frag=alter_recv,
                                  assoc_group_id=0xffffffff-rep.u.assoc_group_id,
                                  ctx_list=[ctx1])
        self.send_pdu(req)
        rep = self.recv_pdu()
        self.verify_pdu(rep, dcerpc.DCERPC_PKT_ALTER_RESP, req.call_id,
                        auth_length=0)
        self.assertEquals(rep.u.max_xmit_frag, rep_both)
        self.assertEquals(rep.u.max_recv_frag, rep_both)
        self.assertEquals(rep.u.assoc_group_id, rep.u.assoc_group_id)
        self.assertEquals(rep.u.secondary_address_size, 0)
        self.assertEquals(len(rep.u._pad1), 2)
        #self.assertEquals(rep.u._pad1, '\0' * 2)
        self.assertEquals(rep.u.num_results, 1)
        self.assertEquals(rep.u.ctx_list[0].result,
                dcerpc.DCERPC_BIND_ACK_RESULT_ACCEPTANCE)
        self.assertEquals(rep.u.ctx_list[0].reason,
                dcerpc.DCERPC_BIND_ACK_REASON_NOT_SPECIFIED)
        self.assertNDRSyntaxEquals(rep.u.ctx_list[0].syntax, ndr32)
        self.assertEquals(rep.u.auth_info, '\0' * 0)

        chunk_size = rep_both - dcerpc.DCERPC_REQUEST_LENGTH
        req = self.generate_request(call_id = 2,
                                    context_id=ctx1.context_id,
                                    opnum=0,
                                    alloc_hint=0xffffffff,
                                    stub="\00" * chunk_size)
        self.send_pdu(req,ndr_print=True,hexdump=True)
        rep = self.recv_pdu(ndr_print=True,hexdump=True)
        self.verify_pdu(rep, dcerpc.DCERPC_PKT_RESPONSE, req.call_id,
                        auth_length=0)
        self.assertNotEquals(rep.u.alloc_hint, 0)
        self.assertEquals(rep.u.context_id, req.u.context_id)
        self.assertEquals(rep.u.cancel_count, 0)
        self.assertGreaterEqual(len(rep.u.stub_and_verifier), rep.u.alloc_hint)

        chunk_size = 5840 - dcerpc.DCERPC_REQUEST_LENGTH
        req = self.generate_request(call_id = 2,
                                    context_id=ctx1.context_id,
                                    opnum=0,
                                    alloc_hint=0xffffffff,
                                    stub="\00" * chunk_size)
        self.send_pdu(req)
        rep = self.recv_pdu()
        self.verify_pdu(rep, dcerpc.DCERPC_PKT_RESPONSE, req.call_id,
                        auth_length=0)
        self.assertNotEquals(rep.u.alloc_hint, 0)
        self.assertEquals(rep.u.context_id, req.u.context_id)
        self.assertEquals(rep.u.cancel_count, 0)
        self.assertGreaterEqual(len(rep.u.stub_and_verifier), rep.u.alloc_hint)

        chunk_size += 1
        req = self.generate_request(call_id = 3,
                                    context_id=ctx1.context_id,
                                    opnum=0,
                                    alloc_hint=0xffffffff,
                                    stub="\00" * chunk_size)
        self.send_pdu(req)
        rep = self.recv_pdu()
        # We get a fault
        self.verify_pdu(rep, dcerpc.DCERPC_PKT_FAULT, req.call_id,
                        auth_length=0)
        self.assertNotEquals(rep.u.alloc_hint, 0)
        self.assertEquals(rep.u.context_id, 0)
        self.assertEquals(rep.u.cancel_count, 0)
        self.assertEquals(rep.u.flags, 0)
        self.assertEquals(rep.u.status, dcerpc.DCERPC_NCA_S_PROTO_ERROR)
        self.assertEquals(rep.u.reserved, 0)
        self.assertEquals(len(rep.u.error_and_verifier), 0)

        # wait for a disconnect
        rep = self.recv_pdu()
        self.assertIsNone(rep)
        self.assertNotConnected()

    def test_neg_xmit_ffff_ffff(self):
        return self._test_neg_xmit_check_values(req_xmit=0xffff,
                                                req_recv=0xffff,
                                                rep_both=5840)

    def test_neg_xmit_0_ffff(self):
        return self._test_neg_xmit_check_values(req_xmit=0,
                                                req_recv=0xffff,
                                                rep_both=2048,
                                                alter_xmit=0xffff,
                                                alter_recv=0xffff)

    def test_neg_xmit_ffff_0(self):
        return self._test_neg_xmit_check_values(req_xmit=0xffff,
                                                req_recv=0,
                                                rep_both=2048)

    def test_neg_xmit_0_0(self):
        return self._test_neg_xmit_check_values(req_xmit=0,
                                                req_recv=0,
                                                rep_both=2048,
                                                alter_xmit=0xffff,
                                                alter_recv=0xffff)

    def test_neg_xmit_3199_0(self):
        return self._test_neg_xmit_check_values(req_xmit=3199,
                                                req_recv=0,
                                                rep_both=2048)
    def test_neg_xmit_0_3199(self):
        return self._test_neg_xmit_check_values(req_xmit=0,
                                                req_recv=3199,
                                                rep_both=2048)

    def test_neg_xmit_3199_ffff(self):
        return self._test_neg_xmit_check_values(req_xmit=3199,
                                                req_recv=0xffff,
                                                rep_both=3192)
    def test_neg_xmit_ffff_3199(self):
        return self._test_neg_xmit_check_values(req_xmit=0xffff,
                                                req_recv=3199,
                                                rep_both=3192)

    def test_alloc_hint(self):
        ndr32 = base.transfer_syntax_ndr()

        tsf1_list = [ndr32]
        ctx = dcerpc.ctx_list()
        ctx.context_id = 0
        ctx.num_transfer_syntaxes = len(tsf1_list)
        ctx.abstract_syntax = samba.dcerpc.mgmt.abstract_syntax()
        ctx.transfer_syntaxes = tsf1_list

        req = self.generate_bind(call_id=0,
                                 ctx_list=[ctx])
        self.send_pdu(req)
        rep = self.recv_pdu()
        self.verify_pdu(rep, dcerpc.DCERPC_PKT_BIND_ACK, req.call_id,
                        auth_length=0)
        self.assertEquals(rep.u.max_xmit_frag, req.u.max_xmit_frag)
        self.assertEquals(rep.u.max_recv_frag, req.u.max_recv_frag)
        self.assertNotEquals(rep.u.assoc_group_id, req.u.assoc_group_id)
        self.assertEquals(rep.u.secondary_address_size, 4)
        self.assertEquals(rep.u.secondary_address, "%d" % self.tcp_port)
        self.assertEquals(len(rep.u._pad1), 2)
        self.assertEquals(rep.u._pad1, '\0' * 2)
        self.assertEquals(rep.u.num_results, 1)
        self.assertEquals(rep.u.ctx_list[0].result,
                dcerpc.DCERPC_BIND_ACK_RESULT_ACCEPTANCE)
        self.assertEquals(rep.u.ctx_list[0].reason,
                dcerpc.DCERPC_BIND_ACK_REASON_NOT_SPECIFIED)
        self.assertNDRSyntaxEquals(rep.u.ctx_list[0].syntax, ndr32)
        self.assertEquals(rep.u.auth_info, '\0' * 0)

        # And now try a request without auth_info
        req = self.generate_request(call_id = 2,
                                    context_id=ctx.context_id,
                                    opnum=0,
                                    alloc_hint=0xffffffff,
                                    stub="")
        self.send_pdu(req)
        rep = self.recv_pdu()
        self.verify_pdu(rep, dcerpc.DCERPC_PKT_RESPONSE, req.call_id,
                        auth_length=0)
        self.assertNotEquals(rep.u.alloc_hint, 0)
        self.assertEquals(rep.u.context_id, req.u.context_id)
        self.assertEquals(rep.u.cancel_count, 0)
        self.assertGreaterEqual(len(rep.u.stub_and_verifier), rep.u.alloc_hint)

        req = self.generate_request(call_id = 3,
                                    context_id=ctx.context_id,
                                    opnum=1,
                                    alloc_hint=0xffffffff,
                                    stub="\04\00\00\00\00\00\00\00")
        self.send_pdu(req)
        rep = self.recv_pdu()
        self.verify_pdu(rep, dcerpc.DCERPC_PKT_RESPONSE, req.call_id,
                        auth_length=0)
        self.assertNotEquals(rep.u.alloc_hint, 0)
        self.assertEquals(rep.u.context_id, req.u.context_id)
        self.assertEquals(rep.u.cancel_count, 0)
        self.assertGreaterEqual(len(rep.u.stub_and_verifier), rep.u.alloc_hint)

        req = self.generate_request(call_id = 4,
                                    context_id=ctx.context_id,
                                    opnum=1,
                                    alloc_hint=1,
                                    stub="\04\00\00\00\00\00\00\00")
        self.send_pdu(req)
        rep = self.recv_pdu()
        self.verify_pdu(rep, dcerpc.DCERPC_PKT_RESPONSE, req.call_id,
                        auth_length=0)
        self.assertNotEquals(rep.u.alloc_hint, 0)
        self.assertEquals(rep.u.context_id, req.u.context_id)
        self.assertEquals(rep.u.cancel_count, 0)
        self.assertGreaterEqual(len(rep.u.stub_and_verifier), rep.u.alloc_hint)

    def _get_netlogon_ctx(self):
        abstract = samba.dcerpc.netlogon.abstract_syntax()
        ndr32 = base.transfer_syntax_ndr()

        (ctx, ack) = self.prepare_presentation(abstract, ndr32, context_id=0,
                                               epmap=True, return_ack=True)

        server = '\\\\' + self.target_hostname
        server_utf16 = unicode(server, 'utf-8').encode('utf-16-le')
        computer = 'UNKNOWNCOMPUTER'
        computer_utf16 = unicode(computer, 'utf-8').encode('utf-16-le')

        real_stub  = struct.pack('<IIII', 0x00200000,
                                 len(server)+1, 0, len(server)+1)
        real_stub += server_utf16 + '\x00\x00'
        mod_len = len(real_stub) % 4
        if mod_len != 0:
            real_stub += '\x00' * (4 - mod_len)
        real_stub += struct.pack('<III',
                                 len(computer)+1, 0, len(computer)+1)
        real_stub += computer_utf16 + '\x00\x00'
        real_stub += '\x11\x22\x33\x44\x55\x66\x77\x88'

        return (ctx, ack, real_stub)

    def _test_fragmented_requests(self, remaining=None, alloc_hint=None,
                                  fault_first=None, fault_last=None):
        (ctx, rep, real_stub) = self._get_netlogon_ctx()

        chunk = rep.u.max_recv_frag - dcerpc.DCERPC_REQUEST_LENGTH

        total = 0
        first = True
        while remaining > 0:
            thistime = min(remaining, chunk)
            remaining -= thistime
            total += thistime

            pfc_flags = 0
            if first:
                pfc_flags |= dcerpc.DCERPC_PFC_FLAG_FIRST
                first = False
                stub = real_stub + '\x00' * (thistime - len(real_stub))
            else:
                stub = "\x00" * thistime

            if remaining == 0:
                pfc_flags |= dcerpc.DCERPC_PFC_FLAG_LAST

            # And now try a request without auth_info
            # netr_ServerReqChallenge()
            req = self.generate_request(call_id = 2,
                                        pfc_flags=pfc_flags,
                                        context_id=ctx.context_id,
                                        opnum=4,
                                        alloc_hint=alloc_hint,
                                        stub=stub)
            if alloc_hint >= thistime:
                alloc_hint -= thistime
            else:
                alloc_hint = 0
            self.send_pdu(req,hexdump=False)
            if fault_first is not None:
                rep = self.recv_pdu()
                # We get a fault back
                self.verify_pdu(rep, dcerpc.DCERPC_PKT_FAULT, req.call_id,
                                auth_length=0)
                self.assertNotEquals(rep.u.alloc_hint, 0)
                self.assertEquals(rep.u.context_id, req.u.context_id)
                self.assertEquals(rep.u.cancel_count, 0)
                self.assertEquals(rep.u.flags, 0)
                self.assertEquals(rep.u.status, fault_first)
                self.assertEquals(rep.u.reserved, 0)
                self.assertEquals(len(rep.u.error_and_verifier), 0)

                # wait for a disconnect
                rep = self.recv_pdu()
                self.assertIsNone(rep)
                self.assertNotConnected()
                return
            if remaining == 0:
                break
            if total >= 0x400000 and fault_last is not None:
                rep = self.recv_pdu()
                # We get a fault back
                self.verify_pdu(rep, dcerpc.DCERPC_PKT_FAULT, req.call_id,
                                auth_length=0)
                self.assertNotEquals(rep.u.alloc_hint, 0)
                self.assertEquals(rep.u.context_id, req.u.context_id)
                self.assertEquals(rep.u.cancel_count, 0)
                self.assertEquals(rep.u.flags, 0)
                self.assertEquals(rep.u.status, fault_last)
                self.assertEquals(rep.u.reserved, 0)
                self.assertEquals(len(rep.u.error_and_verifier), 0)

                # wait for a disconnect
                rep = self.recv_pdu()
                self.assertIsNone(rep)
                self.assertNotConnected()
                return
            rep = self.recv_pdu(timeout=0.01)
            self.assertIsNone(rep)
            self.assertIsConnected()

        if total >= 0x400000 and fault_last is not None:
            rep = self.recv_pdu()
            # We get a fault back
            self.verify_pdu(rep, dcerpc.DCERPC_PKT_FAULT, req.call_id,
                            auth_length=0)
            self.assertNotEquals(rep.u.alloc_hint, 0)
            self.assertEquals(rep.u.context_id, req.u.context_id)
            self.assertEquals(rep.u.cancel_count, 0)
            self.assertEquals(rep.u.flags, 0)
            self.assertEquals(rep.u.status, fault_last)
            self.assertEquals(rep.u.reserved, 0)
            self.assertEquals(len(rep.u.error_and_verifier), 0)

            # wait for a disconnect
            rep = self.recv_pdu()
            self.assertIsNone(rep)
            self.assertNotConnected()
            return
        rep = self.recv_pdu()
        self.verify_pdu(rep, dcerpc.DCERPC_PKT_RESPONSE, req.call_id,
                        auth_length=0)
        self.assertNotEquals(rep.u.alloc_hint, 0)
        self.assertEquals(rep.u.context_id, req.u.context_id)
        self.assertEquals(rep.u.cancel_count, 0)
        self.assertGreaterEqual(len(rep.u.stub_and_verifier), rep.u.alloc_hint)

        self.assertEquals(len(rep.u.stub_and_verifier), 12)
        status = struct.unpack_from("<I", rep.u.stub_and_verifier, len(rep.u.stub_and_verifier) - 4)
        self.assertEquals(status[0], 0)

    def test_fragmented_requests01(self):
        return self._test_fragmented_requests(remaining=0x400000,
                                              alloc_hint=0x400000)

    def test_fragmented_requests02(self):
        return self._test_fragmented_requests(remaining=0x400000,
                                              alloc_hint=0x100000)

    def test_fragmented_requests03(self):
        return self._test_fragmented_requests(remaining=0x400000,
                                              alloc_hint=0)

    def test_fragmented_requests04(self):
        return self._test_fragmented_requests(remaining=0x400000,
                                              alloc_hint=0x400001,
                                              fault_first=dcerpc.DCERPC_FAULT_ACCESS_DENIED)

    def test_fragmented_requests05(self):
        return self._test_fragmented_requests(remaining=0x500001,
                                              alloc_hint=0,
                                              fault_last=dcerpc.DCERPC_FAULT_ACCESS_DENIED)

    def _test_same_requests(self, pfc_flags, fault_1st=False, fault_2nd=False):
        (ctx, rep, real_stub) = self._get_netlogon_ctx()

        # netr_ServerReqChallenge with given flags
        req = self.generate_request(call_id = 2,
                                    pfc_flags=pfc_flags,
                                    context_id=ctx.context_id,
                                    opnum=4,
                                    stub=real_stub)
        self.send_pdu(req)
        if fault_1st:
            rep = self.recv_pdu()
            # We get a fault back
            self.verify_pdu(rep, dcerpc.DCERPC_PKT_FAULT, req.call_id,
                            auth_length=0)
            self.assertNotEquals(rep.u.alloc_hint, 0)
            self.assertEquals(rep.u.context_id, 0)
            self.assertEquals(rep.u.cancel_count, 0)
            self.assertEquals(rep.u.flags, 0)
            self.assertEquals(rep.u.status, dcerpc.DCERPC_NCA_S_PROTO_ERROR)
            self.assertEquals(rep.u.reserved, 0)
            self.assertEquals(len(rep.u.error_and_verifier), 0)

            # wait for a disconnect
            rep = self.recv_pdu()
            self.assertIsNone(rep)
            self.assertNotConnected()
            return
        rep = self.recv_pdu(timeout=0.1)
        self.assertIsNone(rep)
        self.assertIsConnected()

        # netr_ServerReqChallenge without DCERPC_PFC_FLAG_LAST
        # with the same call_id
        req = self.generate_request(call_id = 2,
                                    pfc_flags=pfc_flags,
                                    context_id=ctx.context_id,
                                    opnum=4,
                                    stub=real_stub)
        self.send_pdu(req)
        if fault_2nd:
            rep = self.recv_pdu()
            # We get a fault back
            self.verify_pdu(rep, dcerpc.DCERPC_PKT_FAULT, req.call_id,
                            auth_length=0)
            self.assertNotEquals(rep.u.alloc_hint, 0)
            self.assertEquals(rep.u.context_id, req.u.context_id)
            self.assertEquals(rep.u.cancel_count, 0)
            self.assertEquals(rep.u.flags, 0)
            self.assertEquals(rep.u.status, dcerpc.DCERPC_NCA_S_PROTO_ERROR)
            self.assertEquals(rep.u.reserved, 0)
            self.assertEquals(len(rep.u.error_and_verifier), 0)

            # wait for a disconnect
            rep = self.recv_pdu()
            self.assertIsNone(rep)
            self.assertNotConnected()
            return

        rep = self.recv_pdu(timeout=0.1)
        self.assertIsNone(rep)
        self.assertIsConnected()

    def test_first_only_requests(self):
        return self._test_same_requests(pfc_flags=dcerpc.DCERPC_PFC_FLAG_FIRST,
                                        fault_2nd=True)

    def test_none_only_requests(self):
        return self._test_same_requests(pfc_flags=0, fault_1st=True)

    def test_last_only_requests(self):
        return self._test_same_requests(pfc_flags=dcerpc.DCERPC_PFC_FLAG_LAST,
                                        fault_1st=True)

    def test_first_maybe_requests(self):
        return self._test_same_requests(pfc_flags=dcerpc.DCERPC_PFC_FLAG_FIRST |
                                        dcerpc.DCERPC_PFC_FLAG_MAYBE,
                                        fault_2nd=True)

    def test_first_didnot_requests(self):
        return self._test_same_requests(pfc_flags=dcerpc.DCERPC_PFC_FLAG_FIRST |
                                        dcerpc.DCERPC_PFC_FLAG_DID_NOT_EXECUTE,
                                        fault_2nd=True)

    def test_first_cmpx_requests(self):
        return self._test_same_requests(pfc_flags=dcerpc.DCERPC_PFC_FLAG_FIRST |
                                        dcerpc.DCERPC_PFC_FLAG_CONC_MPX,
                                        fault_2nd=True)

    def test_first_08_requests(self):
        return self._test_same_requests(pfc_flags=dcerpc.DCERPC_PFC_FLAG_FIRST |
                                        0x08,
                                        fault_2nd=True)

    def test_first_cancel_requests(self):
        (ctx, rep, real_stub) = self._get_netlogon_ctx()

        # netr_ServerReqChallenge with given flags
        req = self.generate_request(call_id = 2,
                                    pfc_flags=dcerpc.DCERPC_PFC_FLAG_FIRST |
                                              dcerpc.DCERPC_PFC_FLAG_PENDING_CANCEL,
                                    context_id=ctx.context_id,
                                    opnum=4,
                                    stub=real_stub)
        self.send_pdu(req)
        rep = self.recv_pdu()
        # We get a fault back
        self.verify_pdu(rep, dcerpc.DCERPC_PKT_FAULT, req.call_id,
                        pfc_flags=dcerpc.DCERPC_PFC_FLAG_FIRST |
                        dcerpc.DCERPC_PFC_FLAG_LAST |
                        dcerpc.DCERPC_PFC_FLAG_DID_NOT_EXECUTE,
                        auth_length=0)
        self.assertNotEquals(rep.u.alloc_hint, 0)
        self.assertEquals(rep.u.context_id, 0)
        self.assertEquals(rep.u.cancel_count, 0)
        self.assertEquals(rep.u.flags, 0)
        self.assertEquals(rep.u.status, dcerpc.DCERPC_FAULT_NO_CALL_ACTIVE)
        self.assertEquals(rep.u.reserved, 0)
        self.assertEquals(len(rep.u.error_and_verifier), 0)

        # wait for a disconnect
        rep = self.recv_pdu()
        self.assertIsNone(rep)
        self.assertNotConnected()

    def test_2nd_cancel_requests(self):
        (ctx, rep, real_stub) = self._get_netlogon_ctx()

        # netr_ServerReqChallenge with given flags
        req = self.generate_request(call_id = 2,
                                    pfc_flags=dcerpc.DCERPC_PFC_FLAG_FIRST,
                                    context_id=ctx.context_id,
                                    opnum=4,
                                    stub=real_stub)
        self.send_pdu(req)
        rep = self.recv_pdu(timeout=0.1)
        self.assertIsNone(rep)
        self.assertIsConnected()

        # netr_ServerReqChallenge with given flags
        req = self.generate_request(call_id = 2,
                                    pfc_flags=dcerpc.DCERPC_PFC_FLAG_PENDING_CANCEL,
                                    context_id=ctx.context_id,
                                    opnum=4,
                                    stub=real_stub)
        self.send_pdu(req)
        rep = self.recv_pdu(timeout=0.1)
        self.assertIsNone(rep)
        self.assertIsConnected()

        # netr_ServerReqChallenge with given flags
        req = self.generate_request(call_id = 2,
                                    pfc_flags=dcerpc.DCERPC_PFC_FLAG_LAST,
                                    context_id=ctx.context_id,
                                    opnum=4,
                                    stub=real_stub)
        self.send_pdu(req)
        rep = self.recv_pdu()
        self.verify_pdu(rep, dcerpc.DCERPC_PKT_RESPONSE, req.call_id,
                        auth_length=0)
        self.assertNotEquals(rep.u.alloc_hint, 0)
        self.assertEquals(rep.u.context_id, req.u.context_id)
        self.assertEquals(rep.u.cancel_count, 0)
        self.assertGreaterEqual(len(rep.u.stub_and_verifier), rep.u.alloc_hint)

        self.assertEquals(len(rep.u.stub_and_verifier), 12)
        status = struct.unpack_from("<I", rep.u.stub_and_verifier, len(rep.u.stub_and_verifier) - 4)
        self.assertEquals(status[0], 0)

    def test_last_cancel_requests(self):
        (ctx, rep, real_stub) = self._get_netlogon_ctx()

        # netr_ServerReqChallenge with given flags
        req = self.generate_request(call_id = 2,
                                    pfc_flags=dcerpc.DCERPC_PFC_FLAG_FIRST,
                                    context_id=ctx.context_id,
                                    opnum=4,
                                    stub=real_stub[:4])
        self.send_pdu(req)
        rep = self.recv_pdu(timeout=0.1)
        self.assertIsNone(rep)
        self.assertIsConnected()

        # netr_ServerReqChallenge with given flags
        req = self.generate_request(call_id = 2,
                                    pfc_flags=dcerpc.DCERPC_PFC_FLAG_LAST |
                                    dcerpc.DCERPC_PFC_FLAG_PENDING_CANCEL,
                                    context_id=ctx.context_id,
                                    opnum=4,
                                    stub=real_stub[4:])
        self.send_pdu(req)
        rep = self.recv_pdu()
        self.verify_pdu(rep, dcerpc.DCERPC_PKT_RESPONSE, req.call_id,
                        auth_length=0)
        self.assertNotEquals(rep.u.alloc_hint, 0)
        self.assertEquals(rep.u.context_id, req.u.context_id)
        self.assertEquals(rep.u.cancel_count, 0)
        self.assertGreaterEqual(len(rep.u.stub_and_verifier), rep.u.alloc_hint)

        self.assertEquals(len(rep.u.stub_and_verifier), 12)
        status = struct.unpack_from("<I", rep.u.stub_and_verifier, len(rep.u.stub_and_verifier) - 4)
        self.assertEquals(status[0], 0)

    def test_mix_requests(self):
        (ctx, rep, real_stub) = self._get_netlogon_ctx()

        # netr_ServerReqChallenge with given flags
        req = self.generate_request(call_id = 50,
                                    pfc_flags=dcerpc.DCERPC_PFC_FLAG_FIRST,
                                    context_id=ctx.context_id,
                                    opnum=4,
                                    stub=real_stub)
        self.send_pdu(req)
        rep = self.recv_pdu(timeout=0.1)
        self.assertIsNone(rep)
        self.assertIsConnected()

        # netr_ServerReqChallenge with given flags
        req = self.generate_request(call_id = 51,
                                    pfc_flags=dcerpc.DCERPC_PFC_FLAG_FIRST,
                                    context_id=ctx.context_id,
                                    opnum=4,
                                    stub=real_stub)
        self.send_pdu(req)
        rep = self.recv_pdu()
        # We get a fault back
        self.verify_pdu(rep, dcerpc.DCERPC_PKT_FAULT, 50,
                        pfc_flags=dcerpc.DCERPC_PFC_FLAG_FIRST |
                        dcerpc.DCERPC_PFC_FLAG_LAST,
                        auth_length=0)
        self.assertNotEquals(rep.u.alloc_hint, 0)
        self.assertEquals(rep.u.context_id, req.u.context_id)
        self.assertEquals(rep.u.cancel_count, 0)
        self.assertEquals(rep.u.flags, 0)
        self.assertEquals(rep.u.status, dcerpc.DCERPC_NCA_S_PROTO_ERROR)
        self.assertEquals(rep.u.reserved, 0)
        self.assertEquals(len(rep.u.error_and_verifier), 0)

    def test_co_cancel_no_request(self):
        ndr32 = base.transfer_syntax_ndr()
        abstract = samba.dcerpc.mgmt.abstract_syntax()
        ctx = self.prepare_presentation(abstract, ndr32, context_id=0xff)

        req = self.generate_co_cancel(call_id = 3)
        self.send_pdu(req)
        rep = self.recv_pdu(timeout=0.01)
        self.assertIsNone(rep)
        self.assertIsConnected()

        # And now try a request
        req = self.generate_request(call_id = 1,
                                    context_id=ctx.context_id,
                                    opnum=0,
                                    stub="")
        self.send_pdu(req)
        rep = self.recv_pdu()
        self.verify_pdu(rep, dcerpc.DCERPC_PKT_RESPONSE, req.call_id,
                        auth_length=0)
        self.assertNotEquals(rep.u.alloc_hint, 0)
        self.assertEquals(rep.u.context_id, req.u.context_id)
        self.assertEquals(rep.u.cancel_count, 0)
        self.assertGreaterEqual(len(rep.u.stub_and_verifier), rep.u.alloc_hint)

    def test_co_cancel_request_after_first(self):
        ndr32 = base.transfer_syntax_ndr()
        abstract = samba.dcerpc.mgmt.abstract_syntax()
        ctx = self.prepare_presentation(abstract, ndr32, context_id=0xff)

        req = self.generate_request(call_id = 1,
                                    pfc_flags=dcerpc.DCERPC_PFC_FLAG_FIRST,
                                    context_id=ctx.context_id,
                                    opnum=0,
                                    stub="")
        self.send_pdu(req)
        rep = self.recv_pdu(timeout=0.01)
        self.assertIsNone(rep)
        self.assertIsConnected()

        req = self.generate_co_cancel(call_id = 1)
        self.send_pdu(req)
        rep = self.recv_pdu(timeout=0.01)
        self.assertIsNone(rep)
        self.assertIsConnected()

        req = self.generate_request(call_id = 1,
                                    pfc_flags=dcerpc.DCERPC_PFC_FLAG_LAST,
                                    context_id=ctx.context_id,
                                    opnum=0,
                                    stub="")
        self.send_pdu(req)
        rep = self.recv_pdu()
        self.verify_pdu(rep, dcerpc.DCERPC_PKT_RESPONSE, req.call_id,
                        auth_length=0)
        self.assertNotEquals(rep.u.alloc_hint, 0)
        self.assertEquals(rep.u.context_id, req.u.context_id)
        self.assertEquals(rep.u.cancel_count, 0)
        self.assertGreaterEqual(len(rep.u.stub_and_verifier), rep.u.alloc_hint)

        # And now try a request
        req = self.generate_request(call_id = 2,
                                    context_id=ctx.context_id,
                                    opnum=0,
                                    stub="")
        self.send_pdu(req)
        rep = self.recv_pdu()
        self.verify_pdu(rep, dcerpc.DCERPC_PKT_RESPONSE, req.call_id,
                        auth_length=0)
        self.assertNotEquals(rep.u.alloc_hint, 0)
        self.assertEquals(rep.u.context_id, req.u.context_id)
        self.assertEquals(rep.u.cancel_count, 0)
        self.assertGreaterEqual(len(rep.u.stub_and_verifier), rep.u.alloc_hint)

    def test_orphaned_no_request(self):
        ndr32 = base.transfer_syntax_ndr()
        abstract = samba.dcerpc.mgmt.abstract_syntax()
        ctx = self.prepare_presentation(abstract, ndr32)

        req = self.generate_orphaned(call_id = 3)
        self.send_pdu(req)
        rep = self.recv_pdu(timeout=0.01)
        self.assertIsNone(rep)
        self.assertIsConnected()

        # And now try a request
        req = self.generate_request(call_id = 1,
                                    context_id=ctx.context_id,
                                    opnum=0,
                                    stub="")
        self.send_pdu(req)
        rep = self.recv_pdu()
        self.verify_pdu(rep, dcerpc.DCERPC_PKT_RESPONSE, req.call_id,
                        auth_length=0)
        self.assertNotEquals(rep.u.alloc_hint, 0)
        self.assertEquals(rep.u.context_id, req.u.context_id & 0xff)
        self.assertEquals(rep.u.cancel_count, 0)
        self.assertGreaterEqual(len(rep.u.stub_and_verifier), rep.u.alloc_hint)

    def test_orphaned_request_after_first_last(self):
        ndr32 = base.transfer_syntax_ndr()
        abstract = samba.dcerpc.mgmt.abstract_syntax()
        ctx = self.prepare_presentation(abstract, ndr32)

        req = self.generate_request(call_id = 1,
                                    pfc_flags=dcerpc.DCERPC_PFC_FLAG_FIRST,
                                    context_id=ctx.context_id,
                                    opnum=0,
                                    stub="")
        self.send_pdu(req)
        rep = self.recv_pdu(timeout=0.1)
        self.assertIsNone(rep)
        self.assertIsConnected()

        req = self.generate_orphaned(call_id = 1)
        self.send_pdu(req)
        rep = self.recv_pdu(timeout=0.1)
        self.assertIsNone(rep)
        self.assertIsConnected()

        req = self.generate_request(call_id = 1,
                                    pfc_flags=dcerpc.DCERPC_PFC_FLAG_LAST,
                                    context_id=ctx.context_id,
                                    opnum=0,
                                    stub="")
        self.send_pdu(req)
        rep = self.recv_pdu()
        self.verify_pdu(rep, dcerpc.DCERPC_PKT_RESPONSE, req.call_id,
                        auth_length=0)
        self.assertNotEquals(rep.u.alloc_hint, 0)
        self.assertEquals(rep.u.context_id, req.u.context_id & 0xff)
        self.assertEquals(rep.u.cancel_count, 0)
        self.assertGreaterEqual(len(rep.u.stub_and_verifier), rep.u.alloc_hint)

        # And now try a request
        req = self.generate_request(call_id = 2,
                                    context_id=ctx.context_id,
                                    opnum=0,
                                    stub="")
        self.send_pdu(req)
        rep = self.recv_pdu()
        self.verify_pdu(rep, dcerpc.DCERPC_PKT_RESPONSE, req.call_id,
                        auth_length=0)
        self.assertNotEquals(rep.u.alloc_hint, 0)
        self.assertEquals(rep.u.context_id, req.u.context_id & 0xff)
        self.assertEquals(rep.u.cancel_count, 0)
        self.assertGreaterEqual(len(rep.u.stub_and_verifier), rep.u.alloc_hint)

    def test_orphaned_request_after_first_mpx_last(self):
        ndr32 = base.transfer_syntax_ndr()
        abstract = samba.dcerpc.mgmt.abstract_syntax()

        pfc_flags = samba.dcerpc.dcerpc.DCERPC_PFC_FLAG_FIRST
        pfc_flags |= samba.dcerpc.dcerpc.DCERPC_PFC_FLAG_LAST
        pfc_flags |= samba.dcerpc.dcerpc.DCERPC_PFC_FLAG_CONC_MPX
        ctx = self.prepare_presentation(abstract, ndr32, pfc_flags=pfc_flags)

        req = self.generate_request(call_id = 1,
                                    pfc_flags=dcerpc.DCERPC_PFC_FLAG_FIRST,
                                    context_id=ctx.context_id,
                                    opnum=0,
                                    stub="")
        self.send_pdu(req)
        rep = self.recv_pdu(timeout=0.1)
        self.assertIsNone(rep)
        self.assertIsConnected()

        req = self.generate_orphaned(call_id = 1)
        self.send_pdu(req)
        rep = self.recv_pdu(timeout=0.1)
        self.assertIsNone(rep)
        self.assertIsConnected()

        req = self.generate_request(call_id = 1,
                                    pfc_flags=dcerpc.DCERPC_PFC_FLAG_LAST,
                                    context_id=ctx.context_id,
                                    opnum=0,
                                    stub="")
        self.send_pdu(req)
        rep = self.recv_pdu()
        self.verify_pdu(rep, dcerpc.DCERPC_PKT_RESPONSE, req.call_id,
                        auth_length=0)
        self.assertNotEquals(rep.u.alloc_hint, 0)
        self.assertEquals(rep.u.context_id, req.u.context_id & 0xff)
        self.assertEquals(rep.u.cancel_count, 0)
        self.assertGreaterEqual(len(rep.u.stub_and_verifier), rep.u.alloc_hint)

        # And now try a request
        req = self.generate_request(call_id = 2,
                                    context_id=ctx.context_id,
                                    opnum=0,
                                    stub="")
        self.send_pdu(req)
        rep = self.recv_pdu()
        self.verify_pdu(rep, dcerpc.DCERPC_PKT_RESPONSE, req.call_id,
                        auth_length=0)
        self.assertNotEquals(rep.u.alloc_hint, 0)
        self.assertEquals(rep.u.context_id, req.u.context_id & 0xff)
        self.assertEquals(rep.u.cancel_count, 0)
        self.assertGreaterEqual(len(rep.u.stub_and_verifier), rep.u.alloc_hint)

    def test_orphaned_request_after_first_no_last(self):
        ndr32 = base.transfer_syntax_ndr()
        abstract = samba.dcerpc.mgmt.abstract_syntax()
        ctx = self.prepare_presentation(abstract, ndr32)

        req1 = self.generate_request(call_id = 1,
                                    pfc_flags=dcerpc.DCERPC_PFC_FLAG_FIRST,
                                    context_id=ctx.context_id,
                                    opnum=0,
                                    stub="")
        self.send_pdu(req1)
        rep = self.recv_pdu(timeout=0.1)
        self.assertIsNone(rep)
        self.assertIsConnected()

        req = self.generate_orphaned(call_id = 1)
        self.send_pdu(req)
        rep = self.recv_pdu(timeout=0.1)
        self.assertIsNone(rep)
        self.assertIsConnected()

        # And now try a new request
        req2 = self.generate_request(call_id = 2,
                                    context_id=ctx.context_id,
                                    opnum=0,
                                    stub="")
        self.send_pdu(req2)
        rep = self.recv_pdu()
        self.verify_pdu(rep, dcerpc.DCERPC_PKT_FAULT, req1.call_id,
                        auth_length=0)
        self.assertNotEquals(rep.u.alloc_hint, 0)
        self.assertEquals(rep.u.context_id, req1.u.context_id)
        self.assertEquals(rep.u.cancel_count, 0)
        self.assertEquals(rep.u.flags, 0)
        self.assertEquals(rep.u.status, dcerpc.DCERPC_NCA_S_PROTO_ERROR)
        self.assertEquals(rep.u.reserved, 0)
        self.assertEquals(len(rep.u.error_and_verifier), 0)

        # wait for a disconnect
        rep = self.recv_pdu()
        self.assertIsNone(rep)
        self.assertNotConnected()

    def test_orphaned_request_after_first_mpx_no_last(self):
        ndr32 = base.transfer_syntax_ndr()
        abstract = samba.dcerpc.mgmt.abstract_syntax()

        pfc_flags = samba.dcerpc.dcerpc.DCERPC_PFC_FLAG_FIRST
        pfc_flags |= samba.dcerpc.dcerpc.DCERPC_PFC_FLAG_LAST
        pfc_flags |= samba.dcerpc.dcerpc.DCERPC_PFC_FLAG_CONC_MPX
        ctx = self.prepare_presentation(abstract, ndr32,
                                        pfc_flags=pfc_flags)

        req1 = self.generate_request(call_id = 1,
                                    pfc_flags=dcerpc.DCERPC_PFC_FLAG_FIRST,
                                    context_id=ctx.context_id,
                                    opnum=0,
                                    stub="")
        self.send_pdu(req1)
        rep = self.recv_pdu(timeout=0.1)
        self.assertIsNone(rep)
        self.assertIsConnected()

        req = self.generate_orphaned(call_id = 1)
        self.send_pdu(req)
        rep = self.recv_pdu(timeout=0.1)
        self.assertIsNone(rep)
        self.assertIsConnected()

        # And now try a new request
        req2 = self.generate_request(call_id = 2,
                                    context_id=ctx.context_id-1,
                                    opnum=0,
                                    stub="")
        self.send_pdu(req2)
        rep = self.recv_pdu()
        self.verify_pdu(rep, dcerpc.DCERPC_PKT_FAULT, req2.call_id,
                        auth_length=0)
        self.assertNotEquals(rep.u.alloc_hint, 0)
        self.assertEquals(rep.u.context_id, 0)
        self.assertEquals(rep.u.cancel_count, 0)
        self.assertEquals(rep.u.flags, 0)
        self.assertEquals(rep.u.status, dcerpc.DCERPC_NCA_S_PROTO_ERROR)
        self.assertEquals(rep.u.reserved, 0)
        self.assertEquals(len(rep.u.error_and_verifier), 0)

        # wait for a disconnect
        rep = self.recv_pdu()
        self.assertIsNone(rep)
        self.assertNotConnected()

    def test_spnego_connect_request(self):
        ndr32 = base.transfer_syntax_ndr()

        tsf1_list = [ndr32]
        ctx1 = dcerpc.ctx_list()
        ctx1.context_id = 1
        ctx1.num_transfer_syntaxes = len(tsf1_list)
        ctx1.abstract_syntax = samba.dcerpc.mgmt.abstract_syntax()
        ctx1.transfer_syntaxes = tsf1_list
        ctx_list = [ctx1]

        c = self.get_anon_creds()
        g = gensec.Security.start_client(self.settings)
        g.set_credentials(c)
        g.want_feature(gensec.FEATURE_DCE_STYLE)
        auth_type = dcerpc.DCERPC_AUTH_TYPE_SPNEGO
        auth_level = dcerpc.DCERPC_AUTH_LEVEL_CONNECT
        auth_context_id = 2
        g.start_mech_by_authtype(auth_type, auth_level)
        from_server = ""
        (finished, to_server) = g.update(from_server)
        self.assertFalse(finished)

        auth_info = self.generate_auth(auth_type=auth_type,
                                       auth_level=auth_level,
                                       auth_context_id=auth_context_id,
                                       auth_blob=to_server)

        req = self.generate_bind(call_id=0,
                                 ctx_list=ctx_list,
                                 auth_info=auth_info)

        self.send_pdu(req)
        rep = self.recv_pdu()
        self.verify_pdu(rep, dcerpc.DCERPC_PKT_BIND_ACK, req.call_id)
        self.assertEquals(rep.u.max_xmit_frag, req.u.max_xmit_frag)
        self.assertEquals(rep.u.max_recv_frag, req.u.max_recv_frag)
        self.assertNotEquals(rep.u.assoc_group_id, req.u.assoc_group_id)
        self.assertEquals(rep.u.secondary_address_size, 4)
        self.assertEquals(rep.u.secondary_address, "%d" % self.tcp_port)
        self.assertEquals(len(rep.u._pad1), 2)
        self.assertEquals(rep.u._pad1, '\0' * 2)
        self.assertEquals(rep.u.num_results, 1)
        self.assertEquals(rep.u.ctx_list[0].result,
                dcerpc.DCERPC_BIND_ACK_RESULT_ACCEPTANCE)
        self.assertEquals(rep.u.ctx_list[0].reason,
                dcerpc.DCERPC_BIND_ACK_REASON_NOT_SPECIFIED)
        self.assertNDRSyntaxEquals(rep.u.ctx_list[0].syntax, ndr32)
        self.assertNotEquals(len(rep.u.auth_info), 0)
        a = self.parse_auth(rep.u.auth_info)

        from_server = a.credentials
        (finished, to_server) = g.update(from_server)
        self.assertFalse(finished)

        auth_info = self.generate_auth(auth_type=auth_type,
                                       auth_level=auth_level,
                                       auth_context_id=auth_context_id,
                                       auth_blob=to_server)

        req = self.generate_alter(call_id=0,
                                  ctx_list=ctx_list,
                                  assoc_group_id=rep.u.assoc_group_id,
                                  auth_info=auth_info)

        self.send_pdu(req)
        rep = self.recv_pdu()
        self.verify_pdu(rep, dcerpc.DCERPC_PKT_ALTER_RESP, req.call_id)
        self.assertEquals(rep.u.max_xmit_frag, req.u.max_xmit_frag)
        self.assertEquals(rep.u.max_recv_frag, req.u.max_recv_frag)
        self.assertEquals(rep.u.assoc_group_id, req.u.assoc_group_id)
        self.assertEquals(rep.u.secondary_address_size, 0)
        self.assertEquals(len(rep.u._pad1), 2)
        # Windows sends garbage
        #self.assertEquals(rep.u._pad1, '\0' * 2)
        self.assertEquals(rep.u.num_results, 1)
        self.assertEquals(rep.u.ctx_list[0].result,
                dcerpc.DCERPC_BIND_ACK_RESULT_ACCEPTANCE)
        self.assertEquals(rep.u.ctx_list[0].reason,
                dcerpc.DCERPC_BIND_ACK_REASON_NOT_SPECIFIED)
        self.assertNDRSyntaxEquals(rep.u.ctx_list[0].syntax, ndr32)
        self.assertNotEquals(len(rep.u.auth_info), 0)
        a = self.parse_auth(rep.u.auth_info)

        from_server = a.credentials
        (finished, to_server) = g.update(from_server)
        self.assertTrue(finished)

        # And now try a request without auth_info
        req = self.generate_request(call_id = 2,
                                    context_id=ctx1.context_id,
                                    opnum=0,
                                    stub="")
        self.send_pdu(req)
        rep = self.recv_pdu()
        self.verify_pdu(rep, dcerpc.DCERPC_PKT_RESPONSE, req.call_id,
                        auth_length=0)
        self.assertNotEquals(rep.u.alloc_hint, 0)
        self.assertEquals(rep.u.context_id, req.u.context_id & 0xff)
        self.assertEquals(rep.u.cancel_count, 0)
        self.assertGreaterEqual(len(rep.u.stub_and_verifier), rep.u.alloc_hint)

        # Now a request with auth_info DCERPC_AUTH_LEVEL_CONNECT
        auth_info = self.generate_auth(auth_type=auth_type,
                                       auth_level=auth_level,
                                       auth_context_id=auth_context_id,
                                       auth_blob="\x01"+"\x00"*15)
        req = self.generate_request(call_id = 3,
                                    context_id=ctx1.context_id,
                                    opnum=0,
                                    stub="",
                                    auth_info=auth_info)
        self.send_pdu(req)
        rep = self.recv_pdu()
        # We don't get an auth_info back
        self.verify_pdu(rep, dcerpc.DCERPC_PKT_RESPONSE, req.call_id,
                        auth_length=0)
        self.assertNotEquals(rep.u.alloc_hint, 0)
        self.assertEquals(rep.u.context_id, req.u.context_id & 0xff)
        self.assertEquals(rep.u.cancel_count, 0)
        self.assertGreaterEqual(len(rep.u.stub_and_verifier), rep.u.alloc_hint)

        # Now a request with auth_info DCERPC_AUTH_LEVEL_INTEGRITY
        auth_info = self.generate_auth(auth_type=auth_type,
                                       auth_level=dcerpc.DCERPC_AUTH_LEVEL_INTEGRITY,
                                       auth_context_id=auth_context_id,
                                       auth_blob="\x01"+"\x00"*15)
        req = self.generate_request(call_id = 4,
                                    context_id=ctx1.context_id,
                                    opnum=0,
                                    stub="",
                                    auth_info=auth_info)
        self.send_pdu(req)
        rep = self.recv_pdu()
        # We get a fault back
        self.verify_pdu(rep, dcerpc.DCERPC_PKT_FAULT, req.call_id,
                        auth_length=0)
        self.assertNotEquals(rep.u.alloc_hint, 0)
        self.assertEquals(rep.u.context_id, req.u.context_id)
        self.assertEquals(rep.u.cancel_count, 0)
        self.assertEquals(rep.u.flags, 0)
        self.assertEquals(rep.u.status, dcerpc.DCERPC_FAULT_ACCESS_DENIED)
        self.assertEquals(rep.u.reserved, 0)
        self.assertEquals(len(rep.u.error_and_verifier), 0)

        # wait for a disconnect
        rep = self.recv_pdu()
        self.assertIsNone(rep)
        self.assertNotConnected()

    def test_spnego_integrity_request(self):
        ndr32 = base.transfer_syntax_ndr()

        tsf1_list = [ndr32]
        ctx1 = dcerpc.ctx_list()
        ctx1.context_id = 1
        ctx1.num_transfer_syntaxes = len(tsf1_list)
        ctx1.abstract_syntax = samba.dcerpc.mgmt.abstract_syntax()
        ctx1.transfer_syntaxes = tsf1_list
        ctx_list = [ctx1]

        c = self.get_anon_creds()
        g = gensec.Security.start_client(self.settings)
        g.set_credentials(c)
        g.want_feature(gensec.FEATURE_DCE_STYLE)
        auth_type = dcerpc.DCERPC_AUTH_TYPE_SPNEGO
        auth_level = dcerpc.DCERPC_AUTH_LEVEL_INTEGRITY
        auth_context_id = 2
        g.start_mech_by_authtype(auth_type, auth_level)
        from_server = ""
        (finished, to_server) = g.update(from_server)
        self.assertFalse(finished)

        auth_info = self.generate_auth(auth_type=auth_type,
                                       auth_level=auth_level,
                                       auth_context_id=auth_context_id,
                                       auth_blob=to_server)

        req = self.generate_bind(call_id=0,
                                 ctx_list=ctx_list,
                                 auth_info=auth_info)

        self.send_pdu(req)
        rep = self.recv_pdu()
        self.verify_pdu(rep, dcerpc.DCERPC_PKT_BIND_ACK, req.call_id)
        self.assertEquals(rep.u.max_xmit_frag, req.u.max_xmit_frag)
        self.assertEquals(rep.u.max_recv_frag, req.u.max_recv_frag)
        self.assertNotEquals(rep.u.assoc_group_id, req.u.assoc_group_id)
        self.assertEquals(rep.u.secondary_address_size, 4)
        self.assertEquals(rep.u.secondary_address, "%d" % self.tcp_port)
        self.assertEquals(len(rep.u._pad1), 2)
        self.assertEquals(rep.u._pad1, '\0' * 2)
        self.assertEquals(rep.u.num_results, 1)
        self.assertEquals(rep.u.ctx_list[0].result,
                dcerpc.DCERPC_BIND_ACK_RESULT_ACCEPTANCE)
        self.assertEquals(rep.u.ctx_list[0].reason,
                dcerpc.DCERPC_BIND_ACK_REASON_NOT_SPECIFIED)
        self.assertNDRSyntaxEquals(rep.u.ctx_list[0].syntax, ndr32)
        self.assertNotEquals(len(rep.u.auth_info), 0)
        a = self.parse_auth(rep.u.auth_info)

        from_server = a.credentials
        (finished, to_server) = g.update(from_server)
        self.assertFalse(finished)

        auth_info = self.generate_auth(auth_type=auth_type,
                                       auth_level=auth_level,
                                       auth_context_id=auth_context_id,
                                       auth_blob=to_server)

        req = self.generate_alter(call_id=0,
                                  ctx_list=ctx_list,
                                  assoc_group_id=rep.u.assoc_group_id,
                                  auth_info=auth_info)

        self.send_pdu(req)
        rep = self.recv_pdu()
        self.verify_pdu(rep, dcerpc.DCERPC_PKT_ALTER_RESP, req.call_id)
        self.assertEquals(rep.u.max_xmit_frag, req.u.max_xmit_frag)
        self.assertEquals(rep.u.max_recv_frag, req.u.max_recv_frag)
        self.assertEquals(rep.u.assoc_group_id, req.u.assoc_group_id)
        self.assertEquals(rep.u.secondary_address_size, 0)
        self.assertEquals(len(rep.u._pad1), 2)
        # Windows sends garbage
        #self.assertEquals(rep.u._pad1, '\0' * 2)
        self.assertEquals(rep.u.num_results, 1)
        self.assertEquals(rep.u.ctx_list[0].result,
                dcerpc.DCERPC_BIND_ACK_RESULT_ACCEPTANCE)
        self.assertEquals(rep.u.ctx_list[0].reason,
                dcerpc.DCERPC_BIND_ACK_REASON_NOT_SPECIFIED)
        self.assertNDRSyntaxEquals(rep.u.ctx_list[0].syntax, ndr32)
        self.assertNotEquals(len(rep.u.auth_info), 0)
        a = self.parse_auth(rep.u.auth_info)

        from_server = a.credentials
        (finished, to_server) = g.update(from_server)
        self.assertTrue(finished)

        # Now a request with auth_info DCERPC_AUTH_LEVEL_CONNECT
        auth_info = self.generate_auth(auth_type=auth_type,
                                       auth_level=dcerpc.DCERPC_AUTH_LEVEL_CONNECT,
                                       auth_context_id=auth_context_id,
                                       auth_blob="\x01"+"\x00"*15)
        req = self.generate_request(call_id = 3,
                                    context_id=ctx1.context_id,
                                    opnum=0,
                                    stub="",
                                    auth_info=auth_info)
        self.send_pdu(req)
        rep = self.recv_pdu()
        # We get a fault back
        self.verify_pdu(rep, dcerpc.DCERPC_PKT_FAULT, req.call_id,
                        auth_length=0)
        self.assertNotEquals(rep.u.alloc_hint, 0)
        self.assertEquals(rep.u.context_id, req.u.context_id)
        self.assertEquals(rep.u.cancel_count, 0)
        self.assertEquals(rep.u.flags, 0)
        self.assertEquals(rep.u.status, dcerpc.DCERPC_FAULT_ACCESS_DENIED)
        self.assertEquals(rep.u.reserved, 0)
        self.assertEquals(len(rep.u.error_and_verifier), 0)

        # wait for a disconnect
        rep = self.recv_pdu()
        self.assertIsNone(rep)
        self.assertNotConnected()

    def test_spnego_unfinished_request(self):
        ndr32 = base.transfer_syntax_ndr()

        tsf1_list = [ndr32]
        ctx1 = dcerpc.ctx_list()
        ctx1.context_id = 1
        ctx1.num_transfer_syntaxes = len(tsf1_list)
        ctx1.abstract_syntax = samba.dcerpc.mgmt.abstract_syntax()
        ctx1.transfer_syntaxes = tsf1_list
        ctx_list = [ctx1]

        c = self.get_anon_creds()
        g = gensec.Security.start_client(self.settings)
        g.set_credentials(c)
        g.want_feature(gensec.FEATURE_DCE_STYLE)
        auth_type = dcerpc.DCERPC_AUTH_TYPE_SPNEGO
        auth_level = dcerpc.DCERPC_AUTH_LEVEL_CONNECT
        auth_context_id = 2
        g.start_mech_by_authtype(auth_type, auth_level)
        from_server = ""
        (finished, to_server) = g.update(from_server)
        self.assertFalse(finished)

        auth_info = self.generate_auth(auth_type=auth_type,
                                       auth_level=auth_level,
                                       auth_context_id=auth_context_id,
                                       auth_blob=to_server)

        req = self.generate_bind(call_id=0,
                                 ctx_list=ctx_list,
                                 auth_info=auth_info)

        self.send_pdu(req)
        rep = self.recv_pdu()
        self.verify_pdu(rep, dcerpc.DCERPC_PKT_BIND_ACK, req.call_id)
        self.assertEquals(rep.u.max_xmit_frag, req.u.max_xmit_frag)
        self.assertEquals(rep.u.max_recv_frag, req.u.max_recv_frag)
        self.assertNotEquals(rep.u.assoc_group_id, req.u.assoc_group_id)
        assoc_group_id = rep.u.assoc_group_id
        self.assertEquals(rep.u.secondary_address_size, 4)
        self.assertEquals(rep.u.secondary_address, "%d" % self.tcp_port)
        self.assertEquals(len(rep.u._pad1), 2)
        self.assertEquals(rep.u._pad1, '\0' * 2)
        self.assertEquals(rep.u.num_results, 1)
        self.assertEquals(rep.u.ctx_list[0].result,
                dcerpc.DCERPC_BIND_ACK_RESULT_ACCEPTANCE)
        self.assertEquals(rep.u.ctx_list[0].reason,
                dcerpc.DCERPC_BIND_ACK_REASON_NOT_SPECIFIED)
        self.assertNDRSyntaxEquals(rep.u.ctx_list[0].syntax, ndr32)
        self.assertNotEquals(len(rep.u.auth_info), 0)
        a = self.parse_auth(rep.u.auth_info)

        from_server = a.credentials
        (finished, to_server) = g.update(from_server)
        self.assertFalse(finished)

        # Now a request with auth_info DCERPC_AUTH_LEVEL_CONNECT
        auth_info = self.generate_auth(auth_type=auth_type,
                                       auth_level=auth_level,
                                       auth_context_id=auth_context_id,
                                       auth_blob="\x01"+"\x00"*15)
        req = self.generate_request(call_id = 1,
                                    context_id=ctx1.context_id,
                                    opnum=0,
                                    stub="",
                                    auth_info=auth_info)
        self.send_pdu(req)
        rep = self.recv_pdu()
        # We get a fault
        self.verify_pdu(rep, dcerpc.DCERPC_PKT_FAULT, req.call_id,
                        pfc_flags=req.pfc_flags |
                        dcerpc.DCERPC_PFC_FLAG_DID_NOT_EXECUTE,
                        auth_length=0)
        self.assertNotEquals(rep.u.alloc_hint, 0)
        self.assertEquals(rep.u.context_id, 0)
        self.assertEquals(rep.u.cancel_count, 0)
        self.assertEquals(rep.u.flags, 0)
        self.assertEquals(rep.u.status, dcerpc.DCERPC_NCA_S_PROTO_ERROR)
        self.assertEquals(rep.u.reserved, 0)
        self.assertEquals(len(rep.u.error_and_verifier), 0)

        # wait for a disconnect
        rep = self.recv_pdu()
        self.assertIsNone(rep)
        self.assertNotConnected()

    def test_spnego_auth3(self):
        ndr32 = base.transfer_syntax_ndr()

        tsf1_list = [ndr32]
        ctx1 = dcerpc.ctx_list()
        ctx1.context_id = 1
        ctx1.num_transfer_syntaxes = len(tsf1_list)
        ctx1.abstract_syntax = samba.dcerpc.mgmt.abstract_syntax()
        ctx1.transfer_syntaxes = tsf1_list
        ctx_list = [ctx1]

        c = self.get_anon_creds()
        g = gensec.Security.start_client(self.settings)
        g.set_credentials(c)
        g.want_feature(gensec.FEATURE_DCE_STYLE)
        auth_type = dcerpc.DCERPC_AUTH_TYPE_SPNEGO
        auth_level = dcerpc.DCERPC_AUTH_LEVEL_CONNECT
        auth_context_id = 2
        g.start_mech_by_authtype(auth_type, auth_level)
        from_server = ""
        (finished, to_server) = g.update(from_server)
        self.assertFalse(finished)

        auth_info = self.generate_auth(auth_type=auth_type,
                                       auth_level=auth_level,
                                       auth_context_id=auth_context_id,
                                       auth_blob=to_server)
        req = self.generate_bind(call_id=0,
                                 ctx_list=ctx_list,
                                 auth_info=auth_info)
        self.send_pdu(req)
        rep = self.recv_pdu()
        self.verify_pdu(rep, dcerpc.DCERPC_PKT_BIND_ACK, req.call_id)
        self.assertEquals(rep.u.max_xmit_frag, req.u.max_xmit_frag)
        self.assertEquals(rep.u.max_recv_frag, req.u.max_recv_frag)
        self.assertNotEquals(rep.u.assoc_group_id, req.u.assoc_group_id)
        self.assertEquals(rep.u.secondary_address_size, 4)
        self.assertEquals(rep.u.secondary_address, "%d" % self.tcp_port)
        self.assertEquals(len(rep.u._pad1), 2)
        #self.assertEquals(rep.u._pad1, '\0' * 2)
        self.assertEquals(rep.u.num_results, 1)
        self.assertEquals(rep.u.ctx_list[0].result,
                dcerpc.DCERPC_BIND_ACK_RESULT_ACCEPTANCE)
        self.assertEquals(rep.u.ctx_list[0].reason,
                dcerpc.DCERPC_BIND_ACK_REASON_NOT_SPECIFIED)
        self.assertNDRSyntaxEquals(rep.u.ctx_list[0].syntax, ndr32)
        self.assertNotEquals(len(rep.u.auth_info), 0)
        a = self.parse_auth(rep.u.auth_info)

        from_server = a.credentials
        (finished, to_server) = g.update(from_server)
        self.assertFalse(finished)

        auth_info = self.generate_auth(auth_type=auth_type,
                                       auth_level=auth_level,
                                       auth_context_id=auth_context_id,
                                       auth_blob=to_server)
        req = self.generate_auth3(call_id=0,
                                  auth_info=auth_info)
        self.send_pdu(req)
        rep = self.recv_pdu()
        self.assertIsNone(rep)
        self.assertIsConnected()

        # And now try a request without auth_info
        req = self.generate_request(call_id = 2,
                                    context_id=ctx1.context_id,
                                    opnum=0,
                                    stub="")
        self.send_pdu(req)
        rep = self.recv_pdu()
        # We get a fault back
        self.verify_pdu(rep, dcerpc.DCERPC_PKT_FAULT, req.call_id,
                        auth_length=0)
        self.assertNotEquals(rep.u.alloc_hint, 0)
        self.assertEquals(rep.u.context_id, req.u.context_id)
        self.assertEquals(rep.u.cancel_count, 0)
        self.assertEquals(rep.u.flags, 0)
        self.assertEquals(rep.u.status, dcerpc.DCERPC_FAULT_ACCESS_DENIED)
        self.assertEquals(rep.u.reserved, 0)
        self.assertEquals(len(rep.u.error_and_verifier), 0)

        # wait for a disconnect
        rep = self.recv_pdu()
        self.assertIsNone(rep)
        self.assertNotConnected()

    def test_spnego_connect_reauth_alter(self):
        ndr32 = base.transfer_syntax_ndr()
        ndr64 = base.transfer_syntax_ndr64()

        tsf1_list = [ndr32]
        ctx1 = dcerpc.ctx_list()
        ctx1.context_id = 1
        ctx1.num_transfer_syntaxes = len(tsf1_list)
        ctx1.abstract_syntax = samba.dcerpc.mgmt.abstract_syntax()
        ctx1.transfer_syntaxes = tsf1_list
        ctx_list = [ctx1]

        c = self.get_anon_creds()
        g = gensec.Security.start_client(self.settings)
        g.set_credentials(c)
        g.want_feature(gensec.FEATURE_DCE_STYLE)
        auth_type = dcerpc.DCERPC_AUTH_TYPE_SPNEGO
        auth_level = dcerpc.DCERPC_AUTH_LEVEL_CONNECT
        auth_context_id = 2
        g.start_mech_by_authtype(auth_type, auth_level)
        from_server = ""
        (finished, to_server) = g.update(from_server)
        self.assertFalse(finished)

        auth_info = self.generate_auth(auth_type=auth_type,
                                       auth_level=auth_level,
                                       auth_context_id=auth_context_id,
                                       auth_blob=to_server)

        req = self.generate_bind(call_id=0,
                                 ctx_list=ctx_list,
                                 auth_info=auth_info)

        self.send_pdu(req)
        rep = self.recv_pdu()
        self.verify_pdu(rep, dcerpc.DCERPC_PKT_BIND_ACK, req.call_id)
        self.assertEquals(rep.u.max_xmit_frag, req.u.max_xmit_frag)
        self.assertEquals(rep.u.max_recv_frag, req.u.max_recv_frag)
        self.assertNotEquals(rep.u.assoc_group_id, req.u.assoc_group_id)
        self.assertEquals(rep.u.secondary_address_size, 4)
        self.assertEquals(rep.u.secondary_address, "%d" % self.tcp_port)
        self.assertEquals(len(rep.u._pad1), 2)
        self.assertEquals(rep.u._pad1, '\0' * 2)
        self.assertEquals(rep.u.num_results, 1)
        self.assertEquals(rep.u.ctx_list[0].result,
                dcerpc.DCERPC_BIND_ACK_RESULT_ACCEPTANCE)
        self.assertEquals(rep.u.ctx_list[0].reason,
                dcerpc.DCERPC_BIND_ACK_REASON_NOT_SPECIFIED)
        self.assertNDRSyntaxEquals(rep.u.ctx_list[0].syntax, ndr32)
        self.assertNotEquals(len(rep.u.auth_info), 0)
        a = self.parse_auth(rep.u.auth_info)

        from_server = a.credentials
        (finished, to_server) = g.update(from_server)
        self.assertFalse(finished)

        auth_info = self.generate_auth(auth_type=auth_type,
                                       auth_level=auth_level,
                                       auth_context_id=auth_context_id,
                                       auth_blob=to_server)
        req = self.generate_alter(call_id=0,
                                  ctx_list=[ctx1],
                                  assoc_group_id=rep.u.assoc_group_id,
                                  auth_info=auth_info)
        self.send_pdu(req)
        rep = self.recv_pdu()
        self.verify_pdu(rep, dcerpc.DCERPC_PKT_ALTER_RESP, req.call_id)
        self.assertEquals(rep.u.max_xmit_frag, req.u.max_xmit_frag)
        self.assertEquals(rep.u.max_recv_frag, req.u.max_recv_frag)
        self.assertEquals(rep.u.assoc_group_id, req.u.assoc_group_id)
        self.assertEquals(rep.u.secondary_address_size, 0)
        self.assertEquals(len(rep.u._pad1), 2)
        # Windows sends garbage
        #self.assertEquals(rep.u._pad1, '\0' * 2)
        self.assertEquals(rep.u.num_results, 1)
        self.assertEquals(rep.u.ctx_list[0].result,
                dcerpc.DCERPC_BIND_ACK_RESULT_ACCEPTANCE)
        self.assertEquals(rep.u.ctx_list[0].reason,
                dcerpc.DCERPC_BIND_ACK_REASON_NOT_SPECIFIED)
        self.assertNDRSyntaxEquals(rep.u.ctx_list[0].syntax, ndr32)
        self.assertNotEquals(len(rep.u.auth_info), 0)
        a = self.parse_auth(rep.u.auth_info)

        from_server = a.credentials
        (finished, to_server) = g.update(from_server)
        self.assertTrue(finished)

        # And now try a request without auth_info
        req = self.generate_request(call_id = 2,
                                    context_id=ctx1.context_id,
                                    opnum=0,
                                    stub="")
        self.send_pdu(req)
        rep = self.recv_pdu()
        self.verify_pdu(rep, dcerpc.DCERPC_PKT_RESPONSE, req.call_id,
                        auth_length=0)
        self.assertNotEquals(rep.u.alloc_hint, 0)
        self.assertEquals(rep.u.context_id, req.u.context_id & 0xff)
        self.assertEquals(rep.u.cancel_count, 0)
        self.assertGreaterEqual(len(rep.u.stub_and_verifier), rep.u.alloc_hint)

        # Now a request with auth_info DCERPC_AUTH_LEVEL_CONNECT
        auth_info = self.generate_auth(auth_type=auth_type,
                                       auth_level=auth_level,
                                       auth_context_id=auth_context_id,
                                       auth_blob="\x01"+"\x00"*15)
        req = self.generate_request(call_id = 3,
                                    context_id=ctx1.context_id,
                                    opnum=0,
                                    stub="",
                                    auth_info=auth_info)
        self.send_pdu(req)
        rep = self.recv_pdu()
        # We don't get an auth_info back
        self.verify_pdu(rep, dcerpc.DCERPC_PKT_RESPONSE, req.call_id,
                        auth_length=0)
        self.assertNotEquals(rep.u.alloc_hint, 0)
        self.assertEquals(rep.u.context_id, req.u.context_id)
        self.assertEquals(rep.u.cancel_count, 0)
        self.assertGreaterEqual(len(rep.u.stub_and_verifier), rep.u.alloc_hint)

        # Now a reauth

        g = gensec.Security.start_client(self.settings)
        g.set_credentials(c)
        g.want_feature(gensec.FEATURE_DCE_STYLE)
        auth_type = dcerpc.DCERPC_AUTH_TYPE_SPNEGO
        auth_level = dcerpc.DCERPC_AUTH_LEVEL_CONNECT
        auth_context_id = 2
        g.start_mech_by_authtype(auth_type, auth_level)
        from_server = ""
        (finished, to_server) = g.update(from_server)
        self.assertFalse(finished)

        auth_info = self.generate_auth(auth_type=auth_type,
                                       auth_level=auth_level,
                                       auth_context_id=auth_context_id,
                                       auth_blob=to_server)
        req = self.generate_alter(call_id=0,
                                  ctx_list=ctx_list,
                                  auth_info=auth_info)
        self.send_pdu(req)
        rep = self.recv_pdu()
        # We get a fault
        self.verify_pdu(rep, dcerpc.DCERPC_PKT_FAULT, req.call_id,
                        pfc_flags=req.pfc_flags |
                        dcerpc.DCERPC_PFC_FLAG_DID_NOT_EXECUTE,
                        auth_length=0)
        self.assertNotEquals(rep.u.alloc_hint, 0)
        self.assertEquals(rep.u.context_id, 0)
        self.assertEquals(rep.u.cancel_count, 0)
        self.assertEquals(rep.u.flags, 0)
        self.assertEquals(rep.u.status, dcerpc.DCERPC_FAULT_ACCESS_DENIED)
        self.assertEquals(rep.u.reserved, 0)
        self.assertEquals(len(rep.u.error_and_verifier), 0)

        # wait for a disconnect
        rep = self.recv_pdu()
        self.assertIsNone(rep)
        self.assertNotConnected()

    def test_spnego_connect_reauth_auth3(self):
        ndr32 = base.transfer_syntax_ndr()
        ndr64 = base.transfer_syntax_ndr64()

        tsf1_list = [ndr32]
        ctx1 = dcerpc.ctx_list()
        ctx1.context_id = 1
        ctx1.num_transfer_syntaxes = len(tsf1_list)
        ctx1.abstract_syntax = samba.dcerpc.mgmt.abstract_syntax()
        ctx1.transfer_syntaxes = tsf1_list
        ctx_list = [ctx1]

        c = self.get_anon_creds()
        g = gensec.Security.start_client(self.settings)
        g.set_credentials(c)
        g.want_feature(gensec.FEATURE_DCE_STYLE)
        auth_type = dcerpc.DCERPC_AUTH_TYPE_SPNEGO
        auth_level = dcerpc.DCERPC_AUTH_LEVEL_CONNECT
        auth_context_id = 2
        g.start_mech_by_authtype(auth_type, auth_level)
        from_server = ""
        (finished, to_server) = g.update(from_server)
        self.assertFalse(finished)

        auth_info = self.generate_auth(auth_type=auth_type,
                                       auth_level=auth_level,
                                       auth_context_id=auth_context_id,
                                       auth_blob=to_server)

        req = self.generate_bind(call_id=0,
                                 ctx_list=ctx_list,
                                 auth_info=auth_info)

        self.send_pdu(req)
        rep = self.recv_pdu()
        self.verify_pdu(rep, dcerpc.DCERPC_PKT_BIND_ACK, req.call_id)
        self.assertEquals(rep.u.max_xmit_frag, req.u.max_xmit_frag)
        self.assertEquals(rep.u.max_recv_frag, req.u.max_recv_frag)
        self.assertNotEquals(rep.u.assoc_group_id, req.u.assoc_group_id)
        self.assertEquals(rep.u.secondary_address_size, 4)
        self.assertEquals(rep.u.secondary_address, "%d" % self.tcp_port)
        self.assertEquals(len(rep.u._pad1), 2)
        self.assertEquals(rep.u._pad1, '\0' * 2)
        self.assertEquals(rep.u.num_results, 1)
        self.assertEquals(rep.u.ctx_list[0].result,
                dcerpc.DCERPC_BIND_ACK_RESULT_ACCEPTANCE)
        self.assertEquals(rep.u.ctx_list[0].reason,
                dcerpc.DCERPC_BIND_ACK_REASON_NOT_SPECIFIED)
        self.assertNDRSyntaxEquals(rep.u.ctx_list[0].syntax, ndr32)
        self.assertNotEquals(len(rep.u.auth_info), 0)
        a = self.parse_auth(rep.u.auth_info)

        from_server = a.credentials
        (finished, to_server) = g.update(from_server)
        self.assertFalse(finished)

        auth_info = self.generate_auth(auth_type=auth_type,
                                       auth_level=auth_level,
                                       auth_context_id=auth_context_id,
                                       auth_blob=to_server)
        req = self.generate_alter(call_id=0,
                                  ctx_list=[ctx1],
                                  assoc_group_id=rep.u.assoc_group_id,
                                  auth_info=auth_info)
        self.send_pdu(req)
        rep = self.recv_pdu()
        self.verify_pdu(rep, dcerpc.DCERPC_PKT_ALTER_RESP, req.call_id)
        self.assertEquals(rep.u.max_xmit_frag, req.u.max_xmit_frag)
        self.assertEquals(rep.u.max_recv_frag, req.u.max_recv_frag)
        self.assertEquals(rep.u.assoc_group_id, req.u.assoc_group_id)
        self.assertEquals(rep.u.secondary_address_size, 0)
        self.assertEquals(len(rep.u._pad1), 2)
        # Windows sends garbage
        #self.assertEquals(rep.u._pad1, '\0' * 2)
        self.assertEquals(rep.u.num_results, 1)
        self.assertEquals(rep.u.ctx_list[0].result,
                dcerpc.DCERPC_BIND_ACK_RESULT_ACCEPTANCE)
        self.assertEquals(rep.u.ctx_list[0].reason,
                dcerpc.DCERPC_BIND_ACK_REASON_NOT_SPECIFIED)
        self.assertNDRSyntaxEquals(rep.u.ctx_list[0].syntax, ndr32)
        self.assertNotEquals(len(rep.u.auth_info), 0)
        a = self.parse_auth(rep.u.auth_info)

        from_server = a.credentials
        (finished, to_server) = g.update(from_server)
        self.assertTrue(finished)

        # And now try a request without auth_info
        req = self.generate_request(call_id = 2,
                                    context_id=ctx1.context_id,
                                    opnum=0,
                                    stub="")
        self.send_pdu(req)
        rep = self.recv_pdu()
        self.verify_pdu(rep, dcerpc.DCERPC_PKT_RESPONSE, req.call_id,
                        auth_length=0)
        self.assertNotEquals(rep.u.alloc_hint, 0)
        self.assertEquals(rep.u.context_id, req.u.context_id)
        self.assertEquals(rep.u.cancel_count, 0)
        self.assertGreaterEqual(len(rep.u.stub_and_verifier), rep.u.alloc_hint)

        # Now a request with auth_info DCERPC_AUTH_LEVEL_CONNECT
        auth_info = self.generate_auth(auth_type=auth_type,
                                       auth_level=auth_level,
                                       auth_context_id=auth_context_id,
                                       auth_blob="\x01"+"\x00"*15)
        req = self.generate_request(call_id = 3,
                                    context_id=ctx1.context_id,
                                    opnum=0,
                                    stub="",
                                    auth_info=auth_info)
        self.send_pdu(req)
        rep = self.recv_pdu()
        # We don't get an auth_info back
        self.verify_pdu(rep, dcerpc.DCERPC_PKT_RESPONSE, req.call_id,
                        auth_length=0)
        self.assertNotEquals(rep.u.alloc_hint, 0)
        self.assertEquals(rep.u.context_id, req.u.context_id)
        self.assertEquals(rep.u.cancel_count, 0)
        self.assertGreaterEqual(len(rep.u.stub_and_verifier), rep.u.alloc_hint)

        # Now a reauth

        g = gensec.Security.start_client(self.settings)
        g.set_credentials(c)
        g.want_feature(gensec.FEATURE_DCE_STYLE)
        auth_type = dcerpc.DCERPC_AUTH_TYPE_SPNEGO
        auth_level = dcerpc.DCERPC_AUTH_LEVEL_CONNECT
        auth_context_id = 2
        g.start_mech_by_authtype(auth_type, auth_level)
        from_server = ""
        (finished, to_server) = g.update(from_server)
        self.assertFalse(finished)

        auth_info = self.generate_auth(auth_type=auth_type,
                                       auth_level=auth_level,
                                       auth_context_id=auth_context_id,
                                       auth_blob=to_server)
        req = self.generate_auth3(call_id=0,
                                  auth_info=auth_info)
        self.send_pdu(req)
        rep = self.recv_pdu()
        # We get a fault
        self.verify_pdu(rep, dcerpc.DCERPC_PKT_FAULT, req.call_id,
                        pfc_flags=req.pfc_flags |
                        dcerpc.DCERPC_PFC_FLAG_DID_NOT_EXECUTE,
                        auth_length=0)
        self.assertNotEquals(rep.u.alloc_hint, 0)
        self.assertEquals(rep.u.context_id, 0)
        self.assertEquals(rep.u.cancel_count, 0)
        self.assertEquals(rep.u.flags, 0)
        self.assertEquals(rep.u.status, dcerpc.DCERPC_NCA_S_PROTO_ERROR)
        self.assertEquals(rep.u.reserved, 0)
        self.assertEquals(len(rep.u.error_and_verifier), 0)

        # wait for a disconnect
        rep = self.recv_pdu()
        self.assertIsNone(rep)
        self.assertNotConnected()

    def test_spnego_change_auth_level(self):
        ndr32 = base.transfer_syntax_ndr()

        tsf1_list = [ndr32]
        ctx1 = dcerpc.ctx_list()
        ctx1.context_id = 1
        ctx1.num_transfer_syntaxes = len(tsf1_list)
        ctx1.abstract_syntax = samba.dcerpc.mgmt.abstract_syntax()
        ctx1.transfer_syntaxes = tsf1_list

        c = self.get_anon_creds()
        g = gensec.Security.start_client(self.settings)
        g.set_credentials(c)
        g.want_feature(gensec.FEATURE_DCE_STYLE)
        auth_type = dcerpc.DCERPC_AUTH_TYPE_SPNEGO
        auth_level = dcerpc.DCERPC_AUTH_LEVEL_INTEGRITY
        auth_context_id = 2
        g.start_mech_by_authtype(auth_type, auth_level)
        from_server = ""
        (finished, to_server) = g.update(from_server)
        self.assertFalse(finished)

        auth_info = self.generate_auth(auth_type=auth_type,
                                       auth_level=auth_level,
                                       auth_context_id=auth_context_id,
                                       auth_blob=to_server)
        req = self.generate_bind(call_id=0,
                                 ctx_list=[ctx1],
                                 auth_info=auth_info)
        self.send_pdu(req)
        rep = self.recv_pdu()
        self.verify_pdu(rep, dcerpc.DCERPC_PKT_BIND_ACK, req.call_id)
        self.assertEquals(rep.u.max_xmit_frag, req.u.max_xmit_frag)
        self.assertEquals(rep.u.max_recv_frag, req.u.max_recv_frag)
        self.assertNotEquals(rep.u.assoc_group_id, req.u.assoc_group_id)
        self.assertEquals(rep.u.secondary_address_size, 4)
        self.assertEquals(rep.u.secondary_address, "%d" % self.tcp_port)
        self.assertEquals(len(rep.u._pad1), 2)
        self.assertEquals(rep.u._pad1, '\0' * 2)
        self.assertEquals(rep.u.num_results, 1)
        self.assertEquals(rep.u.ctx_list[0].result,
                dcerpc.DCERPC_BIND_ACK_RESULT_ACCEPTANCE)
        self.assertEquals(rep.u.ctx_list[0].reason,
                dcerpc.DCERPC_BIND_ACK_REASON_NOT_SPECIFIED)
        self.assertNDRSyntaxEquals(rep.u.ctx_list[0].syntax, ndr32)
        self.assertNotEquals(len(rep.u.auth_info), 0)
        a = self.parse_auth(rep.u.auth_info)

        from_server = a.credentials
        (finished, to_server) = g.update(from_server)
        self.assertFalse(finished)

        auth_info = self.generate_auth(auth_type=auth_type,
                                       auth_level=dcerpc.DCERPC_AUTH_LEVEL_PRIVACY,
                                       auth_context_id=auth_context_id,
                                       auth_blob=to_server)
        req = self.generate_alter(call_id=0,
                                  ctx_list=[ctx1],
                                  assoc_group_id=rep.u.assoc_group_id,
                                  auth_info=auth_info)
        self.send_pdu(req)
        rep = self.recv_pdu()
        self.verify_pdu(rep, dcerpc.DCERPC_PKT_FAULT, req.call_id,
                        pfc_flags=req.pfc_flags |
                        dcerpc.DCERPC_PFC_FLAG_DID_NOT_EXECUTE,
                        auth_length=0)
        self.assertNotEquals(rep.u.alloc_hint, 0)
        self.assertEquals(rep.u.context_id, 0)
        self.assertEquals(rep.u.cancel_count, 0)
        self.assertEquals(rep.u.flags, 0)
        self.assertEquals(rep.u.status, dcerpc.DCERPC_FAULT_ACCESS_DENIED)
        self.assertEquals(rep.u.reserved, 0)
        self.assertEquals(len(rep.u.error_and_verifier), 0)

        # wait for a disconnect
        rep = self.recv_pdu()
        self.assertIsNone(rep)
        self.assertNotConnected()

    def test_spnego_change_abstract(self):
        ndr32 = base.transfer_syntax_ndr()

        tsf1_list = [ndr32]
        ctx1 = dcerpc.ctx_list()
        ctx1.context_id = 1
        ctx1.num_transfer_syntaxes = len(tsf1_list)
        ctx1.abstract_syntax = samba.dcerpc.mgmt.abstract_syntax()
        ctx1.transfer_syntaxes = tsf1_list

        ctx1b = dcerpc.ctx_list()
        ctx1b.context_id = 1
        ctx1b.num_transfer_syntaxes = len(tsf1_list)
        ctx1b.abstract_syntax = samba.dcerpc.epmapper.abstract_syntax()
        ctx1b.transfer_syntaxes = tsf1_list

        c = self.get_anon_creds()
        g = gensec.Security.start_client(self.settings)
        g.set_credentials(c)
        g.want_feature(gensec.FEATURE_DCE_STYLE)
        auth_type = dcerpc.DCERPC_AUTH_TYPE_SPNEGO
        auth_level = dcerpc.DCERPC_AUTH_LEVEL_INTEGRITY
        auth_context_id = 2
        g.start_mech_by_authtype(auth_type, auth_level)
        from_server = ""
        (finished, to_server) = g.update(from_server)
        self.assertFalse(finished)

        auth_info = self.generate_auth(auth_type=auth_type,
                                       auth_level=auth_level,
                                       auth_context_id=auth_context_id,
                                       auth_blob=to_server)
        req = self.generate_bind(call_id=0,
                                 ctx_list=[ctx1],
                                 auth_info=auth_info)
        self.send_pdu(req)
        rep = self.recv_pdu()
        self.verify_pdu(rep, dcerpc.DCERPC_PKT_BIND_ACK, req.call_id)
        self.assertEquals(rep.u.max_xmit_frag, req.u.max_xmit_frag)
        self.assertEquals(rep.u.max_recv_frag, req.u.max_recv_frag)
        self.assertNotEquals(rep.u.assoc_group_id, req.u.assoc_group_id)
        self.assertEquals(rep.u.secondary_address_size, 4)
        self.assertEquals(rep.u.secondary_address, "%d" % self.tcp_port)
        self.assertEquals(len(rep.u._pad1), 2)
        #self.assertEquals(rep.u._pad1, '\0' * 2)
        self.assertEquals(rep.u.num_results, 1)
        self.assertEquals(rep.u.ctx_list[0].result,
                dcerpc.DCERPC_BIND_ACK_RESULT_ACCEPTANCE)
        self.assertEquals(rep.u.ctx_list[0].reason,
                dcerpc.DCERPC_BIND_ACK_REASON_NOT_SPECIFIED)
        self.assertNDRSyntaxEquals(rep.u.ctx_list[0].syntax, ndr32)
        self.assertNotEquals(len(rep.u.auth_info), 0)
        a = self.parse_auth(rep.u.auth_info)

        from_server = a.credentials
        (finished, to_server) = g.update(from_server)
        self.assertFalse(finished)

        auth_info = self.generate_auth(auth_type=auth_type,
                                       auth_level=dcerpc.DCERPC_AUTH_LEVEL_PRIVACY,
                                       auth_context_id=auth_context_id,
                                       auth_blob=to_server)
        req = self.generate_alter(call_id=0,
                                  ctx_list=[ctx1b],
                                  assoc_group_id=rep.u.assoc_group_id,
                                  auth_info=auth_info)
        self.send_pdu(req)
        rep = self.recv_pdu()
        self.verify_pdu(rep, dcerpc.DCERPC_PKT_FAULT, req.call_id,
                        pfc_flags=req.pfc_flags |
                        dcerpc.DCERPC_PFC_FLAG_DID_NOT_EXECUTE,
                        auth_length=0)
        self.assertNotEquals(rep.u.alloc_hint, 0)
        self.assertEquals(rep.u.context_id, 0)
        self.assertEquals(rep.u.cancel_count, 0)
        self.assertEquals(rep.u.flags, 0)
        self.assertEquals(rep.u.status, dcerpc.DCERPC_NCA_S_PROTO_ERROR)
        self.assertEquals(rep.u.reserved, 0)
        self.assertEquals(len(rep.u.error_and_verifier), 0)

        # wait for a disconnect
        rep = self.recv_pdu()
        self.assertIsNone(rep)
        self.assertNotConnected()

    def test_spnego_change_transfer(self):
        ndr32 = base.transfer_syntax_ndr()
        ndr64 = base.transfer_syntax_ndr64()

        tsf1_list = [ndr32]
        ctx1 = dcerpc.ctx_list()
        ctx1.context_id = 1
        ctx1.num_transfer_syntaxes = len(tsf1_list)
        ctx1.abstract_syntax = samba.dcerpc.mgmt.abstract_syntax()
        ctx1.transfer_syntaxes = tsf1_list

        tsf1b_list = [ndr32,ndr64]
        ctx1b = dcerpc.ctx_list()
        ctx1b.context_id = 1
        ctx1b.num_transfer_syntaxes = len(tsf1b_list)
        ctx1b.abstract_syntax = samba.dcerpc.mgmt.abstract_syntax()
        ctx1b.transfer_syntaxes = tsf1b_list

        c = self.get_anon_creds()
        g = gensec.Security.start_client(self.settings)
        g.set_credentials(c)
        g.want_feature(gensec.FEATURE_DCE_STYLE)
        auth_type = dcerpc.DCERPC_AUTH_TYPE_SPNEGO
        auth_level = dcerpc.DCERPC_AUTH_LEVEL_INTEGRITY
        auth_context_id = 2
        g.start_mech_by_authtype(auth_type, auth_level)
        from_server = ""
        (finished, to_server) = g.update(from_server)
        self.assertFalse(finished)

        auth_info = self.generate_auth(auth_type=auth_type,
                                       auth_level=auth_level,
                                       auth_context_id=auth_context_id,
                                       auth_blob=to_server)
        req = self.generate_bind(call_id=0,
                                 ctx_list=[ctx1],
                                 auth_info=auth_info)
        self.send_pdu(req)
        rep = self.recv_pdu()
        self.verify_pdu(rep, dcerpc.DCERPC_PKT_BIND_ACK, req.call_id)
        self.assertEquals(rep.u.max_xmit_frag, req.u.max_xmit_frag)
        self.assertEquals(rep.u.max_recv_frag, req.u.max_recv_frag)
        self.assertNotEquals(rep.u.assoc_group_id, req.u.assoc_group_id)
        self.assertEquals(rep.u.secondary_address_size, 4)
        self.assertEquals(rep.u.secondary_address, "%d" % self.tcp_port)
        self.assertEquals(len(rep.u._pad1), 2)
        #self.assertEquals(rep.u._pad1, '\0' * 2)
        self.assertEquals(rep.u.num_results, 1)
        self.assertEquals(rep.u.ctx_list[0].result,
                dcerpc.DCERPC_BIND_ACK_RESULT_ACCEPTANCE)
        self.assertEquals(rep.u.ctx_list[0].reason,
                dcerpc.DCERPC_BIND_ACK_REASON_NOT_SPECIFIED)
        self.assertNDRSyntaxEquals(rep.u.ctx_list[0].syntax, ndr32)
        self.assertNotEquals(len(rep.u.auth_info), 0)
        a = self.parse_auth(rep.u.auth_info)

        from_server = a.credentials
        (finished, to_server) = g.update(from_server)
        self.assertFalse(finished)

        # We change ctx_list and auth_level
        auth_info = self.generate_auth(auth_type=auth_type,
                                       auth_level=dcerpc.DCERPC_AUTH_LEVEL_PRIVACY,
                                       auth_context_id=auth_context_id,
                                       auth_blob=to_server)
        req = self.generate_alter(call_id=0,
                                  ctx_list=[ctx1b],
                                  assoc_group_id=rep.u.assoc_group_id,
                                  auth_info=auth_info)
        self.send_pdu(req)
        rep = self.recv_pdu()
        self.verify_pdu(rep, dcerpc.DCERPC_PKT_FAULT, req.call_id,
                        pfc_flags=req.pfc_flags |
                        dcerpc.DCERPC_PFC_FLAG_DID_NOT_EXECUTE,
                        auth_length=0)
        self.assertNotEquals(rep.u.alloc_hint, 0)
        self.assertEquals(rep.u.context_id, 0)
        self.assertEquals(rep.u.cancel_count, 0)
        self.assertEquals(rep.u.flags, 0)
        self.assertEquals(rep.u.status, dcerpc.DCERPC_NCA_S_PROTO_ERROR)
        self.assertEquals(rep.u.reserved, 0)
        self.assertEquals(len(rep.u.error_and_verifier), 0)

        # wait for a disconnect
        rep = self.recv_pdu()
        self.assertIsNone(rep)
        self.assertNotConnected()

    def test_spnego_change_auth_type1(self):
        ndr32 = base.transfer_syntax_ndr()
        ndr64 = base.transfer_syntax_ndr64()

        tsf1_list = [ndr32]
        ctx1 = dcerpc.ctx_list()
        ctx1.context_id = 1
        ctx1.num_transfer_syntaxes = len(tsf1_list)
        ctx1.abstract_syntax = samba.dcerpc.mgmt.abstract_syntax()
        ctx1.transfer_syntaxes = tsf1_list

        c = self.get_anon_creds()
        g = gensec.Security.start_client(self.settings)
        g.set_credentials(c)
        g.want_feature(gensec.FEATURE_DCE_STYLE)
        auth_type = dcerpc.DCERPC_AUTH_TYPE_SPNEGO
        auth_level = dcerpc.DCERPC_AUTH_LEVEL_INTEGRITY
        auth_context_id = 2
        g.start_mech_by_authtype(auth_type, auth_level)
        from_server = ""
        (finished, to_server) = g.update(from_server)
        self.assertFalse(finished)

        auth_info = self.generate_auth(auth_type=auth_type,
                                       auth_level=auth_level,
                                       auth_context_id=auth_context_id,
                                       auth_blob=to_server)
        req = self.generate_bind(call_id=0,
                                 ctx_list=[ctx1],
                                 auth_info=auth_info)
        self.send_pdu(req)
        rep = self.recv_pdu()
        self.verify_pdu(rep, dcerpc.DCERPC_PKT_BIND_ACK, req.call_id)
        self.assertEquals(rep.u.max_xmit_frag, req.u.max_xmit_frag)
        self.assertEquals(rep.u.max_recv_frag, req.u.max_recv_frag)
        self.assertNotEquals(rep.u.assoc_group_id, req.u.assoc_group_id)
        self.assertEquals(rep.u.secondary_address_size, 4)
        self.assertEquals(rep.u.secondary_address, "%d" % self.tcp_port)
        self.assertEquals(len(rep.u._pad1), 2)
        #self.assertEquals(rep.u._pad1, '\0' * 2)
        self.assertEquals(rep.u.num_results, 1)
        self.assertEquals(rep.u.ctx_list[0].result,
                dcerpc.DCERPC_BIND_ACK_RESULT_ACCEPTANCE)
        self.assertEquals(rep.u.ctx_list[0].reason,
                dcerpc.DCERPC_BIND_ACK_REASON_NOT_SPECIFIED)
        self.assertNDRSyntaxEquals(rep.u.ctx_list[0].syntax, ndr32)
        self.assertNotEquals(len(rep.u.auth_info), 0)
        a = self.parse_auth(rep.u.auth_info)

        from_server = a.credentials
        (finished, to_server) = g.update(from_server)
        self.assertFalse(finished)

        # We change ctx_list and auth_level
        auth_info = self.generate_auth(auth_type=dcerpc.DCERPC_AUTH_TYPE_KRB5,
                                       auth_level=auth_level,
                                       auth_context_id=auth_context_id,
                                       auth_blob=to_server)
        req = self.generate_alter(call_id=0,
                                  ctx_list=[ctx1],
                                  assoc_group_id=rep.u.assoc_group_id,
                                  auth_info=auth_info)
        self.send_pdu(req)
        rep = self.recv_pdu()
        self.verify_pdu(rep, dcerpc.DCERPC_PKT_FAULT, req.call_id,
                        pfc_flags=req.pfc_flags |
                        dcerpc.DCERPC_PFC_FLAG_DID_NOT_EXECUTE,
                        auth_length=0)
        self.assertNotEquals(rep.u.alloc_hint, 0)
        self.assertEquals(rep.u.context_id, 0)
        self.assertEquals(rep.u.cancel_count, 0)
        self.assertEquals(rep.u.flags, 0)
        self.assertEquals(rep.u.status, dcerpc.DCERPC_FAULT_SEC_PKG_ERROR)
        self.assertEquals(rep.u.reserved, 0)
        self.assertEquals(len(rep.u.error_and_verifier), 0)

        # wait for a disconnect
        rep = self.recv_pdu()
        self.assertIsNone(rep)
        self.assertNotConnected()

    def test_spnego_change_auth_type2(self):
        ndr32 = base.transfer_syntax_ndr()
        ndr64 = base.transfer_syntax_ndr64()

        tsf1_list = [ndr32]
        ctx1 = dcerpc.ctx_list()
        ctx1.context_id = 1
        ctx1.num_transfer_syntaxes = len(tsf1_list)
        ctx1.abstract_syntax = samba.dcerpc.mgmt.abstract_syntax()
        ctx1.transfer_syntaxes = tsf1_list

        tsf1b_list = [ndr32,ndr64]
        ctx1b = dcerpc.ctx_list()
        ctx1b.context_id = 1
        ctx1b.num_transfer_syntaxes = len(tsf1b_list)
        ctx1b.abstract_syntax = samba.dcerpc.mgmt.abstract_syntax()
        ctx1b.transfer_syntaxes = tsf1b_list

        c = self.get_anon_creds()
        g = gensec.Security.start_client(self.settings)
        g.set_credentials(c)
        g.want_feature(gensec.FEATURE_DCE_STYLE)
        auth_type = dcerpc.DCERPC_AUTH_TYPE_SPNEGO
        auth_level = dcerpc.DCERPC_AUTH_LEVEL_INTEGRITY
        auth_context_id = 2
        g.start_mech_by_authtype(auth_type, auth_level)
        from_server = ""
        (finished, to_server) = g.update(from_server)
        self.assertFalse(finished)

        auth_info = self.generate_auth(auth_type=auth_type,
                                       auth_level=auth_level,
                                       auth_context_id=auth_context_id,
                                       auth_blob=to_server)
        req = self.generate_bind(call_id=0,
                                 ctx_list=[ctx1],
                                 auth_info=auth_info)
        self.send_pdu(req)
        rep = self.recv_pdu()
        self.verify_pdu(rep, dcerpc.DCERPC_PKT_BIND_ACK, req.call_id)
        self.assertEquals(rep.u.max_xmit_frag, req.u.max_xmit_frag)
        self.assertEquals(rep.u.max_recv_frag, req.u.max_recv_frag)
        self.assertNotEquals(rep.u.assoc_group_id, req.u.assoc_group_id)
        self.assertEquals(rep.u.secondary_address_size, 4)
        self.assertEquals(rep.u.secondary_address, "%d" % self.tcp_port)
        self.assertEquals(len(rep.u._pad1), 2)
        #self.assertEquals(rep.u._pad1, '\0' * 2)
        self.assertEquals(rep.u.num_results, 1)
        self.assertEquals(rep.u.ctx_list[0].result,
                dcerpc.DCERPC_BIND_ACK_RESULT_ACCEPTANCE)
        self.assertEquals(rep.u.ctx_list[0].reason,
                dcerpc.DCERPC_BIND_ACK_REASON_NOT_SPECIFIED)
        self.assertNDRSyntaxEquals(rep.u.ctx_list[0].syntax, ndr32)
        self.assertNotEquals(len(rep.u.auth_info), 0)
        a = self.parse_auth(rep.u.auth_info)

        from_server = a.credentials
        (finished, to_server) = g.update(from_server)
        self.assertFalse(finished)

        # We change ctx_list and auth_level
        auth_info = self.generate_auth(auth_type=dcerpc.DCERPC_AUTH_TYPE_KRB5,
                                       auth_level=auth_level,
                                       auth_context_id=auth_context_id,
                                       auth_blob=to_server)
        req = self.generate_alter(call_id=0,
                                  ctx_list=[ctx1b],
                                  assoc_group_id=rep.u.assoc_group_id,
                                  auth_info=auth_info)
        self.send_pdu(req)
        rep = self.recv_pdu()
        self.verify_pdu(rep, dcerpc.DCERPC_PKT_FAULT, req.call_id,
                        pfc_flags=req.pfc_flags |
                        dcerpc.DCERPC_PFC_FLAG_DID_NOT_EXECUTE,
                        auth_length=0)
        self.assertNotEquals(rep.u.alloc_hint, 0)
        self.assertEquals(rep.u.context_id, 0)
        self.assertEquals(rep.u.cancel_count, 0)
        self.assertEquals(rep.u.flags, 0)
        self.assertEquals(rep.u.status, dcerpc.DCERPC_NCA_S_PROTO_ERROR)
        self.assertEquals(rep.u.reserved, 0)
        self.assertEquals(len(rep.u.error_and_verifier), 0)

        # wait for a disconnect
        rep = self.recv_pdu()
        self.assertIsNone(rep)
        self.assertNotConnected()

    def test_spnego_change_auth_type3(self):
        ndr32 = base.transfer_syntax_ndr()
        ndr64 = base.transfer_syntax_ndr64()

        tsf1_list = [ndr32]
        ctx1 = dcerpc.ctx_list()
        ctx1.context_id = 1
        ctx1.num_transfer_syntaxes = len(tsf1_list)
        ctx1.abstract_syntax = samba.dcerpc.mgmt.abstract_syntax()
        ctx1.transfer_syntaxes = tsf1_list

        tsf1b_list = [ndr32,ndr64]
        ctx1b = dcerpc.ctx_list()
        ctx1b.context_id = 1
        ctx1b.num_transfer_syntaxes = len(tsf1b_list)
        ctx1b.abstract_syntax = samba.dcerpc.mgmt.abstract_syntax()
        ctx1b.transfer_syntaxes = tsf1b_list

        c = self.get_anon_creds()
        g = gensec.Security.start_client(self.settings)
        g.set_credentials(c)
        g.want_feature(gensec.FEATURE_DCE_STYLE)
        auth_type = dcerpc.DCERPC_AUTH_TYPE_SPNEGO
        auth_level = dcerpc.DCERPC_AUTH_LEVEL_INTEGRITY
        auth_context_id = 2
        g.start_mech_by_authtype(auth_type, auth_level)
        from_server = ""
        (finished, to_server) = g.update(from_server)
        self.assertFalse(finished)

        auth_info = self.generate_auth(auth_type=auth_type,
                                       auth_level=auth_level,
                                       auth_context_id=auth_context_id,
                                       auth_blob=to_server)
        req = self.generate_bind(call_id=0,
                                 ctx_list=[ctx1],
                                 auth_info=auth_info)
        self.send_pdu(req)
        rep = self.recv_pdu()
        self.verify_pdu(rep, dcerpc.DCERPC_PKT_BIND_ACK, req.call_id)
        self.assertEquals(rep.u.max_xmit_frag, req.u.max_xmit_frag)
        self.assertEquals(rep.u.max_recv_frag, req.u.max_recv_frag)
        self.assertNotEquals(rep.u.assoc_group_id, req.u.assoc_group_id)
        self.assertEquals(rep.u.secondary_address_size, 4)
        self.assertEquals(rep.u.secondary_address, "%d" % self.tcp_port)
        self.assertEquals(len(rep.u._pad1), 2)
        #self.assertEquals(rep.u._pad1, '\0' * 2)
        self.assertEquals(rep.u.num_results, 1)
        self.assertEquals(rep.u.ctx_list[0].result,
                dcerpc.DCERPC_BIND_ACK_RESULT_ACCEPTANCE)
        self.assertEquals(rep.u.ctx_list[0].reason,
                dcerpc.DCERPC_BIND_ACK_REASON_NOT_SPECIFIED)
        self.assertNDRSyntaxEquals(rep.u.ctx_list[0].syntax, ndr32)
        self.assertNotEquals(len(rep.u.auth_info), 0)
        a = self.parse_auth(rep.u.auth_info)

        from_server = a.credentials
        (finished, to_server) = g.update(from_server)
        self.assertFalse(finished)

        # We change ctx_list and auth_level
        auth_info = self.generate_auth(auth_type=dcerpc.DCERPC_AUTH_TYPE_NONE,
                                       auth_level=auth_level,
                                       auth_context_id=auth_context_id,
                                       auth_blob=to_server)
        req = self.generate_alter(call_id=0,
                                  ctx_list=[ctx1b],
                                  assoc_group_id=rep.u.assoc_group_id,
                                  auth_info=auth_info)
        self.send_pdu(req)
        rep = self.recv_pdu()
        self.verify_pdu(rep, dcerpc.DCERPC_PKT_FAULT, req.call_id,
                        pfc_flags=req.pfc_flags |
                        dcerpc.DCERPC_PFC_FLAG_DID_NOT_EXECUTE,
                        auth_length=0)
        self.assertNotEquals(rep.u.alloc_hint, 0)
        self.assertEquals(rep.u.context_id, 0)
        self.assertEquals(rep.u.cancel_count, 0)
        self.assertEquals(rep.u.flags, 0)
        self.assertEquals(rep.u.status, dcerpc.DCERPC_FAULT_ACCESS_DENIED)
        self.assertEquals(rep.u.reserved, 0)
        self.assertEquals(len(rep.u.error_and_verifier), 0)

        # wait for a disconnect
        rep = self.recv_pdu()
        self.assertIsNone(rep)
        self.assertNotConnected()

    def test_spnego_auth_pad_ok(self):
        ndr32 = base.transfer_syntax_ndr()

        tsf1_list = [ndr32]
        ctx1 = dcerpc.ctx_list()
        ctx1.context_id = 1
        ctx1.num_transfer_syntaxes = len(tsf1_list)
        ctx1.abstract_syntax = samba.dcerpc.mgmt.abstract_syntax()
        ctx1.transfer_syntaxes = tsf1_list
        ctx_list = [ctx1]

        c = self.get_anon_creds()
        g = gensec.Security.start_client(self.settings)
        g.set_credentials(c)
        g.want_feature(gensec.FEATURE_DCE_STYLE)
        auth_type = dcerpc.DCERPC_AUTH_TYPE_SPNEGO
        auth_level = dcerpc.DCERPC_AUTH_LEVEL_CONNECT
        auth_context_id = 2
        g.start_mech_by_authtype(auth_type, auth_level)
        from_server = ""
        (finished, to_server) = g.update(from_server)
        self.assertFalse(finished)

        auth_info = self.generate_auth(auth_type=auth_type,
                                       auth_level=auth_level,
                                       auth_context_id=auth_context_id,
                                       auth_blob=to_server)

        req = self.generate_bind(call_id=0,
                                 ctx_list=ctx_list,
                                 auth_info=auth_info)
        req_pdu = samba.ndr.ndr_pack(req)

        auth_pad_ok = len(req_pdu)
        auth_pad_ok -= dcerpc.DCERPC_REQUEST_LENGTH
        auth_pad_ok -= dcerpc.DCERPC_AUTH_TRAILER_LENGTH
        auth_pad_ok -= len(to_server)

        auth_info = self.generate_auth(auth_type=auth_type,
                                       auth_level=auth_level,
                                       auth_context_id=auth_context_id,
                                       auth_pad_length=auth_pad_ok,
                                       auth_blob=to_server)

        req = self.generate_bind(call_id=0,
                                 ctx_list=ctx_list,
                                 auth_info=auth_info)
        self.send_pdu(req)
        rep = self.recv_pdu()
        self.verify_pdu(rep, dcerpc.DCERPC_PKT_BIND_ACK, req.call_id)
        self.assertEquals(rep.u.max_xmit_frag, req.u.max_xmit_frag)
        self.assertEquals(rep.u.max_recv_frag, req.u.max_recv_frag)
        self.assertNotEquals(rep.u.assoc_group_id, req.u.assoc_group_id)
        self.assertEquals(rep.u.secondary_address_size, 4)
        self.assertEquals(rep.u.secondary_address, "%d" % self.tcp_port)
        self.assertEquals(len(rep.u._pad1), 2)
        #self.assertEquals(rep.u._pad1, '\0' * 2)
        self.assertEquals(rep.u.num_results, 1)
        self.assertEquals(rep.u.ctx_list[0].result,
                dcerpc.DCERPC_BIND_ACK_RESULT_ACCEPTANCE)
        self.assertEquals(rep.u.ctx_list[0].reason,
                dcerpc.DCERPC_BIND_ACK_REASON_NOT_SPECIFIED)
        self.assertNDRSyntaxEquals(rep.u.ctx_list[0].syntax, ndr32)
        self.assertNotEquals(len(rep.u.auth_info), 0)
        a = self.parse_auth(rep.u.auth_info)

        from_server = a.credentials
        (finished, to_server) = g.update(from_server)
        self.assertFalse(finished)

        auth_info = self.generate_auth(auth_type=auth_type,
                                       auth_level=auth_level,
                                       auth_context_id=auth_context_id,
                                       auth_blob=to_server)
        req = self.generate_alter(call_id=0,
                                  ctx_list=ctx_list,
                                  assoc_group_id=rep.u.assoc_group_id,
                                  auth_info=auth_info)
        req_pdu = samba.ndr.ndr_pack(req)

        auth_pad_ok = len(req_pdu)
        auth_pad_ok -= dcerpc.DCERPC_REQUEST_LENGTH
        auth_pad_ok -= dcerpc.DCERPC_AUTH_TRAILER_LENGTH
        auth_pad_ok -= len(to_server)
        auth_info = self.generate_auth(auth_type=auth_type,
                                       auth_level=auth_level,
                                       auth_context_id=auth_context_id,
                                       auth_pad_length=auth_pad_ok,
                                       auth_blob=to_server)
        req = self.generate_alter(call_id=0,
                                  ctx_list=ctx_list,
                                  assoc_group_id=rep.u.assoc_group_id,
                                  auth_info=auth_info)
        self.send_pdu(req)
        rep = self.recv_pdu()
        self.verify_pdu(rep, dcerpc.DCERPC_PKT_ALTER_RESP, req.call_id)
        self.assertEquals(rep.u.max_xmit_frag, req.u.max_xmit_frag)
        self.assertEquals(rep.u.max_recv_frag, req.u.max_recv_frag)
        self.assertEquals(rep.u.assoc_group_id, req.u.assoc_group_id)
        self.assertEquals(rep.u.secondary_address_size, 0)
        self.assertEquals(len(rep.u._pad1), 2)
        # Windows sends garbage
        #self.assertEquals(rep.u._pad1, '\0' * 2)
        self.assertEquals(rep.u.num_results, 1)
        self.assertEquals(rep.u.ctx_list[0].result,
                dcerpc.DCERPC_BIND_ACK_RESULT_ACCEPTANCE)
        self.assertEquals(rep.u.ctx_list[0].reason,
                dcerpc.DCERPC_BIND_ACK_REASON_NOT_SPECIFIED)
        self.assertNDRSyntaxEquals(rep.u.ctx_list[0].syntax, ndr32)
        self.assertNotEquals(len(rep.u.auth_info), 0)
        a = self.parse_auth(rep.u.auth_info)

        from_server = a.credentials
        (finished, to_server) = g.update(from_server)
        self.assertTrue(finished)

        # And now try a request without auth_info
        req = self.generate_request(call_id = 2,
                                    context_id=ctx1.context_id,
                                    opnum=0,
                                    stub="")
        self.send_pdu(req)
        rep = self.recv_pdu()
        self.verify_pdu(rep, dcerpc.DCERPC_PKT_RESPONSE, req.call_id,
                        auth_length=0)
        self.assertNotEquals(rep.u.alloc_hint, 0)
        self.assertEquals(rep.u.context_id, req.u.context_id)
        self.assertEquals(rep.u.cancel_count, 0)
        self.assertGreaterEqual(len(rep.u.stub_and_verifier), rep.u.alloc_hint)

        # Now a request with auth_info DCERPC_AUTH_LEVEL_CONNECT
        auth_info = self.generate_auth(auth_type=auth_type,
                                       auth_level=auth_level,
                                       auth_context_id=auth_context_id,
                                       auth_blob="\x01"+"\x00"*15)
        req = self.generate_request(call_id = 3,
                                    context_id=ctx1.context_id,
                                    opnum=0,
                                    stub="",
                                    auth_info=auth_info)
        self.send_pdu(req)
        rep = self.recv_pdu()
        # We don't get an auth_info back
        self.verify_pdu(rep, dcerpc.DCERPC_PKT_RESPONSE, req.call_id,
                        auth_length=0)
        self.assertNotEquals(rep.u.alloc_hint, 0)
        self.assertEquals(rep.u.context_id, req.u.context_id)
        self.assertEquals(rep.u.cancel_count, 0)
        self.assertGreaterEqual(len(rep.u.stub_and_verifier), rep.u.alloc_hint)

        self._disconnect("disconnect")
        self.assertNotConnected()

    def test_spnego_auth_pad_fail_bind(self):
        ndr32 = base.transfer_syntax_ndr()

        tsf1_list = [ndr32]
        ctx1 = dcerpc.ctx_list()
        ctx1.context_id = 1
        ctx1.num_transfer_syntaxes = len(tsf1_list)
        ctx1.abstract_syntax = samba.dcerpc.mgmt.abstract_syntax()
        ctx1.transfer_syntaxes = tsf1_list
        ctx_list = [ctx1]

        c = self.get_anon_creds()
        g = gensec.Security.start_client(self.settings)
        g.set_credentials(c)
        g.want_feature(gensec.FEATURE_DCE_STYLE)
        auth_type = dcerpc.DCERPC_AUTH_TYPE_SPNEGO
        auth_level = dcerpc.DCERPC_AUTH_LEVEL_CONNECT
        auth_context_id = 2
        g.start_mech_by_authtype(auth_type, auth_level)
        from_server = ""
        (finished, to_server) = g.update(from_server)
        self.assertFalse(finished)

        auth_info = self.generate_auth(auth_type=auth_type,
                                       auth_level=auth_level,
                                       auth_context_id=auth_context_id,
                                       auth_blob=to_server)

        req = self.generate_bind(call_id=0,
                                 ctx_list=ctx_list,
                                 auth_info=auth_info)
        req_pdu = samba.ndr.ndr_pack(req)

        auth_pad_ok = len(req_pdu)
        auth_pad_ok -= dcerpc.DCERPC_REQUEST_LENGTH
        auth_pad_ok -= dcerpc.DCERPC_AUTH_TRAILER_LENGTH
        auth_pad_ok -= len(to_server)
        auth_pad_bad = auth_pad_ok + 1
        auth_info = self.generate_auth(auth_type=auth_type,
                                       auth_level=auth_level,
                                       auth_context_id=auth_context_id,
                                       auth_pad_length=auth_pad_bad,
                                       auth_blob=to_server)

        req = self.generate_bind(call_id=0,
                                 ctx_list=ctx_list,
                                 auth_info=auth_info)
        self.send_pdu(req)
        rep = self.recv_pdu()
        self.verify_pdu(rep, dcerpc.DCERPC_PKT_BIND_NAK, req.call_id,
                        auth_length=0)
        self.assertEquals(rep.u.reject_reason,
                dcerpc.DCERPC_BIND_NAK_REASON_PROTOCOL_VERSION_NOT_SUPPORTED)
        self.assertEquals(rep.u.num_versions, 1)
        self.assertEquals(rep.u.versions[0].rpc_vers, req.rpc_vers)
        self.assertEquals(rep.u.versions[0].rpc_vers_minor, req.rpc_vers_minor)
        self.assertEquals(len(rep.u._pad), 3)
        self.assertEquals(rep.u._pad, '\0' * 3)

        # wait for a disconnect
        rep = self.recv_pdu()
        self.assertIsNone(rep)
        self.assertNotConnected()

    def test_spnego_auth_pad_fail_alter(self):
        ndr32 = base.transfer_syntax_ndr()

        tsf1_list = [ndr32]
        ctx1 = dcerpc.ctx_list()
        ctx1.context_id = 1
        ctx1.num_transfer_syntaxes = len(tsf1_list)
        ctx1.abstract_syntax = samba.dcerpc.mgmt.abstract_syntax()
        ctx1.transfer_syntaxes = tsf1_list
        ctx_list = [ctx1]

        c = self.get_anon_creds()
        g = gensec.Security.start_client(self.settings)
        g.set_credentials(c)
        g.want_feature(gensec.FEATURE_DCE_STYLE)
        auth_type = dcerpc.DCERPC_AUTH_TYPE_SPNEGO
        auth_level = dcerpc.DCERPC_AUTH_LEVEL_CONNECT
        auth_context_id = 2
        g.start_mech_by_authtype(auth_type, auth_level)
        from_server = ""
        (finished, to_server) = g.update(from_server)
        self.assertFalse(finished)

        auth_info = self.generate_auth(auth_type=auth_type,
                                       auth_level=auth_level,
                                       auth_context_id=auth_context_id,
                                       auth_blob=to_server)

        req = self.generate_bind(call_id=0,
                                 ctx_list=ctx_list,
                                 auth_info=auth_info)
        req_pdu = samba.ndr.ndr_pack(req)

        auth_pad_ok = len(req_pdu)
        auth_pad_ok -= dcerpc.DCERPC_REQUEST_LENGTH
        auth_pad_ok -= dcerpc.DCERPC_AUTH_TRAILER_LENGTH
        auth_pad_ok -= len(to_server)

        auth_info = self.generate_auth(auth_type=auth_type,
                                       auth_level=auth_level,
                                       auth_context_id=auth_context_id,
                                       auth_pad_length=auth_pad_ok,
                                       auth_blob=to_server)

        req = self.generate_bind(call_id=0,
                                 ctx_list=ctx_list,
                                 auth_info=auth_info)
        self.send_pdu(req)
        rep = self.recv_pdu()
        self.verify_pdu(rep, dcerpc.DCERPC_PKT_BIND_ACK, req.call_id)
        self.assertEquals(rep.u.max_xmit_frag, req.u.max_xmit_frag)
        self.assertEquals(rep.u.max_recv_frag, req.u.max_recv_frag)
        self.assertNotEquals(rep.u.assoc_group_id, req.u.assoc_group_id)
        self.assertEquals(rep.u.secondary_address_size, 4)
        self.assertEquals(rep.u.secondary_address, "%d" % self.tcp_port)
        self.assertEquals(len(rep.u._pad1), 2)
        #self.assertEquals(rep.u._pad1, '\0' * 2)
        self.assertEquals(rep.u.num_results, 1)
        self.assertEquals(rep.u.ctx_list[0].result,
                dcerpc.DCERPC_BIND_ACK_RESULT_ACCEPTANCE)
        self.assertEquals(rep.u.ctx_list[0].reason,
                dcerpc.DCERPC_BIND_ACK_REASON_NOT_SPECIFIED)
        self.assertNDRSyntaxEquals(rep.u.ctx_list[0].syntax, ndr32)
        self.assertNotEquals(len(rep.u.auth_info), 0)
        a = self.parse_auth(rep.u.auth_info)

        from_server = a.credentials
        (finished, to_server) = g.update(from_server)
        self.assertFalse(finished)

        auth_info = self.generate_auth(auth_type=auth_type,
                                       auth_level=auth_level,
                                       auth_context_id=auth_context_id,
                                       auth_blob=to_server)
        req = self.generate_alter(call_id=0,
                                  ctx_list=ctx_list,
                                  assoc_group_id=rep.u.assoc_group_id,
                                  auth_info=auth_info)
        req_pdu = samba.ndr.ndr_pack(req)

        auth_pad_ok = len(req_pdu)
        auth_pad_ok -= dcerpc.DCERPC_REQUEST_LENGTH
        auth_pad_ok -= dcerpc.DCERPC_AUTH_TRAILER_LENGTH
        auth_pad_ok -= len(to_server)
        auth_pad_bad = auth_pad_ok + 1
        auth_info = self.generate_auth(auth_type=auth_type,
                                       auth_level=auth_level,
                                       auth_context_id=auth_context_id,
                                       auth_pad_length=auth_pad_bad,
                                       auth_blob=to_server)
        req = self.generate_alter(call_id=0,
                                  ctx_list=ctx_list,
                                  assoc_group_id=rep.u.assoc_group_id,
                                  auth_info=auth_info)
        self.send_pdu(req)
        rep = self.recv_pdu()
        self.verify_pdu(rep, dcerpc.DCERPC_PKT_FAULT, req.call_id,
                        pfc_flags=req.pfc_flags |
                        dcerpc.DCERPC_PFC_FLAG_DID_NOT_EXECUTE,
                        auth_length=0)
        self.assertNotEquals(rep.u.alloc_hint, 0)
        self.assertEquals(rep.u.context_id, 0)
        self.assertEquals(rep.u.cancel_count, 0)
        self.assertEquals(rep.u.flags, 0)
        self.assertEquals(rep.u.status, dcerpc.DCERPC_NCA_S_PROTO_ERROR)
        self.assertEquals(rep.u.reserved, 0)
        self.assertEquals(len(rep.u.error_and_verifier), 0)

        # wait for a disconnect
        rep = self.recv_pdu()
        self.assertIsNone(rep)
        self.assertNotConnected()

    def test_ntlmssp_auth_pad_ok(self):
        ndr32 = base.transfer_syntax_ndr()

        tsf1_list = [ndr32]
        ctx1 = dcerpc.ctx_list()
        ctx1.context_id = 1
        ctx1.num_transfer_syntaxes = len(tsf1_list)
        ctx1.abstract_syntax = samba.dcerpc.mgmt.abstract_syntax()
        ctx1.transfer_syntaxes = tsf1_list
        ctx_list = [ctx1]

        c = self.get_anon_creds()
        g = gensec.Security.start_client(self.settings)
        g.set_credentials(c)
        g.want_feature(gensec.FEATURE_DCE_STYLE)
        auth_type = dcerpc.DCERPC_AUTH_TYPE_NTLMSSP
        auth_level = dcerpc.DCERPC_AUTH_LEVEL_CONNECT
        auth_context_id = 2
        g.start_mech_by_authtype(auth_type, auth_level)
        from_server = ""
        (finished, to_server) = g.update(from_server)
        self.assertFalse(finished)

        auth_info = self.generate_auth(auth_type=auth_type,
                                       auth_level=auth_level,
                                       auth_context_id=auth_context_id,
                                       auth_blob=to_server)

        req = self.generate_bind(call_id=0,
                                 ctx_list=ctx_list,
                                 auth_info=auth_info)
        req_pdu = samba.ndr.ndr_pack(req)

        auth_pad_ok = len(req_pdu)
        auth_pad_ok -= dcerpc.DCERPC_REQUEST_LENGTH
        auth_pad_ok -= dcerpc.DCERPC_AUTH_TRAILER_LENGTH
        auth_pad_ok -= len(to_server)

        auth_info = self.generate_auth(auth_type=auth_type,
                                       auth_level=auth_level,
                                       auth_context_id=auth_context_id,
                                       auth_pad_length=auth_pad_ok,
                                       auth_blob=to_server)

        req = self.generate_bind(call_id=0,
                                 ctx_list=ctx_list,
                                 auth_info=auth_info)
        self.send_pdu(req)
        rep = self.recv_pdu()
        self.verify_pdu(rep, dcerpc.DCERPC_PKT_BIND_ACK, req.call_id)
        self.assertEquals(rep.u.max_xmit_frag, req.u.max_xmit_frag)
        self.assertEquals(rep.u.max_recv_frag, req.u.max_recv_frag)
        self.assertNotEquals(rep.u.assoc_group_id, req.u.assoc_group_id)
        self.assertEquals(rep.u.secondary_address_size, 4)
        self.assertEquals(rep.u.secondary_address, "%d" % self.tcp_port)
        self.assertEquals(len(rep.u._pad1), 2)
        #self.assertEquals(rep.u._pad1, '\0' * 2)
        self.assertEquals(rep.u.num_results, 1)
        self.assertEquals(rep.u.ctx_list[0].result,
                dcerpc.DCERPC_BIND_ACK_RESULT_ACCEPTANCE)
        self.assertEquals(rep.u.ctx_list[0].reason,
                dcerpc.DCERPC_BIND_ACK_REASON_NOT_SPECIFIED)
        self.assertNDRSyntaxEquals(rep.u.ctx_list[0].syntax, ndr32)
        self.assertNotEquals(len(rep.u.auth_info), 0)
        a = self.parse_auth(rep.u.auth_info)

        from_server = a.credentials
        (finished, to_server) = g.update(from_server)
        self.assertTrue(finished)

        auth_pad_ok = 0
        auth_info = self.generate_auth(auth_type=auth_type,
                                       auth_level=auth_level,
                                       auth_context_id=auth_context_id,
                                       auth_pad_length=auth_pad_ok,
                                       auth_blob=to_server)
        req = self.generate_auth3(call_id=0,
                                  auth_info=auth_info)
        self.send_pdu(req)
        self.assertIsConnected()

        # And now try a request without auth_info
        req = self.generate_request(call_id = 2,
                                    context_id=ctx1.context_id,
                                    opnum=0,
                                    stub="")
        self.send_pdu(req)
        rep = self.recv_pdu()
        self.verify_pdu(rep, dcerpc.DCERPC_PKT_RESPONSE, req.call_id,
                        auth_length=0)
        self.assertNotEquals(rep.u.alloc_hint, 0)
        self.assertEquals(rep.u.context_id, req.u.context_id)
        self.assertEquals(rep.u.cancel_count, 0)
        self.assertGreaterEqual(len(rep.u.stub_and_verifier), rep.u.alloc_hint)

        # Now a request with auth_info DCERPC_AUTH_LEVEL_CONNECT
        auth_info = self.generate_auth(auth_type=auth_type,
                                       auth_level=auth_level,
                                       auth_context_id=auth_context_id,
                                       auth_blob="\x01"+"\x00"*15)
        req = self.generate_request(call_id = 3,
                                    context_id=ctx1.context_id,
                                    opnum=0,
                                    stub="",
                                    auth_info=auth_info)
        self.send_pdu(req)
        rep = self.recv_pdu()
        # We don't get an auth_info back
        self.verify_pdu(rep, dcerpc.DCERPC_PKT_RESPONSE, req.call_id,
                        auth_length=0)
        self.assertNotEquals(rep.u.alloc_hint, 0)
        self.assertEquals(rep.u.context_id, req.u.context_id)
        self.assertEquals(rep.u.cancel_count, 0)
        self.assertGreaterEqual(len(rep.u.stub_and_verifier), rep.u.alloc_hint)

        self._disconnect("disconnect")
        self.assertNotConnected()

    def test_ntlmssp_auth_pad_fail_auth3(self):
        ndr32 = base.transfer_syntax_ndr()

        tsf1_list = [ndr32]
        ctx1 = dcerpc.ctx_list()
        ctx1.context_id = 1
        ctx1.num_transfer_syntaxes = len(tsf1_list)
        ctx1.abstract_syntax = samba.dcerpc.mgmt.abstract_syntax()
        ctx1.transfer_syntaxes = tsf1_list
        ctx_list = [ctx1]

        c = self.get_anon_creds()
        g = gensec.Security.start_client(self.settings)
        g.set_credentials(c)
        g.want_feature(gensec.FEATURE_DCE_STYLE)
        auth_type = dcerpc.DCERPC_AUTH_TYPE_NTLMSSP
        auth_level = dcerpc.DCERPC_AUTH_LEVEL_CONNECT
        auth_context_id = 2
        g.start_mech_by_authtype(auth_type, auth_level)
        from_server = ""
        (finished, to_server) = g.update(from_server)
        self.assertFalse(finished)

        auth_info = self.generate_auth(auth_type=auth_type,
                                       auth_level=auth_level,
                                       auth_context_id=auth_context_id,
                                       auth_blob=to_server)

        req = self.generate_bind(call_id=0,
                                 ctx_list=ctx_list,
                                 auth_info=auth_info)
        req_pdu = samba.ndr.ndr_pack(req)

        auth_pad_ok = len(req_pdu)
        auth_pad_ok -= dcerpc.DCERPC_REQUEST_LENGTH
        auth_pad_ok -= dcerpc.DCERPC_AUTH_TRAILER_LENGTH
        auth_pad_ok -= len(to_server)

        auth_info = self.generate_auth(auth_type=auth_type,
                                       auth_level=auth_level,
                                       auth_context_id=auth_context_id,
                                       auth_pad_length=auth_pad_ok,
                                       auth_blob=to_server)

        req = self.generate_bind(call_id=0,
                                 ctx_list=ctx_list,
                                 auth_info=auth_info)
        self.send_pdu(req)
        rep = self.recv_pdu()
        self.verify_pdu(rep, dcerpc.DCERPC_PKT_BIND_ACK, req.call_id)
        self.assertEquals(rep.u.max_xmit_frag, req.u.max_xmit_frag)
        self.assertEquals(rep.u.max_recv_frag, req.u.max_recv_frag)
        self.assertNotEquals(rep.u.assoc_group_id, req.u.assoc_group_id)
        self.assertEquals(rep.u.secondary_address_size, 4)
        self.assertEquals(rep.u.secondary_address, "%d" % self.tcp_port)
        self.assertEquals(len(rep.u._pad1), 2)
        #self.assertEquals(rep.u._pad1, '\0' * 2)
        self.assertEquals(rep.u.num_results, 1)
        self.assertEquals(rep.u.ctx_list[0].result,
                dcerpc.DCERPC_BIND_ACK_RESULT_ACCEPTANCE)
        self.assertEquals(rep.u.ctx_list[0].reason,
                dcerpc.DCERPC_BIND_ACK_REASON_NOT_SPECIFIED)
        self.assertNDRSyntaxEquals(rep.u.ctx_list[0].syntax, ndr32)
        self.assertNotEquals(len(rep.u.auth_info), 0)
        a = self.parse_auth(rep.u.auth_info)

        from_server = a.credentials
        (finished, to_server) = g.update(from_server)
        self.assertTrue(finished)

        auth_pad_bad = 1
        auth_info = self.generate_auth(auth_type=auth_type,
                                       auth_level=auth_level,
                                       auth_context_id=auth_context_id,
                                       auth_pad_length=auth_pad_bad,
                                       auth_blob=to_server)
        req = self.generate_auth3(call_id=0,
                                  auth_info=auth_info)
        self.send_pdu(req)
        rep = self.recv_pdu()
        self.verify_pdu(rep, dcerpc.DCERPC_PKT_FAULT, req.call_id,
                        pfc_flags=req.pfc_flags |
                        dcerpc.DCERPC_PFC_FLAG_DID_NOT_EXECUTE,
                        auth_length=0)
        self.assertNotEquals(rep.u.alloc_hint, 0)
        self.assertEquals(rep.u.context_id, 0)
        self.assertEquals(rep.u.cancel_count, 0)
        self.assertEquals(rep.u.flags, 0)
        self.assertEquals(rep.u.status, dcerpc.DCERPC_NCA_S_FAULT_REMOTE_NO_MEMORY)
        self.assertEquals(rep.u.reserved, 0)
        self.assertEquals(len(rep.u.error_and_verifier), 0)

        # wait for a disconnect
        rep = self.recv_pdu()
        self.assertIsNone(rep)
        self.assertNotConnected()

    def _test_spnego_bind_auth_level(self, auth_level, auth_context_id, ctx,
                                     g_auth_level=dcerpc.DCERPC_AUTH_LEVEL_INTEGRITY,
                                     alter_fault=None):
        creds = self.get_user_creds()
        auth_context = self.get_auth_context_creds(creds=creds,
                                                   auth_type=dcerpc.DCERPC_AUTH_TYPE_SPNEGO,
                                                   auth_level=auth_level,
                                                   auth_context_id=auth_context_id,
                                                   g_auth_level=g_auth_level)
        if auth_context is None:
            return None
        ack = self.do_generic_bind(ctx=ctx,
                                   auth_context=auth_context,
                                   alter_fault=alter_fault)
        if ack is None:
            return None
        return auth_context["gensec"]

    def _test_spnego_level_bind_nak(self, auth_level,
                                   reason=dcerpc.DCERPC_BIND_NAK_REASON_INVALID_CHECKSUM):
        c = self.get_user_creds()
        return self._test_auth_type_level_bind_nak(auth_type=dcerpc.DCERPC_AUTH_TYPE_SPNEGO,
                                                   auth_level=auth_level, creds=c, reason=reason)

    def _test_spnego_level_bind(self, auth_level,
                                g_auth_level=dcerpc.DCERPC_AUTH_LEVEL_INTEGRITY,
                                alter_fault=None,
                                request_fault=None,
                                response_fault_flags=0):
        ndr32 = base.transfer_syntax_ndr()

        tsf1_list = [ndr32]
        ctx1 = dcerpc.ctx_list()
        ctx1.context_id = 0x1001
        ctx1.num_transfer_syntaxes = len(tsf1_list)
        ctx1.abstract_syntax = samba.dcerpc.mgmt.abstract_syntax()
        ctx1.transfer_syntaxes = tsf1_list

        auth_type = dcerpc.DCERPC_AUTH_TYPE_SPNEGO
        auth_context_id = 2

        g = self._test_spnego_bind_auth_level(auth_level=auth_level,
                                              auth_context_id=auth_context_id,
                                              ctx=ctx1,
                                              g_auth_level=g_auth_level,
                                              alter_fault=alter_fault)

        if request_fault is None:
            return

        self.assertIsNotNone(g)

        stub_bin = '\x00' * 17
        mod_len = len(stub_bin) % dcerpc.DCERPC_AUTH_PAD_ALIGNMENT
        auth_pad_length = 0
        if mod_len > 0:
            auth_pad_length = dcerpc.DCERPC_AUTH_PAD_ALIGNMENT - mod_len
        stub_bin += '\x00' * auth_pad_length

        if g_auth_level >= dcerpc.DCERPC_AUTH_LEVEL_INTEGRITY:
            sig_size = g.sig_size(len(stub_bin))
        else:
            sig_size = 16
        zero_sig = "\x00"*sig_size

        auth_info = self.generate_auth(auth_type=auth_type,
                                       auth_level=auth_level,
                                       auth_pad_length=auth_pad_length,
                                       auth_context_id=auth_context_id,
                                       auth_blob=zero_sig)
        req = self.generate_request(call_id = 4,
                                    context_id=ctx1.context_id,
                                    opnum=0xffff,
                                    stub=stub_bin,
                                    auth_info=auth_info)
        if g_auth_level >= dcerpc.DCERPC_AUTH_LEVEL_INTEGRITY:
            req_blob = samba.ndr.ndr_pack(req)
            ofs_stub = dcerpc.DCERPC_REQUEST_LENGTH
            ofs_sig = len(req_blob) - req.auth_length
            ofs_trailer = ofs_sig - dcerpc.DCERPC_AUTH_TRAILER_LENGTH
            req_data = req_blob[ofs_stub:ofs_trailer]
            req_whole = req_blob[0:ofs_sig]
            sig = g.sign_packet(req_data, req_whole)
            auth_info = self.generate_auth(auth_type=auth_type,
                                           auth_level=auth_level,
                                           auth_pad_length=auth_pad_length,
                                           auth_context_id=auth_context_id,
                                           auth_blob=sig)
            req = self.generate_request(call_id = 4,
                                        context_id=ctx1.context_id,
                                        opnum=0xffff,
                                        stub=stub_bin,
                                        auth_info=auth_info)
        self.send_pdu(req)
        rep = self.recv_pdu()
        self.verify_pdu(rep, dcerpc.DCERPC_PKT_FAULT, req.call_id,
                        pfc_flags=req.pfc_flags | response_fault_flags,
                        auth_length=0)
        self.assertNotEquals(rep.u.alloc_hint, 0)
        self.assertEquals(rep.u.context_id, ctx1.context_id)
        self.assertEquals(rep.u.cancel_count, 0)
        self.assertEquals(rep.u.flags, 0)
        self.assertEquals(rep.u.status, request_fault)
        self.assertEquals(rep.u.reserved, 0)
        self.assertEquals(len(rep.u.error_and_verifier), 0)

        if response_fault_flags & dcerpc.DCERPC_PFC_FLAG_DID_NOT_EXECUTE:
            return

        # wait for a disconnect
        rep = self.recv_pdu()
        self.assertIsNone(rep)
        self.assertNotConnected()

    def test_spnego_none_bind(self):
        return self._test_spnego_level_bind_nak(dcerpc.DCERPC_AUTH_LEVEL_NONE,
                            reason=dcerpc.DCERPC_BIND_NAK_REASON_NOT_SPECIFIED)

    def test_spnego_call_bind(self):
        return self._test_spnego_level_bind_nak(dcerpc.DCERPC_AUTH_LEVEL_CALL,
                            reason=dcerpc.DCERPC_BIND_NAK_REASON_INVALID_CHECKSUM)

    def test_spnego_0_bind(self):
        return self._test_spnego_level_bind_nak(0,
                            reason=dcerpc.DCERPC_BIND_NAK_REASON_NOT_SPECIFIED)

    def test_spnego_7_bind(self):
        return self._test_spnego_level_bind_nak(7,
                            reason=dcerpc.DCERPC_BIND_NAK_REASON_NOT_SPECIFIED)

    def test_spnego_255_bind(self):
        return self._test_spnego_level_bind_nak(255,
                            reason=dcerpc.DCERPC_BIND_NAK_REASON_NOT_SPECIFIED)

    def test_spnego_connect_bind_none(self):
        return self._test_spnego_level_bind(auth_level=dcerpc.DCERPC_AUTH_LEVEL_CONNECT,
                                    g_auth_level=dcerpc.DCERPC_AUTH_LEVEL_CONNECT)

    def test_spnego_connect_bind_sign(self):
        return self._test_spnego_level_bind(auth_level=dcerpc.DCERPC_AUTH_LEVEL_CONNECT,
                                    g_auth_level=dcerpc.DCERPC_AUTH_LEVEL_INTEGRITY)

    def test_spnego_connect_bind_seal(self):
        return self._test_spnego_level_bind(auth_level=dcerpc.DCERPC_AUTH_LEVEL_CONNECT,
                                    g_auth_level=dcerpc.DCERPC_AUTH_LEVEL_PRIVACY)

    def test_spnego_packet_bind_none(self):
        # DCERPC_AUTH_LEVEL_PACKET is handled as alias of
        # DCERPC_AUTH_LEVEL_INTEGRITY
        return self._test_spnego_level_bind(auth_level=dcerpc.DCERPC_AUTH_LEVEL_PACKET,
                                    g_auth_level=dcerpc.DCERPC_AUTH_LEVEL_CONNECT,
                                    request_fault=dcerpc.DCERPC_FAULT_SEC_PKG_ERROR)

    def test_spnego_packet_bind_sign(self):
        # DCERPC_AUTH_LEVEL_PACKET is handled as alias of
        # DCERPC_AUTH_LEVEL_INTEGRITY
        return self._test_spnego_level_bind(auth_level=dcerpc.DCERPC_AUTH_LEVEL_PACKET,
                                    g_auth_level=dcerpc.DCERPC_AUTH_LEVEL_INTEGRITY,
                                    request_fault=dcerpc.DCERPC_NCA_S_OP_RNG_ERROR,
                                    response_fault_flags=dcerpc.DCERPC_PFC_FLAG_DID_NOT_EXECUTE)

    def test_spnego_packet_bind_sign(self):
        # DCERPC_AUTH_LEVEL_PACKET is handled as alias of
        # DCERPC_AUTH_LEVEL_INTEGRITY
        return self._test_spnego_level_bind(auth_level=dcerpc.DCERPC_AUTH_LEVEL_PACKET,
                                    g_auth_level=dcerpc.DCERPC_AUTH_LEVEL_PRIVACY,
                                    request_fault=dcerpc.DCERPC_NCA_S_OP_RNG_ERROR,
                                    response_fault_flags=dcerpc.DCERPC_PFC_FLAG_DID_NOT_EXECUTE)

    def test_spnego_integrity_bind_none(self):
        return self._test_spnego_level_bind(auth_level=dcerpc.DCERPC_AUTH_LEVEL_INTEGRITY,
                                    g_auth_level=dcerpc.DCERPC_AUTH_LEVEL_CONNECT,
                                    request_fault=dcerpc.DCERPC_FAULT_SEC_PKG_ERROR)

    def test_spnego_integrity_bind_sign(self):
        return self._test_spnego_level_bind(auth_level=dcerpc.DCERPC_AUTH_LEVEL_INTEGRITY,
                                    g_auth_level=dcerpc.DCERPC_AUTH_LEVEL_INTEGRITY,
                                    request_fault=dcerpc.DCERPC_NCA_S_OP_RNG_ERROR,
                                    response_fault_flags=dcerpc.DCERPC_PFC_FLAG_DID_NOT_EXECUTE)

    def test_spnego_integrity_bind_seal(self):
        return self._test_spnego_level_bind(auth_level=dcerpc.DCERPC_AUTH_LEVEL_INTEGRITY,
                                    g_auth_level=dcerpc.DCERPC_AUTH_LEVEL_PRIVACY,
                                    request_fault=dcerpc.DCERPC_NCA_S_OP_RNG_ERROR,
                                    response_fault_flags=dcerpc.DCERPC_PFC_FLAG_DID_NOT_EXECUTE)

    def test_spnego_privacy_bind_none(self):
        # This fails...
        return self._test_spnego_level_bind(auth_level=dcerpc.DCERPC_AUTH_LEVEL_PRIVACY,
                                    g_auth_level=dcerpc.DCERPC_AUTH_LEVEL_CONNECT,
                                    alter_fault=dcerpc.DCERPC_FAULT_SEC_PKG_ERROR)

    def test_spnego_privacy_bind_sign(self):
        # This fails...
        return self._test_spnego_level_bind(auth_level=dcerpc.DCERPC_AUTH_LEVEL_PRIVACY,
                                    g_auth_level=dcerpc.DCERPC_AUTH_LEVEL_INTEGRITY,
                                    alter_fault=dcerpc.DCERPC_FAULT_SEC_PKG_ERROR)

    def test_spnego_privacy_bind_seal(self):
        return self._test_spnego_level_bind(auth_level=dcerpc.DCERPC_AUTH_LEVEL_PRIVACY,
                                    g_auth_level=dcerpc.DCERPC_AUTH_LEVEL_PRIVACY)



    def _test_spnego_signing_auth_level_request(self, auth_level):
        ndr32 = base.transfer_syntax_ndr()

        tsf1_list = [ndr32]
        ctx1 = dcerpc.ctx_list()
        ctx1.context_id = 0x1001
        ctx1.num_transfer_syntaxes = len(tsf1_list)
        ctx1.abstract_syntax = samba.dcerpc.mgmt.abstract_syntax()
        ctx1.transfer_syntaxes = tsf1_list
        ctx_list = [ctx1]

        auth_type = dcerpc.DCERPC_AUTH_TYPE_SPNEGO
        auth_context_id = 2

        g = self._test_spnego_bind_auth_level(auth_level=auth_level,
                                              auth_context_id=auth_context_id,
                                              ctx=ctx1)

        stub_bin = '\x00' * 0
        mod_len = len(stub_bin) % dcerpc.DCERPC_AUTH_PAD_ALIGNMENT
        auth_pad_length = 0
        if mod_len > 0:
            auth_pad_length = dcerpc.DCERPC_AUTH_PAD_ALIGNMENT - mod_len
        stub_bin += '\x00' * auth_pad_length

        sig_size = g.sig_size(len(stub_bin))
        zero_sig = "\x00"*sig_size

        auth_info = self.generate_auth(auth_type=auth_type,
                                       auth_level=auth_level,
                                       auth_pad_length=auth_pad_length,
                                       auth_context_id=auth_context_id,
                                       auth_blob=zero_sig)
        req = self.generate_request(call_id = 3,
                                    context_id=ctx1.context_id,
                                    opnum=0,
                                    stub=stub_bin,
                                    auth_info=auth_info)
        req_blob = samba.ndr.ndr_pack(req)
        ofs_stub = dcerpc.DCERPC_REQUEST_LENGTH
        ofs_sig = len(req_blob) - req.auth_length
        ofs_trailer = ofs_sig - dcerpc.DCERPC_AUTH_TRAILER_LENGTH
        req_data = req_blob[ofs_stub:ofs_trailer]
        req_whole = req_blob[0:ofs_sig]
        sig = g.sign_packet(req_data, req_whole)
        auth_info = self.generate_auth(auth_type=auth_type,
                                       auth_level=auth_level,
                                       auth_pad_length=auth_pad_length,
                                       auth_context_id=auth_context_id,
                                       auth_blob=sig)
        req = self.generate_request(call_id = 3,
                                    context_id=ctx1.context_id,
                                    opnum=0,
                                    stub=stub_bin,
                                    auth_info=auth_info)
        self.send_pdu(req)
        (rep, rep_blob) = self.recv_pdu_raw()
        self.verify_pdu(rep, dcerpc.DCERPC_PKT_RESPONSE, req.call_id,
                        auth_length=sig_size)
        self.assertNotEquals(rep.u.alloc_hint, 0)
        self.assertEquals(rep.u.context_id, req.u.context_id & 0xff)
        self.assertEquals(rep.u.cancel_count, 0)
        self.assertGreaterEqual(len(rep.u.stub_and_verifier), rep.u.alloc_hint)
        self.assertEquals(rep.auth_length, sig_size)

        ofs_stub = dcerpc.DCERPC_REQUEST_LENGTH
        ofs_sig = rep.frag_length - rep.auth_length
        ofs_trailer = ofs_sig - dcerpc.DCERPC_AUTH_TRAILER_LENGTH
        rep_data = rep_blob[ofs_stub:ofs_trailer]
        rep_whole = rep_blob[0:ofs_sig]
        rep_sig = rep_blob[ofs_sig:]
        rep_auth_info_blob = rep_blob[ofs_trailer:]

        rep_auth_info = self.parse_auth(rep_auth_info_blob)
        self.assertEquals(rep_auth_info.auth_type, auth_type)
        self.assertEquals(rep_auth_info.auth_level, auth_level)
        # mgmt_inq_if_ids() returns no fixed size results
        #self.assertEquals(rep_auth_info.auth_pad_length, 0)
        self.assertEquals(rep_auth_info.auth_reserved, 0)
        self.assertEquals(rep_auth_info.auth_context_id, auth_context_id)
        self.assertEquals(rep_auth_info.credentials, rep_sig)

        g.check_packet(rep_data, rep_whole, rep_sig)

        stub_bin = '\x00' * 17
        mod_len = len(stub_bin) % dcerpc.DCERPC_AUTH_PAD_ALIGNMENT
        auth_pad_length = 0
        if mod_len > 0:
            auth_pad_length = dcerpc.DCERPC_AUTH_PAD_ALIGNMENT - mod_len
        stub_bin += '\x00' * auth_pad_length

        sig_size = g.sig_size(len(stub_bin))
        zero_sig = "\x00"*sig_size

        auth_info = self.generate_auth(auth_type=auth_type,
                                       auth_level=auth_level,
                                       auth_pad_length=auth_pad_length,
                                       auth_context_id=auth_context_id,
                                       auth_blob=zero_sig)
        req = self.generate_request(call_id = 4,
                                    context_id=ctx1.context_id,
                                    opnum=0xffff,
                                    stub=stub_bin,
                                    auth_info=auth_info)
        req_blob = samba.ndr.ndr_pack(req)
        ofs_stub = dcerpc.DCERPC_REQUEST_LENGTH
        ofs_sig = len(req_blob) - req.auth_length
        ofs_trailer = ofs_sig - dcerpc.DCERPC_AUTH_TRAILER_LENGTH
        req_data = req_blob[ofs_stub:ofs_trailer]
        req_whole = req_blob[0:ofs_sig]
        sig = g.sign_packet(req_data, req_whole)
        auth_info = self.generate_auth(auth_type=auth_type,
                                       auth_level=auth_level,
                                       auth_pad_length=auth_pad_length,
                                       auth_context_id=auth_context_id,
                                       auth_blob=sig)
        req = self.generate_request(call_id = 4,
                                    context_id=ctx1.context_id,
                                    opnum=0xffff,
                                    stub=stub_bin,
                                    auth_info=auth_info)
        self.send_pdu(req)
        rep = self.recv_pdu()
        self.verify_pdu(rep, dcerpc.DCERPC_PKT_FAULT, req.call_id,
                        pfc_flags=req.pfc_flags |
                        dcerpc.DCERPC_PFC_FLAG_DID_NOT_EXECUTE,
                        auth_length=0)
        self.assertNotEquals(rep.u.alloc_hint, 0)
        self.assertEquals(rep.u.context_id, ctx1.context_id)
        self.assertEquals(rep.u.cancel_count, 0)
        self.assertEquals(rep.u.flags, 0)
        self.assertEquals(rep.u.status, dcerpc.DCERPC_NCA_S_OP_RNG_ERROR)
        self.assertEquals(rep.u.reserved, 0)
        self.assertEquals(len(rep.u.error_and_verifier), 0)

        stub_bin = '\x00' * 8
        mod_len = len(stub_bin) % dcerpc.DCERPC_AUTH_PAD_ALIGNMENT
        auth_pad_length = 0
        if mod_len > 0:
            auth_pad_length = dcerpc.DCERPC_AUTH_PAD_ALIGNMENT - mod_len
        stub_bin += '\x00' * auth_pad_length

        sig_size = g.sig_size(len(stub_bin))
        zero_sig = "\x00"*sig_size

        auth_info = self.generate_auth(auth_type=auth_type,
                                       auth_level=auth_level,
                                       auth_pad_length=auth_pad_length,
                                       auth_context_id=auth_context_id,
                                       auth_blob=zero_sig)
        req = self.generate_request(call_id = 5,
                                    context_id=ctx1.context_id,
                                    opnum=1,
                                    stub=stub_bin,
                                    auth_info=auth_info)
        req_blob = samba.ndr.ndr_pack(req)
        ofs_stub = dcerpc.DCERPC_REQUEST_LENGTH
        ofs_sig = len(req_blob) - req.auth_length
        ofs_trailer = ofs_sig - dcerpc.DCERPC_AUTH_TRAILER_LENGTH
        req_data = req_blob[ofs_stub:ofs_trailer]
        req_whole = req_blob[0:ofs_sig]
        sig = g.sign_packet(req_data, req_whole)
        auth_info = self.generate_auth(auth_type=auth_type,
                                       auth_level=auth_level,
                                       auth_pad_length=auth_pad_length,
                                       auth_context_id=auth_context_id,
                                       auth_blob=sig)
        req = self.generate_request(call_id = 5,
                                    context_id=ctx1.context_id,
                                    opnum=1,
                                    stub=stub_bin,
                                    auth_info=auth_info)
        self.send_pdu(req)
        (rep, rep_blob) = self.recv_pdu_raw()
        self.verify_pdu(rep, dcerpc.DCERPC_PKT_RESPONSE, req.call_id,
                        auth_length=sig_size)
        self.assertNotEquals(rep.u.alloc_hint, 0)
        self.assertEquals(rep.u.context_id, req.u.context_id & 0xff)
        self.assertEquals(rep.u.cancel_count, 0)
        self.assertGreaterEqual(len(rep.u.stub_and_verifier), rep.u.alloc_hint)
        self.assertEquals(rep.auth_length, sig_size)

        ofs_stub = dcerpc.DCERPC_REQUEST_LENGTH
        ofs_sig = rep.frag_length - rep.auth_length
        ofs_trailer = ofs_sig - dcerpc.DCERPC_AUTH_TRAILER_LENGTH
        rep_data = rep_blob[ofs_stub:ofs_trailer]
        rep_whole = rep_blob[0:ofs_sig]
        rep_sig = rep_blob[ofs_sig:]
        rep_auth_info_blob = rep_blob[ofs_trailer:]

        rep_auth_info = self.parse_auth(rep_auth_info_blob)
        self.assertEquals(rep_auth_info.auth_type, auth_type)
        self.assertEquals(rep_auth_info.auth_level, auth_level)
        self.assertEquals(rep_auth_info.auth_pad_length, 4)
        self.assertEquals(rep_auth_info.auth_reserved, 0)
        self.assertEquals(rep_auth_info.auth_context_id, auth_context_id)
        self.assertEquals(rep_auth_info.credentials, rep_sig)

        g.check_packet(rep_data, rep_whole, rep_sig)

        stub_bin = '\x00' * 8
        mod_len = len(stub_bin) % dcerpc.DCERPC_AUTH_PAD_ALIGNMENT
        auth_pad_length = 0
        if mod_len > 0:
            auth_pad_length = dcerpc.DCERPC_AUTH_PAD_ALIGNMENT - mod_len
        stub_bin += '\x00' * auth_pad_length

        sig_size = g.sig_size(len(stub_bin))
        zero_sig = "\x00"*sig_size

        auth_info = self.generate_auth(auth_type=auth_type,
                                       auth_level=auth_level,
                                       auth_pad_length=auth_pad_length,
                                       auth_context_id=auth_context_id,
                                       auth_blob=zero_sig)
        req = self.generate_request(call_id = 6,
                                    context_id=ctx1.context_id,
                                    opnum=3,
                                    stub=stub_bin,
                                    auth_info=auth_info)
        req_blob = samba.ndr.ndr_pack(req)
        ofs_stub = dcerpc.DCERPC_REQUEST_LENGTH
        ofs_sig = len(req_blob) - req.auth_length
        ofs_trailer = ofs_sig - dcerpc.DCERPC_AUTH_TRAILER_LENGTH
        req_data = req_blob[ofs_stub:ofs_trailer]
        req_whole = req_blob[0:ofs_sig]
        sig = g.sign_packet(req_data, req_whole)
        auth_info = self.generate_auth(auth_type=auth_type,
                                       auth_level=auth_level,
                                       auth_pad_length=auth_pad_length,
                                       auth_context_id=auth_context_id,
                                       auth_blob=sig)
        req = self.generate_request(call_id = 6,
                                    context_id=ctx1.context_id,
                                    opnum=3,
                                    stub=stub_bin,
                                    auth_info=auth_info)
        self.send_pdu(req)
        (rep, rep_blob) = self.recv_pdu_raw()
        self.verify_pdu(rep, dcerpc.DCERPC_PKT_RESPONSE, req.call_id,
                        auth_length=sig_size)
        self.assertNotEquals(rep.u.alloc_hint, 0)
        self.assertEquals(rep.u.context_id, req.u.context_id & 0xff)
        self.assertEquals(rep.u.cancel_count, 0)
        self.assertGreaterEqual(len(rep.u.stub_and_verifier), rep.u.alloc_hint)
        self.assertEquals(rep.auth_length, sig_size)

        ofs_stub = dcerpc.DCERPC_REQUEST_LENGTH
        ofs_sig = rep.frag_length - rep.auth_length
        ofs_trailer = ofs_sig - dcerpc.DCERPC_AUTH_TRAILER_LENGTH
        rep_data = rep_blob[ofs_stub:ofs_trailer]
        rep_whole = rep_blob[0:ofs_sig]
        rep_sig = rep_blob[ofs_sig:]
        rep_auth_info_blob = rep_blob[ofs_trailer:]

        rep_auth_info = self.parse_auth(rep_auth_info_blob)
        self.assertEquals(rep_auth_info.auth_type, auth_type)
        self.assertEquals(rep_auth_info.auth_level, auth_level)
        self.assertEquals(rep_auth_info.auth_pad_length, 12)
        self.assertEquals(rep_auth_info.auth_reserved, 0)
        self.assertEquals(rep_auth_info.auth_context_id, auth_context_id)
        self.assertEquals(rep_auth_info.credentials, rep_sig)

        g.check_packet(rep_data, rep_whole, rep_sig)

    def test_spnego_signing_packet(self):
        # DCERPC_AUTH_LEVEL_PACKET is handled as alias of
        # DCERPC_AUTH_LEVEL_INTEGRITY
        return self._test_spnego_signing_auth_level_request(dcerpc.DCERPC_AUTH_LEVEL_PACKET)

    def test_spnego_signing_integrity(self):
        return self._test_spnego_signing_auth_level_request(dcerpc.DCERPC_AUTH_LEVEL_INTEGRITY)


    def test_assoc_group_fail1(self):
        abstract = samba.dcerpc.mgmt.abstract_syntax()
        transfer = base.transfer_syntax_ndr()

        tsf1_list = [transfer]
        ctx = samba.dcerpc.dcerpc.ctx_list()
        ctx.context_id = 1
        ctx.num_transfer_syntaxes = len(tsf1_list)
        ctx.abstract_syntax = abstract
        ctx.transfer_syntaxes = tsf1_list

        ack = self.do_generic_bind(ctx=ctx, assoc_group_id=1,
                                   nak_reason=dcerpc.DCERPC_BIND_NAK_REASON_NOT_SPECIFIED)
        return

    def test_assoc_group_fail2(self):
        abstract = samba.dcerpc.mgmt.abstract_syntax()
        transfer = base.transfer_syntax_ndr()

        tsf1_list = [transfer]
        ctx = samba.dcerpc.dcerpc.ctx_list()
        ctx.context_id = 1
        ctx.num_transfer_syntaxes = len(tsf1_list)
        ctx.abstract_syntax = abstract
        ctx.transfer_syntaxes = tsf1_list

        ack = self.do_generic_bind(ctx=ctx)

        self._disconnect("test_assoc_group_fail2")
        self.connect()

        ack2 = self.do_generic_bind(ctx=ctx,assoc_group_id=ack.u.assoc_group_id,
                                    nak_reason=dcerpc.DCERPC_BIND_NAK_REASON_NOT_SPECIFIED)
        return

    def test_assoc_group_diff1(self):
        abstract = samba.dcerpc.mgmt.abstract_syntax()
        transfer = base.transfer_syntax_ndr()

        (ctx1, ack1) = self.prepare_presentation(abstract, transfer,
                                                 context_id=1, return_ack=True)

        conn2 = self.second_connection()
        (ctx2, ack2) = conn2.prepare_presentation(abstract, transfer,
                                                  context_id=2, return_ack=True)
        self.assertNotEqual(ack2.u.assoc_group_id, ack1.u.assoc_group_id)

        return

    def test_assoc_group_ok1(self):
        abstract = samba.dcerpc.mgmt.abstract_syntax()
        transfer = base.transfer_syntax_ndr()

        (ctx1, ack1) = self.prepare_presentation(abstract, transfer,
                                                 context_id=1, return_ack=True)

        conn2 = self.second_connection()
        (ctx2, ack2) = conn2.prepare_presentation(abstract, transfer,
                                                  assoc_group_id=ack1.u.assoc_group_id,
                                                  context_id=2, return_ack=True)

        inq_if_ids = samba.dcerpc.mgmt.inq_if_ids()
        self.do_single_request(call_id = 1, ctx=ctx1, io=inq_if_ids)
        conn2.do_single_request(call_id = 1, ctx=ctx2, io=inq_if_ids)

        conn2.do_single_request(call_id = 1, ctx=ctx1, io=inq_if_ids,
                                fault_pfc_flags = samba.dcerpc.dcerpc.DCERPC_PFC_FLAG_FIRST |
                                                  samba.dcerpc.dcerpc.DCERPC_PFC_FLAG_LAST |
                                                  samba.dcerpc.dcerpc.DCERPC_PFC_FLAG_DID_NOT_EXECUTE,
                                fault_status=dcerpc.DCERPC_NCA_S_UNKNOWN_IF,
                                fault_context_id=0)

        self.do_single_request(call_id = 1, ctx=ctx1, io=inq_if_ids)
        conn2.do_single_request(call_id = 1, ctx=ctx2, io=inq_if_ids)
        return

if __name__ == "__main__":
    global_ndr_print = True
    global_hexdump = True
    import unittest
    unittest.main()
