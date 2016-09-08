# Unix SMB/CIFS implementation.
# Copyright (C) Jelmer Vernooij <jelmer@samba.org> 2007-2010
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
import socket
import struct
import samba.dcerpc.dcerpc
import samba.dcerpc.base
import samba.dcerpc.epmapper
import samba.tests
from samba import gensec
from samba.credentials import Credentials
from samba.tests import TestCase


class RawDCERPCTest(TestCase):
    """A raw DCE/RPC Test case."""

    def _disconnect(self, reason):
        if self.s is None:
            return
        self.s.close()
        self.s = None
        if self.do_hexdump:
            sys.stderr.write("disconnect[%s]\n" % reason)

    def connect(self):
        try:
            self.a = socket.getaddrinfo(self.host, self.tcp_port, socket.AF_UNSPEC,
                                        socket.SOCK_STREAM, socket.SOL_TCP,
                                        0)
            self.s = socket.socket(self.a[0][0], self.a[0][1], self.a[0][2])
            self.s.settimeout(10)
            self.s.connect(self.a[0][4])
        except socket.error as e:
            self.s.close()
            raise
        except IOError as e:
            self.s.close()
            raise
        except Exception as e:
            raise
        finally:
            pass

    def setUp(self):
        super(RawDCERPCTest, self).setUp()
        self.do_ndr_print = False
        self.do_hexdump = False

        self.host = samba.tests.env_get_var_value('SERVER')
        self.target_hostname = samba.tests.env_get_var_value('TARGET_HOSTNAME', allow_missing=True)
        if self.target_hostname is None:
            self.target_hostname = self.host
        self.tcp_port = 135

        self.settings = {}
        self.settings["lp_ctx"] = self.lp_ctx = samba.tests.env_loadparm()
        self.settings["target_hostname"] = self.target_hostname

        self.connect()

    def noop(self):
        return

    def second_connection(self, tcp_port=None):
        c = RawDCERPCTest(methodName='noop')
        c.do_ndr_print = self.do_ndr_print
        c.do_hexdump = self.do_hexdump

        c.host = self.host
        c.target_hostname = self.target_hostname
        if tcp_port is not None:
            c.tcp_port = tcp_port
        else:
            c.tcp_port = self.tcp_port

        c.settings = self.settings

        c.connect()
        return c

    def get_user_creds(self):
        c = Credentials()
        c.guess()
        username = samba.tests.env_get_var_value('USERNAME')
        password = samba.tests.env_get_var_value('PASSWORD')
        c.set_username(username)
        c.set_password(password)
        return c

    def get_anon_creds(self):
        c = Credentials()
        c.set_anonymous()
        return c

    def get_auth_context_creds(self, creds, auth_type, auth_level,
                               auth_context_id,
                               g_auth_level=None):

        if g_auth_level is None:
            g_auth_level = auth_level

        g = gensec.Security.start_client(self.settings)
        g.set_credentials(creds)
        g.want_feature(gensec.FEATURE_DCE_STYLE)
        g.start_mech_by_authtype(auth_type, g_auth_level)

        auth_context = {}
        auth_context["auth_type"] = auth_type
        auth_context["auth_level"] = auth_level
        auth_context["auth_context_id"] = auth_context_id
        auth_context["g_auth_level"] = g_auth_level
        auth_context["gensec"] = g

        return auth_context

    def do_generic_bind(self, ctx, auth_context=None,
                        pfc_flags=samba.dcerpc.dcerpc.DCERPC_PFC_FLAG_FIRST |
                        samba.dcerpc.dcerpc.DCERPC_PFC_FLAG_LAST,
                        assoc_group_id=0, call_id=0,
                        nak_reason=None, alter_fault=None):
        ctx_list = [ctx]

        if auth_context is not None:
            from_server = ""
            (finished, to_server) = auth_context["gensec"].update(from_server)
            self.assertFalse(finished)

            auth_info = self.generate_auth(auth_type=auth_context["auth_type"],
                                           auth_level=auth_context["auth_level"],
                                           auth_context_id=auth_context["auth_context_id"],
                                           auth_blob=to_server)
        else:
            auth_info = ""

        req = self.generate_bind(call_id=call_id,
                                 pfc_flags=pfc_flags,
                                 ctx_list=ctx_list,
                                 assoc_group_id=assoc_group_id,
                                 auth_info=auth_info)
        self.send_pdu(req)
        rep = self.recv_pdu()
        if nak_reason is not None:
            self.verify_pdu(rep, samba.dcerpc.dcerpc.DCERPC_PKT_BIND_NAK, req.call_id,
                            auth_length=0)
            self.assertEquals(rep.u.reject_reason, nak_reason)
            self.assertEquals(rep.u.num_versions, 1)
            self.assertEquals(rep.u.versions[0].rpc_vers, req.rpc_vers)
            self.assertEquals(rep.u.versions[0].rpc_vers_minor, req.rpc_vers_minor)
            self.assertEquals(len(rep.u._pad), 3)
            self.assertEquals(rep.u._pad, '\0' * 3)
            return
        self.verify_pdu(rep, samba.dcerpc.dcerpc.DCERPC_PKT_BIND_ACK, req.call_id,
                        pfc_flags=pfc_flags)
        self.assertEquals(rep.u.max_xmit_frag, req.u.max_xmit_frag)
        self.assertEquals(rep.u.max_recv_frag, req.u.max_recv_frag)
        if assoc_group_id != 0:
            self.assertEquals(rep.u.assoc_group_id, assoc_group_id)
        else:
            self.assertNotEquals(rep.u.assoc_group_id, 0)
            assoc_group_id = rep.u.assoc_group_id
        port_str = "%d" % self.tcp_port
        port_len = len(port_str) + 1
        mod_len = (2 + port_len) % 4
        if mod_len != 0:
            port_pad = 4 - mod_len
        else:
            port_pad = 0
        self.assertEquals(rep.u.secondary_address_size, port_len)
        self.assertEquals(rep.u.secondary_address, port_str)
        self.assertEquals(len(rep.u._pad1), port_pad)
        # sometimes windows sends random bytes
        # self.assertEquals(rep.u._pad1, '\0' * port_pad)
        self.assertEquals(rep.u.num_results, 1)
        self.assertEquals(rep.u.ctx_list[0].result,
                samba.dcerpc.dcerpc.DCERPC_BIND_ACK_RESULT_ACCEPTANCE)
        self.assertEquals(rep.u.ctx_list[0].reason,
                samba.dcerpc.dcerpc.DCERPC_BIND_ACK_REASON_NOT_SPECIFIED)
        self.assertNDRSyntaxEquals(rep.u.ctx_list[0].syntax, ctx.transfer_syntaxes[0])
        ack = rep
        if auth_context is None:
            self.assertEquals(rep.auth_length, 0)
            self.assertEquals(len(rep.u.auth_info), 0)
            return ack
        self.assertNotEquals(rep.auth_length, 0)
        self.assertGreater(len(rep.u.auth_info), samba.dcerpc.dcerpc.DCERPC_AUTH_TRAILER_LENGTH)
        self.assertEquals(rep.auth_length, len(rep.u.auth_info) - samba.dcerpc.dcerpc.DCERPC_AUTH_TRAILER_LENGTH)

        a = self.parse_auth(rep.u.auth_info)

        from_server = a.credentials
        (finished, to_server) = auth_context["gensec"].update(from_server)
        self.assertFalse(finished)

        auth_info = self.generate_auth(auth_type=auth_context["auth_type"],
                                       auth_level=auth_context["auth_level"],
                                       auth_context_id=auth_context["auth_context_id"],
                                       auth_blob=to_server)
        req = self.generate_alter(call_id=call_id,
                                  ctx_list=ctx_list,
                                  assoc_group_id=0xffffffff-assoc_group_id,
                                  auth_info=auth_info)
        self.send_pdu(req)
        rep = self.recv_pdu()
        if alter_fault is not None:
            self.verify_pdu(rep, samba.dcerpc.dcerpc.DCERPC_PKT_FAULT, req.call_id,
                            pfc_flags=req.pfc_flags |
                            samba.dcerpc.dcerpc.DCERPC_PFC_FLAG_DID_NOT_EXECUTE,
                            auth_length=0)
            self.assertNotEquals(rep.u.alloc_hint, 0)
            self.assertEquals(rep.u.context_id, 0)
            self.assertEquals(rep.u.cancel_count, 0)
            self.assertEquals(rep.u.flags, 0)
            self.assertEquals(rep.u.status, alter_fault)
            self.assertEquals(rep.u.reserved, 0)
            self.assertEquals(len(rep.u.error_and_verifier), 0)
            return None
        self.verify_pdu(rep, samba.dcerpc.dcerpc.DCERPC_PKT_ALTER_RESP, req.call_id)
        self.assertEquals(rep.u.max_xmit_frag, req.u.max_xmit_frag)
        self.assertEquals(rep.u.max_recv_frag, req.u.max_recv_frag)
        self.assertEquals(rep.u.assoc_group_id, assoc_group_id)
        self.assertEquals(rep.u.secondary_address_size, 0)
        self.assertEquals(rep.u.secondary_address, '')
        self.assertEquals(len(rep.u._pad1), 2)
        # sometimes windows sends random bytes
        # self.assertEquals(rep.u._pad1, '\0' * 2)
        self.assertEquals(rep.u.num_results, 1)
        self.assertEquals(rep.u.ctx_list[0].result,
                samba.dcerpc.dcerpc.DCERPC_BIND_ACK_RESULT_ACCEPTANCE)
        self.assertEquals(rep.u.ctx_list[0].reason,
                samba.dcerpc.dcerpc.DCERPC_BIND_ACK_REASON_NOT_SPECIFIED)
        self.assertNDRSyntaxEquals(rep.u.ctx_list[0].syntax, ctx.transfer_syntaxes[0])
        self.assertNotEquals(rep.auth_length, 0)
        self.assertGreater(len(rep.u.auth_info), samba.dcerpc.dcerpc.DCERPC_AUTH_TRAILER_LENGTH)
        self.assertEquals(rep.auth_length, len(rep.u.auth_info) - samba.dcerpc.dcerpc.DCERPC_AUTH_TRAILER_LENGTH)

        a = self.parse_auth(rep.u.auth_info)

        from_server = a.credentials
        (finished, to_server) = auth_context["gensec"].update(from_server)
        self.assertTrue(finished)

        return ack

    def prepare_presentation(self, abstract, transfer, object=None,
                             context_id=0xffff, epmap=False, auth_context=None,
                             pfc_flags=samba.dcerpc.dcerpc.DCERPC_PFC_FLAG_FIRST |
                             samba.dcerpc.dcerpc.DCERPC_PFC_FLAG_LAST,
                             assoc_group_id=0,
                             return_ack=False):
        if epmap:
            self.epmap_reconnect(abstract, transfer=transfer, object=object)

        tsf1_list = [transfer]
        ctx = samba.dcerpc.dcerpc.ctx_list()
        ctx.context_id = context_id
        ctx.num_transfer_syntaxes = len(tsf1_list)
        ctx.abstract_syntax = abstract
        ctx.transfer_syntaxes = tsf1_list

        ack = self.do_generic_bind(ctx=ctx,
                                   auth_context=auth_context,
                                   pfc_flags=pfc_flags,
                                   assoc_group_id=assoc_group_id)
        if ack is None:
            ctx = None

        if return_ack:
            return (ctx, ack)
        return ctx

    def do_single_request(self, call_id, ctx, io,
                          auth_context=None,
                          object=None,
                          bigendian=False, ndr64=False,
                          allow_remaining=False,
                          send_req=True,
                          recv_rep=True,
                          fault_pfc_flags = samba.dcerpc.dcerpc.DCERPC_PFC_FLAG_FIRST |
                          samba.dcerpc.dcerpc.DCERPC_PFC_FLAG_LAST,
                          fault_status=None,
                          fault_context_id=None,
                          timeout=None,
                          ndr_print=None,
                          hexdump=None):

        if fault_context_id is None:
            fault_context_id = ctx.context_id

        if ndr_print is None:
            ndr_print = self.do_ndr_print
        if hexdump is None:
            hexdump = self.do_hexdump

        if send_req:
            if ndr_print:
                sys.stderr.write("in: %s" % samba.ndr.ndr_print_in(io))
            stub_in = samba.ndr.ndr_pack_in(io, bigendian=bigendian, ndr64=ndr64)
            if hexdump:
                sys.stderr.write("stub_in: %d\n%s" % (len(stub_in), self.hexdump(stub_in)))
        else:
            # only used for sig_size calculation
            stub_in = '\xff' * samba.dcerpc.dcerpc.DCERPC_AUTH_PAD_ALIGNMENT

        sig_size = 0
        if auth_context is not None:
            mod_len = len(stub_in) % samba.dcerpc.dcerpc.DCERPC_AUTH_PAD_ALIGNMENT
            auth_pad_length = 0
            if mod_len > 0:
                auth_pad_length = samba.dcerpc.dcerpc.DCERPC_AUTH_PAD_ALIGNMENT - mod_len
            stub_in += '\x00' * auth_pad_length

            if auth_context["g_auth_level"] >= samba.dcerpc.dcerpc.DCERPC_AUTH_LEVEL_PACKET:
                sig_size = auth_context["gensec"].sig_size(len(stub_in))
            else:
                sig_size = 16

            zero_sig = "\x00"*sig_size
            auth_info = self.generate_auth(auth_type=auth_context["auth_type"],
                                           auth_level=auth_context["auth_level"],
                                           auth_pad_length=auth_pad_length,
                                           auth_context_id=auth_context["auth_context_id"],
                                           auth_blob=zero_sig)
        else:
            auth_info=""

        pfc_flags =  samba.dcerpc.dcerpc.DCERPC_PFC_FLAG_FIRST
        pfc_flags |= samba.dcerpc.dcerpc.DCERPC_PFC_FLAG_LAST
        if object is not None:
            pfc_flags |= samba.dcerpc.dcerpc.DCERPC_PFC_FLAG_OBJECT_UUID

        req = self.generate_request(call_id=call_id,
                                    context_id=ctx.context_id,
                                    pfc_flags=pfc_flags,
                                    object=object,
                                    opnum=io.opnum(),
                                    stub=stub_in,
                                    auth_info=auth_info)

        if send_req:
            if sig_size != 0 and auth_context["auth_level"] >= samba.dcerpc.dcerpc.DCERPC_AUTH_LEVEL_PACKET:
                req_blob = samba.ndr.ndr_pack(req)
                ofs_stub = samba.dcerpc.dcerpc.DCERPC_REQUEST_LENGTH
                ofs_sig = len(req_blob) - req.auth_length
                ofs_trailer = ofs_sig - samba.dcerpc.dcerpc.DCERPC_AUTH_TRAILER_LENGTH
                req_data = req_blob[ofs_stub:ofs_trailer]
                req_whole = req_blob[0:ofs_sig]
                sig = auth_context["gensec"].sign_packet(req_data, req_whole)
                auth_info = self.generate_auth(auth_type=auth_context["auth_type"],
                                               auth_level=auth_context["auth_level"],
                                               auth_pad_length=auth_pad_length,
                                               auth_context_id=auth_context["auth_context_id"],
                                               auth_blob=sig)
                req = self.generate_request(call_id=call_id,
                                            context_id=ctx.context_id,
                                            pfc_flags=pfc_flags,
                                            object=object,
                                            opnum=io.opnum(),
                                            stub=stub_in,
                                            auth_info=auth_info)
            self.send_pdu(req, ndr_print=ndr_print, hexdump=hexdump)
        if recv_rep:
            (rep, rep_blob) = self.recv_pdu_raw(timeout=timeout,
                                                ndr_print=ndr_print,
                                                hexdump=hexdump)
            if fault_status:
                self.verify_pdu(rep, samba.dcerpc.dcerpc.DCERPC_PKT_FAULT, req.call_id,
                                pfc_flags=fault_pfc_flags, auth_length=0)
                self.assertNotEquals(rep.u.alloc_hint, 0)
                self.assertEquals(rep.u.context_id, fault_context_id)
                self.assertEquals(rep.u.cancel_count, 0)
                self.assertEquals(rep.u.flags, 0)
                self.assertEquals(rep.u.status, fault_status)
                self.assertEquals(rep.u.reserved, 0)
                self.assertEquals(len(rep.u.error_and_verifier), 0)
                return

            self.verify_pdu(rep, samba.dcerpc.dcerpc.DCERPC_PKT_RESPONSE, req.call_id,
                            auth_length=sig_size)
            self.assertNotEquals(rep.u.alloc_hint, 0)
            self.assertEquals(rep.u.context_id, req.u.context_id & 0xff)
            self.assertEquals(rep.u.cancel_count, 0)
            self.assertGreaterEqual(len(rep.u.stub_and_verifier), rep.u.alloc_hint)
            if sig_size != 0:

                ofs_stub = samba.dcerpc.dcerpc.DCERPC_REQUEST_LENGTH
                ofs_sig = rep.frag_length - rep.auth_length
                ofs_trailer = ofs_sig - samba.dcerpc.dcerpc.DCERPC_AUTH_TRAILER_LENGTH
                rep_data = rep_blob[ofs_stub:ofs_trailer]
                rep_whole = rep_blob[0:ofs_sig]
                rep_sig = rep_blob[ofs_sig:]
                rep_auth_info_blob = rep_blob[ofs_trailer:]

                rep_auth_info = self.parse_auth(rep_auth_info_blob)
                self.assertEquals(rep_auth_info.auth_type, auth_context["auth_type"])
                self.assertEquals(rep_auth_info.auth_level, auth_context["auth_level"])
                self.assertLessEqual(rep_auth_info.auth_pad_length, len(rep_data))
                self.assertEquals(rep_auth_info.auth_reserved, 0)
                self.assertEquals(rep_auth_info.auth_context_id, auth_context["auth_context_id"])
                self.assertEquals(rep_auth_info.credentials, rep_sig)

                if auth_context["auth_level"] >= samba.dcerpc.dcerpc.DCERPC_AUTH_LEVEL_PACKET:
                    auth_context["gensec"].check_packet(rep_data, rep_whole, rep_sig)

                stub_out = rep_data[0:-rep_auth_info.auth_pad_length]
            else:
                stub_out = rep.u.stub_and_verifier

            if hexdump:
                sys.stderr.write("stub_out: %d\n%s" % (len(stub_out), self.hexdump(stub_out)))
            samba.ndr.ndr_unpack_out(io, stub_out, bigendian=bigendian, ndr64=ndr64,
                                     allow_remaining=allow_remaining)
            if ndr_print:
                sys.stderr.write("out: %s" % samba.ndr.ndr_print_out(io))

    def epmap_reconnect(self, abstract, transfer=None, object=None):
        ndr32 = samba.dcerpc.base.transfer_syntax_ndr()

        if transfer is None:
            transfer = ndr32

        if object is None:
            object = samba.dcerpc.misc.GUID()

        ctx = self.prepare_presentation(samba.dcerpc.epmapper.abstract_syntax(),
                                        transfer, context_id=0)

        data1 = samba.ndr.ndr_pack(abstract)
        lhs1 = samba.dcerpc.epmapper.epm_lhs()
        lhs1.protocol = samba.dcerpc.epmapper.EPM_PROTOCOL_UUID
        lhs1.lhs_data = data1[:18]
        rhs1 = samba.dcerpc.epmapper.epm_rhs_uuid()
        rhs1.unknown = data1[18:]
        floor1 = samba.dcerpc.epmapper.epm_floor()
        floor1.lhs = lhs1
        floor1.rhs = rhs1
        data2 = samba.ndr.ndr_pack(transfer)
        lhs2 = samba.dcerpc.epmapper.epm_lhs()
        lhs2.protocol = samba.dcerpc.epmapper.EPM_PROTOCOL_UUID
        lhs2.lhs_data = data2[:18]
        rhs2 = samba.dcerpc.epmapper.epm_rhs_uuid()
        rhs2.unknown = data1[18:]
        floor2 = samba.dcerpc.epmapper.epm_floor()
        floor2.lhs = lhs2
        floor2.rhs = rhs2
        lhs3 = samba.dcerpc.epmapper.epm_lhs()
        lhs3.protocol = samba.dcerpc.epmapper.EPM_PROTOCOL_NCACN
        lhs3.lhs_data = ""
        floor3 = samba.dcerpc.epmapper.epm_floor()
        floor3.lhs = lhs3
        floor3.rhs.minor_version = 0
        lhs4 = samba.dcerpc.epmapper.epm_lhs()
        lhs4.protocol = samba.dcerpc.epmapper.EPM_PROTOCOL_TCP
        lhs4.lhs_data = ""
        floor4 = samba.dcerpc.epmapper.epm_floor()
        floor4.lhs = lhs4
        floor4.rhs.port = self.tcp_port
        lhs5 = samba.dcerpc.epmapper.epm_lhs()
        lhs5.protocol = samba.dcerpc.epmapper.EPM_PROTOCOL_IP
        lhs5.lhs_data = ""
        floor5 = samba.dcerpc.epmapper.epm_floor()
        floor5.lhs = lhs5
        floor5.rhs.ipaddr = "0.0.0.0"

        floors = [floor1,floor2,floor3,floor4,floor5]
        req_tower = samba.dcerpc.epmapper.epm_tower()
        req_tower.num_floors = len(floors)
        req_tower.floors = floors
        req_twr = samba.dcerpc.epmapper.epm_twr_t()
        req_twr.tower = req_tower

        epm_map = samba.dcerpc.epmapper.epm_Map()
        epm_map.in_object = object
        epm_map.in_map_tower = req_twr
        epm_map.in_entry_handle = samba.dcerpc.misc.policy_handle()
        epm_map.in_max_towers = 4

        self.do_single_request(call_id=2, ctx=ctx, io=epm_map)

        self.assertGreaterEqual(epm_map.out_num_towers, 1)
        rep_twr = epm_map.out_towers[0].twr
        self.assertIsNotNone(rep_twr)
        self.assertEqual(rep_twr.tower_length, 75)
        self.assertEqual(rep_twr.tower.num_floors, 5)
        self.assertEqual(len(rep_twr.tower.floors), 5)
        self.assertEqual(rep_twr.tower.floors[3].lhs.protocol,
                          samba.dcerpc.epmapper.EPM_PROTOCOL_TCP)
        self.assertEqual(rep_twr.tower.floors[3].lhs.protocol,
                          samba.dcerpc.epmapper.EPM_PROTOCOL_TCP)

        # reconnect to the given port
        self._disconnect("epmap_reconnect")
        self.tcp_port = rep_twr.tower.floors[3].rhs.port
        self.connect()

    def send_pdu(self, req, ndr_print=None, hexdump=None):
        if ndr_print is None:
            ndr_print = self.do_ndr_print
        if hexdump is None:
            hexdump = self.do_hexdump
        try:
            req_pdu = samba.ndr.ndr_pack(req)
            if ndr_print:
                sys.stderr.write("send_pdu: %s" % samba.ndr.ndr_print(req))
            if hexdump:
                sys.stderr.write("send_pdu: %d\n%s" % (len(req_pdu), self.hexdump(req_pdu)))
            while True:
                sent = self.s.send(req_pdu, 0)
                if sent == len(req_pdu):
                    break
                req_pdu = req_pdu[sent:]
        except socket.error as e:
            self._disconnect("send_pdu: %s" % e)
            raise
        except IOError as e:
            self._disconnect("send_pdu: %s" % e)
            raise
        finally:
            pass

    def recv_raw(self, hexdump=None, timeout=None):
        rep_pdu = None
        if hexdump is None:
            hexdump = self.do_hexdump
        try:
            if timeout is not None:
                self.s.settimeout(timeout)
            rep_pdu = self.s.recv(0xffff, 0)
            self.s.settimeout(10)
            if len(rep_pdu) == 0:
                self._disconnect("recv_raw: EOF")
                return None
            if hexdump:
                sys.stderr.write("recv_raw: %d\n%s" % (len(rep_pdu), self.hexdump(rep_pdu)))
        except socket.timeout as e:
            self.s.settimeout(10)
            sys.stderr.write("recv_raw: TIMEOUT\n")
            pass
        except socket.error as e:
            self._disconnect("recv_raw: %s" % e)
            raise
        except IOError as e:
            self._disconnect("recv_raw: %s" % e)
            raise
        finally:
            pass
        return rep_pdu

    def recv_pdu_raw(self, ndr_print=None, hexdump=None, timeout=None):
        rep_pdu = None
        rep = None
        if ndr_print is None:
            ndr_print = self.do_ndr_print
        if hexdump is None:
            hexdump = self.do_hexdump
        try:
            rep_pdu = self.recv_raw(hexdump=hexdump, timeout=timeout)
            if rep_pdu is None:
                return (None,None)
            rep = samba.ndr.ndr_unpack(samba.dcerpc.dcerpc.ncacn_packet, rep_pdu, allow_remaining=True)
            if ndr_print:
                sys.stderr.write("recv_pdu: %s" % samba.ndr.ndr_print(rep))
            self.assertEqual(rep.frag_length, len(rep_pdu))
        finally:
            pass
        return (rep, rep_pdu)

    def recv_pdu(self, ndr_print=None, hexdump=None, timeout=None):
        (rep, rep_pdu) = self.recv_pdu_raw(ndr_print=ndr_print,
                                           hexdump=hexdump,
                                           timeout=timeout)
        return rep

    def generate_auth(self,
                      auth_type=None,
                      auth_level=None,
                      auth_pad_length=0,
                      auth_context_id=None,
                      auth_blob=None,
                      ndr_print=None, hexdump=None):
        if ndr_print is None:
            ndr_print = self.do_ndr_print
        if hexdump is None:
            hexdump = self.do_hexdump

        if auth_type is not None:
            a = samba.dcerpc.dcerpc.auth()
            a.auth_type = auth_type
            a.auth_level = auth_level
            a.auth_pad_length = auth_pad_length
            a.auth_context_id= auth_context_id
            a.credentials = auth_blob

            ai = samba.ndr.ndr_pack(a)
            if ndr_print:
                sys.stderr.write("generate_auth: %s" % samba.ndr.ndr_print(a))
            if hexdump:
                sys.stderr.write("generate_auth: %d\n%s" % (len(ai), self.hexdump(ai)))
        else:
            ai = ""

        return ai

    def parse_auth(self, auth_info, ndr_print=None, hexdump=None):
        if ndr_print is None:
            ndr_print = self.do_ndr_print
        if hexdump is None:
            hexdump = self.do_hexdump

        if (len(auth_info) <= samba.dcerpc.dcerpc.DCERPC_AUTH_TRAILER_LENGTH):
            return None

        if hexdump:
            sys.stderr.write("parse_auth: %d\n%s" % (len(auth_info), self.hexdump(auth_info)))
        a = samba.ndr.ndr_unpack(samba.dcerpc.dcerpc.auth, auth_info, allow_remaining=True)
        if ndr_print:
            sys.stderr.write("parse_auth: %s" % samba.ndr.ndr_print(a))

        return a

    def generate_pdu(self, ptype, call_id, payload,
                     rpc_vers=5,
                     rpc_vers_minor=0,
                     pfc_flags = samba.dcerpc.dcerpc.DCERPC_PFC_FLAG_FIRST |
                                 samba.dcerpc.dcerpc.DCERPC_PFC_FLAG_LAST,
                     drep = [samba.dcerpc.dcerpc.DCERPC_DREP_LE, 0, 0, 0],
                     ndr_print=None, hexdump=None):

        if getattr(payload, 'auth_info', None):
            ai = payload.auth_info
        else:
            ai = ""

        p = samba.dcerpc.dcerpc.ncacn_packet()
        p.rpc_vers = rpc_vers
        p.rpc_vers_minor = rpc_vers_minor
        p.ptype = ptype
        p.pfc_flags = pfc_flags
        p.drep = drep
        p.frag_length = 0
        if len(ai) > samba.dcerpc.dcerpc.DCERPC_AUTH_TRAILER_LENGTH:
            p.auth_length = len(ai) - samba.dcerpc.dcerpc.DCERPC_AUTH_TRAILER_LENGTH
        else:
            p.auth_length = 0
        p.call_id = call_id
        p.u = payload

        pdu = samba.ndr.ndr_pack(p)
        p.frag_length = len(pdu)

        return p

    def verify_pdu(self, p, ptype, call_id,
                   rpc_vers=5,
                   rpc_vers_minor=0,
                   pfc_flags = samba.dcerpc.dcerpc.DCERPC_PFC_FLAG_FIRST |
                               samba.dcerpc.dcerpc.DCERPC_PFC_FLAG_LAST,
                   drep = [samba.dcerpc.dcerpc.DCERPC_DREP_LE, 0, 0, 0],
                   auth_length=None):

        self.assertIsNotNone(p, "No valid pdu")

        if getattr(p.u, 'auth_info', None):
            ai = p.u.auth_info
        else:
            ai = ""

        self.assertEqual(p.rpc_vers, rpc_vers)
        self.assertEqual(p.rpc_vers_minor, rpc_vers_minor)
        self.assertEqual(p.ptype, ptype)
        self.assertEqual(p.pfc_flags, pfc_flags)
        self.assertEqual(p.drep, drep)
        self.assertGreaterEqual(p.frag_length,
                samba.dcerpc.dcerpc.DCERPC_NCACN_PAYLOAD_OFFSET)
        if len(ai) > samba.dcerpc.dcerpc.DCERPC_AUTH_TRAILER_LENGTH:
            self.assertEqual(p.auth_length,
                    len(ai) - samba.dcerpc.dcerpc.DCERPC_AUTH_TRAILER_LENGTH)
        elif auth_length is not None:
            self.assertEqual(p.auth_length, auth_length)
        else:
            self.assertEqual(p.auth_length, 0)
        self.assertEqual(p.call_id, call_id)

        return

    def generate_bind(self, call_id,
                      pfc_flags = samba.dcerpc.dcerpc.DCERPC_PFC_FLAG_FIRST |
                                  samba.dcerpc.dcerpc.DCERPC_PFC_FLAG_LAST,
                      max_xmit_frag=5840,
                      max_recv_frag=5840,
                      assoc_group_id=0,
                      ctx_list=[],
                      auth_info="",
                      ndr_print=None, hexdump=None):

        b = samba.dcerpc.dcerpc.bind()
        b.max_xmit_frag = max_xmit_frag
        b.max_recv_frag = max_recv_frag
        b.assoc_group_id = assoc_group_id
        b.num_contexts = len(ctx_list)
        b.ctx_list = ctx_list
        b.auth_info = auth_info

        p = self.generate_pdu(ptype=samba.dcerpc.dcerpc.DCERPC_PKT_BIND,
                              pfc_flags=pfc_flags,
                              call_id=call_id,
                              payload=b,
                              ndr_print=ndr_print, hexdump=hexdump)

        return p

    def generate_alter(self, call_id,
                       pfc_flags = samba.dcerpc.dcerpc.DCERPC_PFC_FLAG_FIRST |
                                   samba.dcerpc.dcerpc.DCERPC_PFC_FLAG_LAST,
                       max_xmit_frag=5840,
                       max_recv_frag=5840,
                       assoc_group_id=0,
                       ctx_list=[],
                       auth_info="",
                       ndr_print=None, hexdump=None):

        a = samba.dcerpc.dcerpc.bind()
        a.max_xmit_frag = max_xmit_frag
        a.max_recv_frag = max_recv_frag
        a.assoc_group_id = assoc_group_id
        a.num_contexts = len(ctx_list)
        a.ctx_list = ctx_list
        a.auth_info = auth_info

        p = self.generate_pdu(ptype=samba.dcerpc.dcerpc.DCERPC_PKT_ALTER,
                              pfc_flags=pfc_flags,
                              call_id=call_id,
                              payload=a,
                              ndr_print=ndr_print, hexdump=hexdump)

        return p

    def generate_auth3(self, call_id,
                       pfc_flags = samba.dcerpc.dcerpc.DCERPC_PFC_FLAG_FIRST |
                                   samba.dcerpc.dcerpc.DCERPC_PFC_FLAG_LAST,
                       auth_info="",
                       ndr_print=None, hexdump=None):

        a = samba.dcerpc.dcerpc.auth3()
        a.auth_info = auth_info

        p = self.generate_pdu(ptype=samba.dcerpc.dcerpc.DCERPC_PKT_AUTH3,
                              pfc_flags=pfc_flags,
                              call_id=call_id,
                              payload=a,
                              ndr_print=ndr_print, hexdump=hexdump)

        return p

    def generate_request(self, call_id,
                         pfc_flags = samba.dcerpc.dcerpc.DCERPC_PFC_FLAG_FIRST |
                                     samba.dcerpc.dcerpc.DCERPC_PFC_FLAG_LAST,
                         alloc_hint=None,
                         context_id=None,
                         opnum=None,
                         object=None,
                         stub=None,
                         auth_info="",
                         ndr_print=None, hexdump=None):

        if alloc_hint is None:
            alloc_hint = len(stub)

        r = samba.dcerpc.dcerpc.request()
        r.alloc_hint = alloc_hint
        r.context_id = context_id
        r.opnum = opnum
        if object is not None:
            r.object = object
        r.stub_and_verifier = stub + auth_info

        p = self.generate_pdu(ptype=samba.dcerpc.dcerpc.DCERPC_PKT_REQUEST,
                              pfc_flags=pfc_flags,
                              call_id=call_id,
                              payload=r,
                              ndr_print=ndr_print, hexdump=hexdump)

        if len(auth_info) > samba.dcerpc.dcerpc.DCERPC_AUTH_TRAILER_LENGTH:
            p.auth_length = len(auth_info) - samba.dcerpc.dcerpc.DCERPC_AUTH_TRAILER_LENGTH

        return p

    def generate_co_cancel(self, call_id,
                           pfc_flags = samba.dcerpc.dcerpc.DCERPC_PFC_FLAG_FIRST |
                                       samba.dcerpc.dcerpc.DCERPC_PFC_FLAG_LAST,
                           auth_info="",
                           ndr_print=None, hexdump=None):

        c = samba.dcerpc.dcerpc.co_cancel()
        c.auth_info = auth_info

        p = self.generate_pdu(ptype=samba.dcerpc.dcerpc.DCERPC_PKT_CO_CANCEL,
                              pfc_flags=pfc_flags,
                              call_id=call_id,
                              payload=c,
                              ndr_print=ndr_print, hexdump=hexdump)

        return p

    def generate_orphaned(self, call_id,
                          pfc_flags = samba.dcerpc.dcerpc.DCERPC_PFC_FLAG_FIRST |
                                      samba.dcerpc.dcerpc.DCERPC_PFC_FLAG_LAST,
                          auth_info="",
                          ndr_print=None, hexdump=None):

        o = samba.dcerpc.dcerpc.orphaned()
        o.auth_info = auth_info

        p = self.generate_pdu(ptype=samba.dcerpc.dcerpc.DCERPC_PKT_ORPHANED,
                              pfc_flags=pfc_flags,
                              call_id=call_id,
                              payload=o,
                              ndr_print=ndr_print, hexdump=hexdump)

        return p

    def generate_shutdown(self, call_id,
                          pfc_flags = samba.dcerpc.dcerpc.DCERPC_PFC_FLAG_FIRST |
                                      samba.dcerpc.dcerpc.DCERPC_PFC_FLAG_LAST,
                          ndr_print=None, hexdump=None):

        s = samba.dcerpc.dcerpc.shutdown()

        p = self.generate_pdu(ptype=samba.dcerpc.dcerpc.DCERPC_PKT_SHUTDOWN,
                              pfc_flags=pfc_flags,
                              call_id=call_id,
                              payload=s,
                              ndr_print=ndr_print, hexdump=hexdump)

        return p

    def assertIsConnected(self):
        self.assertIsNotNone(self.s, msg="Not connected")
        return

    def assertNotConnected(self):
        self.assertIsNone(self.s, msg="Is connected")
        return

    def assertNDRSyntaxEquals(self, s1, s2):
        self.assertEqual(s1.uuid, s2.uuid)
        self.assertEqual(s1.if_version, s2.if_version)
        return
