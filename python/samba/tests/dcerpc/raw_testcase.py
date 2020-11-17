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
import samba.dcerpc.dcerpc as dcerpc
import samba.dcerpc.base
import samba.dcerpc.epmapper
import samba.dcerpc.security as security
import samba.tests
from samba import gensec
from samba.credentials import Credentials
from samba.tests import TestCase
from samba.ndr import ndr_pack, ndr_unpack, ndr_unpack_out
from samba.compat import text_type
from samba.ntstatus import (
    NT_STATUS_CONNECTION_DISCONNECTED,
    NT_STATUS_PIPE_DISCONNECTED,
    NT_STATUS_IO_TIMEOUT
)
from samba import NTSTATUSError
from samba.samba3 import param as s3param
from samba.samba3 import libsmb_samba_internal as libsmb

class smb_pipe_socket(object):

    def __init__(self, target_hostname, pipename, creds, impersonation_level, lp):
        lp3 = s3param.get_context()
        lp3.load(lp.configfile)
        self.smbconn = libsmb.Conn(target_hostname, 'IPC$', lp3,
                                   creds=creds, sign=True)
        self.smbfid = self.smbconn.create(pipename,
                                          DesiredAccess=0x12019f,
                                          ShareAccess=0x7,
                                          CreateDisposition=1,
                                          CreateOptions=0x400040,
                                          ImpersonationLevel=impersonation_level)
        return

    def close(self):
        self.smbconn.close(self.smbfid)
        del self.smbconn

    def settimeout(self, timeo):
        # The socket module we simulate there
        # specifies the timeo as seconds as float.
        msecs = int(timeo * 1000)
        assert msecs >= 0
        self.smbconn.settimeout(msecs)
        return

    def send(self, buf, flags=0):
        return self.smbconn.write(self.smbfid, buffer=buf, offset=0, mode=8)

    def recv(self, len, flags=0):
        try:
            return self.smbconn.read(self.smbfid, offset=0, size=len)
        except NTSTATUSError as e:
            if e.args[0] == NT_STATUS_CONNECTION_DISCONNECTED:
                return b'\0' * 0
            if e.args[0] == NT_STATUS_PIPE_DISCONNECTED:
                return b'\0' * 0
            if e.args[0] == NT_STATUS_IO_TIMEOUT:
                raise socket.timeout(str(e))
            raise e

class RawDCERPCTest(TestCase):
    """A raw DCE/RPC Test case."""

    def _disconnect(self, reason):
        if self.s is None:
            return
        self.s.close()
        self.s = None
        if self.do_hexdump:
            sys.stderr.write("disconnect[%s]\n" % reason)

    def _connect_tcp(self):
        tcp_port = int(self.primary_address)
        try:
            self.a = socket.getaddrinfo(self.host, tcp_port, socket.AF_UNSPEC,
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
        self.max_xmit_frag = 5840
        self.max_recv_frag = 5840
        if self.secondary_address is None:
            self.secondary_address = self.primary_address
        # compat for older tests
        self.tcp_port = tcp_port

    def _connect_smb(self):
        a = self.primary_address.split('\\')
        self.assertEqual(len(a), 3)
        self.assertEqual(a[0], "")
        self.assertEqual(a[1], "pipe")
        pipename = a[2]
        self.s = smb_pipe_socket(self.target_hostname,
                                 pipename,
                                 self.transport_creds,
                                 self.transport_impersonation,
                                 self.lp_ctx)
        self.max_xmit_frag = 4280
        self.max_recv_frag = 4280
        if self.secondary_address is None:
            self.secondary_address = self.primary_address

    def connect(self):
        self.assertNotConnected()
        if self.primary_address.startswith("\\pipe\\"):
            self._connect_smb()
        else:
            self._connect_tcp()
        if self.secondary_address is None:
            self.secondary_address = self.primary_address
        return

    def setUp(self):
        super(RawDCERPCTest, self).setUp()
        self.do_ndr_print = False
        self.do_hexdump = False

        self.ignore_random_pad = samba.tests.env_get_var_value('IGNORE_RANDOM_PAD',
                                                               allow_missing=True)
        self.host = samba.tests.env_get_var_value('SERVER')
        self.target_hostname = samba.tests.env_get_var_value('TARGET_HOSTNAME', allow_missing=True)
        if self.target_hostname is None:
            self.target_hostname = self.host
        self.primary_address = "135"
        self.secondary_address = None
        self.transport_creds = self.get_anon_creds()
        self.transport_impersonation = 0x2

        self.settings = {}
        self.settings["lp_ctx"] = self.lp_ctx = samba.tests.env_loadparm()
        self.settings["target_hostname"] = self.target_hostname

        self.s = None
        self.connect()

    def tearDown(self):
        self._disconnect("tearDown")
        super(TestCase, self).tearDown()

    def noop(self):
        return

    def reconnect_smb_pipe(self, primary_address, secondary_address=None,
                           transport_creds=None, transport_impersonation=None):
        self._disconnect("reconnect_smb_pipe")
        self.assertIsNotNone(primary_address)
        self.primary_address = primary_address
        if secondary_address is not None:
            self.secondary_address = secondary_address
        else:
            self.secondary_address = None

        if transport_creds is not None:
            self.transport_creds = transport_creds

        if transport_impersonation is not None:
            self.transport_impersonation = transport_impersonation

        self.connect()
        return

    def second_connection(self, primary_address=None, secondary_address=None,
                          transport_creds=None, transport_impersonation=None):
        c = RawDCERPCTest(methodName='noop')
        c.do_ndr_print = self.do_ndr_print
        c.do_hexdump = self.do_hexdump
        c.ignore_random_pad = self.ignore_random_pad

        c.host = self.host
        c.target_hostname = self.target_hostname
        if primary_address is not None:
            c.primary_address = primary_address
            if secondary_address is not None:
                c.secondary_address = secondary_address
            else:
                c.secondary_address = None
        else:
            self.assertIsNone(secondary_address)
            c.primary_address = self.primary_address
            c.secondary_address = self.secondary_address

        if transport_creds is not None:
            c.transport_creds = transport_creds
        else:
            c.transport_creds = self.transport_creds

        if transport_impersonation is not None:
            c.transport_impersonation = transport_impersonation
        else:
            c.transport_impersonation = self.transport_impersonation

        c.lp_ctx = self.lp_ctx
        c.settings = self.settings

        c.s = None
        c.connect()
        return c

    def get_user_creds(self):
        c = Credentials()
        c.guess()
        domain = samba.tests.env_get_var_value('DOMAIN')
        realm = samba.tests.env_get_var_value('REALM')
        username = samba.tests.env_get_var_value('USERNAME')
        password = samba.tests.env_get_var_value('PASSWORD')
        c.set_domain(domain)
        c.set_realm(realm)
        c.set_username(username)
        c.set_password(password)
        return c

    def get_anon_creds(self):
        c = Credentials()
        c.set_anonymous()
        return c

    def get_auth_context_creds(self, creds, auth_type, auth_level,
                               auth_context_id,
                               g_auth_level=None,
                               hdr_signing=False):

        if g_auth_level is None:
            g_auth_level = auth_level

        g = gensec.Security.start_client(self.settings)
        g.set_credentials(creds)
        g.want_feature(gensec.FEATURE_DCE_STYLE)
        g.start_mech_by_authtype(auth_type, g_auth_level)

        if auth_type == dcerpc.DCERPC_AUTH_TYPE_KRB5:
            expect_3legs = True
        elif auth_type == dcerpc.DCERPC_AUTH_TYPE_NTLMSSP:
            expect_3legs = True
        else:
            expect_3legs = False

        auth_context = {}
        auth_context["auth_type"] = auth_type
        auth_context["auth_level"] = auth_level
        auth_context["auth_context_id"] = auth_context_id
        auth_context["g_auth_level"] = g_auth_level
        auth_context["gensec"] = g
        auth_context["hdr_signing"] = hdr_signing
        auth_context["expect_3legs"] = expect_3legs

        return auth_context

    def do_generic_bind(self, ctx, auth_context=None,
                        pfc_flags=samba.dcerpc.dcerpc.DCERPC_PFC_FLAG_FIRST |
                        samba.dcerpc.dcerpc.DCERPC_PFC_FLAG_LAST,
                        assoc_group_id=0, call_id=0,
                        nak_reason=None, alter_fault=None,
                        start_with_alter=False,
                        pfc_flags_2nd=samba.dcerpc.dcerpc.DCERPC_PFC_FLAG_FIRST |
                        samba.dcerpc.dcerpc.DCERPC_PFC_FLAG_LAST,
                        use_auth3=False):
        ctx_list = [ctx]

        if auth_context is not None:
            if auth_context['hdr_signing']:
                pfc_flags |= dcerpc.DCERPC_PFC_FLAG_SUPPORT_HEADER_SIGN

            expect_3legs = auth_context["expect_3legs"]

            from_server = b""
            (finished, to_server) = auth_context["gensec"].update(from_server)
            self.assertFalse(finished)

            auth_info = self.generate_auth(auth_type=auth_context["auth_type"],
                                           auth_level=auth_context["auth_level"],
                                           auth_context_id=auth_context["auth_context_id"],
                                           auth_blob=to_server)
        else:
            auth_info = b""

        if start_with_alter:
            req = self.generate_alter(call_id=call_id,
                                      pfc_flags=pfc_flags,
                                      ctx_list=ctx_list,
                                      assoc_group_id=0xffffffff - assoc_group_id,
                                      auth_info=auth_info)
            self.send_pdu(req)
            rep = self.recv_pdu()
            if alter_fault is not None:
                self.verify_pdu(rep, samba.dcerpc.dcerpc.DCERPC_PKT_FAULT, req.call_id,
                                pfc_flags=req.pfc_flags |
                                samba.dcerpc.dcerpc.DCERPC_PFC_FLAG_DID_NOT_EXECUTE,
                                auth_length=0)
                self.assertNotEqual(rep.u.alloc_hint, 0)
                self.assertEqual(rep.u.context_id, 0)
                self.assertEqual(rep.u.cancel_count, 0)
                self.assertEqual(rep.u.flags, 0)
                self.assertEqual(rep.u.status, alter_fault)
                self.assertEqual(rep.u.reserved, 0)
                self.assertEqual(len(rep.u.error_and_verifier), 0)
                return None
            self.verify_pdu(rep, samba.dcerpc.dcerpc.DCERPC_PKT_ALTER_RESP, req.call_id,
                            pfc_flags=req.pfc_flags)
            self.assertEqual(rep.u.max_xmit_frag, req.u.max_xmit_frag)
            self.assertEqual(rep.u.max_recv_frag, req.u.max_recv_frag)
            self.assertEqual(rep.u.assoc_group_id, assoc_group_id)
            self.assertEqual(rep.u.secondary_address_size, 0)
            self.assertEqual(rep.u.secondary_address, '')
            self.assertPadding(rep.u._pad1, 2)
        else:
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
                self.assertEqual(rep.u.reject_reason, nak_reason)
                self.assertEqual(rep.u.num_versions, 1)
                self.assertEqual(rep.u.versions[0].rpc_vers, req.rpc_vers)
                self.assertEqual(rep.u.versions[0].rpc_vers_minor, req.rpc_vers_minor)
                self.assertPadding(rep.u._pad, 3)
                return
            self.verify_pdu(rep, samba.dcerpc.dcerpc.DCERPC_PKT_BIND_ACK, req.call_id,
                            pfc_flags=pfc_flags)
            self.assertEqual(rep.u.max_xmit_frag, req.u.max_xmit_frag)
            self.assertEqual(rep.u.max_recv_frag, req.u.max_recv_frag)
            if assoc_group_id != 0:
                self.assertEqual(rep.u.assoc_group_id, assoc_group_id)
            else:
                self.assertNotEqual(rep.u.assoc_group_id, 0)
                assoc_group_id = rep.u.assoc_group_id
            sda_str = self.secondary_address
            sda_len = len(sda_str) + 1
            mod_len = (2 + sda_len) % 4
            if mod_len != 0:
                sda_pad = 4 - mod_len
            else:
                sda_pad = 0
            self.assertEqual(rep.u.secondary_address_size, sda_len)
            self.assertEqual(rep.u.secondary_address, sda_str)
            self.assertPadding(rep.u._pad1, sda_pad)

        self.assertEqual(rep.u.num_results, 1)
        self.assertEqual(rep.u.ctx_list[0].result,
                          samba.dcerpc.dcerpc.DCERPC_BIND_ACK_RESULT_ACCEPTANCE)
        self.assertEqual(rep.u.ctx_list[0].reason,
                          samba.dcerpc.dcerpc.DCERPC_BIND_ACK_REASON_NOT_SPECIFIED)
        self.assertNDRSyntaxEquals(rep.u.ctx_list[0].syntax, ctx.transfer_syntaxes[0])
        ack = rep
        if auth_context is None:
            self.assertEqual(rep.auth_length, 0)
            self.assertEqual(len(rep.u.auth_info), 0)
            return ack
        self.assertNotEqual(rep.auth_length, 0)
        self.assertGreater(len(rep.u.auth_info), samba.dcerpc.dcerpc.DCERPC_AUTH_TRAILER_LENGTH)
        self.assertEqual(rep.auth_length, len(rep.u.auth_info) - samba.dcerpc.dcerpc.DCERPC_AUTH_TRAILER_LENGTH)

        a = self.parse_auth(rep.u.auth_info, auth_context=auth_context)

        from_server = a.credentials
        (finished, to_server) = auth_context["gensec"].update(from_server)
        if expect_3legs:
            self.assertTrue(finished)
            if auth_context['hdr_signing']:
                auth_context["gensec"].want_feature(gensec.FEATURE_SIGN_PKT_HEADER)
        else:
            self.assertFalse(use_auth3)
            self.assertFalse(finished)

        auth_info = self.generate_auth(auth_type=auth_context["auth_type"],
                                       auth_level=auth_context["auth_level"],
                                       auth_context_id=auth_context["auth_context_id"],
                                       auth_blob=to_server)
        if use_auth3:
            req = self.generate_auth3(call_id=call_id,
                                      pfc_flags=pfc_flags_2nd,
                                      auth_info=auth_info)
            self.send_pdu(req)
            rep = self.recv_pdu(timeout=0.01)
            self.assertIsNone(rep)
            self.assertIsConnected()
            return ack
        req = self.generate_alter(call_id=call_id,
                                  ctx_list=ctx_list,
                                  pfc_flags=pfc_flags_2nd,
                                  assoc_group_id=0xffffffff - assoc_group_id,
                                  auth_info=auth_info)
        self.send_pdu(req)
        rep = self.recv_pdu()
        if alter_fault is not None:
            self.verify_pdu(rep, samba.dcerpc.dcerpc.DCERPC_PKT_FAULT, req.call_id,
                            pfc_flags=req.pfc_flags |
                            samba.dcerpc.dcerpc.DCERPC_PFC_FLAG_DID_NOT_EXECUTE,
                            auth_length=0)
            self.assertNotEqual(rep.u.alloc_hint, 0)
            self.assertEqual(rep.u.context_id, 0)
            self.assertEqual(rep.u.cancel_count, 0)
            self.assertEqual(rep.u.flags, 0)
            self.assertEqual(rep.u.status, alter_fault)
            self.assertEqual(rep.u.reserved, 0)
            self.assertEqual(len(rep.u.error_and_verifier), 0)
            return None
        self.verify_pdu(rep, samba.dcerpc.dcerpc.DCERPC_PKT_ALTER_RESP, req.call_id,
                        pfc_flags=req.pfc_flags)
        self.assertEqual(rep.u.max_xmit_frag, req.u.max_xmit_frag)
        self.assertEqual(rep.u.max_recv_frag, req.u.max_recv_frag)
        self.assertEqual(rep.u.assoc_group_id, assoc_group_id)
        self.assertEqual(rep.u.secondary_address_size, 0)
        self.assertEqual(rep.u.secondary_address, '')
        self.assertPadding(rep.u._pad1, 2)
        self.assertEqual(rep.u.num_results, 1)
        self.assertEqual(rep.u.ctx_list[0].result,
                          samba.dcerpc.dcerpc.DCERPC_BIND_ACK_RESULT_ACCEPTANCE)
        self.assertEqual(rep.u.ctx_list[0].reason,
                          samba.dcerpc.dcerpc.DCERPC_BIND_ACK_REASON_NOT_SPECIFIED)
        self.assertNDRSyntaxEquals(rep.u.ctx_list[0].syntax, ctx.transfer_syntaxes[0])
        if finished:
            self.assertEqual(rep.auth_length, 0)
        else:
            self.assertNotEqual(rep.auth_length, 0)
        self.assertGreaterEqual(len(rep.u.auth_info), samba.dcerpc.dcerpc.DCERPC_AUTH_TRAILER_LENGTH)
        self.assertEqual(rep.auth_length, len(rep.u.auth_info) - samba.dcerpc.dcerpc.DCERPC_AUTH_TRAILER_LENGTH)

        a = self.parse_auth(rep.u.auth_info, auth_context=auth_context)

        if finished:
            return ack

        from_server = a.credentials
        (finished, to_server) = auth_context["gensec"].update(from_server)
        self.assertTrue(finished)
        if auth_context['hdr_signing']:
            auth_context["gensec"].want_feature(gensec.FEATURE_SIGN_PKT_HEADER)

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
                          fault_pfc_flags=(
                              samba.dcerpc.dcerpc.DCERPC_PFC_FLAG_FIRST |
                              samba.dcerpc.dcerpc.DCERPC_PFC_FLAG_LAST),
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

            pfc_flags = samba.dcerpc.dcerpc.DCERPC_PFC_FLAG_FIRST
            pfc_flags |= samba.dcerpc.dcerpc.DCERPC_PFC_FLAG_LAST
            if object is not None:
                pfc_flags |= samba.dcerpc.dcerpc.DCERPC_PFC_FLAG_OBJECT_UUID

            req = self.generate_request_auth(call_id=call_id,
                                             context_id=ctx.context_id,
                                             pfc_flags=pfc_flags,
                                             object=object,
                                             opnum=io.opnum(),
                                             stub=stub_in,
                                             auth_context=auth_context)
            self.send_pdu(req, ndr_print=ndr_print, hexdump=hexdump)
        if recv_rep:
            (rep, rep_blob) = self.recv_pdu_raw(timeout=timeout,
                                                ndr_print=ndr_print,
                                                hexdump=hexdump)
            if fault_status:
                self.verify_pdu(rep, samba.dcerpc.dcerpc.DCERPC_PKT_FAULT, call_id,
                                pfc_flags=fault_pfc_flags, auth_length=0)
                self.assertNotEqual(rep.u.alloc_hint, 0)
                self.assertEqual(rep.u.context_id, fault_context_id)
                self.assertEqual(rep.u.cancel_count, 0)
                self.assertEqual(rep.u.flags, 0)
                self.assertEqual(rep.u.status, fault_status)
                self.assertEqual(rep.u.reserved, 0)
                self.assertEqual(len(rep.u.error_and_verifier), 0)
                return

            expected_auth_length = 0
            if auth_context is not None and \
               auth_context["auth_level"] >= dcerpc.DCERPC_AUTH_LEVEL_PACKET:
                if send_req:
                    expected_auth_length = req.auth_length
                else:
                    expected_auth_length = rep.auth_length


            self.verify_pdu(rep, samba.dcerpc.dcerpc.DCERPC_PKT_RESPONSE, call_id,
                            auth_length=expected_auth_length)
            self.assertNotEqual(rep.u.alloc_hint, 0)
            self.assertEqual(rep.u.context_id, ctx.context_id & 0xff)
            self.assertEqual(rep.u.cancel_count, 0)
            self.assertGreaterEqual(len(rep.u.stub_and_verifier), rep.u.alloc_hint)
            stub_out = self.check_response_auth(rep, rep_blob, auth_context)
            self.assertEqual(len(stub_out), rep.u.alloc_hint)

            if hexdump:
                sys.stderr.write("stub_out: %d\n%s" % (len(stub_out), self.hexdump(stub_out)))
            ndr_unpack_out(io, stub_out, bigendian=bigendian, ndr64=ndr64,
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

        data1 = ndr_pack(abstract)
        lhs1 = samba.dcerpc.epmapper.epm_lhs()
        lhs1.protocol = samba.dcerpc.epmapper.EPM_PROTOCOL_UUID
        lhs1.lhs_data = data1[:18]
        rhs1 = samba.dcerpc.epmapper.epm_rhs_uuid()
        rhs1.unknown = data1[18:]
        floor1 = samba.dcerpc.epmapper.epm_floor()
        floor1.lhs = lhs1
        floor1.rhs = rhs1
        data2 = ndr_pack(transfer)
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
        lhs3.lhs_data = b""
        floor3 = samba.dcerpc.epmapper.epm_floor()
        floor3.lhs = lhs3
        floor3.rhs.minor_version = 0
        lhs4 = samba.dcerpc.epmapper.epm_lhs()
        lhs4.protocol = samba.dcerpc.epmapper.EPM_PROTOCOL_TCP
        lhs4.lhs_data = b""
        floor4 = samba.dcerpc.epmapper.epm_floor()
        floor4.lhs = lhs4
        floor4.rhs.port = int(self.primary_address)
        lhs5 = samba.dcerpc.epmapper.epm_lhs()
        lhs5.protocol = samba.dcerpc.epmapper.EPM_PROTOCOL_IP
        lhs5.lhs_data = b""
        floor5 = samba.dcerpc.epmapper.epm_floor()
        floor5.lhs = lhs5
        floor5.rhs.ipaddr = "0.0.0.0"

        floors = [floor1, floor2, floor3, floor4, floor5]
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
        self.primary_address = "%d" % rep_twr.tower.floors[3].rhs.port
        self.secondary_address = None
        self.connect()

    def send_pdu(self, req, ndr_print=None, hexdump=None):
        if ndr_print is None:
            ndr_print = self.do_ndr_print
        if hexdump is None:
            hexdump = self.do_hexdump
        try:
            req_pdu = ndr_pack(req)
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
        except NTSTATUSError as e:
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
                return (None, None)
            rep = ndr_unpack(samba.dcerpc.dcerpc.ncacn_packet, rep_pdu, allow_remaining=True)
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
            a.auth_context_id = auth_context_id
            a.credentials = auth_blob

            ai = ndr_pack(a)
            if ndr_print:
                sys.stderr.write("generate_auth: %s" % samba.ndr.ndr_print(a))
            if hexdump:
                sys.stderr.write("generate_auth: %d\n%s" % (len(ai), self.hexdump(ai)))
        else:
            ai = b""

        return ai

    def parse_auth(self, auth_info, ndr_print=None, hexdump=None,
                   auth_context=None, stub_len=0):
        if ndr_print is None:
            ndr_print = self.do_ndr_print
        if hexdump is None:
            hexdump = self.do_hexdump

        if (len(auth_info) <= samba.dcerpc.dcerpc.DCERPC_AUTH_TRAILER_LENGTH):
            return None

        if hexdump:
            sys.stderr.write("parse_auth: %d\n%s" % (len(auth_info), self.hexdump(auth_info)))
        a = ndr_unpack(samba.dcerpc.dcerpc.auth, auth_info, allow_remaining=True)
        if ndr_print:
            sys.stderr.write("parse_auth: %s" % samba.ndr.ndr_print(a))

        if auth_context is not None:
            self.assertEqual(a.auth_type, auth_context["auth_type"])
            self.assertEqual(a.auth_level, auth_context["auth_level"])
            self.assertEqual(a.auth_reserved, 0)
            self.assertEqual(a.auth_context_id, auth_context["auth_context_id"])

            self.assertLessEqual(a.auth_pad_length, dcerpc.DCERPC_AUTH_PAD_ALIGNMENT)
            self.assertLessEqual(a.auth_pad_length, stub_len)

        return a

    def check_response_auth(self, rep, rep_blob, auth_context=None,
                            auth_pad_length=None):

        if auth_context is None:
            self.assertEqual(rep.auth_length, 0)
            return rep.u.stub_and_verifier

        if auth_context["auth_level"] == dcerpc.DCERPC_AUTH_LEVEL_CONNECT:
            self.assertEqual(rep.auth_length, 0)
            return rep.u.stub_and_verifier

        self.assertGreater(rep.auth_length, 0)

        ofs_stub = dcerpc.DCERPC_REQUEST_LENGTH
        ofs_sig = rep.frag_length - rep.auth_length
        ofs_trailer = ofs_sig - dcerpc.DCERPC_AUTH_TRAILER_LENGTH
        rep_data = rep_blob[ofs_stub:ofs_trailer]
        rep_whole = rep_blob[0:ofs_sig]
        rep_sig = rep_blob[ofs_sig:]
        rep_auth_info_blob = rep_blob[ofs_trailer:]

        rep_auth_info = self.parse_auth(rep_auth_info_blob,
                                        auth_context=auth_context,
                                        stub_len=len(rep_data))
        if auth_pad_length is not None:
            self.assertEqual(rep_auth_info.auth_pad_length, auth_pad_length)
        self.assertEqual(rep_auth_info.credentials, rep_sig)

        if auth_context["auth_level"] >= dcerpc.DCERPC_AUTH_LEVEL_PRIVACY:
            # TODO: not yet supported here
            self.assertTrue(False)
        elif auth_context["auth_level"] >= dcerpc.DCERPC_AUTH_LEVEL_PACKET:
            auth_context["gensec"].check_packet(rep_data, rep_whole, rep_sig)

        stub_out = rep_data[0:len(rep_data)-rep_auth_info.auth_pad_length]

        return stub_out

    def generate_pdu(self, ptype, call_id, payload,
                     rpc_vers=5,
                     rpc_vers_minor=0,
                     pfc_flags=(samba.dcerpc.dcerpc.DCERPC_PFC_FLAG_FIRST |
                                samba.dcerpc.dcerpc.DCERPC_PFC_FLAG_LAST),
                     drep=[samba.dcerpc.dcerpc.DCERPC_DREP_LE, 0, 0, 0],
                     ndr_print=None, hexdump=None):

        if getattr(payload, 'auth_info', None):
            ai = payload.auth_info
        else:
            ai = b""

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

        pdu = ndr_pack(p)
        p.frag_length = len(pdu)

        return p

    def generate_request_auth(self, call_id,
                              pfc_flags=(dcerpc.DCERPC_PFC_FLAG_FIRST |
                                         dcerpc.DCERPC_PFC_FLAG_LAST),
                              alloc_hint=None,
                              context_id=None,
                              opnum=None,
                              object=None,
                              stub=None,
                              auth_context=None,
                              ndr_print=None, hexdump=None):

        if stub is None:
            stub = b""

        sig_size = 0
        if auth_context is not None:
            mod_len = len(stub) % dcerpc.DCERPC_AUTH_PAD_ALIGNMENT
            auth_pad_length = 0
            if mod_len > 0:
                auth_pad_length = dcerpc.DCERPC_AUTH_PAD_ALIGNMENT - mod_len
            stub += b'\x00' * auth_pad_length

            if auth_context["g_auth_level"] >= samba.dcerpc.dcerpc.DCERPC_AUTH_LEVEL_PACKET:
                sig_size = auth_context["gensec"].sig_size(len(stub))
            else:
                sig_size = 16

            zero_sig = b"\x00" * sig_size
            auth_info = self.generate_auth(auth_type=auth_context["auth_type"],
                                           auth_level=auth_context["auth_level"],
                                           auth_pad_length=auth_pad_length,
                                           auth_context_id=auth_context["auth_context_id"],
                                           auth_blob=zero_sig)
        else:
            auth_info = b""

        req = self.generate_request(call_id=call_id,
                                    pfc_flags=pfc_flags,
                                    alloc_hint=alloc_hint,
                                    context_id=context_id,
                                    opnum=opnum,
                                    object=object,
                                    stub=stub,
                                    auth_info=auth_info,
                                    ndr_print=ndr_print,
                                    hexdump=hexdump)
        if auth_context is None:
            return req

        req_blob = samba.ndr.ndr_pack(req)
        ofs_stub = dcerpc.DCERPC_REQUEST_LENGTH
        ofs_sig = len(req_blob) - req.auth_length
        ofs_trailer = ofs_sig - dcerpc.DCERPC_AUTH_TRAILER_LENGTH
        req_data = req_blob[ofs_stub:ofs_trailer]
        req_whole = req_blob[0:ofs_sig]

        if auth_context["g_auth_level"] >= dcerpc.DCERPC_AUTH_LEVEL_PRIVACY:
            # TODO: not yet supported here
            self.assertTrue(False)
        elif auth_context["g_auth_level"] >= dcerpc.DCERPC_AUTH_LEVEL_PACKET:
            req_sig = auth_context["gensec"].sign_packet(req_data, req_whole)
        elif auth_context["g_auth_level"] >= dcerpc.DCERPC_AUTH_LEVEL_CONNECT:
            self.assertEqual(auth_context["auth_type"],
                              dcerpc.DCERPC_AUTH_TYPE_NTLMSSP)
            req_sig = b"\x01" +b"\x00" *15
        else:
            return req
        self.assertEqual(len(req_sig), req.auth_length)
        self.assertEqual(len(req_sig), sig_size)

        stub_sig_ofs = len(req.u.stub_and_verifier) - sig_size
        stub = req.u.stub_and_verifier[0:stub_sig_ofs] + req_sig
        req.u.stub_and_verifier = stub

        return req

    def verify_pdu(self, p, ptype, call_id,
                   rpc_vers=5,
                   rpc_vers_minor=0,
                   pfc_flags=(samba.dcerpc.dcerpc.DCERPC_PFC_FLAG_FIRST |
                              samba.dcerpc.dcerpc.DCERPC_PFC_FLAG_LAST),
                   drep=[samba.dcerpc.dcerpc.DCERPC_DREP_LE, 0, 0, 0],
                   auth_length=None):

        self.assertIsNotNone(p, "No valid pdu")

        if getattr(p.u, 'auth_info', None):
            ai = p.u.auth_info
        else:
            ai = b""

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
                      pfc_flags=(samba.dcerpc.dcerpc.DCERPC_PFC_FLAG_FIRST |
                                 samba.dcerpc.dcerpc.DCERPC_PFC_FLAG_LAST),
                      max_xmit_frag=None,
                      max_recv_frag=None,
                      assoc_group_id=0,
                      ctx_list=[],
                      auth_info=b"",
                      ndr_print=None, hexdump=None):

        if max_xmit_frag is None:
            max_xmit_frag=self.max_xmit_frag
        if max_recv_frag is None:
            max_recv_frag=self.max_recv_frag

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
                       pfc_flags=(samba.dcerpc.dcerpc.DCERPC_PFC_FLAG_FIRST |
                                  samba.dcerpc.dcerpc.DCERPC_PFC_FLAG_LAST),
                       max_xmit_frag=None,
                       max_recv_frag=None,
                       assoc_group_id=0,
                       ctx_list=[],
                       auth_info=b"",
                       ndr_print=None, hexdump=None):

        if max_xmit_frag is None:
            max_xmit_frag=self.max_xmit_frag
        if max_recv_frag is None:
            max_recv_frag=self.max_recv_frag

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
                       pfc_flags=(samba.dcerpc.dcerpc.DCERPC_PFC_FLAG_FIRST |
                                  samba.dcerpc.dcerpc.DCERPC_PFC_FLAG_LAST),
                       auth_info=b"",
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
                         pfc_flags=(samba.dcerpc.dcerpc.DCERPC_PFC_FLAG_FIRST |
                                    samba.dcerpc.dcerpc.DCERPC_PFC_FLAG_LAST),
                         alloc_hint=None,
                         context_id=None,
                         opnum=None,
                         object=None,
                         stub=None,
                         auth_info=b"",
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
                           pfc_flags=(samba.dcerpc.dcerpc.DCERPC_PFC_FLAG_FIRST |
                                      samba.dcerpc.dcerpc.DCERPC_PFC_FLAG_LAST),
                           auth_info=b"",
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
                          pfc_flags=(samba.dcerpc.dcerpc.DCERPC_PFC_FLAG_FIRST |
                                     samba.dcerpc.dcerpc.DCERPC_PFC_FLAG_LAST),
                          auth_info=b"",
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
                          pfc_flags=(samba.dcerpc.dcerpc.DCERPC_PFC_FLAG_FIRST |
                                     samba.dcerpc.dcerpc.DCERPC_PFC_FLAG_LAST),
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

    def assertPadding(self, pad, length):
        self.assertEqual(len(pad), length)
        #
        # sometimes windows sends random bytes
        #
        # we have IGNORE_RANDOM_PAD=1 to
        # disable the check
        #
        if self.ignore_random_pad:
            return
        zero_pad = b'\0' * length
        self.assertEqual(pad, zero_pad)

    def assertEqualsStrLower(self, s1, s2):
        self.assertEqual(str(s1).lower(), str(s2).lower())
