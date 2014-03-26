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

"""Samba Python tests."""

import os
import ldb
import samba
import samba.auth
from samba import param
from samba.samdb import SamDB
from samba import credentials
import samba.ndr
import samba.dcerpc.dcerpc
import samba.dcerpc.base
import samba.dcerpc.epmapper
import socket
import struct
import subprocess
import sys
import tempfile
import unittest

try:
    from unittest import SkipTest
except ImportError:
    class SkipTest(Exception):
        """Test skipped."""

HEXDUMP_FILTER=''.join([(len(repr(chr(x)))==3) and chr(x) or '.' for x in range(256)])

class TestCase(unittest.TestCase):
    """A Samba test case."""

    def setUp(self):
        super(TestCase, self).setUp()
        test_debug_level = os.getenv("TEST_DEBUG_LEVEL")
        if test_debug_level is not None:
            test_debug_level = int(test_debug_level)
            self._old_debug_level = samba.get_debug_level()
            samba.set_debug_level(test_debug_level)
            self.addCleanup(samba.set_debug_level, test_debug_level)

    def get_loadparm(self):
        return env_loadparm()

    def get_credentials(self):
        return cmdline_credentials

    def hexdump(self, src):
        N = 0
        result = ''
        while src:
            ll = src[:8]
            lr = src[8:16]
            src = src[16:]
            hl = ' '.join(["%02X" % ord(x) for x in ll])
            hr = ' '.join(["%02X" % ord(x) for x in lr])
            ll = ll.translate(HEXDUMP_FILTER)
            lr = lr.translate(HEXDUMP_FILTER)
            result += "[%04X] %-*s  %-*s  %s %s\n" % (N, 8*3, hl, 8*3, hr, ll, lr)
            N += 16
        return result

    # These functions didn't exist before Python2.7:
    if sys.version_info < (2, 7):
        import warnings

        def skipTest(self, reason):
            raise SkipTest(reason)

        def assertIn(self, member, container, msg=None):
            self.assertTrue(member in container, msg)

        def assertIs(self, a, b, msg=None):
            self.assertTrue(a is b, msg)

        def assertIsNot(self, a, b, msg=None):
            self.assertTrue(a is not b, msg)

        def assertIsNotNone(self, a, msg=None):
            self.assertTrue(a is not None)

        def assertIsInstance(self, a, b, msg=None):
            self.assertTrue(isinstance(a, b), msg)

        def assertIsNone(self, a, msg=None):
            self.assertTrue(a is None, msg)

        def assertGreater(self, a, b, msg=None):
            self.assertTrue(a > b, msg)

        def assertGreaterEqual(self, a, b, msg=None):
            self.assertTrue(a >= b, msg)

        def assertLess(self, a, b, msg=None):
            self.assertTrue(a < b, msg)

        def assertLessEqual(self, a, b, msg=None):
            self.assertTrue(a <= b, msg)

        def addCleanup(self, fn, *args, **kwargs):
            self._cleanups = getattr(self, "_cleanups", []) + [
                (fn, args, kwargs)]

        def _addSkip(self, result, reason):
            addSkip = getattr(result, 'addSkip', None)
            if addSkip is not None:
                addSkip(self, reason)
            else:
                warnings.warn("TestResult has no addSkip method, skips not reported",
                              RuntimeWarning, 2)
                result.addSuccess(self)

        def run(self, result=None):
            if result is None: result = self.defaultTestResult()
            result.startTest(self)
            testMethod = getattr(self, self._testMethodName)
            try:
                try:
                    self.setUp()
                except SkipTest, e:
                    self._addSkip(result, str(e))
                    return
                except KeyboardInterrupt:
                    raise
                except:
                    result.addError(self, self._exc_info())
                    return

                ok = False
                try:
                    testMethod()
                    ok = True
                except SkipTest, e:
                    self._addSkip(result, str(e))
                    return
                except self.failureException:
                    result.addFailure(self, self._exc_info())
                except KeyboardInterrupt:
                    raise
                except:
                    result.addError(self, self._exc_info())

                try:
                    self.tearDown()
                except SkipTest, e:
                    self._addSkip(result, str(e))
                except KeyboardInterrupt:
                    raise
                except:
                    result.addError(self, self._exc_info())
                    ok = False

                for (fn, args, kwargs) in reversed(getattr(self, "_cleanups", [])):
                    fn(*args, **kwargs)
                if ok: result.addSuccess(self)
            finally:
                result.stopTest(self)


class LdbTestCase(TestCase):
    """Trivial test case for running tests against a LDB."""

    def setUp(self):
        super(LdbTestCase, self).setUp()
        self.filename = os.tempnam()
        self.ldb = samba.Ldb(self.filename)

    def set_modules(self, modules=[]):
        """Change the modules for this Ldb."""
        m = ldb.Message()
        m.dn = ldb.Dn(self.ldb, "@MODULES")
        m["@LIST"] = ",".join(modules)
        self.ldb.add(m)
        self.ldb = samba.Ldb(self.filename)


class TestCaseInTempDir(TestCase):

    def setUp(self):
        super(TestCaseInTempDir, self).setUp()
        self.tempdir = tempfile.mkdtemp()
        self.addCleanup(self._remove_tempdir)

    def _remove_tempdir(self):
        self.assertEquals([], os.listdir(self.tempdir))
        os.rmdir(self.tempdir)
        self.tempdir = None


def env_loadparm():
    lp = param.LoadParm()
    try:
        lp.load(os.environ["SMB_CONF_PATH"])
    except KeyError:
        raise KeyError("SMB_CONF_PATH not set")
    return lp


def env_get_var_value(var_name):
    """Returns value for variable in os.environ

    Function throws AssertionError if variable is defined.
    Unit-test based python tests require certain input params
    to be set in environment, otherwise they can't be run
    """
    assert var_name in os.environ.keys(), "Please supply %s in environment" % var_name
    return os.environ[var_name]


cmdline_credentials = None

class RpcInterfaceTestCase(TestCase):
    """DCE/RPC Test case."""

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
        self.tcp_port = 135

        self.settings = {}
        self.settings["lp_ctx"] = self.lp_ctx = samba.tests.env_loadparm()
        self.settings["target_hostname"] = self.host

        self.connect()

    def epmap_reconnect(self, abstract):
        ndr32 = samba.dcerpc.base.transfer_syntax_ndr()

        tsf0_list = [ndr32]
        ctx0 = samba.dcerpc.dcerpc.ctx_list()
        ctx0.context_id = 1
        ctx0.num_transfer_syntaxes = len(tsf0_list)
        ctx0.abstract_syntax = samba.dcerpc.epmapper.abstract_syntax()
        ctx0.transfer_syntaxes = tsf0_list

        req = self.generate_bind(call_id=0, ctx_list=[ctx0])
        self.send_pdu(req)
        rep = self.recv_pdu()
        self.verify_pdu(rep, samba.dcerpc.dcerpc.DCERPC_PKT_BIND_ACK,
                        req.call_id, auth_length=0)
        self.assertEqual(rep.u.max_xmit_frag, req.u.max_xmit_frag)
        self.assertEqual(rep.u.max_recv_frag, req.u.max_recv_frag)
        self.assertNotEqual(rep.u.assoc_group_id, req.u.assoc_group_id)
        self.assertEqual(rep.u.secondary_address_size, 4)
        self.assertEqual(rep.u.secondary_address, "%d" % self.tcp_port)
        self.assertEqual(len(rep.u._pad1), 2)
        self.assertEqual(rep.u._pad1, '\0' * 2)
        self.assertEqual(rep.u.num_results, 1)
        self.assertEqual(rep.u.ctx_list[0].result,
                samba.dcerpc.dcerpc.DCERPC_BIND_ACK_RESULT_ACCEPTANCE)
        self.assertEqual(rep.u.ctx_list[0].reason,
                samba.dcerpc.dcerpc.DCERPC_BIND_ACK_REASON_NOT_SPECIFIED)
        self.assertNDRSyntaxEquals(rep.u.ctx_list[0].syntax, ndr32)
        self.assertEqual(rep.u.auth_info, '\0' * 0)

        # And now try a request
        data1 = samba.ndr.ndr_pack(abstract)
        lhs1 = samba.dcerpc.epmapper.epm_lhs()
        lhs1.protocol = samba.dcerpc.epmapper.EPM_PROTOCOL_UUID
        lhs1.lhs_data = data1[:18]
        rhs1 = samba.dcerpc.epmapper.epm_rhs_uuid()
        rhs1.unknown = data1[18:]
        floor1 = samba.dcerpc.epmapper.epm_floor()
        floor1.lhs = lhs1
        floor1.rhs = rhs1
        data2 = samba.ndr.ndr_pack(ndr32)
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

        pack_twr = samba.ndr.ndr_pack(req_twr)

        # object
        stub =  "\x01\x00\x00\x00"
        stub += "\x00" * 16
        # tower
        stub += "\x02\x00\x00\x00"
        stub += pack_twr
        # padding?
        stub += "\x00" * 1
        # handle
        stub += "\x00" * 20
        # max_towers
        stub += "\x04\x00\x00\x00"

        # we do an epm_Map() request
        req = self.generate_request(call_id = 1,
                                    context_id=ctx0.context_id,
                                    opnum=3,
                                    stub=stub)
        self.send_pdu(req)
        rep = self.recv_pdu()
        self.verify_pdu(rep, samba.dcerpc.dcerpc.DCERPC_PKT_RESPONSE,
                        req.call_id, auth_length=0)
        self.assertNotEqual(rep.u.alloc_hint, 0)
        self.assertEqual(rep.u.context_id, req.u.context_id)
        self.assertEqual(rep.u.cancel_count, 0)
        self.assertGreaterEqual(len(rep.u.stub_and_verifier), rep.u.alloc_hint)

        num_towers = struct.unpack_from("<I", rep.u.stub_and_verifier, 20)
        (array_max, array_ofs, array_cnt) = struct.unpack_from("<III", rep.u.stub_and_verifier, 24)
        status = struct.unpack_from("<I", rep.u.stub_and_verifier, len(rep.u.stub_and_verifier) - 4)
        self.assertEqual(status[0], 0)
        self.assertGreaterEqual(num_towers[0], 1)
        self.assertEqual(array_max, 4)
        self.assertEqual(array_ofs, 0)
        self.assertGreaterEqual(array_cnt, 1)

        unpack_twr = rep.u.stub_and_verifier[(36 + 4 * array_cnt):-4]
        rep_twr = samba.ndr.ndr_unpack(samba.dcerpc.epmapper.epm_twr_t, unpack_twr, allow_remaining=True)
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

    def recv_pdu(self, ndr_print=None, hexdump=None, timeout=None):
        rep = None
        if ndr_print is None:
            ndr_print = self.do_ndr_print
        if hexdump is None:
            hexdump = self.do_hexdump
        try:
            rep_pdu = self.recv_raw(hexdump=hexdump, timeout=timeout)
            if rep_pdu is None:
                return None
            rep = samba.ndr.ndr_unpack(samba.dcerpc.dcerpc.ncacn_packet, rep_pdu, allow_remaining=True)
            if ndr_print:
                sys.stderr.write("recv_pdu: %s" % samba.ndr.ndr_print(rep))
            self.assertEqual(rep.frag_length, len(rep_pdu))
        finally:
            pass
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

class ValidNetbiosNameTests(TestCase):

    def test_valid(self):
        self.assertTrue(samba.valid_netbios_name("FOO"))

    def test_too_long(self):
        self.assertFalse(samba.valid_netbios_name("FOO"*10))

    def test_invalid_characters(self):
        self.assertFalse(samba.valid_netbios_name("*BLA"))


class BlackboxProcessError(Exception):
    """This is raised when check_output() process returns a non-zero exit status

    Exception instance should contain the exact exit code (S.returncode),
    command line (S.cmd), process output (S.stdout) and process error stream
    (S.stderr)
    """

    def __init__(self, returncode, cmd, stdout, stderr):
        self.returncode = returncode
        self.cmd = cmd
        self.stdout = stdout
        self.stderr = stderr

    def __str__(self):
        return "Command '%s'; exit status %d; stdout: '%s'; stderr: '%s'" % (self.cmd, self.returncode,
                                                                             self.stdout, self.stderr)

class BlackboxTestCase(TestCaseInTempDir):
    """Base test case for blackbox tests."""

    def _make_cmdline(self, line):
        bindir = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../../bin"))
        parts = line.split(" ")
        if os.path.exists(os.path.join(bindir, parts[0])):
            parts[0] = os.path.join(bindir, parts[0])
        line = " ".join(parts)
        return line

    def check_run(self, line):
        line = self._make_cmdline(line)
        p = subprocess.Popen(line, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
        retcode = p.wait()
        if retcode:
            raise BlackboxProcessError(retcode, line, p.stdout.read(), p.stderr.read())

    def check_output(self, line):
        line = self._make_cmdline(line)
        p = subprocess.Popen(line, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, close_fds=True)
        retcode = p.wait()
        if retcode:
            raise BlackboxProcessError(retcode, line, p.stdout.read(), p.stderr.read())
        return p.stdout.read()


def connect_samdb(samdb_url, lp=None, session_info=None, credentials=None,
                  flags=0, ldb_options=None, ldap_only=False, global_schema=True):
    """Create SamDB instance and connects to samdb_url database.

    :param samdb_url: Url for database to connect to.
    :param lp: Optional loadparm object
    :param session_info: Optional session information
    :param credentials: Optional credentials, defaults to anonymous.
    :param flags: Optional LDB flags
    :param ldap_only: If set, only remote LDAP connection will be created.
    :param global_schema: Whether to use global schema.

    Added value for tests is that we have a shorthand function
    to make proper URL for ldb.connect() while using default
    parameters for connection based on test environment
    """
    if not "://" in samdb_url:
        if not ldap_only and os.path.isfile(samdb_url):
            samdb_url = "tdb://%s" % samdb_url
        else:
            samdb_url = "ldap://%s" % samdb_url
    # use 'paged_search' module when connecting remotely
    if samdb_url.startswith("ldap://"):
        ldb_options = ["modules:paged_searches"]
    elif ldap_only:
        raise AssertionError("Trying to connect to %s while remote "
                             "connection is required" % samdb_url)

    # set defaults for test environment
    if lp is None:
        lp = env_loadparm()
    if session_info is None:
        session_info = samba.auth.system_session(lp)
    if credentials is None:
        credentials = cmdline_credentials

    return SamDB(url=samdb_url,
                 lp=lp,
                 session_info=session_info,
                 credentials=credentials,
                 flags=flags,
                 options=ldb_options,
                 global_schema=global_schema)


def connect_samdb_ex(samdb_url, lp=None, session_info=None, credentials=None,
                     flags=0, ldb_options=None, ldap_only=False):
    """Connects to samdb_url database

    :param samdb_url: Url for database to connect to.
    :param lp: Optional loadparm object
    :param session_info: Optional session information
    :param credentials: Optional credentials, defaults to anonymous.
    :param flags: Optional LDB flags
    :param ldap_only: If set, only remote LDAP connection will be created.
    :return: (sam_db_connection, rootDse_record) tuple
    """
    sam_db = connect_samdb(samdb_url, lp, session_info, credentials,
                           flags, ldb_options, ldap_only)
    # fetch RootDse
    res = sam_db.search(base="", expression="", scope=ldb.SCOPE_BASE,
                        attrs=["*"])
    return (sam_db, res[0])


def connect_samdb_env(env_url, env_username, env_password, lp=None):
    """Connect to SamDB by getting URL and Credentials from environment

    :param env_url: Environment variable name to get lsb url from
    :param env_username: Username environment variable
    :param env_password: Password environment variable
    :return: sam_db_connection
    """
    samdb_url = env_get_var_value(env_url)
    creds = credentials.Credentials()
    if lp is None:
        # guess Credentials parameters here. Otherwise workstation
        # and domain fields are NULL and gencache code segfalts
        lp = param.LoadParm()
        creds.guess(lp)
    creds.set_username(env_get_var_value(env_username))
    creds.set_password(env_get_var_value(env_password))
    return connect_samdb(samdb_url, credentials=creds, lp=lp)


def delete_force(samdb, dn):
    try:
        samdb.delete(dn)
    except ldb.LdbError, (num, errstr):
        assert num == ldb.ERR_NO_SUCH_OBJECT, "ldb.delete() failed: %s" % errstr
