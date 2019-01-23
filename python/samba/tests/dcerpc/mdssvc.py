#
# Unix SMB/CIFS implementation.
# Copyright Ralph Boehme <slow@samba.org> 2019
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

"""Tests for samba.dcerpc.mdssvc"""

import os
import time
import threading
import logging
import json
from http.server import HTTPServer, BaseHTTPRequestHandler
from samba.dcerpc import mdssvc
from samba.tests import RpcInterfaceTestCase
from samba.samba3 import mdscli
from samba.logger import get_samba_logger

logger = get_samba_logger(name=__name__)

testfiles = [
    "foo",
    "bar",
    "x+x",
    "x*x",
    "x=x",
    "x'x",
    "x?x",
    "x\"x",
    "x\\x",
    "x(x",
    "x x",
]

class MdssvcHTTPRequestHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        content_length = int(self.headers['content-length'])
        body = self.rfile.read(content_length)

        actual_json = json.loads((body))
        expected_json = json.loads(self.server.json_in)

        if actual_json != expected_json:
            logger.error("Bad request, expected:\n%s\nGot:\n%s\n" % (expected_json, actual_json))
            self.send_error(400,
                            "Bad request",
                            "Expected: %s\n"
                            "Got: %s\n" %
                            (expected_json, actual_json))
            return

        resp = bytes(self.server.json_out, encoding="utf-8")

        self.send_response(200)
        self.send_header('content-type', 'application/json; charset=UTF-8')
        self.send_header('content-length', len(resp))
        self.end_headers()
        self.wfile.write(resp)

class MdssvcTests(RpcInterfaceTestCase):

    def setUp(self):
        super(MdssvcTests, self).setUp()

        self.pipe = mdssvc.mdssvc('ncacn_np:fileserver[/pipe/mdssvc]', self.get_loadparm())

        self.server = HTTPServer(('10.53.57.35', 8080),
                                 MdssvcHTTPRequestHandler,
                                 bind_and_activate=False)

        self.t = threading.Thread(target=MdssvcTests.http_server, args=(self,))
        self.t.setDaemon(True)
        self.t.start()
        time.sleep(1)

        conn = mdscli.conn(self.pipe, 'spotlight', '/foo')
        self.sharepath = conn.sharepath()
        conn.disconnect(self.pipe)

        for file in testfiles:
            f = open("%s/%s" % (self.sharepath, file), "w")
            f.close()

    def tearDown(self):
        super(RpcInterfaceTestCase, self).tearDown()
        for file in testfiles:
            os.remove("%s/%s" % (self.sharepath, file))

    def http_server(self):
        self.server.server_bind()
        self.server.server_activate()
        self.server.serve_forever()

    def run_test(self, query, expect, json_in, json_out):
        expect = [s.replace("%BASEPATH%", self.sharepath) for s in expect]
        self.server.json_in = json_in.replace("%BASEPATH%", self.sharepath)
        self.server.json_out = json_out.replace("%BASEPATH%", self.sharepath)

        self.conn = mdscli.conn(self.pipe, 'spotlight', '/foo')
        search = self.conn.search(self.pipe, query, self.sharepath)

        # Give it some time, the get_results() below returns immediately
        # what's available, so if we ask to soon, we might get back no results
        # as the server is still processing the request
        time.sleep(1)

        results = search.get_results(self.pipe)
        self.assertEqual(results, expect)

        search.close(self.pipe)
        self.conn.disconnect(self.pipe)

    def test_mdscli_search(self):
        exp_json_query = r'''{
          "from": 0, "size": 100, "_source": ["path.real"],
          "query": {
            "query_string": {
              "query": "(samba*) AND path.real.fulltext:\"%BASEPATH%\""
            }
          }
        }'''
        fake_json_response = '''{
          "hits" : {
            "total" : { "value" : 2},
            "hits" : [
              {"_source" : {"path" : {"real" : "%BASEPATH%/foo"}}},
              {"_source" : {"path" : {"real" : "%BASEPATH%/bar"}}}
            ]
          }
        }'''
        exp_results = ["%BASEPATH%/foo", "%BASEPATH%/bar"]
        self.run_test('*=="samba*"', exp_results, exp_json_query, fake_json_response)

    def test_mdscli_search_escapes(self):
        sl_query = (
            r'kMDItemFSName=="x+x"||'
            r'kMDItemFSName=="x\*x"||'
            r'kMDItemFSName=="x=x"||'
            'kMDItemFSName=="x\'x"||'
            r'kMDItemFSName=="x?x"||'
            r'kMDItemFSName=="x x"||'
            r'kMDItemFSName=="x(x"||'
            r'kMDItemFSName=="x\"x"||'
            r'kMDItemFSName=="x\\x"'
        )
        exp_json_query = r'''{
          "from": 0, "size": 100, "_source": ["path.real"],
          "query": {
            "query_string": {
              "query": "(file.filename:x\\+x OR file.filename:x\\*x OR file.filename:x=x OR file.filename:x'x OR file.filename:x\\?x OR file.filename:x\\ x OR file.filename:x\\(x OR file.filename:x\\\"x OR file.filename:x\\\\x) AND path.real.fulltext:\"%BASEPATH%\""
            }
          }
        }'''
        fake_json_response = r'''{
          "hits" : {
            "total" : {"value" : 2},
            "hits" : [
              {"_source" : {"path" : {"real" : "%BASEPATH%/x+x"}}},
              {"_source" : {"path" : {"real" : "%BASEPATH%/x*x"}}},
              {"_source" : {"path" : {"real" : "%BASEPATH%/x=x"}}},
              {"_source" : {"path" : {"real" : "%BASEPATH%/x'x"}}},
              {"_source" : {"path" : {"real" : "%BASEPATH%/x?x"}}},
              {"_source" : {"path" : {"real" : "%BASEPATH%/x x"}}},
              {"_source" : {"path" : {"real" : "%BASEPATH%/x(x"}}},
              {"_source" : {"path" : {"real" : "%BASEPATH%/x\"x"}}},
              {"_source" : {"path" : {"real" : "%BASEPATH%/x\\x"}}}
            ]
          }
        }'''
        exp_results = [
            r"%BASEPATH%/x+x",
            r"%BASEPATH%/x*x",
            r"%BASEPATH%/x=x",
            r"%BASEPATH%/x'x",
            r"%BASEPATH%/x?x",
            r"%BASEPATH%/x x",
            r"%BASEPATH%/x(x",
            "%BASEPATH%/x\"x",
            r"%BASEPATH%/x\x",
        ]
        self.run_test(sl_query, exp_results, exp_json_query, fake_json_response)
