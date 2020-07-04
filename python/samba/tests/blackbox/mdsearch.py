#
# Blackbox tests for mdsearch
#
# Copyright (C) Ralph Boehme                    2019
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

"""Blackbox test for mdsearch"""

import os
import time
import threading
import logging
import json
from http.server import HTTPServer, BaseHTTPRequestHandler
from samba.dcerpc import mdssvc
from samba.tests import BlackboxTestCase
from samba.samba3 import mdscli
from samba.logger import get_samba_logger

logger = get_samba_logger(name=__name__)

testfiles = [
    "foo",
    "bar",
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

class MdfindBlackboxTests(BlackboxTestCase):

    def setUp(self):
        super(MdfindBlackboxTests, self).setUp()

        self.server = HTTPServer(('10.53.57.35', 8080),
                                 MdssvcHTTPRequestHandler,
                                 bind_and_activate=False)

        self.t = threading.Thread(target=MdfindBlackboxTests.http_server, args=(self,))
        self.t.setDaemon(True)
        self.t.start()
        time.sleep(1)

        pipe = mdssvc.mdssvc('ncacn_np:fileserver[/pipe/mdssvc]', self.get_loadparm())
        conn = mdscli.conn(pipe, 'spotlight', '/foo')
        self.sharepath = conn.sharepath()
        conn.disconnect(pipe)

        for file in testfiles:
            f = open("%s/%s" % (self.sharepath, file), "w")
            f.close()

    def tearDown(self):
        super(BlackboxTestCase, self).tearDown()
        for file in testfiles:
            os.remove("%s/%s" % (self.sharepath, file))

    def http_server(self):
        self.server.server_bind()
        self.server.server_activate()
        self.server.serve_forever()

    def test_mdsearch(self):
        """Simple blackbox test for mdsearch"""

        username = os.environ["USERNAME"]
        password = os.environ["PASSWORD"]
        config = os.environ["SMB_CONF_PATH"]

        json_in = r'''{
          "from": 0, "size": 100, "_source": ["path.real"],
          "query": {
            "query_string": {
              "query": "(samba*) AND path.real.fulltext:\"%BASEPATH%\""
            }
          }
        }'''
        json_out = '''{
          "hits" : {
            "total" : { "value" : 2},
            "hits" : [
              {"_source" : {"path" : {"real" : "%BASEPATH%/foo"}}},
              {"_source" : {"path" : {"real" : "%BASEPATH%/bar"}}}
            ]
          }
        }'''

        self.server.json_in = json_in.replace("%BASEPATH%", self.sharepath)
        self.server.json_out = json_out.replace("%BASEPATH%", self.sharepath)

        output = self.check_output("mdsearch -s %s -U %s%%%s fileserver spotlight '*==\"samba*\"'" % (config, username, password))

        actual = output.decode('utf-8').splitlines()
        expected = ["%s/%s" % (self.sharepath, file) for file in testfiles]
        self.assertEqual(expected, actual)
