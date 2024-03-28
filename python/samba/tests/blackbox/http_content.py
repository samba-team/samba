# Blackbox tests for http_test
#
# Copyright (C) Noel Power noel.power@suse.com
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
import time
import threading
import logging
import json
from http.server import HTTPServer, BaseHTTPRequestHandler
from samba.logger import get_samba_logger
from samba.tests import BlackboxTestCase, BlackboxProcessError

logger = get_samba_logger(name=__name__)
COMMAND = "bin/http_test"

# simple handler, spits back the 'path' passed in
# GET or POST and a chunked encoded http response
# where the chunk size is 10 octets
class ContentHTTPRequestHandler(BaseHTTPRequestHandler):
    def handle_req(self):
        msg = bytes(self.path, encoding="utf-8")

        self.send_response(200)
        self.send_header('content-type', 'application/json; charset=UTF-8')
        self.send_header('content-length', len(msg))
        self.end_headers()
        self.wfile.write(msg)

    def do_POST(self):
        self.handle_req()
    def do_GET(self):
        self.handle_req()

class HttpContentBlackboxTests(BlackboxTestCase):
    def setUp(self):
        self.server = HTTPServer((os.getenv("SERVER_IP", "localhost"), 8080),
                                 ContentHTTPRequestHandler,
                                 bind_and_activate=False)
        self.t = threading.Thread(target=HttpContentBlackboxTests.http_server, args=(self,))
        self.t.setDaemon(True)
        self.t.start()
        time.sleep(1)

    def tearDown(self):
        super().tearDown()

    def http_server(self):
        self.server.server_bind()
        self.server.server_activate()
        self.server.serve_forever()

    def notest_simple_msg(self):
        try:
            msg = "simplemessage"
            resp = self.check_output("%s -U%% -I%s --uri %s" % (COMMAND, os.getenv("SERVER_IP", "localhost"), msg))
            self.assertEqual(msg, resp.decode('utf-8'))
        except BlackboxProcessError as e:
            print("Failed with: %s" % e)
            self.fail(str(e))

    def test_exceed_request_size(self):
        try:
            msg = "012345678" # 9 bytes
            # limit response to 8 bytes
            resp = self.check_output("%s -d11 -U%% -I%s --rsize 8 --uri %s" % (COMMAND, os.getenv("SERVER_IP", "localhost"), msg))
            self.fail("unexpected success")
        except BlackboxProcessError as e:
            if "unexpected 0 len response" not in e.stdout.decode('utf-8'):
                self.fail(str(e))
            if "http_parse_headers: Skipping body for code 200" not in e.stderr.decode('utf-8'):
                self.fail(str(e))

    def test_exact_request_size(self):
        try:
            msg = "012345678" # 9 bytes
            # limit response to 9 bytes
            resp = self.check_output("%s -U%% -I%s --rsize 9 --uri %s" % (COMMAND, os.getenv("SERVER_IP", "localhost"), msg))
            self.assertEqual(msg, resp.decode('utf-8'))
        except BlackboxProcessError as e:
            print("Failed with: %s" % e)
            self.fail(str(e))
