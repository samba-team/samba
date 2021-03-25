# Blackbox tests for WSP
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
#
import os
import time
import threading
import logging
import json
from http.server import HTTPServer, BaseHTTPRequestHandler
from samba.tests import BlackboxTestCase, BlackboxProcessError
from samba.logger import get_samba_logger
import subprocess

logger = get_samba_logger(name=__name__)


class BaseHandler:
    def __init__(self, handler, model):
        self.http_handler = handler
        self.model = model
        self.json_in = None
        self.json_out_s = None
        if 'content-length' in self.http_handler.headers:
            content_length = int(self.http_handler.headers['content-length'])
            body = self.http_handler.rfile.read(content_length)
            self.json_in = json.loads((body))
    def process(self):
        pass

class StatsApiHandler(BaseHandler):
    def process(self):
        # minimal stats json that wsp server expects to parse
        stats_template = '{"_all": {"total": {"docs": {"count": %d, "deleted": 0}}}}'
        self.json_out_s = stats_template % len(self.model["files"])
        return True

class SearchApiHandler(BaseHandler):
    def process(self):
        search_result = {
            "took" : 0,
            "timed_out" : False,
            "_shards" : {
                "total" : 1,
                "successful" : 1,
                "skipped" : 0,
                "failed" : 0
            },
            "hits" : {
                "total" : {
                    "value" : 0,
                    "relation" : "eq"
                },
                "max_score" : None,
                "hits" : []
            }
        }
        search_result["hits"]["total"]["value"] = len(self.model["files"])
        if self.json_in["from"] != 0 or self.json_in["size"] !=0:
            hits = []
            docid = 123456789
            start = self.json_in["from"]
            size = self.json_in["size"]
            if start < len(self.model["files"]):
                for afile in self.model["files"][start:min(size, len(self.model["files"]))]:
                    hit = { "_index" : "someindex",
                        "_type" : "_doc",
                        "_id" : "%032x" % docid,
                        "_score" : 1.0002395,
                           "_source" : { "path" : { "real" : afile["file"]["url"][len("file://"):]}}
                       }
                    hits.append(hit)
                    docid = docid + 1
                search_result["hits"]["hits"] = hits
        self.json_out_s = json.dumps(search_result)
        return True

# map of handlers for basic elasticsearch api
fake_elastic_server = { "GET" : { "/_all/_stats" : StatsApiHandler },
                        "POST" : { "/_all/_search" : SearchApiHandler },
                      }

class ESHTTPRequestHandler(BaseHTTPRequestHandler):

    def handle_req(self):
        # wtf httpserver closes the connection after
        # servicing every request
        self.close_connection = False
        path = self.path.split("?pretty")[0]
        logger.info("processing cmd ->%s<- path ->%s<-" % (self.command, path))
        if not (self.command in fake_elastic_server) or not (path in fake_elastic_server[self.command]):
                self.send_error(400, "Bad Request", "Unhandled command %s with %s\n" % (self.command, self.path))
                return

        handler = fake_elastic_server[self.command][path](self, self.server.model)
        if not handler.process():
            self.send_error(400, "Bad Request", "handler for %s:%s failed\n" % (self.command, self.path))
            return

        resp = bytes(handler.json_out_s, encoding="utf-8")

        self.send_response(200)
        self.send_header('content-type', 'application/json; charset=UTF-8')
        self.send_header('content-length', len(resp))
        self.end_headers()
        self.wfile.write(resp)

    def do_POST(self):
        self.handle_req()
    def do_GET(self):
        self.handle_req()

class WspTestBlackboxBase(BlackboxTestCase):

    def http_server(self):
        logger.info("# about to bind\n")
        self.server.server_bind()
        logger.info("# about to activate\n")
        self.server.server_activate()
        logger.info("# about to serve\n")
        self.server.serve_forever()

    def setUp(self):
        super(WspTestBlackboxBase, self).setUp()
        self.base_path = "%s" % os.getenv("LOCAL_PATH", "")
        self.server = HTTPServer((os.getenv("SERVER_IP", "localhost"), 8080),
                                 ESHTTPRequestHandler,
                                 bind_and_activate=False)
        t = threading.Thread(target=WspTestBlackboxBase.http_server, args=(self,))
        t.setDaemon(True)
        t.start()
        time.sleep(1)

        self.server.model = None
        self.server.expected_auth = None # anonymous
        self.server.expected_run_as = None
        logger.info("setup complete")

    def create_model_files(self):
        for afile in self.server.model["files"]:
            url = afile["file"]["url"]
            fullname = url[len("file://"):]
            apath, f = os.path.split(fullname)
            if not os.path.exists(apath):
                os.makedirs(apath)
            f = open(fullname, "w")
            f.close()

    def delete_model_files(self):
        if self.server.model:
            for afile in self.server.model["files"]:
                url = afile["file"]["url"]
                fullname = url[len("file://"):]
                os.unlink(fullname)

    def tearDown(self):
        super(WspTestBlackboxBase, self).tearDown()
        self.delete_model_files()
        logger.info("teardown complete")


class WspSanityTest(WspTestBlackboxBase):
    def test_curl_stats(self):
        cmd = ["/usr/bin/curl"]
        # this test is for testing the test harness
        # itself, if we don't have curl don't bother with
        # it
        if not os.path.exists(cmd[0]):
            return
        args = ["-X", "GET", "http://%s:8080/_all/_stats?pretty" % os.getenv("SERVER_IP", "localhost")]
        expected = '{"_all": {"total": {"docs": {"count": 2, "deleted": 0}}}}'
        cmd.extend(args)
        model = { "files" : [
                        { "file" : {"url" : "file://" + os.path.join(self.base_path, "wspdir/file1")}},
                        { "file" : {"url" : "file://" + os.path.join(self.base_path, "wspdir/file2")}},],
                  "base_path" : self.base_path
                }
        self.server.model = model
        self.create_model_files()
        try:
            result = self.check_output(cmd)

        except BlackboxProcessError as e:
            self.fail(str(e))
        self.assertEqual(result.decode(), expected)

    def test_curl_query_image_no_size(self):
        cmd = ["/usr/bin/curl"]
        # this test is for testing the test harness
        # itself, if we don't have curl don't bother with
        # it
        if not os.path.exists(cmd[0]):
            return
        model = { "files" : [
                        { "file" : {"url" : "file://" + os.path.join(self.base_path, "wspdir/file1")}},
                        { "file" : {"url" : "file://" + os.path.join(self.base_path, "wspdir/file2")}},],
                  "base_path" : self.base_path
                }
        args = ["-X", "POST", "http://%s:8080/_all/_search?pretty" % os.getenv("SERVER_IP", "localhost"), "-H", "Content-Type: application/json", "-d", '{    "from": 0,    "size": 0,    "_source": ["file.url"],    "query": { "bool" :{ "must": [{ "bool" :{ "must": [{ "bool" :{ "must": [{ "query_string":{ "query" : "(file.content_type:image\\\/*)" } } ,{ "query_string":{ "query" : "(path.real.fulltext:%s)" } } ] } } ] } } ] } } }' % model["base_path"]]
        expected = '{"took": 0, "timed_out": false, "_shards": {"total": 1, "successful": 1, "skipped": 0, "failed": 0}, "hits": {"total": {"value": 2, "relation": "eq"}, "max_score": null, "hits": []}}'
        cmd.extend(args)
        self.server.model = model
        self.create_model_files()
        try:
            result = self.check_output(cmd)
        except BlackboxProcessError as e:
            self.fail(str(e))
        self.assertEqual(result.decode(), expected)

    def test_curl_query_image_0_to_4(self):
        cmd = ["/usr/bin/curl"]
        # this test is for testing the test harness
        # itself, if we don't have curl don't bother with
        # it
        if not os.path.exists(cmd[0]):
            return
        model = {   "files" : [
                        { "file" : {"url" : "file://" + os.path.join(self.base_path, "wspdir/file1")}},
                        { "file" : {"url" : "file://" + os.path.join(self.base_path, "wspdir/file2")}},
                        { "file" : {"url" : "file://" + os.path.join(self.base_path, "wspdir/file3")}},
                        { "file" : {"url" : "file://" + os.path.join(self.base_path, "wspdir/file4")}},
                    ],
                    "base_path" : self.base_path,
                }
        args = ["-X", "POST", "http://%s:8080/_all/_search?pretty" % os.getenv("SERVER_IP", "localhost"), "-H", "Content-Type: application/json", "-d", '{    "from": 0,    "size": 4,    "_source": ["file.url"],    "query": { "bool" :{ "must": [{ "bool" :{ "must": [{ "bool" :{ "must": [{ "query_string":{ "query" : "(file.content_type:image\\\/*)" } } ,{ "query_string":{ "query" : "(path.real.fulltext:%s)" } } ] } } ] } } ] } } }' % model["base_path"]]
        expected = '{"took": 0, "timed_out": false, "_shards": {"total": 1, "successful": 1, "skipped": 0, "failed": 0}, "hits": {"total": {"value": 4, "relation": "eq"}, "max_score": null, "hits": [{"_index": "someindex", "_type": "_doc", "_id": "000000000000000000000000075bcd15", "_score": 1.0002395, "_source": {"path": {"real": "%s/wspdir/file1"}}}, {"_index": "someindex", "_type": "_doc", "_id": "000000000000000000000000075bcd16", "_score": 1.0002395, "_source": {"path": {"real": "%s/wspdir/file2"}}}, {"_index": "someindex", "_type": "_doc", "_id": "000000000000000000000000075bcd17", "_score": 1.0002395, "_source": {"path": {"real": "%s/wspdir/file3"}}}, {"_index": "someindex", "_type": "_doc", "_id": "000000000000000000000000075bcd18", "_score": 1.0002395, "_source": {"path": {"real": "%s/wspdir/file4"}}}]}}' % (self.base_path, self.base_path, self.base_path, self.base_path)
        cmd.extend(args)
        self.server.model = model
        self.create_model_files()
        try:
            result = self.check_output(cmd)
        except BlackboxProcessError as e:
            self.fail(str(e))
        self.assertEqual(result.decode(), expected)

class WspSearchTest(WspTestBlackboxBase):
    def test_wspsearch_picture(self):
        cmd = ["wspsearch", "-U%s%%%s" % (os.environ["USER"], os.environ["PASSWORD"]), "//%s/wsp" % os.environ["SERVER"], "--kind", "Picture"]
        model = {   "files" : [
                        { "file" : {"url" : "file://" + os.path.join(self.base_path, "wspdir/file1")}},
                        { "file" : {"url" : "file://" + os.path.join(self.base_path, "wspdir/file2")}},
                        { "file" : {"url" : "file://" + os.path.join(self.base_path, "wspdir/file3")}}],
                    "base_path" : self.base_path,
                }
        self.server.model = model
        self.create_model_files()
        try:
            result = self.check_output(cmd)
        except BlackboxProcessError as e:
            self.fail(str(e))
        # first just verify we got 3 results
        self.assertTrue("found 3 results" in result.decode())
        # next add some more checks on the results
