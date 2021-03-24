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
from samba.tests import BlackboxTestCase, BlackboxProcessError
import os
import json

class WspToTest(BlackboxTestCase):

    def setUp(self):
        super(BlackboxTestCase, self).setUp()
        self.server = os.environ["SERVER"]
        self.dflt_cmd = ["wsp-to", "elastic"]
    # parse the output from end of wsp-to
    # e.g.
    # Col[0] System.FileName is mapped/converted from elastic col[0]
    # file.filename to a simple WSP property to elastic property map
    def parse_cols(self, col_lines):
        cols = {}
        for col in col_lines.split('\n'):
            if not len(col):
                continue
            key = col.split()[1]
            value = col.split()[-1]
            cols[key] = value
        return cols

    def normalize_query(self, query_in):
        query_out = query_in
        temp = query_in[2:-2]
        jquery = json.loads(temp).get("query")
        return json.dumps(jquery)

    def check_wsp_to_output(self, cmd_args):
        result = self.check_output(cmd_args)
        # parse query
        query_including_cols = result.decode().split("query is:")[1]
        query = query_including_cols.split("selected columns:")[0]
        query = self.normalize_query(query)
        cols_section = query_including_cols.split("selected columns:")[1]
        cols = self.parse_cols(cols_section)
        return query, cols;

    def test_simple_folder_query(self):
        query_args = ["--query", "SELECT System.FileName WHERE System.Kind:Folder"]
        expected_query = '{"query_string": {"query": "file.content_type:(text\\\\/directory)"}}'
        expected_cols = {'System.FileName': 'file.filename'}
        try:
            cmd = self.dflt_cmd
            cmd.extend(query_args)
            query_result, cols = self.check_wsp_to_output(cmd)
        except BlackboxProcessError as e:
             self.fail(str(e))
        # test the query part
        self.assertEqual(query_result, expected_query)
        # test the requested columns
        self.assertEqual(expected_cols, cols)

    def test_simple_picture_query(self):
        query_args = ["--query", "SELECT System.FileName WHERE System.Kind:Picture"]
        expected_query = '{"query_string": {"query": "file.content_type:(image\\\\/*)"}}'
        expected_cols = {'System.FileName': 'file.filename'}
        try:
            cmd = self.dflt_cmd
            cmd.extend(query_args)
            query_result, cols = self.check_wsp_to_output(cmd)
        except BlackboxProcessError as e:
             self.fail(str(e))
        # test the query part
        self.assertEqual(query_result, expected_query)
        # test the requested columns
        self.assertEqual(expected_cols, cols)

    def test_simple_music_query(self):
        query_args = ["--query", "SELECT System.FileName WHERE System.Kind:Music"]
        expected_query = '{"query_string": {"query": "file.content_type:(audio\\\\/*)"}}'
        expected_cols = {'System.FileName': 'file.filename'}
        try:
            cmd = self.dflt_cmd
            cmd.extend(query_args)
            query_result, cols = self.check_wsp_to_output(cmd)
        except BlackboxProcessError as e:
             self.fail(str(e))
        # test the query part
        self.assertEqual(query_result, expected_query)
        # test the requested columns
        self.assertEqual(expected_cols, cols)

    def test_simple_video_query(self):
        query_args = ["--query", "SELECT System.FileName WHERE System.Kind:Video"]
        expected_query = '{"query_string": {"query": "file.content_type:(video\\\\/* application\\\\/mp4)"}}'
        expected_cols = {'System.FileName': 'file.filename'}
        try:
            cmd = self.dflt_cmd
            cmd.extend(query_args)
            query_result, cols = self.check_wsp_to_output(cmd)
        except BlackboxProcessError as e:
             self.fail(str(e))
        # test the query part
        self.assertEqual(query_result, expected_query)
        # test the requested columns
        self.assertEqual(expected_cols, cols)

    def test_simple_documents_query(self):
        query_args = ["--query", "SELECT System.FileName WHERE System.Kind:Document"]
        self.maxDiff = None
        expected_query = '{"query_string": {"query": "file.content_type:(application\\\\/vnd.oasis.opendocument* application\\\\/pdf* text\\\\/csv*  text\\\\/plain* text\\\\/tsv* text\\\\/html* application\\\\/msword* application\\\\/vnd.ms\\\\-powerpoint* application\\\\/vnd.ms\\\\-excel* application\\\\/vnd.openxmlformats\\\\-officedocument*)"}}'
        expected_cols = {'System.FileName': 'file.filename'}
        try:
            cmd = self.dflt_cmd
            cmd.extend(query_args)
            query_result, cols = self.check_wsp_to_output(cmd)
        except BlackboxProcessError as e:
             self.fail(str(e))
        # test the query part
        self.assertEqual(query_result, expected_query)
        # test the requested columns
        self.assertEqual(expected_cols, cols)
