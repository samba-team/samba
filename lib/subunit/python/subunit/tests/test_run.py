#
#  subunit: extensions to python unittest to get test results from subprocesses.
#  Copyright (C) 2011  Robert Collins <robertc@robertcollins.net>
#
#  Licensed under either the Apache License, Version 2.0 or the BSD 3-clause
#  license at the users choice. A copy of both licenses are available in the
#  project source as Apache-2.0 and BSD. You may not use this file except in
#  compliance with one of these two licences.
#  
#  Unless required by applicable law or agreed to in writing, software
#  distributed under these licenses is distributed on an "AS IS" BASIS, WITHOUT
#  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  See the
#  license you chose for the specific language governing permissions and
#  limitations under that license.
#

from testtools.compat import BytesIO
import unittest

from testtools import PlaceHolder

import subunit
from subunit.run import SubunitTestRunner


def test_suite():
    loader = subunit.tests.TestUtil.TestLoader()
    result = loader.loadTestsFromName(__name__)
    return result


class TimeCollectingTestResult(unittest.TestResult):

    def __init__(self, *args, **kwargs):
        super(TimeCollectingTestResult, self).__init__(*args, **kwargs)
        self.time_called = []

    def time(self, a_time):
        self.time_called.append(a_time)


class TestSubunitTestRunner(unittest.TestCase):

    def test_includes_timing_output(self):
        io = BytesIO()
        runner = SubunitTestRunner(stream=io)
        test = PlaceHolder('name')
        runner.run(test)
        client = TimeCollectingTestResult()
        io.seek(0)
        subunit.TestProtocolServer(client).readFrom(io)
        self.assertTrue(len(client.time_called) > 0)
