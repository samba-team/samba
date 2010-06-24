#!/usr/bin/env python
#
# Simple subunit testrunner for python
# Copyright (C) Jelmer Vernooij <jelmer@samba.org> 2007
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

"""Run a unittest testcase reporting results as Subunit.

  $ python -m subunit.run mylib.tests.test_suite
"""

import sys

from subunit import TestProtocolClient, get_default_formatter


class SubunitTestRunner(object):
    def __init__(self, stream=sys.stdout):
        self.stream = stream

    def run(self, test):
        "Run the given test case or test suite."
        result = TestProtocolClient(self.stream)
        test(result)
        return result


if __name__ == '__main__':
    import optparse
    from unittest import TestProgram
    parser = optparse.OptionParser(__doc__)
    args = parser.parse_args()[1]
    stream = get_default_formatter()
    runner = SubunitTestRunner(stream)
    program = TestProgram(module=None, argv=[sys.argv[0]] + args,
                          testRunner=runner)
