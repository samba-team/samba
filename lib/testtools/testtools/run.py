# Copyright (c) 2009 Jonathan M. Lange. See LICENSE for details.

"""python -m testtools.run testspec [testspec...]

Run some tests with the testtools extended API.

For instance, to run the testtools test suite.
 $ python -m testtools.run testtools.tests.test_suite
"""

import sys

from testtools.tests import test_suite
from testtools import TextTestResult


class TestToolsTestRunner(object):
    """ A thunk object to support unittest.TestProgram."""

    def run(self, test):
        "Run the given test case or test suite."
        result = TextTestResult(sys.stdout)
        result.startTestRun()
        try:
            return test.run(result)
        finally:
            result.stopTestRun()


if __name__ == '__main__':
    import optparse
    from unittest import TestProgram
    parser = optparse.OptionParser(__doc__)
    args = parser.parse_args()[1]
    if not args:
        parser.error("No testspecs given.")
    runner = TestToolsTestRunner()
    program = TestProgram(module=None, argv=[sys.argv[0]] + args,
        testRunner=runner)
