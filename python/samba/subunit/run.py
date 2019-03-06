#!/usr/bin/env python3
#
# Simple subunit testrunner for python
# Copyright (C) Jelmer Vernooij <jelmer@samba.org> 2014

# Cobbled together from testtools and subunit:
# Copyright (C) 2005-2011 Robert Collins <robertc@robertcollins.net>
# Copyright (c) 2008-2011 testtools developers.
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

  $ python -m samba.subunit.run mylib.tests.test_suite
"""

from iso8601.iso8601 import UTC

import datetime
import os
import sys
import traceback
import unittest


# Whether or not to hide layers of the stack trace that are
# unittest/testtools internal code.  Defaults to True since the
# system-under-test is rarely unittest or testtools.
HIDE_INTERNAL_STACK = True


def write_traceback(stream, err, test):
    """Converts a sys.exc_info()-style tuple of values into a string.

    Copied from Python 2.7's unittest.TestResult._exc_info_to_string.
    """
    def _is_relevant_tb_level(tb):
        return '__unittest' in tb.tb_frame.f_globals

    def _count_relevant_tb_levels(tb):
        length = 0
        while tb and not _is_relevant_tb_level(tb):
            length += 1
            tb = tb.tb_next
        return length

    exctype, value, tb = err
    # Skip test runner traceback levels
    if HIDE_INTERNAL_STACK:
        while tb and _is_relevant_tb_level(tb):
            tb = tb.tb_next

    format_exception = traceback.format_exception

    if (HIDE_INTERNAL_STACK and test.failureException
        and isinstance(value, test.failureException)):
        # Skip assert*() traceback levels
        length = _count_relevant_tb_levels(tb)
        msgLines = format_exception(exctype, value, tb, length)
    else:
        msgLines = format_exception(exctype, value, tb)
    stream.writelines(msgLines)


class TestProtocolClient(unittest.TestResult):
    """A TestResult which generates a subunit stream for a test run.

    # Get a TestSuite or TestCase to run
    suite = make_suite()
    # Create a stream (any object with a 'write' method). This should accept
    # bytes not strings: subunit is a byte orientated protocol.
    stream = open('tests.log', 'wb')
    # Create a subunit result object which will output to the stream
    result = subunit.TestProtocolClient(stream)
    # Optionally, to get timing data for performance analysis, wrap the
    # serialiser with a timing decorator
    result = subunit.test_results.AutoTimingTestResultDecorator(result)
    # Run the test suite reporting to the subunit result object
    suite.run(result)
    # Close the stream.
    stream.close()
    """

    def __init__(self, stream):
        unittest.TestResult.__init__(self)
        self._stream = stream
        self.failed = False

    def wasSuccessful(self):
        return not self.failed

    def addError(self, test, error=None):
        """Report an error in test test.

        :param error: Standard unittest positional argument form - an
            exc_info tuple.
        """
        self._addOutcome("error", test, error=error)
        self.failed = True

    def addExpectedFailure(self, test, error=None):
        """Report an expected failure in test test.

        :param error: Standard unittest positional argument form - an
            exc_info tuple.
        """
        self._addOutcome("xfail", test, error=error)

    def addFailure(self, test, error=None):
        """Report a failure in test test.

        :param error: Standard unittest positional argument form - an
            exc_info tuple.
        """
        self._addOutcome("failure", test, error=error)
        self.failed = True

    def _addOutcome(self, outcome, test, error=None, error_permitted=True):
        """Report a failure in test test.

        :param outcome: A string describing the outcome - used as the
            event name in the subunit stream.
        :param error: Standard unittest positional argument form - an
            exc_info tuple.
        :param error_permitted: If True then error must be supplied.
            If False then error must not be supplied.
        """
        self._stream.write(("%s: " % outcome) + test.id())
        if error_permitted:
            if error is None:
                raise ValueError
        else:
            if error is not None:
                raise ValueError
        if error is not None:
            self._stream.write(" [\n")
            write_traceback(self._stream, error, test)
        else:
            self._stream.write("\n")
        if error is not None:
            self._stream.write("]\n")

    def addSkip(self, test, reason=None):
        """Report a skipped test."""
        if reason is None:
            self._addOutcome("skip", test, error=None)
        else:
            self._stream.write("skip: %s [\n" % test.id())
            self._stream.write("%s\n" % reason)
            self._stream.write("]\n")

    def addSuccess(self, test):
        """Report a success in a test."""
        self._addOutcome("successful", test, error_permitted=False)

    def addUnexpectedSuccess(self, test):
        """Report an unexpected success in test test.
        """
        self._addOutcome("uxsuccess", test, error_permitted=False)
        self.failed = True

    def startTest(self, test):
        """Mark a test as starting its test run."""
        super(TestProtocolClient, self).startTest(test)
        self._stream.write("test: " + test.id() + "\n")
        self._stream.flush()

    def stopTest(self, test):
        super(TestProtocolClient, self).stopTest(test)
        self._stream.flush()

    def time(self, a_datetime):
        """Inform the client of the time.

        ":param datetime: A datetime.datetime object.
        """
        time = a_datetime.astimezone(UTC)
        self._stream.write("time: %04d-%02d-%02d %02d:%02d:%02d.%06dZ\n" % (
            time.year, time.month, time.day, time.hour, time.minute,
            time.second, time.microsecond))


def _flatten_tests(suite_or_case, unpack_outer=False):
    try:
        tests = iter(suite_or_case)
    except TypeError:
        # Not iterable, assume it's a test case.
        return [(suite_or_case.id(), suite_or_case)]
    if (type(suite_or_case) in (unittest.TestSuite,) or
        unpack_outer):
        # Plain old test suite (or any others we may add).
        result = []
        for test in tests:
            # Recurse to flatten.
            result.extend(_flatten_tests(test))
        return result
    else:
        # Find any old actual test and grab its id.
        suite_id = None
        tests = iterate_tests(suite_or_case)
        for test in tests:
            suite_id = test.id()
            break
        # If it has a sort_tests method, call that.
        if getattr(suite_or_case, 'sort_tests', None) is not None:
            suite_or_case.sort_tests()
        return [(suite_id, suite_or_case)]


def sorted_tests(suite_or_case, unpack_outer=False):
    """Sort suite_or_case while preserving non-vanilla TestSuites."""
    tests = _flatten_tests(suite_or_case, unpack_outer=unpack_outer)
    tests.sort()
    return unittest.TestSuite([test for (sort_key, test) in tests])


def iterate_tests(test_suite_or_case):
    """Iterate through all of the test cases in 'test_suite_or_case'."""
    try:
        suite = iter(test_suite_or_case)
    except TypeError:
        yield test_suite_or_case
    else:
        for test in suite:
            for subtest in iterate_tests(test):
                yield subtest


defaultTestLoader = unittest.defaultTestLoader
defaultTestLoaderCls = unittest.TestLoader

if getattr(defaultTestLoader, 'discover', None) is None:
    try:
        import discover
        defaultTestLoader = discover.DiscoveringTestLoader()
        defaultTestLoaderCls = discover.DiscoveringTestLoader
        have_discover = True
    except ImportError:
        have_discover = False
else:
    have_discover = True


####################
# Taken from python 2.7 and slightly modified for compatibility with
# older versions. Delete when 2.7 is the oldest supported version.
# Modifications:
#  - Use have_discover to raise an error if the user tries to use
#    discovery on an old version and doesn't have discover installed.
#  - If --catch is given check that installHandler is available, as
#    it won't be on old python versions.
#  - print calls have been been made single-source python3 compatibile.
#  - exception handling likewise.
#  - The default help has been changed to USAGE_AS_MAIN and USAGE_FROM_MODULE
#    removed.
#  - A tweak has been added to detect 'python -m *.run' and use a
#    better progName in that case.
#  - self.module is more comprehensively set to None when being invoked from
#    the commandline - __name__ is used as a sentinel value.
#  - --list has been added which can list tests (should be upstreamed).
#  - --load-list has been added which can reduce the tests used (should be
#    upstreamed).
#  - The limitation of using getopt is declared to the user.
#  - http://bugs.python.org/issue16709 is worked around, by sorting tests when
#    discover is used.

CATCHBREAK   = "  -c, --catch      Catch control-C and display results\n"
BUFFEROUTPUT = "  -b, --buffer     Buffer stdout and stderr during test runs\n"

USAGE_AS_MAIN = """\
Usage: %(progName)s [options] [tests]

Options:
  -h, --help       Show this message
  -v, --verbose    Verbose output
  -q, --quiet      Minimal output
  -l, --list       List tests rather than executing them.
  --load-list      Specifies a file containing test ids, only tests matching
                   those ids are executed.
%(catchbreak)s%(buffer)s
Examples:
  %(progName)s test_module               - run tests from test_module
  %(progName)s module.TestClass          - run tests from module.TestClass
  %(progName)s module.Class.test_method  - run specified test method

All options must come before [tests].  [tests] can be a list of any number of
test modules, classes and test methods.

Alternative Usage: %(progName)s discover [options]

Options:
  -v, --verbose    Verbose output
s%(catchbreak)s%(buffer)s  -s directory     Directory to start discovery ('.' default)
  -p pattern       Pattern to match test files ('test*.py' default)
  -t directory     Top level directory of project (default to
                   start directory)
  -l, --list       List tests rather than executing them.
  --load-list      Specifies a file containing test ids, only tests matching
                   those ids are executed.

For test discovery all test modules must be importable from the top
level directory of the project.
"""


# NOT a TestResult, because we are implementing the interface, not inheriting
# it.
class TestResultDecorator(object):
    """General pass-through decorator.

    This provides a base that other TestResults can inherit from to
    gain basic forwarding functionality. It also takes care of
    handling the case where the target doesn't support newer methods
    or features by degrading them.
    """

    def __init__(self, decorated):
        """Create a TestResultDecorator forwarding to decorated."""
        # Make every decorator degrade gracefully.
        self.decorated = decorated

    def startTest(self, test):
        return self.decorated.startTest(test)

    def startTestRun(self):
        return self.decorated.startTestRun()

    def stopTest(self, test):
        return self.decorated.stopTest(test)

    def stopTestRun(self):
        return self.decorated.stopTestRun()

    def addError(self, test, err=None):
        return self.decorated.addError(test, err)

    def addFailure(self, test, err=None):
        return self.decorated.addFailure(test, err)

    def addSuccess(self, test):
        return self.decorated.addSuccess(test)

    def addSkip(self, test, reason=None):
        return self.decorated.addSkip(test, reason)

    def addExpectedFailure(self, test, err=None):
        return self.decorated.addExpectedFailure(test, err)

    def addUnexpectedSuccess(self, test):
        return self.decorated.addUnexpectedSuccess(test)

    def wasSuccessful(self):
        return self.decorated.wasSuccessful()

    @property
    def shouldStop(self):
        return self.decorated.shouldStop

    def stop(self):
        return self.decorated.stop()

    @property
    def testsRun(self):
        return self.decorated.testsRun

    def time(self, a_datetime):
        return self.decorated.time(a_datetime)


class HookedTestResultDecorator(TestResultDecorator):
    """A TestResult which calls a hook on every event."""

    def __init__(self, decorated):
        self.super = super(HookedTestResultDecorator, self)
        self.super.__init__(decorated)

    def startTest(self, test):
        self._before_event()
        return self.super.startTest(test)

    def startTestRun(self):
        self._before_event()
        return self.super.startTestRun()

    def stopTest(self, test):
        self._before_event()
        return self.super.stopTest(test)

    def stopTestRun(self):
        self._before_event()
        return self.super.stopTestRun()

    def addError(self, test, err=None):
        self._before_event()
        return self.super.addError(test, err)

    def addFailure(self, test, err=None):
        self._before_event()
        return self.super.addFailure(test, err)

    def addSuccess(self, test):
        self._before_event()
        return self.super.addSuccess(test)

    def addSkip(self, test, reason=None):
        self._before_event()
        return self.super.addSkip(test, reason)

    def addExpectedFailure(self, test, err=None):
        self._before_event()
        return self.super.addExpectedFailure(test, err)

    def addUnexpectedSuccess(self, test):
        self._before_event()
        return self.super.addUnexpectedSuccess(test)

    def wasSuccessful(self):
        self._before_event()
        return self.super.wasSuccessful()

    @property
    def shouldStop(self):
        self._before_event()
        return self.super.shouldStop

    def stop(self):
        self._before_event()
        return self.super.stop()

    def time(self, a_datetime):
        self._before_event()
        return self.super.time(a_datetime)


class AutoTimingTestResultDecorator(HookedTestResultDecorator):
    """Decorate a TestResult to add time events to a test run.

    By default this will cause a time event before every test event,
    but if explicit time data is being provided by the test run, then
    this decorator will turn itself off to prevent causing confusion.
    """

    def __init__(self, decorated):
        self._time = None
        super(AutoTimingTestResultDecorator, self).__init__(decorated)

    def _before_event(self):
        time = self._time
        if time is not None:
            return
        time = datetime.datetime.utcnow().replace(tzinfo=UTC)
        self.decorated.time(time)

    @property
    def shouldStop(self):
        return self.decorated.shouldStop

    def time(self, a_datetime):
        """Provide a timestamp for the current test activity.

        :param a_datetime: If None, automatically add timestamps before every
            event (this is the default behaviour if time() is not called at
            all).  If not None, pass the provided time onto the decorated
            result object and disable automatic timestamps.
        """
        self._time = a_datetime
        return self.decorated.time(a_datetime)


class SubunitTestRunner(object):

    def __init__(self, verbosity=None, buffer=None, stream=None):
        """Create a SubunitTestRunner.

        :param verbosity: Ignored.
        :param buffer: Ignored.
        """
        self.stream = stream or sys.stdout

    def run(self, test):
        "Run the given test case or test suite."
        result = TestProtocolClient(self.stream)
        result = AutoTimingTestResultDecorator(result)
        test(result)
        return result


class TestProgram(object):
    """A command-line program that runs a set of tests; this is primarily
       for making test modules conveniently executable.
    """
    USAGE = USAGE_AS_MAIN

    # defaults for testing
    catchbreak = buffer = progName = None

    def __init__(self, module=__name__, defaultTest=None, argv=None,
                    testRunner=None, testLoader=defaultTestLoader,
                    exit=True, verbosity=1, catchbreak=None,
                    buffer=None, stdout=None):
        if module == __name__:
            self.module = None
        elif isinstance(module, str):
            self.module = __import__(module)
            for part in module.split('.')[1:]:
                self.module = getattr(self.module, part)
        else:
            self.module = module
        if argv is None:
            argv = sys.argv
        if stdout is None:
            stdout = sys.stdout
        if testRunner is None:
            testRunner = SubunitTestRunner()

        self.exit = exit
        self.catchbreak = catchbreak
        self.verbosity = verbosity
        self.buffer = buffer
        self.defaultTest = defaultTest
        self.listtests = False
        self.load_list = None
        self.testRunner = testRunner
        self.testLoader = testLoader
        progName = argv[0]
        if progName.endswith('%srun.py' % os.path.sep):
            elements = progName.split(os.path.sep)
            progName = '%s.run' % elements[-2]
        else:
            progName = os.path.basename(argv[0])
        self.progName = progName
        self.parseArgs(argv)
        if self.load_list:
            # TODO: preserve existing suites (like testresources does in
            # OptimisingTestSuite.add, but with a standard protocol).
            # This is needed because the load_tests hook allows arbitrary
            # suites, even if that is rarely used.
            source = open(self.load_list, 'rb')
            try:
                lines = source.readlines()
            finally:
                source.close()
            test_ids = set(line.strip().decode('utf-8') for line in lines)
            filtered = unittest.TestSuite()
            for test in iterate_tests(self.test):
                if test.id() in test_ids:
                    filtered.addTest(test)
            self.test = filtered
        if not self.listtests:
            self.runTests()
        else:
            for test in iterate_tests(self.test):
                stdout.write('%s\n' % test.id())

    def parseArgs(self, argv):
        if len(argv) > 1 and argv[1].lower() == 'discover':
            self._do_discovery(argv[2:])
            return

        import getopt
        long_opts = ['help', 'verbose', 'quiet', 'catch', 'buffer',
            'list', 'load-list=']
        try:
            options, args = getopt.getopt(argv[1:], 'hHvqfcbl', long_opts)
            for opt, value in options:
                if opt in ('-h','-H','--help'):
                    self.usageExit()
                if opt in ('-q','--quiet'):
                    self.verbosity = 0
                if opt in ('-v','--verbose'):
                    self.verbosity = 2
                if opt in ('-c','--catch'):
                    if self.catchbreak is None:
                        self.catchbreak = True
                    # Should this raise an exception if -c is not valid?
                if opt in ('-b','--buffer'):
                    if self.buffer is None:
                        self.buffer = True
                    # Should this raise an exception if -b is not valid?
                if opt in ('-l', '--list'):
                    self.listtests = True
                if opt == '--load-list':
                    self.load_list = value
            if len(args) == 0 and self.defaultTest is None:
                # createTests will load tests from self.module
                self.testNames = None
            elif len(args) > 0:
                self.testNames = args
            else:
                self.testNames = (self.defaultTest,)
            self.createTests()
        except getopt.error:
            self.usageExit(sys.exc_info()[1])

    def createTests(self):
        if self.testNames is None:
            self.test = self.testLoader.loadTestsFromModule(self.module)
        else:
            self.test = self.testLoader.loadTestsFromNames(self.testNames,
                                                           self.module)

    def _do_discovery(self, argv, Loader=defaultTestLoaderCls):
        # handle command line args for test discovery
        if not have_discover:
            raise AssertionError("Unable to use discovery, must use python 2.7 "
                    "or greater, or install the discover package.")
        self.progName = '%s discover' % self.progName
        import optparse
        parser = optparse.OptionParser()
        parser.prog = self.progName
        parser.add_option('-v', '--verbose', dest='verbose', default=False,
                          help='Verbose output', action='store_true')
        if self.catchbreak != False:
            parser.add_option('-c', '--catch', dest='catchbreak', default=False,
                              help='Catch ctrl-C and display results so far',
                              action='store_true')
        if self.buffer != False:
            parser.add_option('-b', '--buffer', dest='buffer', default=False,
                              help='Buffer stdout and stderr during tests',
                              action='store_true')
        parser.add_option('-s', '--start-directory', dest='start', default='.',
                          help="Directory to start discovery ('.' default)")
        parser.add_option('-p', '--pattern', dest='pattern', default='test*.py',
                          help="Pattern to match tests ('test*.py' default)")
        parser.add_option('-t', '--top-level-directory', dest='top', default=None,
                          help='Top level directory of project (defaults to start directory)')
        parser.add_option('-l', '--list', dest='listtests', default=False, action="store_true",
                          help='List tests rather than running them.')
        parser.add_option('--load-list', dest='load_list', default=None,
                          help='Specify a filename containing the test ids to use.')

        options, args = parser.parse_args(argv)
        if len(args) > 3:
            self.usageExit()

        for name, value in zip(('start', 'pattern', 'top'), args):
            setattr(options, name, value)

        # only set options from the parsing here
        # if they weren't set explicitly in the constructor
        if self.catchbreak is None:
            self.catchbreak = options.catchbreak
        if self.buffer is None:
            self.buffer = options.buffer
        self.listtests = options.listtests
        self.load_list = options.load_list

        if options.verbose:
            self.verbosity = 2

        start_dir = options.start
        pattern = options.pattern
        top_level_dir = options.top

        loader = Loader()
        # See http://bugs.python.org/issue16709
        # While sorting here is intrusive, its better than being random.
        # Rules for the sort:
        # - standard suites are flattened, and the resulting tests sorted by
        #   id.
        # - non-standard suites are preserved as-is, and sorted into position
        #   by the first test found by iterating the suite.
        # We do this by a DSU process: flatten and grab a key, sort, strip the
        # keys.
        loaded = loader.discover(start_dir, pattern, top_level_dir)
        self.test = sorted_tests(loaded)

    def runTests(self):
        if (self.catchbreak
            and getattr(unittest, 'installHandler', None) is not None):
            unittest.installHandler()
        self.result = self.testRunner.run(self.test)
        if self.exit:
            sys.exit(not self.result.wasSuccessful())

    def usageExit(self, msg=None):
        if msg:
            print (msg)
        usage = {'progName': self.progName, 'catchbreak': '',
                 'buffer': ''}
        if self.catchbreak != False:
            usage['catchbreak'] = CATCHBREAK
        if self.buffer != False:
            usage['buffer'] = BUFFEROUTPUT
        usage_text = self.USAGE % usage
        usage_lines = usage_text.split('\n')
        usage_lines.insert(2, "Run a test suite with a subunit reporter.")
        usage_lines.insert(3, "")
        print('\n'.join(usage_lines))
        sys.exit(2)


if __name__ == '__main__':
    TestProgram(module=None, argv=sys.argv, stdout=sys.stdout)
