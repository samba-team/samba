# Copyright (c) 2009-2011 testtools developers. See LICENSE for details.

"""Test suites and related things."""

__metaclass__ = type
__all__ = [
  'ConcurrentTestSuite',
  'iterate_tests',
  ]

from testtools.helpers import try_imports

Queue = try_imports(['Queue.Queue', 'queue.Queue'])

import threading
import unittest

import testtools


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


class ConcurrentTestSuite(unittest.TestSuite):
    """A TestSuite whose run() calls out to a concurrency strategy."""

    def __init__(self, suite, make_tests, wrap_result=None):
        """Create a ConcurrentTestSuite to execute suite.

        :param suite: A suite to run concurrently.
        :param make_tests: A helper function to split the tests in the
            ConcurrentTestSuite into some number of concurrently executing
            sub-suites. make_tests must take a suite, and return an iterable
            of TestCase-like object, each of which must have a run(result)
            method.
        :param wrap_result: An optional function that takes a thread-safe
            result and a thread number and must return a ``TestResult``
            object. If not provided, then ``ConcurrentTestSuite`` will just
            use a ``ThreadsafeForwardingResult`` wrapped around the result
            passed to ``run()``.
        """
        super(ConcurrentTestSuite, self).__init__([suite])
        self.make_tests = make_tests
        if wrap_result:
            self._wrap_result = wrap_result

    def _wrap_result(self, thread_safe_result, thread_number):
        """Wrap a thread-safe result before sending it test results.

        You can either override this in a subclass or pass your own
        ``wrap_result`` in to the constructor.  The latter is preferred.
        """
        return thread_safe_result

    def run(self, result):
        """Run the tests concurrently.

        This calls out to the provided make_tests helper, and then serialises
        the results so that result only sees activity from one TestCase at
        a time.

        ConcurrentTestSuite provides no special mechanism to stop the tests
        returned by make_tests, it is up to the make_tests to honour the
        shouldStop attribute on the result object they are run with, which will
        be set if an exception is raised in the thread which
        ConcurrentTestSuite.run is called in.
        """
        tests = self.make_tests(self)
        try:
            threads = {}
            queue = Queue()
            semaphore = threading.Semaphore(1)
            for i, test in enumerate(tests):
                process_result = self._wrap_result(
                    testtools.ThreadsafeForwardingResult(result, semaphore), i)
                reader_thread = threading.Thread(
                    target=self._run_test, args=(test, process_result, queue))
                threads[test] = reader_thread, process_result
                reader_thread.start()
            while threads:
                finished_test = queue.get()
                threads[finished_test][0].join()
                del threads[finished_test]
        except:
            for thread, process_result in threads.values():
                process_result.stop()
            raise

    def _run_test(self, test, process_result, queue):
        try:
            test.run(process_result)
        finally:
            queue.put(test)


class FixtureSuite(unittest.TestSuite):

    def __init__(self, fixture, tests):
        super(FixtureSuite, self).__init__(tests)
        self._fixture = fixture

    def run(self, result):
        self._fixture.setUp()
        try:
            super(FixtureSuite, self).run(result)
        finally:
            self._fixture.cleanUp()
