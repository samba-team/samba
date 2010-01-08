# Copyright (c) 2009 Jonathan M. Lange. See LICENSE for details.

"""Individual test case execution."""

__metaclass__ = type
__all__ = [
    'RunTest',
    ]

import sys

from testtools.testresult import ExtendedToOriginalDecorator


class RunTest:
    """An object to run a test.

    RunTest objects are used to implement the internal logic involved in
    running a test. TestCase.__init__ stores _RunTest as the class of RunTest
    to execute.  Passing the runTest= parameter to TestCase.__init__ allows a
    different RunTest class to be used to execute the test.

    Subclassing or replacing RunTest can be useful to add functionality to the
    way that tests are run in a given project.

    :ivar case: The test case that is to be run.
    :ivar result: The result object a case is reporting to.
    :ivar handlers: A list of (ExceptionClass->handler code) for exceptions
        that should be caught if raised from the user code. Exceptions that
        are caught are checked against this list in first to last order.
        There is a catchall of Exception at the end of the list, so to add
        a new exception to the list, insert it at the front (which ensures that
        it will be checked before any existing base classes in the list. If you
        add multiple exceptions some of which are subclasses of each other, add
        the most specific exceptions last (so they come before their parent
        classes in the list).
    :ivar exception_caught: An object returned when _run_user catches an
        exception.
    """

    def __init__(self, case, handlers=None):
        """Create a RunTest to run a case.

        :param case: A testtools.TestCase test case object.
        :param handlers: Exception handlers for this RunTest. These are stored
            in self.handlers and can be modified later if needed.
        """
        self.case = case
        self.handlers = handlers or []
        self.exception_caught = object()

    def run(self, result=None):
        """Run self.case reporting activity to result.

        :param result: Optional testtools.TestResult to report activity to.
        :return: The result object the test was run against.
        """
        if result is None:
            actual_result = self.case.defaultTestResult()
            actual_result.startTestRun()
        else:
            actual_result = result
        try:
            return self._run_one(actual_result)
        finally:
            if result is None:
                actual_result.stopTestRun()

    def _run_one(self, result):
        """Run one test reporting to result.

        :param result: A testtools.TestResult to report activity to.
            This result object is decorated with an ExtendedToOriginalDecorator
            to ensure that the latest TestResult API can be used with
            confidence by client code.
        :return: The result object the test was run against.
        """
        return self._run_prepared_result(ExtendedToOriginalDecorator(result))

    def _run_prepared_result(self, result):
        """Run one test reporting to result.

        :param result: A testtools.TestResult to report activity to.
        :return: The result object the test was run against.
        """
        result.startTest(self.case)
        self.result = result
        try:
            self._run_core()
        finally:
            result.stopTest(self.case)
        return result

    def _run_core(self):
        """Run the user supplied test code."""
        if self.exception_caught == self._run_user(self.case._run_setup,
            self.result):
            # Don't run the test method if we failed getting here.
            self.case._runCleanups(self.result)
            return
        # Run everything from here on in. If any of the methods raise an
        # exception we'll have failed.
        failed = False
        try:
            if self.exception_caught == self._run_user(
                self.case._run_test_method, self.result):
                failed = True
        finally:
            try:
                if self.exception_caught == self._run_user(
                    self.case._run_teardown, self.result):
                    failed = True
            finally:
                try:
                    if not self._run_user(
                        self.case._runCleanups, self.result):
                        failed = True
                finally:
                    if not failed:
                        self.result.addSuccess(self.case,
                            details=self.case.getDetails())

    def _run_user(self, fn, *args):
        """Run a user supplied function.

        Exceptions are processed by self.handlers.
        """
        try:
            return fn(*args)
        except KeyboardInterrupt:
            raise
        except Exception:
            # Note that bare exceptions are not caught, so raised strings will
            # escape: but they are deprecated anyway.
            exc_info = sys.exc_info()
            e = exc_info[1]
            for exc_class, handler in self.handlers:
                self.case.onException(exc_info)
                if isinstance(e, exc_class):
                    handler(self.case, self.result, e)
                    return self.exception_caught
            raise e
