# Copyright (c) 2008 Jonathan M. Lange. See LICENSE for details.

"""Test results and related things."""

__metaclass__ = type
__all__ = [
    'ExtendedToOriginalDecorator',
    'MultiTestResult',
    'TestResult',
    'ThreadsafeForwardingResult',
    ]

import datetime
import unittest


class TestResult(unittest.TestResult):
    """Subclass of unittest.TestResult extending the protocol for flexability.

    This test result supports an experimental protocol for providing additional
    data to in test outcomes. All the outcome methods take an optional dict
    'details'. If supplied any other detail parameters like 'err' or 'reason'
    should not be provided. The details dict is a mapping from names to
    MIME content objects (see testtools.content). This permits attaching
    tracebacks, log files, or even large objects like databases that were
    part of the test fixture. Until this API is accepted into upstream
    Python it is considered experimental: it may be replaced at any point
    by a newer version more in line with upstream Python. Compatibility would
    be aimed for in this case, but may not be possible.

    :ivar skip_reasons: A dict of skip-reasons -> list of tests. See addSkip.
    """

    def __init__(self):
        super(TestResult, self).__init__()
        self.skip_reasons = {}
        self.__now = None
        # -- Start: As per python 2.7 --
        self.expectedFailures = []
        self.unexpectedSuccesses = []
        # -- End:   As per python 2.7 --

    def addExpectedFailure(self, test, err=None, details=None):
        """Called when a test has failed in an expected manner.

        Like with addSuccess and addError, testStopped should still be called.

        :param test: The test that has been skipped.
        :param err: The exc_info of the error that was raised.
        :return: None
        """
        # This is the python 2.7 implementation
        self.expectedFailures.append(
            (test, self._err_details_to_string(test, err, details)))

    def addError(self, test, err=None, details=None):
        """Called when an error has occurred. 'err' is a tuple of values as
        returned by sys.exc_info().

        :param details: Alternative way to supply details about the outcome.
            see the class docstring for more information.
        """
        self.errors.append((test,
            self._err_details_to_string(test, err, details)))

    def addFailure(self, test, err=None, details=None):
        """Called when an error has occurred. 'err' is a tuple of values as
        returned by sys.exc_info().

        :param details: Alternative way to supply details about the outcome.
            see the class docstring for more information.
        """
        self.failures.append((test,
            self._err_details_to_string(test, err, details)))

    def addSkip(self, test, reason=None, details=None):
        """Called when a test has been skipped rather than running.

        Like with addSuccess and addError, testStopped should still be called.

        This must be called by the TestCase. 'addError' and 'addFailure' will
        not call addSkip, since they have no assumptions about the kind of
        errors that a test can raise.

        :param test: The test that has been skipped.
        :param reason: The reason for the test being skipped. For instance,
            u"pyGL is not available".
        :param details: Alternative way to supply details about the outcome.
            see the class docstring for more information.
        :return: None
        """
        if reason is None:
            reason = details.get('reason')
            if reason is None:
                reason = 'No reason given'
            else:
                reason = ''.join(reason.iter_text())
        skip_list = self.skip_reasons.setdefault(reason, [])
        skip_list.append(test)

    def addSuccess(self, test, details=None):
        """Called when a test succeeded."""

    def addUnexpectedSuccess(self, test, details=None):
        """Called when a test was expected to fail, but succeed."""
        self.unexpectedSuccesses.append(test)

    def _err_details_to_string(self, test, err=None, details=None):
        """Convert an error in exc_info form or a contents dict to a string."""
        if err is not None:
            return self._exc_info_to_string(err, test)
        return _details_to_str(details)

    def _now(self):
        """Return the current 'test time'.

        If the time() method has not been called, this is equivalent to
        datetime.now(), otherwise its the last supplied datestamp given to the
        time() method.
        """
        if self.__now is None:
            return datetime.datetime.now()
        else:
            return self.__now

    def startTestRun(self):
        """Called before a test run starts.

        New in python 2.7
        """

    def stopTestRun(self):
        """Called after a test run completes

        New in python 2.7
        """

    def time(self, a_datetime):
        """Provide a timestamp to represent the current time.

        This is useful when test activity is time delayed, or happening
        concurrently and getting the system time between API calls will not
        accurately represent the duration of tests (or the whole run).

        Calling time() sets the datetime used by the TestResult object.
        Time is permitted to go backwards when using this call.

        :param a_datetime: A datetime.datetime object with TZ information or
            None to reset the TestResult to gathering time from the system.
        """
        self.__now = a_datetime

    def done(self):
        """Called when the test runner is done.

        deprecated in favour of stopTestRun.
        """


class MultiTestResult(TestResult):
    """A test result that dispatches to many test results."""

    def __init__(self, *results):
        TestResult.__init__(self)
        self._results = map(ExtendedToOriginalDecorator, results)

    def _dispatch(self, message, *args, **kwargs):
        for result in self._results:
            getattr(result, message)(*args, **kwargs)

    def startTest(self, test):
        self._dispatch('startTest', test)

    def stopTest(self, test):
        self._dispatch('stopTest', test)

    def addError(self, test, error=None, details=None):
        self._dispatch('addError', test, error, details=details)

    def addExpectedFailure(self, test, err=None, details=None):
        self._dispatch('addExpectedFailure', test, err, details=details)

    def addFailure(self, test, err=None, details=None):
        self._dispatch('addFailure', test, err, details=details)

    def addSkip(self, test, reason=None, details=None):
        self._dispatch('addSkip', test, reason, details=details)

    def addSuccess(self, test, details=None):
        self._dispatch('addSuccess', test, details=details)

    def addUnexpectedSuccess(self, test, details=None):
        self._dispatch('addUnexpectedSuccess', test, details=details)

    def startTestRun(self):
        self._dispatch('startTestRun')

    def stopTestRun(self):
        self._dispatch('stopTestRun')

    def done(self):
        self._dispatch('done')


class TextTestResult(TestResult):
    """A TestResult which outputs activity to a text stream."""

    def __init__(self, stream):
        """Construct a TextTestResult writing to stream."""
        super(TextTestResult, self).__init__()
        self.stream = stream
        self.sep1 = '=' * 70 + '\n'
        self.sep2 = '-' * 70 + '\n'

    def _delta_to_float(self, a_timedelta):
        return (a_timedelta.days * 86400.0 + a_timedelta.seconds +
            a_timedelta.microseconds / 1000000.0)

    def _show_list(self, label, error_list):
        for test, output in error_list:
            self.stream.write(self.sep1)
            self.stream.write("%s: %s\n" % (label, test.id()))
            self.stream.write(self.sep2)
            self.stream.write(output)

    def startTestRun(self):
        super(TextTestResult, self).startTestRun()
        self.__start = self._now()
        self.stream.write("Tests running...\n")

    def stopTestRun(self):
        if self.testsRun != 1:
            plural = 's'
        else:
            plural = ''
        stop = self._now()
        self._show_list('ERROR', self.errors)
        self._show_list('FAIL', self.failures)
        self.stream.write("Ran %d test%s in %.3fs\n\n" %
            (self.testsRun, plural,
             self._delta_to_float(stop - self.__start)))
        if self.wasSuccessful():
            self.stream.write("OK\n")
        else:
            self.stream.write("FAILED (")
            details = []
            details.append("failures=%d" % (
                len(self.failures) + len(self.errors)))
            self.stream.write(", ".join(details))
            self.stream.write(")\n")
        super(TextTestResult, self).stopTestRun()


class ThreadsafeForwardingResult(TestResult):
    """A TestResult which ensures the target does not receive mixed up calls.

    This is used when receiving test results from multiple sources, and batches
    up all the activity for a single test into a thread-safe batch where all
    other ThreadsafeForwardingResult objects sharing the same semaphore will be
    locked out.

    Typical use of ThreadsafeForwardingResult involves creating one
    ThreadsafeForwardingResult per thread in a ConcurrentTestSuite. These
    forward to the TestResult that the ConcurrentTestSuite run method was
    called with.

    target.done() is called once for each ThreadsafeForwardingResult that
    forwards to the same target. If the target's done() takes special action,
    care should be taken to accommodate this.
    """

    def __init__(self, target, semaphore):
        """Create a ThreadsafeForwardingResult forwarding to target.

        :param target: A TestResult.
        :param semaphore: A threading.Semaphore with limit 1.
        """
        TestResult.__init__(self)
        self.result = ExtendedToOriginalDecorator(target)
        self.semaphore = semaphore

    def addError(self, test, err=None, details=None):
        self.semaphore.acquire()
        try:
            self.result.startTest(test)
            self.result.addError(test, err, details=details)
            self.result.stopTest(test)
        finally:
            self.semaphore.release()

    def addExpectedFailure(self, test, err=None, details=None):
        self.semaphore.acquire()
        try:
            self.result.startTest(test)
            self.result.addExpectedFailure(test, err, details=details)
            self.result.stopTest(test)
        finally:
            self.semaphore.release()

    def addFailure(self, test, err=None, details=None):
        self.semaphore.acquire()
        try:
            self.result.startTest(test)
            self.result.addFailure(test, err, details=details)
            self.result.stopTest(test)
        finally:
            self.semaphore.release()

    def addSkip(self, test, reason=None, details=None):
        self.semaphore.acquire()
        try:
            self.result.startTest(test)
            self.result.addSkip(test, reason, details=details)
            self.result.stopTest(test)
        finally:
            self.semaphore.release()

    def addSuccess(self, test, details=None):
        self.semaphore.acquire()
        try:
            self.result.startTest(test)
            self.result.addSuccess(test, details=details)
            self.result.stopTest(test)
        finally:
            self.semaphore.release()

    def addUnexpectedSuccess(self, test, details=None):
        self.semaphore.acquire()
        try:
            self.result.startTest(test)
            self.result.addUnexpectedSuccess(test, details=details)
            self.result.stopTest(test)
        finally:
            self.semaphore.release()

    def startTestRun(self):
        self.semaphore.acquire()
        try:
            self.result.startTestRun()
        finally:
            self.semaphore.release()

    def stopTestRun(self):
        self.semaphore.acquire()
        try:
            self.result.stopTestRun()
        finally:
            self.semaphore.release()

    def done(self):
        self.semaphore.acquire()
        try:
            self.result.done()
        finally:
            self.semaphore.release()


class ExtendedToOriginalDecorator(object):
    """Permit new TestResult API code to degrade gracefully with old results.

    This decorates an existing TestResult and converts missing outcomes
    such as addSkip to older outcomes such as addSuccess. It also supports
    the extended details protocol. In all cases the most recent protocol
    is attempted first, and fallbacks only occur when the decorated result
    does not support the newer style of calling.
    """

    def __init__(self, decorated):
        self.decorated = decorated

    def __getattr__(self, name):
        return getattr(self.decorated, name)

    def addError(self, test, err=None, details=None):
        self._check_args(err, details)
        if details is not None:
            try:
                return self.decorated.addError(test, details=details)
            except TypeError:
                # have to convert
                err = self._details_to_exc_info(details)
        return self.decorated.addError(test, err)

    def addExpectedFailure(self, test, err=None, details=None):
        self._check_args(err, details)
        addExpectedFailure = getattr(
            self.decorated, 'addExpectedFailure', None)
        if addExpectedFailure is None:
            return self.addSuccess(test)
        if details is not None:
            try:
                return addExpectedFailure(test, details=details)
            except TypeError:
                # have to convert
                err = self._details_to_exc_info(details)
        return addExpectedFailure(test, err)

    def addFailure(self, test, err=None, details=None):
        self._check_args(err, details)
        if details is not None:
            try:
                return self.decorated.addFailure(test, details=details)
            except TypeError:
                # have to convert
                err = self._details_to_exc_info(details)
        return self.decorated.addFailure(test, err)

    def addSkip(self, test, reason=None, details=None):
        self._check_args(reason, details)
        addSkip = getattr(self.decorated, 'addSkip', None)
        if addSkip is None:
            return self.decorated.addSuccess(test)
        if details is not None:
            try:
                return addSkip(test, details=details)
            except TypeError:
                # have to convert
                reason = _details_to_str(details)
        return addSkip(test, reason)

    def addUnexpectedSuccess(self, test, details=None):
        outcome = getattr(self.decorated, 'addUnexpectedSuccess', None)
        if outcome is None:
            return self.decorated.addSuccess(test)
        if details is not None:
            try:
                return outcome(test, details=details)
            except TypeError:
                pass
        return outcome(test)

    def addSuccess(self, test, details=None):
        if details is not None:
            try:
                return self.decorated.addSuccess(test, details=details)
            except TypeError:
                pass
        return self.decorated.addSuccess(test)

    def _check_args(self, err, details):
        param_count = 0
        if err is not None:
            param_count += 1
        if details is not None:
            param_count += 1
        if param_count != 1:
            raise ValueError("Must pass only one of err '%s' and details '%s"
                % (err, details))

    def _details_to_exc_info(self, details):
        """Convert a details dict to an exc_info tuple."""
        return (_StringException,
            _StringException(_details_to_str(details)), None)

    def done(self):
        try:
            return self.decorated.done()
        except AttributeError:
            return

    def progress(self, offset, whence):
        method = getattr(self.decorated, 'progress', None)
        if method is None:
            return
        return method(offset, whence)

    @property
    def shouldStop(self):
        return self.decorated.shouldStop

    def startTest(self, test):
        return self.decorated.startTest(test)

    def startTestRun(self):
        try:
            return self.decorated.startTestRun()
        except AttributeError:
            return

    def stop(self):
        return self.decorated.stop()

    def stopTest(self, test):
        return self.decorated.stopTest(test)

    def stopTestRun(self):
        try:
            return self.decorated.stopTestRun()
        except AttributeError:
            return

    def tags(self, new_tags, gone_tags):
        method = getattr(self.decorated, 'tags', None)
        if method is None:
            return
        return method(new_tags, gone_tags)

    def time(self, a_datetime):
        method = getattr(self.decorated, 'time', None)
        if method is None:
            return
        return method(a_datetime)

    def wasSuccessful(self):
        return self.decorated.wasSuccessful()


class _StringException(Exception):
    """An exception made from an arbitrary string."""

    def __hash__(self):
        return id(self)

    def __str__(self):
        """Stringify better than 2.x's default behaviour of ascii encoding."""
        return self.args[0]

    def __eq__(self, other):
        try:
            return self.args == other.args
        except AttributeError:
            return False


def _details_to_str(details):
    """Convert a details dict to a string."""
    chars = []
    # sorted is for testing, may want to remove that and use a dict
    # subclass with defined order for items instead.
    for key, content in sorted(details.items()):
        if content.content_type.type != 'text':
            chars.append('Binary content: %s\n' % key)
            continue
        chars.append('Text attachment: %s\n' % key)
        chars.append('------------\n')
        chars.extend(content.iter_text())
        if not chars[-1].endswith('\n'):
            chars.append('\n')
        chars.append('------------\n')
    return ''.join(chars)
