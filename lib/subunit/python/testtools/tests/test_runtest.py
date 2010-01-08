# Copyright (c) 2009 Jonathan M. Lange. See LICENSE for details.

"""Tests for the RunTest single test execution logic."""

from testtools import (
    ExtendedToOriginalDecorator,
    RunTest,
    TestCase,
    TestResult,
    )
from testtools.tests.helpers import ExtendedTestResult


class TestRunTest(TestCase):

    def make_case(self):
        class Case(TestCase):
            def test(self):
                pass
        return Case('test')

    def test___init___short(self):
        run = RunTest("bar")
        self.assertEqual("bar", run.case)
        self.assertEqual([], run.handlers)

    def test__init____handlers(self):
        handlers = [("quux", "baz")]
        run = RunTest("bar", handlers)
        self.assertEqual(handlers, run.handlers)

    def test_run_with_result(self):
        # test.run passes result down to _run_test_method.
        log = []
        class Case(TestCase):
            def _run_test_method(self, result):
                log.append(result)
        case = Case('_run_test_method')
        run = RunTest(case, lambda x: log.append(x))
        result = TestResult()
        run.run(result)
        self.assertEqual(1, len(log))
        self.assertEqual(result, log[0].decorated)

    def test_run_no_result_manages_new_result(self):
        log = []
        run = RunTest(self.make_case(), lambda x: log.append(x) or x)
        result = run.run()
        self.assertIsInstance(result.decorated, TestResult)

    def test__run_core_called(self):
        case = self.make_case()
        log = []
        run = RunTest(case, lambda x: x)
        run._run_core = lambda: log.append('foo')
        run.run()
        self.assertEqual(['foo'], log)

    def test__run_user_does_not_catch_keyboard(self):
        case = self.make_case()
        def raises():
            raise KeyboardInterrupt("yo")
        run = RunTest(case, None)
        run.result = ExtendedTestResult()
        self.assertRaises(KeyboardInterrupt, run._run_user, raises)
        self.assertEqual([], run.result._events)

    def test__run_user_calls_onException(self):
        case = self.make_case()
        log = []
        def handler(exc_info):
            log.append("got it")
            self.assertEqual(3, len(exc_info))
            self.assertIsInstance(exc_info[1], KeyError)
            self.assertIs(KeyError, exc_info[0])
        case.addOnException(handler)
        e = KeyError('Yo')
        def raises():
            raise e
        def log_exc(self, result, err):
            log.append((result, err))
        run = RunTest(case, [(KeyError, log_exc)])
        run.result = ExtendedTestResult()
        status = run._run_user(raises)
        self.assertEqual(run.exception_caught, status)
        self.assertEqual([], run.result._events)
        self.assertEqual(["got it", (run.result, e)], log)

    def test__run_user_can_catch_Exception(self):
        case = self.make_case()
        e = Exception('Yo')
        def raises():
            raise e
        log = []
        def log_exc(self, result, err):
            log.append((result, err))
        run = RunTest(case, [(Exception, log_exc)])
        run.result = ExtendedTestResult()
        status = run._run_user(raises)
        self.assertEqual(run.exception_caught, status)
        self.assertEqual([], run.result._events)
        self.assertEqual([(run.result, e)], log)

    def test__run_user_uncaught_Exception_raised(self):
        case = self.make_case()
        e = KeyError('Yo')
        def raises():
            raise e
        log = []
        def log_exc(self, result, err):
            log.append((result, err))
        run = RunTest(case, [(ValueError, log_exc)])
        run.result = ExtendedTestResult()
        self.assertRaises(KeyError, run._run_user, raises)
        self.assertEqual([], run.result._events)
        self.assertEqual([], log)

    def test__run_user_uncaught_Exception_from_exception_handler_raised(self):
        case = self.make_case()
        def broken_handler(exc_info):
            # ValueError because thats what we know how to catch - and must
            # not.
            raise ValueError('boo')
        case.addOnException(broken_handler)
        e = KeyError('Yo')
        def raises():
            raise e
        log = []
        def log_exc(self, result, err):
            log.append((result, err))
        run = RunTest(case, [(ValueError, log_exc)])
        run.result = ExtendedTestResult()
        self.assertRaises(ValueError, run._run_user, raises)
        self.assertEqual([], run.result._events)
        self.assertEqual([], log)

    def test__run_user_returns_result(self):
        case = self.make_case()
        def returns():
            return 1
        run = RunTest(case)
        run.result = ExtendedTestResult()
        self.assertEqual(1, run._run_user(returns))
        self.assertEqual([], run.result._events)

    def test__run_one_decorates_result(self):
        log = []
        class Run(RunTest):
            def _run_prepared_result(self, result):
                log.append(result)
                return result
        run = Run(self.make_case(), lambda x: x)
        result = run._run_one('foo')
        self.assertEqual([result], log)
        self.assertIsInstance(log[0], ExtendedToOriginalDecorator)
        self.assertEqual('foo', result.decorated)

    def test__run_prepared_result_calls_start_and_stop_test(self):
        result = ExtendedTestResult()
        case = self.make_case()
        run = RunTest(case, lambda x: x)
        run.run(result)
        self.assertEqual([
            ('startTest', case),
            ('addSuccess', case),
            ('stopTest', case),
            ], result._events)

    def test__run_prepared_result_calls_stop_test_always(self):
        result = ExtendedTestResult()
        case = self.make_case()
        def inner():
            raise Exception("foo")
        run = RunTest(case, lambda x: x)
        run._run_core = inner
        self.assertRaises(Exception, run.run, result)
        self.assertEqual([
            ('startTest', case),
            ('stopTest', case),
            ], result._events)


def test_suite():
    from unittest import TestLoader
    return TestLoader().loadTestsFromName(__name__)
