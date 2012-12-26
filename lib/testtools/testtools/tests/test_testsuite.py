# Copyright (c) 2009-2011 testtools developers. See LICENSE for details.

"""Test ConcurrentTestSuite and related things."""

__metaclass__ = type

import unittest

from testtools import (
    ConcurrentTestSuite,
    iterate_tests,
    PlaceHolder,
    TestCase,
    )
from testtools.helpers import try_import
from testtools.testsuite import FixtureSuite, iterate_tests, sorted_tests
from testtools.tests.helpers import LoggingResult

FunctionFixture = try_import('fixtures.FunctionFixture')

class Sample(TestCase):
    def __hash__(self):
        return id(self)
    def test_method1(self):
        pass
    def test_method2(self):
        pass

class TestConcurrentTestSuiteRun(TestCase):

    def test_trivial(self):
        log = []
        result = LoggingResult(log)
        test1 = Sample('test_method1')
        test2 = Sample('test_method2')
        original_suite = unittest.TestSuite([test1, test2])
        suite = ConcurrentTestSuite(original_suite, self.split_suite)
        suite.run(result)
        # log[0] is the timestamp for the first test starting.
        test1 = log[1][1]
        test2 = log[-1][1]
        self.assertIsInstance(test1, Sample)
        self.assertIsInstance(test2, Sample)
        self.assertNotEqual(test1.id(), test2.id())

    def test_wrap_result(self):
        # ConcurrentTestSuite has a hook for wrapping the per-thread result.
        wrap_log = []

        def wrap_result(thread_safe_result, thread_number):
            wrap_log.append(
                (thread_safe_result.result.decorated, thread_number))
            return thread_safe_result

        result_log = []
        result = LoggingResult(result_log)
        test1 = Sample('test_method1')
        test2 = Sample('test_method2')
        original_suite = unittest.TestSuite([test1, test2])
        suite = ConcurrentTestSuite(
            original_suite, self.split_suite, wrap_result=wrap_result)
        suite.run(result)
        self.assertEqual(
            [(result, 0),
             (result, 1),
             ], wrap_log)
        # Smoke test to make sure everything ran OK.
        self.assertNotEqual([], result_log)

    def split_suite(self, suite):
        tests = list(iterate_tests(suite))
        return tests[0], tests[1]


class TestFixtureSuite(TestCase):

    def setUp(self):
        super(TestFixtureSuite, self).setUp()
        if FunctionFixture is None:
            self.skip("Need fixtures")

    def test_fixture_suite(self):
        log = []
        class Sample(TestCase):
            def test_one(self):
                log.append(1)
            def test_two(self):
                log.append(2)
        fixture = FunctionFixture(
            lambda: log.append('setUp'),
            lambda fixture: log.append('tearDown'))
        suite = FixtureSuite(fixture, [Sample('test_one'), Sample('test_two')])
        suite.run(LoggingResult([]))
        self.assertEqual(['setUp', 1, 2, 'tearDown'], log)


class TestSortedTests(TestCase):

    def test_sorts_custom_suites(self):
        a = PlaceHolder('a')
        b = PlaceHolder('b')
        class Subclass(unittest.TestSuite):
            def sort_tests(self):
                self._tests = sorted_tests(self, True)
        input_suite = Subclass([b, a])
        suite = sorted_tests(input_suite)
        self.assertEqual([a, b], list(iterate_tests(suite)))
        self.assertEqual([input_suite], list(iter(suite)))

    def test_custom_suite_without_sort_tests_works(self):
        a = PlaceHolder('a')
        b = PlaceHolder('b')
        class Subclass(unittest.TestSuite):pass
        input_suite = Subclass([b, a])
        suite = sorted_tests(input_suite)
        self.assertEqual([b, a], list(iterate_tests(suite)))
        self.assertEqual([input_suite], list(iter(suite)))

    def test_sorts_simple_suites(self):
        a = PlaceHolder('a')
        b = PlaceHolder('b')
        suite = sorted_tests(unittest.TestSuite([b, a]))
        self.assertEqual([a, b], list(iterate_tests(suite)))


def test_suite():
    from unittest import TestLoader
    return TestLoader().loadTestsFromName(__name__)
