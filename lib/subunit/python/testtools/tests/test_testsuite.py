# Copyright (c) 2009 Jonathan M. Lange. See LICENSE for details.

"""Test ConcurrentTestSuite and related things."""

__metaclass__ = type

import unittest

from testtools import (
    ConcurrentTestSuite,
    iterate_tests,
    TestCase,
    )
from testtools.matchers import (
    Equals,
    )
from testtools.tests.helpers import LoggingResult


class TestConcurrentTestSuiteRun(TestCase):

    def test_trivial(self):
        log = []
        result = LoggingResult(log)
        class Sample(TestCase):
            def __hash__(self):
                return id(self)

            def test_method1(self):
                pass
            def test_method2(self):
                pass
        test1 = Sample('test_method1')
        test2 = Sample('test_method2')
        original_suite = unittest.TestSuite([test1, test2])
        suite = ConcurrentTestSuite(original_suite, self.split_suite)
        suite.run(result)
        test1 = log[0][1]
        test2 = log[-1][1]
        self.assertIsInstance(test1, Sample)
        self.assertIsInstance(test2, Sample)
        self.assertNotEqual(test1.id(), test2.id())
        # We expect the start/outcome/stop to be grouped
        expected = [('startTest', test1), ('addSuccess', test1),
            ('stopTest', test1), ('startTest', test2), ('addSuccess', test2),
            ('stopTest', test2)]
        self.assertThat(log, Equals(expected))

    def split_suite(self, suite):
        tests = list(iterate_tests(suite))
        return tests[0], tests[1]


def test_suite():
    from unittest import TestLoader
    return TestLoader().loadTestsFromName(__name__)
