# Copyright (c) 2008 Jonathan M. Lange. See LICENSE for details.

"""Tests for matchers."""

import doctest

from testtools import (
    Matcher, # check that Matcher is exposed at the top level for docs.
    TestCase,
    )
from testtools.matchers import (
    Annotate,
    Equals,
    DocTestMatches,
    MatchesAny,
    MatchesAll,
    Not,
    NotEquals,
    )


class TestMatchersInterface:

    def test_matches_match(self):
        matcher = self.matches_matcher
        matches = self.matches_matches
        mismatches = self.matches_mismatches
        for candidate in matches:
            self.assertEqual(None, matcher.match(candidate))
        for candidate in mismatches:
            mismatch = matcher.match(candidate)
            self.assertNotEqual(None, mismatch)
            self.assertNotEqual(None, getattr(mismatch, 'describe', None))

    def test__str__(self):
        # [(expected, object to __str__)].
        examples = self.str_examples
        for expected, matcher in examples:
            self.assertThat(matcher, DocTestMatches(expected))

    def test_describe_difference(self):
        # [(expected, matchee, matcher), ...]
        examples = self.describe_examples
        for difference, matchee, matcher in examples:
            mismatch = matcher.match(matchee)
            self.assertEqual(difference, mismatch.describe())


class TestDocTestMatchesInterface(TestCase, TestMatchersInterface):

    matches_matcher = DocTestMatches("Ran 1 test in ...s", doctest.ELLIPSIS)
    matches_matches = ["Ran 1 test in 0.000s", "Ran 1 test in 1.234s"]
    matches_mismatches = ["Ran 1 tests in 0.000s", "Ran 2 test in 0.000s"]

    str_examples = [("DocTestMatches('Ran 1 test in ...s\\n')",
        DocTestMatches("Ran 1 test in ...s")),
        ("DocTestMatches('foo\\n', flags=8)", DocTestMatches("foo", flags=8)),
        ]

    describe_examples = [('Expected:\n    Ran 1 tests in ...s\nGot:\n'
        '    Ran 1 test in 0.123s\n', "Ran 1 test in 0.123s",
        DocTestMatches("Ran 1 tests in ...s", doctest.ELLIPSIS))]


class TestDocTestMatchesSpecific(TestCase):

    def test___init__simple(self):
        matcher = DocTestMatches("foo")
        self.assertEqual("foo\n", matcher.want)

    def test___init__flags(self):
        matcher = DocTestMatches("bar\n", doctest.ELLIPSIS)
        self.assertEqual("bar\n", matcher.want)
        self.assertEqual(doctest.ELLIPSIS, matcher.flags)


class TestEqualsInterface(TestCase, TestMatchersInterface):

    matches_matcher = Equals(1)
    matches_matches = [1]
    matches_mismatches = [2]

    str_examples = [("Equals(1)", Equals(1)), ("Equals('1')", Equals('1'))]

    describe_examples = [("1 != 2", 2, Equals(1))]


class TestNotEqualsInterface(TestCase, TestMatchersInterface):

    matches_matcher = NotEquals(1)
    matches_matches = [2]
    matches_mismatches = [1]

    str_examples = [
        ("NotEquals(1)", NotEquals(1)), ("NotEquals('1')", NotEquals('1'))]

    describe_examples = [("1 == 1", 1, NotEquals(1))]


class TestNotInterface(TestCase, TestMatchersInterface):

    matches_matcher = Not(Equals(1))
    matches_matches = [2]
    matches_mismatches = [1]

    str_examples = [
        ("Not(Equals(1))", Not(Equals(1))),
        ("Not(Equals('1'))", Not(Equals('1')))]

    describe_examples = [('1 matches Equals(1)', 1, Not(Equals(1)))]


class TestMatchersAnyInterface(TestCase, TestMatchersInterface):

    matches_matcher = MatchesAny(DocTestMatches("1"), DocTestMatches("2"))
    matches_matches = ["1", "2"]
    matches_mismatches = ["3"]

    str_examples = [(
        "MatchesAny(DocTestMatches('1\\n'), DocTestMatches('2\\n'))",
        MatchesAny(DocTestMatches("1"), DocTestMatches("2"))),
        ]

    describe_examples = [("""Differences: [
Expected:
    1
Got:
    3

Expected:
    2
Got:
    3

]
""",
        "3", MatchesAny(DocTestMatches("1"), DocTestMatches("2")))]


class TestMatchesAllInterface(TestCase, TestMatchersInterface):

    matches_matcher = MatchesAll(NotEquals(1), NotEquals(2))
    matches_matches = [3, 4]
    matches_mismatches = [1, 2]

    str_examples = [
        ("MatchesAll(NotEquals(1), NotEquals(2))",
         MatchesAll(NotEquals(1), NotEquals(2)))]

    describe_examples = [("""Differences: [
1 == 1
]
""",
                          1, MatchesAll(NotEquals(1), NotEquals(2)))]


class TestAnnotate(TestCase, TestMatchersInterface):

    matches_matcher = Annotate("foo", Equals(1))
    matches_matches = [1]
    matches_mismatches = [2]

    str_examples = [
        ("Annotate('foo', Equals(1))", Annotate("foo", Equals(1)))]

    describe_examples = [("1 != 2: foo", 2, Annotate('foo', Equals(1)))]


def test_suite():
    from unittest import TestLoader
    return TestLoader().loadTestsFromName(__name__)
