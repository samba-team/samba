# Copyright (c) 2009 Jonathan M. Lange. See LICENSE for details.

"""Matchers, a way to express complex assertions outside the testcase.

Inspired by 'hamcrest'.

Matcher provides the abstract API that all matchers need to implement.

Bundled matchers are listed in __all__: a list can be obtained by running
$ python -c 'import testtools.matchers; print testtools.matchers.__all__'
"""

__metaclass__ = type
__all__ = [
    'Annotate',
    'DocTestMatches',
    'Equals',
    'MatchesAll',
    'MatchesAny',
    'NotEquals',
    'Not',
    ]

import doctest


class Matcher:
    """A pattern matcher.

    A Matcher must implement match and __str__ to be used by
    testtools.TestCase.assertThat. Matcher.match(thing) returns None when
    thing is completely matched, and a Mismatch object otherwise.

    Matchers can be useful outside of test cases, as they are simply a
    pattern matching language expressed as objects.

    testtools.matchers is inspired by hamcrest, but is pythonic rather than
    a Java transcription.
    """

    def match(self, something):
        """Return None if this matcher matches something, a Mismatch otherwise.
        """
        raise NotImplementedError(self.match)

    def __str__(self):
        """Get a sensible human representation of the matcher.

        This should include the parameters given to the matcher and any
        state that would affect the matches operation.
        """
        raise NotImplementedError(self.__str__)


class Mismatch:
    """An object describing a mismatch detected by a Matcher."""

    def describe(self):
        """Describe the mismatch.

        This should be either a human-readable string or castable to a string.
        """
        raise NotImplementedError(self.describe_difference)


class DocTestMatches:
    """See if a string matches a doctest example."""

    def __init__(self, example, flags=0):
        """Create a DocTestMatches to match example.

        :param example: The example to match e.g. 'foo bar baz'
        :param flags: doctest comparison flags to match on. e.g.
            doctest.ELLIPSIS.
        """
        if not example.endswith('\n'):
            example += '\n'
        self.want = example # required variable name by doctest.
        self.flags = flags
        self._checker = doctest.OutputChecker()

    def __str__(self):
        if self.flags:
            flagstr = ", flags=%d" % self.flags
        else:
            flagstr = ""
        return 'DocTestMatches(%r%s)' % (self.want, flagstr)

    def _with_nl(self, actual):
        result = str(actual)
        if not result.endswith('\n'):
            result += '\n'
        return result

    def match(self, actual):
        with_nl = self._with_nl(actual)
        if self._checker.check_output(self.want, with_nl, self.flags):
            return None
        return DocTestMismatch(self, with_nl)

    def _describe_difference(self, with_nl):
        return self._checker.output_difference(self, with_nl, self.flags)


class DocTestMismatch:
    """Mismatch object for DocTestMatches."""

    def __init__(self, matcher, with_nl):
        self.matcher = matcher
        self.with_nl = with_nl

    def describe(self):
        return self.matcher._describe_difference(self.with_nl)


class Equals:
    """Matches if the items are equal."""

    def __init__(self, expected):
        self.expected = expected

    def match(self, other):
        if self.expected == other:
            return None
        return EqualsMismatch(self.expected, other)

    def __str__(self):
        return "Equals(%r)" % self.expected


class EqualsMismatch:
    """Two things differed."""

    def __init__(self, expected, other):
        self.expected = expected
        self.other = other

    def describe(self):
        return "%r != %r" % (self.expected, self.other)


class NotEquals:
    """Matches if the items are not equal.

    In most cases, this is equivalent to `Not(Equals(foo))`. The difference
    only matters when testing `__ne__` implementations.
    """

    def __init__(self, expected):
        self.expected = expected

    def __str__(self):
        return 'NotEquals(%r)' % (self.expected,)

    def match(self, other):
        if self.expected != other:
            return None
        return NotEqualsMismatch(self.expected, other)


class NotEqualsMismatch:
    """Two things are the same."""

    def __init__(self, expected, other):
        self.expected = expected
        self.other = other

    def describe(self):
        return '%r == %r' % (self.expected, self.other)


class MatchesAny:
    """Matches if any of the matchers it is created with match."""

    def __init__(self, *matchers):
        self.matchers = matchers

    def match(self, matchee):
        results = []
        for matcher in self.matchers:
            mismatch = matcher.match(matchee)
            if mismatch is None:
                return None
            results.append(mismatch)
        return MismatchesAll(results)

    def __str__(self):
        return "MatchesAny(%s)" % ', '.join([
            str(matcher) for matcher in self.matchers])


class MatchesAll:
    """Matches if all of the matchers it is created with match."""

    def __init__(self, *matchers):
        self.matchers = matchers

    def __str__(self):
        return 'MatchesAll(%s)' % ', '.join(map(str, self.matchers))

    def match(self, matchee):
        results = []
        for matcher in self.matchers:
            mismatch = matcher.match(matchee)
            if mismatch is not None:
                results.append(mismatch)
        if results:
            return MismatchesAll(results)
        else:
            return None


class MismatchesAll:
    """A mismatch with many child mismatches."""

    def __init__(self, mismatches):
        self.mismatches = mismatches

    def describe(self):
        descriptions = ["Differences: ["]
        for mismatch in self.mismatches:
            descriptions.append(mismatch.describe())
        descriptions.append("]\n")
        return '\n'.join(descriptions)


class Not:
    """Inverts a matcher."""

    def __init__(self, matcher):
        self.matcher = matcher

    def __str__(self):
        return 'Not(%s)' % (self.matcher,)

    def match(self, other):
        mismatch = self.matcher.match(other)
        if mismatch is None:
            return MatchedUnexpectedly(self.matcher, other)
        else:
            return None


class MatchedUnexpectedly:
    """A thing matched when it wasn't supposed to."""

    def __init__(self, matcher, other):
        self.matcher = matcher
        self.other = other

    def describe(self):
        return "%r matches %s" % (self.other, self.matcher)


class Annotate:
    """Annotates a matcher with a descriptive string.

    Mismatches are then described as '<mismatch>: <annotation>'.
    """

    def __init__(self, annotation, matcher):
        self.annotation = annotation
        self.matcher = matcher

    def __str__(self):
        return 'Annotate(%r, %s)' % (self.annotation, self.matcher)

    def match(self, other):
        mismatch = self.matcher.match(other)
        if mismatch is not None:
            return AnnotatedMismatch(self.annotation, mismatch)


class AnnotatedMismatch:
    """A mismatch annotated with a descriptive string."""

    def __init__(self, annotation, mismatch):
        self.annotation = annotation
        self.mismatch = mismatch

    def describe(self):
        return '%s: %s' % (self.mismatch.describe(), self.annotation)
