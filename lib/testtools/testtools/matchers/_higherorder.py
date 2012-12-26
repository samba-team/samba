# Copyright (c) 2009-2012 testtools developers. See LICENSE for details.

__all__ = [
    'AfterPreprocessing',
    'AllMatch',
    'Annotate',
    'MatchesAny',
    'MatchesAll',
    'Not',
    ]

import types

from ._impl import (
    Matcher,
    Mismatch,
    MismatchDecorator,
    )


class MatchesAny(object):
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


class MatchesAll(object):
    """Matches if all of the matchers it is created with match."""

    def __init__(self, *matchers, **options):
        """Construct a MatchesAll matcher.

        Just list the component matchers as arguments in the ``*args``
        style. If you want only the first mismatch to be reported, past in
        first_only=True as a keyword argument. By default, all mismatches are
        reported.
        """
        self.matchers = matchers
        self.first_only = options.get('first_only', False)

    def __str__(self):
        return 'MatchesAll(%s)' % ', '.join(map(str, self.matchers))

    def match(self, matchee):
        results = []
        for matcher in self.matchers:
            mismatch = matcher.match(matchee)
            if mismatch is not None:
                if self.first_only:
                    return mismatch
                results.append(mismatch)
        if results:
            return MismatchesAll(results)
        else:
            return None


class MismatchesAll(Mismatch):
    """A mismatch with many child mismatches."""

    def __init__(self, mismatches, wrap=True):
        self.mismatches = mismatches
        self._wrap = wrap

    def describe(self):
        descriptions = []
        if self._wrap:
            descriptions = ["Differences: ["]
        for mismatch in self.mismatches:
            descriptions.append(mismatch.describe())
        if self._wrap:
            descriptions.append("]")
        return '\n'.join(descriptions)


class Not(object):
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


class MatchedUnexpectedly(Mismatch):
    """A thing matched when it wasn't supposed to."""

    def __init__(self, matcher, other):
        self.matcher = matcher
        self.other = other

    def describe(self):
        return "%r matches %s" % (self.other, self.matcher)


class Annotate(object):
    """Annotates a matcher with a descriptive string.

    Mismatches are then described as '<mismatch>: <annotation>'.
    """

    def __init__(self, annotation, matcher):
        self.annotation = annotation
        self.matcher = matcher

    @classmethod
    def if_message(cls, annotation, matcher):
        """Annotate ``matcher`` only if ``annotation`` is non-empty."""
        if not annotation:
            return matcher
        return cls(annotation, matcher)

    def __str__(self):
        return 'Annotate(%r, %s)' % (self.annotation, self.matcher)

    def match(self, other):
        mismatch = self.matcher.match(other)
        if mismatch is not None:
            return AnnotatedMismatch(self.annotation, mismatch)


class PostfixedMismatch(MismatchDecorator):
    """A mismatch annotated with a descriptive string."""

    def __init__(self, annotation, mismatch):
        super(PostfixedMismatch, self).__init__(mismatch)
        self.annotation = annotation
        self.mismatch = mismatch

    def describe(self):
        return '%s: %s' % (self.original.describe(), self.annotation)


AnnotatedMismatch = PostfixedMismatch


class PrefixedMismatch(MismatchDecorator):

    def __init__(self, prefix, mismatch):
        super(PrefixedMismatch, self).__init__(mismatch)
        self.prefix = prefix

    def describe(self):
        return '%s: %s' % (self.prefix, self.original.describe())


class AfterPreprocessing(object):
    """Matches if the value matches after passing through a function.

    This can be used to aid in creating trivial matchers as functions, for
    example::

      def PathHasFileContent(content):
          def _read(path):
              return open(path).read()
          return AfterPreprocessing(_read, Equals(content))
    """

    def __init__(self, preprocessor, matcher, annotate=True):
        """Create an AfterPreprocessing matcher.

        :param preprocessor: A function called with the matchee before
            matching.
        :param matcher: What to match the preprocessed matchee against.
        :param annotate: Whether or not to annotate the matcher with
            something explaining how we transformed the matchee. Defaults
            to True.
        """
        self.preprocessor = preprocessor
        self.matcher = matcher
        self.annotate = annotate

    def _str_preprocessor(self):
        if isinstance(self.preprocessor, types.FunctionType):
            return '<function %s>' % self.preprocessor.__name__
        return str(self.preprocessor)

    def __str__(self):
        return "AfterPreprocessing(%s, %s)" % (
            self._str_preprocessor(), self.matcher)

    def match(self, value):
        after = self.preprocessor(value)
        if self.annotate:
            matcher = Annotate(
                "after %s on %r" % (self._str_preprocessor(), value),
                self.matcher)
        else:
            matcher = self.matcher
        return matcher.match(after)


# This is the old, deprecated. spelling of the name, kept for backwards
# compatibility.
AfterPreproccessing = AfterPreprocessing


class AllMatch(object):
    """Matches if all provided values match the given matcher."""

    def __init__(self, matcher):
        self.matcher = matcher

    def __str__(self):
        return 'AllMatch(%s)' % (self.matcher,)

    def match(self, values):
        mismatches = []
        for value in values:
            mismatch = self.matcher.match(value)
            if mismatch:
                mismatches.append(mismatch)
        if mismatches:
            return MismatchesAll(mismatches)


class AnyMatch(object):
    """Matches if any of the provided values match the given matcher."""

    def __init__(self, matcher):
        self.matcher = matcher

    def __str__(self):
        return 'AnyMatch(%s)' % (self.matcher,)

    def match(self, values):
        mismatches = []
        for value in values:
            mismatch = self.matcher.match(value)
            if mismatch:
                mismatches.append(mismatch)
            else:
                return None
        return MismatchesAll(mismatches)


class MatchesPredicate(Matcher):
    """Match if a given function returns True.

    It is reasonably common to want to make a very simple matcher based on a
    function that you already have that returns True or False given a single
    argument (i.e. a predicate function).  This matcher makes it very easy to
    do so. e.g.::

      IsEven = MatchesPredicate(lambda x: x % 2 == 0, '%s is not even')
      self.assertThat(4, IsEven)
    """

    def __init__(self, predicate, message):
        """Create a ``MatchesPredicate`` matcher.

        :param predicate: A function that takes a single argument and returns
            a value that will be interpreted as a boolean.
        :param message: A message to describe a mismatch.  It will be formatted
            with '%' and be given whatever was passed to ``match()``. Thus, it
            needs to contain exactly one thing like '%s', '%d' or '%f'.
        """
        self.predicate = predicate
        self.message = message

    def __str__(self):
        return '%s(%r, %r)' % (
            self.__class__.__name__, self.predicate, self.message)

    def match(self, x):
        if not self.predicate(x):
            return Mismatch(self.message % x)
