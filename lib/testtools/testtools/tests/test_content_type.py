# Copyright (c) 2008 Jonathan M. Lange. See LICENSE for details.

import unittest
from testtools.content_type import ContentType


def test_suite():
    from unittest import TestLoader
    return TestLoader().loadTestsFromName(__name__)


class TestContentType(unittest.TestCase):

    def test___init___None_errors(self):
        self.assertRaises(ValueError, ContentType, None, None)
        self.assertRaises(ValueError, ContentType, None, "traceback")
        self.assertRaises(ValueError, ContentType, "text", None)

    def test___init___sets_ivars(self):
        content_type = ContentType("foo", "bar")
        self.assertEqual("foo", content_type.type)
        self.assertEqual("bar", content_type.subtype)
        self.assertEqual({}, content_type.parameters)

    def test___init___with_parameters(self):
        content_type = ContentType("foo", "bar", {"quux":"thing"})
        self.assertEqual({"quux":"thing"}, content_type.parameters)

    def test___eq__(self):
        content_type1 = ContentType("foo", "bar", {"quux":"thing"})
        content_type2 = ContentType("foo", "bar", {"quux":"thing"})
        content_type3 = ContentType("foo", "bar", {"quux":"thing2"})
        self.assertTrue(content_type1.__eq__(content_type2))
        self.assertFalse(content_type1.__eq__(content_type3))
