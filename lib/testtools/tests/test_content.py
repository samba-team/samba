# Copyright (c) 2008 Jonathan M. Lange. See LICENSE for details.

import unittest
from testtools.content import Content, TracebackContent
from testtools.content_type import ContentType
from testtools.utils import _u
from testtools.tests.helpers import an_exc_info


def test_suite():
    from unittest import TestLoader
    return TestLoader().loadTestsFromName(__name__)


class TestContent(unittest.TestCase):

    def test___init___None_errors(self):
        self.assertRaises(ValueError, Content, None, None)
        self.assertRaises(ValueError, Content, None, lambda: ["traceback"])
        self.assertRaises(ValueError, Content,
            ContentType("text", "traceback"), None)

    def test___init___sets_ivars(self):
        content_type = ContentType("foo", "bar")
        content = Content(content_type, lambda: ["bytes"])
        self.assertEqual(content_type, content.content_type)
        self.assertEqual(["bytes"], list(content.iter_bytes()))

    def test___eq__(self):
        content_type = ContentType("foo", "bar")
        content1 = Content(content_type, lambda: ["bytes"])
        content2 = Content(content_type, lambda: ["bytes"])
        content3 = Content(content_type, lambda: ["by", "tes"])
        content4 = Content(content_type, lambda: ["by", "te"])
        content5 = Content(ContentType("f", "b"), lambda: ["by", "tes"])
        self.assertEqual(content1, content2)
        self.assertEqual(content1, content3)
        self.assertNotEqual(content1, content4)
        self.assertNotEqual(content1, content5)

    def test_iter_text_not_text_errors(self):
        content_type = ContentType("foo", "bar")
        content = Content(content_type, lambda: ["bytes"])
        self.assertRaises(ValueError, content.iter_text)

    def test_iter_text_decodes(self):
        content_type = ContentType("text", "strange", {"charset": "utf8"})
        content = Content(
            content_type, lambda: [_u("bytes\xea").encode("utf8")])
        self.assertEqual([_u("bytes\xea")], list(content.iter_text()))

    def test_iter_text_default_charset_iso_8859_1(self):
        content_type = ContentType("text", "strange")
        text = _u("bytes\xea")
        iso_version = text.encode("ISO-8859-1")
        content = Content(content_type, lambda: [iso_version])
        self.assertEqual([text], list(content.iter_text()))


class TestTracebackContent(unittest.TestCase):

    def test___init___None_errors(self):
        self.assertRaises(ValueError, TracebackContent, None, None)

    def test___init___sets_ivars(self):
        content = TracebackContent(an_exc_info, self)
        content_type = ContentType("text", "x-traceback",
            {"language": "python", "charset": "utf8"})
        self.assertEqual(content_type, content.content_type)
        result = unittest.TestResult()
        expected = result._exc_info_to_string(an_exc_info, self)
        self.assertEqual(expected, ''.join(list(content.iter_text())))
