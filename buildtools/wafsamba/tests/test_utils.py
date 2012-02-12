from wafsamba.tests import TestCase

from wafsamba.samba_utils import TO_LIST

class ToListTests(TestCase):

    def test_none(self):
        self.assertEquals([], TO_LIST(None))

    def test_already_list(self):
        self.assertEquals(["foo", "bar", 1], TO_LIST(["foo", "bar", 1]))

    def test_default_delimiter(self):
        self.assertEquals(["foo", "bar"], TO_LIST("foo bar"))
        self.assertEquals(["foo", "bar"], TO_LIST("  foo bar  "))
        self.assertEquals(["foo ", "bar"], TO_LIST("  \"foo \" bar  "))

    def test_delimiter(self):
        self.assertEquals(["foo", "bar"], TO_LIST("foo,bar", ","))
        self.assertEquals(["  foo", "bar  "], TO_LIST("  foo,bar  ", ","))
        self.assertEquals(["  \" foo\"", " bar  "], TO_LIST("  \" foo\", bar  ", ","))
