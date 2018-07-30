# Subunit handling
# Copyright (C) Jelmer Vernooij <jelmer@samba.org> 2014
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

"""Subunit test protocol."""

import samba

samba.ensure_third_party_module("iso8601", "pyiso8601")
import iso8601

import unittest


PROGRESS_SET = 0
PROGRESS_CUR = 1
PROGRESS_PUSH = 2
PROGRESS_POP = 3


def RemoteError(description=""):
    return (Exception, Exception(description), None)


class RemotedTestCase(unittest.TestCase):
    """A class to represent test cases run in child processes.

    Instances of this class are used to provide the Python test API a TestCase
    that can be printed to the screen, introspected for metadata and so on.
    However, as they are a simply a memoisation of a test that was actually
    run in the past by a separate process, they cannot perform any interactive
    actions.
    """

    def __eq__(self, other):
        try:
            return self.__description == other.__description
        except AttributeError:
            return False

    def __init__(self, description):
        """Create a psuedo test case with description description."""
        self.__description = description

    def error(self, label):
        raise NotImplementedError("%s on RemotedTestCases is not permitted." %
                                  label)

    def setUp(self):
        self.error("setUp")

    def tearDown(self):
        self.error("tearDown")

    def shortDescription(self):
        return self.__description

    def id(self):
        return "%s" % (self.__description,)

    def __str__(self):
        return "%s (%s)" % (self.__description, self._strclass())

    def __repr__(self):
        return "<%s description='%s'>" % \
               (self._strclass(), self.__description)

    def run(self, result=None):
        if result is None:
            result = self.defaultTestResult()
        result.startTest(self)
        result.addError(self, RemoteError("Cannot run RemotedTestCases.\n"))
        result.stopTest(self)

    def _strclass(self):
        cls = self.__class__
        return "%s.%s" % (cls.__module__, cls.__name__)
