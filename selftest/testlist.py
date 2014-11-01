# testlist.py -- Test list
# Copyright (C) 2012 Jelmer Vernooij <jelmer@samba.org>
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; version 3
# of the License or (at your option) any later version of
# the License.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
# MA  02110-1301, USA.

"""Selftest test list management."""

__all__ = ['find_in_list', 'read_test_regexes', 'read_testlist']

import os
import re
import sys

def find_in_list(list, fullname):
    """Find test in list.

    :param list: List with 2-tuples with regex and reason
    """
    for (regex, reason) in list:
        if re.match(regex, fullname):
            if reason is not None:
                return reason
            else:
                return ""
    return None


def read_test_regexes(f):
    """Read tuples with regular expression and optional string from a file.

    :param f: File-like object to read from
    :return: Iterator over tuples with regular expression and test name
    """
    for l in f.readlines():
        l = l.strip()
        if l[0] == "#":
            continue
        try:
            (test, reason) = l.split("#", 1)
        except ValueError:
            yield l, None
        else:
            yield test.strip(), reason.strip()


def should_run_test(tests, name):
    if tests == []:
        return True
    for test in tests:
        if re.match(test, name):
            return True
    return False


def read_testlist(inf, outf):
    """Read a list of tests from a file.

    :param inf: File-like object to read from.
    :param outf: File-like object to write to.
    :return: Iterator over tuples describing tests
    """
    while True:
        l = inf.readline()
        if l == '':
            return
        if l.startswith("-- TEST") and l.endswith(" --\n"):
            supports_loadlist = l.startswith("-- TEST-LOADLIST")
            name = inf.readline().rstrip("\n")
            env = inf.readline().rstrip("\n")
            if supports_loadlist:
                loadlist = inf.readline().rstrip("\n")
            else:
                loadlist = None
            cmdline = inf.readline().rstrip("\n")
            yield (name, env, cmdline, loadlist)
        else:
            outf.write(l)


def read_restricted_test_list(f):
    for l in f.readlines():
        yield l.strip()


class RestrictedTestManager(object):
    """Test manager which can filter individual tests that should be run."""

    def __init__(self, test_list):
        self.test_list = test_list
        self.unused = set(self.test_list)

    @classmethod
    def from_path(cls, path):
        f = open(path, 'r')
        try:
            return cls(read_restricted_test_list(f))
        finally:
            f.close()

    def should_run_testsuite(self, name):
        """Determine whether a testsuite should be run.

        :param name: Name of the testsuite
        :return: None if full testsuite should be run,
            a list of subtests to run or [] if it should
            not be run.
        """
        match = []
        for r in self.test_list:
            if r == name:
                match = None
                if r in self.unused:
                    self.unused.remove(r)
            elif r.startswith(name + "."):
                if match is not None:
                    match.append(r[len(name+"."):])
                if r in self.unused:
                    self.unused.remove(r)
        return match

    def iter_unused(self):
        """Iterate over entry entries that were unused.

        :return: Iterator over test list entries that were not used.
        """
        return iter(self.unused)


def open_file_or_pipe(path, mode):
    """Open a file or pipe.

    :param path: Path to open; if it ends with | it is assumed to be a
        command to run
    :param mode: Mode with which to open it
    :return: File-like object
    """
    if path.endswith("|"):
        return os.popen(path[:-1], mode)
    return open(path, mode)


def read_testlist_file(fn, outf=None):
    """Read testlist file.

    :param fn: Path to read (assumed to be a command to run if it ends with |)
    :param outf: File-like object to pass non-test data through to
        (defaults to stdout)
    :return: Iterator over test suites (see read_testlist)
    """
    if outf is None:
        outf = sys.stdout
    inf = open_file_or_pipe(fn, 'r')
    try:
        for testsuite in read_testlist(inf, outf):
            yield testsuite
    finally:
        inf.close()
