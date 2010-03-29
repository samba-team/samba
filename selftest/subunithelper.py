# Python module for parsing and generating the Subunit protocol
# (Samba-specific)
# Copyright (C) 2008-2009 Jelmer Vernooij <jelmer@samba.org>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

__all__ = ['parse_results']

import re
import time

VALID_RESULTS = ['success', 'successful', 'failure', 'fail', 'skip', 'knownfail', 'error', 'xfail', 'skip-testsuite', 'testsuite-failure', 'testsuite-xfail', 'testsuite-success', 'testsuite-error']

def parse_results(msg_ops, statistics, fh):
    expected_fail = 0
    open_tests = []

    while fh:
        l = fh.readline()
        if l == "":
            break
        if l.startswith("test: "):
            msg_ops.control_msg(l)
            name = l.split(":", 1)[1].strip()
            msg_ops.start_test(name)
            open_tests.append(name)
        elif l.startswith("time: "):
            grp = re.match(
                "^time: (\d+)-(\d+)-(\d+) (\d+):(\d+):(\d+)\n", l)
            msg_ops.report_time(time.mktime((int(grp.group(1)), int(grp.group(2)), int(grp.group(3)), int(grp.group(4)), int(grp.group(5)), int(grp.group(6)), 0, 0, 0)))
        elif re.match("^(" + "|".join(VALID_RESULTS) + "): (.*?)( \[)?([ \t]*)( multipart)?\n", l):
            msg_ops.control_msg(l)
            grp = re.match("^(" + "|".join(VALID_RESULTS) + "): (.*?)( \[)?([ \t]*)( multipart)?\n", l)
            (result, testname, hasreason) = (grp.group(1), grp.group(2), grp.group(3))
            if hasreason:
                reason = ""
                # reason may be specified in next lines
                terminated = False
                while fh:
                    l = fh.readline()
                    if l == "":
                        break
                    msg_ops.control_msg(l)
                    if l == "]\n":
                        terminated = True
                        break
                    else:
                        reason += l
                
                if not terminated:
                    statistics['TESTS_ERROR']+=1
                    msg_ops.end_test(testname, "error", True, 
                                       "reason (%s) interrupted" % result)
                    return 1
            else:
                reason = None
            if result in ("success", "successful"):
                open_tests.pop() #FIXME: Check that popped value == $testname 
                statistics['TESTS_EXPECTED_OK']+=1
                msg_ops.end_test(testname, "success", False, reason)
            elif result in ("xfail", "knownfail"):
                open_tests.pop() #FIXME: Check that popped value == $testname
                statistics['TESTS_EXPECTED_FAIL']+=1
                msg_ops.end_test(testname, "xfail", False, reason)
                expected_fail+=1
            elif result in ("failure", "fail"):
                open_tests.pop() #FIXME: Check that popped value == $testname
                statistics['TESTS_UNEXPECTED_FAIL']+=1
                msg_ops.end_test(testname, "failure", True, reason)
            elif result == "skip":
                statistics['TESTS_SKIP']+=1
                # Allow tests to be skipped without prior announcement of test
                last = open_tests.pop()
                if last is not None and last != testname:
                    open_tests.append(testname)
                msg_ops.end_test(testname, "skip", False, reason)
            elif result == "error":
                statistics['TESTS_ERROR']+=1
                open_tests.pop() #FIXME: Check that popped value == $testname
                msg_ops.end_test(testname, "error", True, reason)
            elif result == "skip-testsuite":
                msg_ops.skip_testsuite(testname)
            elif result == "testsuite-success":
                msg_ops.end_testsuite(testname, "success", reason)
            elif result == "testsuite-failure":
                msg_ops.end_testsuite(testname, "failure", reason)
            elif result == "testsuite-xfail":
                msg_ops.end_testsuite(testname, "xfail", reason)
            elif result == "testsuite-error":
                msg_ops.end_testsuite(testname, "error", reason)
        elif l.startswith("testsuite: "):
            msg_ops.start_testsuite(l.split(":", 1)[1].strip())
        elif l.startswith("testsuite-count: "):
            msg_ops.testsuite_count(int(l.split(":", 1)[1].strip()))
        else:
            msg_ops.output_msg(l)

    while open_tests:
        msg_ops.end_test(open_tests.pop(), "error", True,
                   "was started but never finished!")
        statistics['TESTS_ERROR']+=1

    if statistics['TESTS_ERROR'] > 0:
        return 1
    if statistics['TESTS_UNEXPECTED_FAIL'] > 0:
        return 1 
    return 0


class SubunitOps(object):

    def start_test(self, testname):
        print "test: %s" % testname

    def end_test(self, name, result, reason=None):
        if reason:
            print "%s: %s [" % (result, name)
            print "%s" % reason
            print "]"
        else:
            print "%s: %s" % (result, name)

    def skip_test(self, name, reason=None):
        self.end_test(name, "skip", reason)

    def fail_test(self, name, reason=None):
        self.end_test(name, "fail", reason)

    def success_test(self, name, reason=None):
        self.end_test(name, "success", reason)

    def xfail_test(self, name, reason=None):
        self.end_test(name, "xfail", reason)

    def report_time(self, t):
        (sec, min, hour, mday, mon, year, wday, yday, isdst) = time.localtimet(t)
        print "time: %04d-%02d-%02d %02d:%02d:%02d" % (year+1900, mon+1, mday, hour, min, sec)

    # The following are Samba extensions:
    def start_testsuite(self, name):
        print "testsuite: %s" % name

    def skip_testsuite(self, name, reason=None):
        if reason:
            print "skip-testsuite: %s [\n%s\n]" % (name, reason)
        else:
            print "skip-testsuite: %s" % name

    def end_testsuite(self, name, result, reason=None):
        if reason:
            print "testsuite-$result: %s [" % name
            print "%s" % reason
            print "]"
        else:
            print "testsuite-$result: %s" % name

    def testsuite_count(self, count):
        print "testsuite-count: %d" % count
