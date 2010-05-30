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
import sys
import subunit
import time

VALID_RESULTS = ['success', 'successful', 'failure', 'fail', 'skip', 'knownfail', 'error', 'xfail', 'skip-testsuite', 'testsuite-failure', 'testsuite-xfail', 'testsuite-success', 'testsuite-error']

def parse_results(msg_ops, statistics, fh):
    expected_fail = 0
    open_tests = []

    while fh:
        l = fh.readline()
        if l == "":
            break
        parts = l.split(None, 1)
        if not len(parts) == 2 or not l.startswith(parts[0]):
            continue
        command = parts[0].rstrip(":")
        arg = parts[1]
        if command in ("test", "testing"):
            msg_ops.control_msg(l)
            msg_ops.start_test(arg.rstrip())
            open_tests.append(arg.rstrip())
        elif command == "time":
            msg_ops.control_msg(l)
            grp = re.match(
                "(\d+)-(\d+)-(\d+) (\d+):(\d+):(\d+)\n", arg)
            msg_ops.report_time(time.mktime((int(grp.group(1)), int(grp.group(2)), int(grp.group(3)), int(grp.group(4)), int(grp.group(5)), int(grp.group(6)), 0, 0, 0)))
        elif command in VALID_RESULTS:
            msg_ops.control_msg(l)
            result = command
            grp = re.match("(.*?)( \[)?([ \t]*)( multipart)?\n", arg)
            (testname, hasreason) = (grp.group(1), grp.group(2))
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
                try:
                    open_tests.remove(testname)
                except ValueError:
                    statistics['TESTS_ERROR']+=1
                    msg_ops.end_test(testname, "error", True, 
                            "Test was never started")
                else:
                    statistics['TESTS_EXPECTED_OK']+=1
                    msg_ops.end_test(testname, "success", False, reason)
            elif result in ("xfail", "knownfail"):
                try:
                    open_tests.remove(testname)
                except ValueError:
                    statistics['TESTS_ERROR']+=1
                    msg_ops.end_test(testname, "error", True, 
                            "Test was never started")
                else:
                    statistics['TESTS_EXPECTED_FAIL']+=1
                    msg_ops.end_test(testname, "xfail", False, reason)
                    expected_fail+=1
            elif result in ("failure", "fail"):
                try:
                    open_tests.remove(testname)
                except ValueError:
                    statistics['TESTS_ERROR']+=1
                    msg_ops.end_test(testname, "error", True, 
                            "Test was never started")
                else:
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
                try:
                    open_tests.remove(testname)
                except ValueError:
                    pass
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
        elif command == "testsuite":
            msg_ops.start_testsuite(arg.strip())
        elif command == "progress":
            arg = arg.strip()
            if arg == "pop":
                msg_ops.progress(None, subunit.PROGRESS_POP)
            elif arg == "push":
                msg_ops.progress(None, subunit.PROGRESS_PUSH)
            elif arg[0] in '+-':
                msg_ops.progress(int(arg), subunit.PROGRESS_CUR)
            else:
                msg_ops.progress(int(arg), subunit.PROGRESS_SET)
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
        (year, mon, mday, hour, min, sec, wday, yday, isdst) = time.localtime(t)
        print "time: %04d-%02d-%02d %02d:%02d:%02d" % (year, mon, mday, hour, min, sec)

    def progress(self, offset, whence):
        if whence == subunit.PROGRESS_CUR and offset > -1:
            prefix = "+"
        elif whence == subunit.PROGRESS_PUSH:
            prefix = ""
            offset = "push"
        elif whence == subunit.PROGRESS_POP:
            prefix = ""
            offset = "pop"
        else:
            prefix = ""
        print "progress: %s%s" % (prefix, offset)

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
            print "testsuite-%s: %s [" % (result, name)
            print "%s" % reason
            print "]"
        else:
            print "testsuite-%s: %s" % (result, name)


def read_test_regexes(name):
    ret = {}
    f = open(name, 'r')
    try:
        for l in f:
            l = l.strip()
            if l == "" or l[0] == "#":
                continue
            if "#" in l:
                (regex, reason) = l.split("#", 1)
                ret[regex.strip()] = reason.strip()
            else:
                ret[l] = None
    finally:
        f.close()
    return ret


def find_in_list(regexes, fullname):
    for regex, reason in regexes.iteritems():
        if re.match(regex, fullname):
            if reason is None:
                return ""
            return reason
    return None


class FilterOps(object):

    def control_msg(self, msg):
        pass # We regenerate control messages, so ignore this

    def report_time(self, time):
        self._ops.report_time(time)

    def progress(self, delta, whence):
        self._ops.progress(delta, whence)

    def output_msg(self, msg):
        if self.output is None:
            sys.stdout.write(msg)
        else:
            self.output+=msg

    def start_test(self, testname):
        if self.prefix is not None:
            testname = self.prefix + testname

        if self.strip_ok_output:
           self.output = ""

        self._ops.start_test(testname)

    def end_test(self, testname, result, unexpected, reason):
        if self.prefix is not None:
            testname = self.prefix + testname

        if result in ("fail", "failure") and not unexpected:
            result = "xfail"
            self.xfail_added+=1
            self.total_xfail+=1
        xfail_reason = find_in_list(self.expected_failures, testname)
        if xfail_reason is not None and result in ("fail", "failure"):
            result = "xfail"
            self.xfail_added+=1
            self.total_xfail+=1
            reason += xfail_reason

        if result in ("fail", "failure"):
            self.fail_added+=1
            self.total_fail+=1

        if result == "error":
            self.error_added+=1
            self.total_error+=1

        if self.strip_ok_output:
            if result not in ("success", "xfail", "skip"):
                print self.output
        self.output = None

        self._ops.end_test(testname, result, reason)

    def skip_testsuite(self, name, reason=None):
        self._ops.skip_testsuite(name, reason)

    def start_testsuite(self, name):
        self._ops.start_testsuite(name)

        self.error_added = 0
        self.fail_added = 0
        self.xfail_added = 0

    def end_testsuite(self, name, result, reason=None):
        xfail = False

        if self.xfail_added > 0:
            xfail = True
        if self.fail_added > 0 or self.error_added > 0:
            xfail = False

        if xfail and result in ("fail", "failure"):
            result = "xfail"

        if self.fail_added > 0 and result != "failure":
            result = "failure"
            if reason is None:
                reason = "Subunit/Filter Reason"
            reason += "\n failures[%d]" % self.fail_added

        if self.error_added > 0 and result != "error":
            result = "error"
            if reason is None:
                reason = "Subunit/Filter Reason"
            reason += "\n errors[%d]" % self.error_added

        self._ops.end_testsuite(name, result, reason)

    def __init__(self, prefix, expected_failures, strip_ok_output):
        self._ops = SubunitOps()
        self.output = None
        self.prefix = prefix
        self.expected_failures = expected_failures
        self.strip_ok_output = strip_ok_output
        self.xfail_added = 0
        self.total_xfail = 0
        self.total_error = 0
        self.total_fail = 0
