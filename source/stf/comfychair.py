#! /usr/bin/env python

# Copyright (C) 2002, 2003 by Martin Pool <mbp@samba.org>
# 
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License as
# published by the Free Software Foundation; either version 2 of the
# License, or (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307
# USA

"""comfychair: a Python-based instrument of software torture.

Copyright (C) 2002, 2003 by Martin Pool <mbp@samba.org>

This is a test framework designed for testing programs written in
Python, or (through a fork/exec interface) any other language.

For more information, see the file README.comfychair.

To run a test suite based on ComfyChair, just run it as a program.
"""

# TODO: Put everything into a temporary directory?

# TODO: Have a means for tests to customize the display of their
# failure messages.  In particular, if a shell command failed, then
# give its stderr.

import sys, re

class TestCase:
    """A base class for tests.  This class defines required functions which
    can optionally be overridden by subclasses.  It also provides some
    utility functions for"""

    def __init__(self):
        self.test_log = ""
        self.background_pids = []
    
    def setup(self):
        """Set up test fixture."""
        pass

    def teardown(self):
        """Tear down test fixture."""
        pass

    def runtest(self):
        """Run the test."""
        pass

    def fail(self, reason = ""):
        """Say the test failed."""
        raise AssertionError(reason)


    #############################################################
    # Requisition methods

    def require(self, predicate, message):
        """Check a predicate for running this test.

If the predicate value is not true, the test is skipped with a message explaining
why."""
        if not predicate:
            raise NotRunError, message

    def require_root(self):
        """Skip this test unless run by root."""
        import os
        self.require(os.getuid() == 0,
                     "must be root to run this test")

    #############################################################
    # Assertion methods

    def assert_(self, expr, reason = ""):
        if not expr:
            raise AssertionError(reason)

    def assert_equal(self, a, b):
        if not a == b:
            raise AssertionError("assertEquals failed: %s" % `(a, b)`)
            
    def assert_notequal(self, a, b):
        if a == b:
            raise AssertionError("assertNotEqual failed: %s" % `(a, b)`)

    def assert_re_match(self, pattern, s):
        """Assert that a string matches a particular pattern

        Inputs:
          pattern      string: regular expression
          s            string: to be matched

        Raises:
          AssertionError if not matched
          """
        if not re.match(pattern, s):
            raise AssertionError("string does not match regexp\n"
                                 "    string: %s\n"
                                 "    re: %s" % (`s`, `pattern`))

    def assert_re_search(self, pattern, s):
        """Assert that a string *contains* a particular pattern

        Inputs:
          pattern      string: regular expression
          s            string: to be searched

        Raises:
          AssertionError if not matched
          """
        if not re.search(pattern, s):
            raise AssertionError("string does not contain regexp\n"
                                 "    string: %s\n"
                                 "    re: %s" % (`s`, `pattern`))


    def assert_no_file(self, filename):
        import os.path
        assert not os.path.exists(filename), ("file exists but should not: %s" % filename)


    #############################################################
    # Methods for running programs

    def runcmd_background(self, cmd):
        import os
        name = cmd[0]
        self.test_log = self.test_log + "Run in background:\n" + `cmd` + "\n"
        pid = os.spawnvp(os.P_NOWAIT, name, cmd)
        self.test_log = self.test_log + "pid: %d\n" % pid
        return pid


    def runcmd(self, cmd, expectedResult = 0):
        """Run a command, fail if the command returns an unexpected exit
        code.  Return the output produced."""
        rc, output = self.runcmd_unchecked(cmd)
        if rc != expectedResult:
            raise AssertionError("command returned %d; expected %s: \"%s\"" %
                                 (rc, expectedResult, cmd))

        return output

    def runcmd_unchecked(self, cmd, skip_on_noexec = 0):
        """Invoke a command; return (exitcode, stdout)"""
        import os, popen2
        pobj = popen2.Popen4(cmd)
        output = pobj.fromchild.read()
        waitstatus = pobj.wait()
        assert not os.WIFSIGNALED(waitstatus), \
               ("%s terminated with signal %d", cmd, os.WTERMSIG(waitstatus))
        rc = os.WEXITSTATUS(waitstatus)
        self.test_log = self.test_log + ("""Run command: %s
Wait status: %#x
Output:
%s""" % (cmd, waitstatus, output))
        if skip_on_noexec and rc == 127:
            # Either we could not execute the command or the command
            # returned exit code 127.  According to system(3) we can't
            # tell the difference.
            raise NotRunError, "could not execute %s" % cmd
        return rc, output

    def explain_failure(self, exc_info = None):
        import traceback
        # Move along, nothing to see here
        if not exc_info and self.test_log == "":
            return
        print "-----------------------------------------------------------------"
        if exc_info:
            traceback.print_exc(file=sys.stdout)
        print self.test_log
        print "-----------------------------------------------------------------"


    def log(self, msg):
        """Log a message to the test log.  This message is displayed if
        the test fails, or when the runtests function is invoked with
        the verbose option."""
        self.test_log = self.test_log + msg + "\n"


class NotRunError(Exception):
    """Raised if a test must be skipped because of missing resources"""
    def __init__(self, value = None):
        self.value = value


def runtests(test_list, verbose = 0):
    """Run a series of tests.

    Eventually, this routine will also examine sys.argv[] to handle
    extra options.

    Inputs:
      test_list    sequence of callable test objects

    Returns:
      unix return code: 0 for success, 1 for failures, 2 for test failure
    """
    import traceback
    ret = 0
    for test_class in test_list:
        print "%-60s" % _test_name(test_class),
        # flush now so that long running tests are easier to follow
        sys.stdout.flush()

        try:
            try: # run test and show result
                obj = test_class()
                if hasattr(obj, "setup"):
                    obj.setup()
                obj.runtest()
                print "OK"
            except KeyboardInterrupt:
                print "INTERRUPT"
                obj.explain_failure(sys.exc_info())
                ret = 2
                break
            except NotRunError, msg:
                print "NOTRUN, %s" % msg.value
            except:
                print "FAIL"
                obj.explain_failure(sys.exc_info())
                ret = 1
        finally:
            try:
                if hasattr(obj, "teardown"):
                    obj.teardown()
            except KeyboardInterrupt:
                print "interrupted during teardown"
                obj.explain_failure(sys.exc_info())
                ret = 2
                break
            except:
                print "error during teardown"
                obj.explain_failure(sys.exc_info())
                ret = 1
        # Display log file if we're verbose
        if ret == 0 and verbose:
            obj.explain_failure()
            
    return ret


def _test_name(test_class):
    """Return a human-readable name for a test class.
    """
    try:
        return test_class.__name__
    except:
        return `test_class`


def print_help():
    """Help for people running tests"""
    import sys
    print """%s: software test suite based on ComfyChair

usage:
    To run all tests, just run this program.  To run particular tests,
    list them on the command line.

options:
    --help           show usage message
    --list           list available tests
    --verbose        show more information while running tests
""" % sys.argv[0]


def print_list(test_list):
    """Show list of available tests"""
    for test_class in test_list:
        print "    %s" % _test_name(test_class)


def main(tests):
    """Main entry point for test suites based on ComfyChair.

Test suites should contain this boilerplate:

    if __name__ == '__main__':
        comfychair.main(tests)

This function handles standard options such as --help and --list, and
by default runs all tests in the suggested order.

Calls sys.exit() on completion.
"""
    from sys import argv
    import getopt, sys

    verbose = 0

    opts, args = getopt.getopt(argv[1:], '', ['help', 'list', 'verbose'])
    if ('--help', '') in opts:
        print_help()
        return
    elif ('--list', '') in opts:
        print_list(tests)
        return 

    if ('--verbose', '') in opts:
        verbose = 1

    if args:
        by_name = {}
        for t in tests:
            by_name[_test_name(t)] = t
        which_tests = [by_name[name] for name in args]
    else:
        which_tests = tests

    sys.exit(runtests(which_tests, verbose))


if __name__ == '__main__':
    print __doc__
