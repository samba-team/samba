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
Python, or (through a fork/exec interface) any other language.  It is
similar in design to the very nice 'svntest' system used by
Subversion, but has no Subversion-specific features.

It is somewhat similar to PyUnit, except:

 - it allows capture of detailed log messages from a test, to be
   optionally displayed if the test fails.

 - it allows execution of a specified subset of tests

 - it avoids Java idioms that are not so useful in Python

WRITING TESTS:

  Each test case is a callable object, typically a function.  Its
  documentation string describes the test, and the first line of the
  docstring should be a brief name.

  The test should return 0 for pass, or non-zero for failure.
  Alternatively they may raise an exception.

  Tests may import this "comfychair" module to get some useful
  utilities, but that is not strictly required.
  
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
    
    def setUp(self):
        """Set up test fixture."""
        pass

    def tearDown(self):
        """Tear down test fixture."""
        pass

    def runTest(self):
        """Run the test."""
        pass

    def fail(self, reason = ""):
        """Say the test failed."""
        raise AssertionError(reason)

    def assert_(self, expr, reason = ""):
        if not expr:
            raise AssertionError(reason)

    def assert_re_match(self, pattern, s):
        """Assert that a string matches a particular pattern

        Inputs:
          pattern      string: regular expression
          s            string: to be matched

        Raises:
          AssertionError if not matched
          """
        if not re.match(pattern, s):
            raise AssertionError("string %s does not match regexp %s" % (`s`, `pattern`))

    def assert_regexp(self, pattern, s):
        """Assert that a string *contains* a particular pattern

        Inputs:
          pattern      string: regular expression
          s            string: to be searched

        Raises:
          AssertionError if not matched
          """
        if not re.search(pattern, s):
            raise AssertionError("string %s does not contain regexp %s" % (`s`, `pattern`))


    def assert_no_file(self, filename):
        import os.path
        assert not os.path.exists(filename), ("file exists but should not: %s" % filename)


    def runCmdNoWait(self, cmd):
        import os
        name = cmd[0]
        self.test_log = self.test_log + "Run in background:\n" + `cmd` + "\n"
        pid = os.spawnvp(os.P_NOWAIT, name, cmd)
        self.test_log = self.test_log + "pid: %d\n" % pid
        return pid


    def runCmd(self, cmd, expectedResult = 0):
        """Run a command, fail if the command returns an unexpected exit
        code.  Return the output produced."""
        rc, output = self.runCmdUnchecked(cmd)
        if rc != expectedResult:
            raise AssertionError("command returned %d; expected %s: \"%s\"" %
                                 (rc, expectedResult, cmd))

        return output

    def runCmdUnchecked(self, cmd, skip_on_noexec = 0):
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

    def explainFailure(self, exc_info = None):
        import traceback
        # Move along, nothing to see here
        if not exc_info and self.test_log == "":
            return
        print "-----------------------------------------------------------------"
        if exc_info:
            traceback.print_exc(file=sys.stdout)
        print self.test_log
        print "-----------------------------------------------------------------"

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

    def log(self, msg):
        """Log a message to the test log.  This message is displayed if
        the test fails, or when the runtests function is invoked with
        the verbose option."""
        self.test_log = self.test_log + msg + "\n"

class NotRunError(Exception):
    def __init__(self, value = None):
        self.value = value

def test_name(test):
    """Return a human-readable name for a test.

    Inputs:
      test         some kind of callable test object

    Returns:
      name         string: a short printable name
      """
    try:
        return test.__name__
    except:
        return `test`

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
    for test in test_list:
        print "%-60s" % test_name(test),
        # flush now so that long running tests are easier to follow
        sys.stdout.flush()

        try:
            try: # run test and show result
                obj = test()
                if hasattr(obj, "setUp"):
                    obj.setUp()
                obj.runTest()
                print "OK"
            except KeyboardInterrupt:
                print "INTERRUPT"
                obj.explainFailure(sys.exc_info())
                ret = 2
                break
            except NotRunError, msg:
                print "NOTRUN, %s" % msg.value
            except:
                print "FAIL"
                obj.explainFailure(sys.exc_info())
                ret = 1
        finally:
            try:
                if hasattr(obj, "tearDown"):
                    obj.tearDown()
            except KeyboardInterrupt:
                print "interrupted during tearDown"
                obj.explainFailure(sys.exc_info())
                ret = 2
                break
            except:
                print "error during tearDown"
                obj.explainFailure(sys.exc_info())
                ret = 1
        # Display log file if we're verbose
        if ret == 0 and verbose:
            obj.explainFailure()
            
    return ret

if __name__ == '__main__':
    print __doc__
