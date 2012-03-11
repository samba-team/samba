#!/usr/bin/python -u
# Bootstrap Samba and run a number of tests against it.
# Copyright (C) 2012 Jelmer Vernooij <jelmer@samba.org>

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

"""Test command running."""

import datetime
from subunit import iso8601
import os
import subprocess
import subunit
import sys
import tempfile
import warnings

# expand strings from %ENV
def expand_environment_strings(s, vars):
    # we use a reverse sort so we do the longer ones first
    for k in sorted(vars.keys(), reverse=True):
        v = vars[k]
        s = s.replace("$%s" % k, v)
    return s


def expand_command_list(cmd):
    if not "$LISTOPT" in cmd:
        return None
    return cmd.replace("$LISTOPT", "--list")


def expand_command_run(cmd, supports_loadfile, supports_idlist, subtests=None):
    """Expand a test command.

    :param cmd: Command to expand
    :param supports_loadfile: Whether command supports loadfile
    :param supports_idlist: Whether the command supports running specific
        subtests
    :param subtests: List of subtests to run - None for all subtests
    :return: Tuple with command to run and temporary file to remove after
        running (or None)
    """
    # Generate a file with the individual tests to run, if the
    # test runner for this test suite supports it.
    if subtests is None:
        return (cmd.replace("$LOADLIST", ""), None)
    if supports_loadfile:
        (fd, listid_file) = tempfile.mkstemp()
        f = os.fdopen(fd, 'w')
        try:
            for test in subtests:
                f.write(test+"\n")
        finally:
            f.close()
        return (
            cmd.replace("$LOADLIST", "--load-list=%s" % listid_file),
            listid_file)
    elif supports_idlist:
        cmd += " " + " ".join(subtests)
        return (cmd, None)
    else:
        warnings.warn(
            "Running subtests requested, but command does not support "
            "this.")
        return (cmd, None)


def exported_envvars_str(vars, names):
    out = ""
    for n in names:
        if not n in vars:
            continue
        out += "%s=%s\n" % (n, vars[n])
    return out


def now():
    """Return datetime instance for current time in UTC.
    """
    return datetime.datetime.utcnow().replace(tzinfo=iso8601.Utc())


def run_testsuite_command(name, cmd, subunit_ops, env=None, outf=None):
    """Run a testsuite command.

    :param name: Name of the testsuite
    :param cmd: Command to run
    :param subunit_ops: Subunit ops to use for reporting results
    :param env: Environment the test is run in
    :param outf: File-like object to write standard out to (defaults to sys.stdout)
    :return: Exit code or None if the test failed to run completely
    """
    if outf is None:
        outf = sys.stdout
    subunit_ops.start_testsuite(name)
    subunit_ops.progress(None, subunit.PROGRESS_PUSH)
    subunit_ops.time(now())
    try:
        exitcode = subprocess.call(cmd, shell=True, stdout=outf)
    except Exception, e:
        subunit_ops.time(now())
        subunit_ops.progress(None, subunit.PROGRESS_POP)
        subunit_ops.end_testsuite(name, "error", "Unable to run %r: %s" % (cmd, e))
        return None

    subunit_ops.time(now())
    subunit_ops.progress(None, subunit.PROGRESS_POP)

    if env is not None:
        envlog = env.get_log()
        if envlog != "":
            outf.write("envlog: %s\n" % envlog)

    outf.write("command: %s\n" % cmd)
    outf.write("expanded command: %s\n" % expand_environment_strings(cmd, os.environ))

    if exitcode == 0:
        subunit_ops.end_testsuite(name, "success")
    else:
        subunit_ops.end_testsuite(name, "failure", "Exit code was %d" % exitcode)

    return exitcode
