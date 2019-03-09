# Copyright (C) Catalyst IT Ltd. 2017

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

"""
Blackbox tests for blackboxtest check output methods.
"""

import signal
from samba.tests import BlackboxTestCase


class TimeoutHelper():
    """
    Timeout class using alarm signal.

    Raise a Timeout exception if a function timeout.
    Usage:

        try:
            with Timeout(3):
                foobar("Request 1")
        except TimeoutHelper.Timeout:
            print("Timeout")
    """

    class Timeout(Exception):
        pass

    def __init__(self, sec):
        self.sec = sec

    def __enter__(self):
        signal.signal(signal.SIGALRM, self.raise_timeout)
        signal.alarm(self.sec)

    def __exit__(self, *args):
        signal.alarm(0)    # disable alarm

    def raise_timeout(self, *args):
        raise TimeoutHelper.Timeout()


def _make_cmdline(data='$', repeat=(5 * 1024 * 1024), retcode=0):
    """Build a command to call gen_output.py to generate large output"""
    return 'gen_output.py --data {0} --repeat {1} --retcode {2}'.format(data,
                                                                        repeat,
                                                                        retcode)


class CheckOutputTests(BlackboxTestCase):
    """
    Blackbox tests for check_xxx methods.

    The check_xxx methods in BlackboxTestCase will deadlock
    on large output from command which caused by Popen.wait().

    This is a test case to show the deadlock issue,
    will fix in another commit.
    """

    def test_check_run_timeout(self):
        """Call check_run with large output."""
        try:
            with TimeoutHelper(10):
                self.check_run(_make_cmdline())
        except TimeoutHelper.Timeout:
            self.fail(msg='Timeout!')

    def test_check_exit_code_with_large_output_success(self):
        try:
            with TimeoutHelper(10):
                self.check_exit_code(_make_cmdline(retcode=0), 0)
        except TimeoutHelper.Timeout:
            self.fail(msg='Timeout!')

    def test_check_exit_code_with_large_output_failure(self):
        try:
            with TimeoutHelper(10):
                self.check_exit_code(_make_cmdline(retcode=1), 1)
        except TimeoutHelper.Timeout:
            self.fail(msg='Timeout!')

    def test_check_output_with_large_output(self):
        data = '@'
        repeat = 5 * 1024 * 1024  # 5M
        expected = data * repeat
        cmdline = _make_cmdline(data=data, repeat=repeat)

        try:
            with TimeoutHelper(10):
                actual = self.check_output(cmdline)
                # check_output will return bytes
                # convert expected to bytes for python 3
                self.assertEqual(actual, expected.encode('utf-8'))
        except TimeoutHelper.Timeout:
            self.fail(msg='Timeout!')
