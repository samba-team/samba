# Black box tests for script/traffic_leaner
#
# Copyright (C) Catalyst IT Ltd. 2017
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

"""Blackbox tests for traffic_replay"""

from contextlib import contextmanager
import os
import tempfile

from samba.tests import BlackboxTestCase

DATA_DIR      = "python/samba/tests/blackbox/testdata"
SCRIPT        = "script/traffic_replay"
FIXED         = "--fixed-password trafficreplay01%"
SERVER        = os.environ["SERVER"]
PASSWORD      = os.environ["PASSWORD"]
USER          = os.environ["USERNAME"]
STD_OPTIONS   = "-U%s%%%s %s" % (USER, PASSWORD, SERVER)
SUMMARY       = os.path.join(DATA_DIR, "traffic-sample-very-short.txt")
EXPECTED_NAME = os.path.join(DATA_DIR, "traffic_replay.expected")


@contextmanager
def temp_file(temp_dir):
    try:
        tf   = tempfile.NamedTemporaryFile(dir=temp_dir)
        name = tf.name
        tf.close()
        yield name
    finally:
        if os.path.exists(name):
            os.remove(name)


class TrafficLearnerTests(BlackboxTestCase):

    def tearDown(self):
        options = "--clean-up"
        command  = "%s %s %s" % (SCRIPT, options, STD_OPTIONS)
        self.check_run(command)

    def test_generate_users_only(self):
        """Ensure the generate users only option functions correctly
           """
        options = ("--generate-users-only --number-of-users 20 "
                   "--number-of-groups 5 --average-groups-per-user 2")
        command  = "%s %s %s %s %s" % (
            SCRIPT, SUMMARY, options, FIXED, STD_OPTIONS)
        self.check_run(command)

    def test_summary_generation(self):
        """Ensure a summary file is generated and the contents are correct"""

        with temp_file(self.tempdir) as output:
            options  = "--traffic-summary %s " % (output)
            command  = "%s %s %s %s %s" % (
                SCRIPT, SUMMARY, options, FIXED, STD_OPTIONS)
            self.check_run(command)
            expected = (open(EXPECTED_NAME).readlines())
            actual = open(output).readlines()
            self.assertEquals(expected, actual)

    def test_summary_replay(self):
        """Ensure a summary file can be replayed against a DC
           """

        command  = "%s %s %s %s" % (SCRIPT, SUMMARY, FIXED, STD_OPTIONS)
        self.check_run(command)

    def test_summary_replay_no_fixed(self):
        """Ensure a summary file with no fixed password fails
           """

        command  = "%s %s %s" % (SCRIPT, SUMMARY, STD_OPTIONS)
        self.check_exit_code(command, 1)

    def test_model_replay(self):
        """Ensure a model can be replayed against a DC
           """

        model   = "testdata/traffic-sample-very-short.model"
        command = "%s %s-D 5 %s %s" % (SCRIPT, model, FIXED, STD_OPTIONS)
        self.check_run(command)

    def test_generate_users_only_no_password(self):
        """Ensure the generate users only fails if no fixed_password supplied"
           """
        options = ("--generate-users-only --number-of-users 20 "
                   "--number-of-groups 5 --average-groups-per-user 2")
        summary  = "testdata/traffic-sample-very-short.txt"
        command  = "%s %s %s %s" % (SCRIPT, summary, options, STD_OPTIONS)
        self.check_exit_code(command, 1)
