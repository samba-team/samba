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

import os
import tempfile

from samba.tests import BlackboxTestCase

DATA_DIR      = "python/samba/tests/blackbox/testdata"
SCRIPT        = "script/traffic_replay"
FIXED         = "--fixed-password=trafficreplay01%"
SERVER        = os.environ["SERVER"]
PASSWORD      = os.environ["PASSWORD"]
USER          = os.environ["USERNAME"]
CREDS         = "-U%s%%%s" % (USER, PASSWORD)
MODEL         = os.path.join(DATA_DIR, "traffic-sample-very-short.model")
EXPECTED_OUTPUT = os.path.join(DATA_DIR, "traffic_replay-%s.expected")


class TrafficLearnerTests(BlackboxTestCase):

    def tearDown(self):
        options = "--clean-up"
        command = "%s %s %s %s" % (SCRIPT, options, CREDS, SERVER)
        self.check_run(command)

    def test_generate_users_only(self):
        """Ensure the generate users only option functions correctly
           """
        options = ("--generate-users-only --number-of-users 20 "
                   "--number-of-groups 5 --average-groups-per-user 2")
        command = "%s %s %s %s %s" % (
            SCRIPT, options, FIXED, CREDS, SERVER)
        self.check_run(command)
        command = "%s %s %s %s %s %s" % (
            SCRIPT, MODEL, options, FIXED, CREDS, SERVER)
        self.check_run(command)

    def test_summary_generation(self):
        """Ensure a summary file is generated and the contents are correct"""

        for i, opts in enumerate((["--random-seed=3"],
                                  ["--random-seed=4"],
                                  ["--random-seed=3",
                                   "--conversation-persistence=0.5"],
                                  ["--random-seed=3",
                                   "--old-scale",
                                   "--conversation-persistence=0.95"],
                                  )):
            with self.mktemp() as output:
                command = ([SCRIPT, MODEL,
                            "--traffic-summary", output,
                            "-D1", "-S0.1"] +
                           opts +
                           [FIXED, CREDS, SERVER])
                self.check_run(command)
                expected = open(EXPECTED_OUTPUT % i).read()
                actual = open(output).read()
                self.assertStringsEqual(expected, actual)

    def test_summary_replay_no_fixed(self):
        """Ensure a summary file with no fixed password fails
           """
        command = [SCRIPT, MODEL, CREDS, SERVER]
        self.check_exit_code(command, 1)

    def test_model_replay(self):
        """Ensure a model can be replayed against a DC
           """
        command = [SCRIPT, MODEL,
                   FIXED,
                   '-D2', '-S0.1',
                   CREDS, SERVER]
        self.check_run(command)

    def test_generate_users_only_no_password(self):
        """Ensure the generate users only fails if no fixed_password supplied"
           """
        options = ("--generate-users-only --number-of-users 20 "
                   "--number-of-groups 5 --average-groups-per-user 2")
        command  = "%s %s %s %s" % (SCRIPT, options, CREDS, SERVER)
        self.check_exit_code(command, 1)
        command = "%s %s %s %s %s" % (SCRIPT, MODEL, options, CREDS, SERVER)
        self.check_exit_code(command, 1)
