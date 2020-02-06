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

"""Blackbox tests for traffic_leaner"""

import os
import json
import tempfile
from samba.emulate import traffic

from samba.tests import BlackboxTestCase

LEARNER  = "script/traffic_learner"
DATA_DIR = "python/samba/tests/blackbox/testdata"


class TrafficLearnerTests(BlackboxTestCase):

    def test_no_output_file(self):
        """Run the script with no output file specified. Should fail."""
        self.check_exit_code(LEARNER, 1)

    def test_model_generation(self):
        """Ensure a model is generated from a summary file and it is
           correct"""

        with self.mktemp() as output:
            summary = os.path.join(DATA_DIR, "traffic-sample-very-short.txt")
            command = "%s %s --out %s" % (LEARNER, summary, output)
            self.check_run(command)

            expected_fn = os.path.join(DATA_DIR, "traffic_learner.expected")
            expected = traffic.TrafficModel()
            f=open(expected_fn)
            expected.load(f)
            f.close()

            f=open(output)
            actual = traffic.TrafficModel()
            actual.load(f)
            f.close()

            actual_ngrams = {k: sorted(v) for k, v in actual.ngrams.items()}
            expected_ngrams = {k: sorted(v) for k, v in expected.ngrams.items()}

            self.assertEqual(expected_ngrams, actual_ngrams)

            actual_details = {k: sorted(v) for k, v in actual.query_details.items()}
            expected_details = {k: sorted(v) for k, v in expected.query_details.items()}
            self.assertEqual(expected_details, actual_details)
            self.assertEqual(expected.cumulative_duration, actual.cumulative_duration)
            self.assertEqual(expected.packet_rate, actual.packet_rate)

            with open(expected_fn) as f1, open(output) as f2:
                expected_json = json.load(f1)
                actual_json = json.load(f2)
                self.assertEqual(expected_json, actual_json)
