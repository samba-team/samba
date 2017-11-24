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

from contextlib import contextmanager
import os
import tempfile

from samba.tests import BlackboxTestCase

LEARNER  = "script/traffic_learner"
DATA_DIR = "python/samba/tests/blackbox/testdata"


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

    def test_no_output_file(self):
        """Run the script with no output file specified"""
        expected = ("No output file was specified to write the model to.\n"
                    "Please specify a filename using the --out option.\n")
        actual = self.check_output(LEARNER)
        self.assertEquals(expected, actual)

    def test_model_generation(self):
        """Ensure a model is generated from a summary file and it is
           correct"""

        with temp_file(self.tempdir) as output:
            summary  = os.path.join(DATA_DIR, "traffic-sample-very-short.txt")
            command  = "%s %s --out %s" % (LEARNER, summary, output)
            self.check_run(command)
            expected_fn = os.path.join(DATA_DIR, "traffic_learner.expected")
            expected = open(expected_fn).readlines()
            actual = open(output).readlines()
            self.assertEquals(expected, actual)
