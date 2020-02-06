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

"""Blackbox tests for traffic_summary"""

import os
import subprocess
import tempfile

from samba.tests import BlackboxTestCase

SCRIPT      = "script/traffic_summary.pl"
DATA_DIR    = "python/samba/tests/blackbox/testdata"
INPUT       = os.path.join(DATA_DIR, "traffic_summary.pdml")
EXPECTED_FN = os.path.join(DATA_DIR, "traffic_summary.expected")


class TrafficSummaryTests(BlackboxTestCase):

    def check_twig(self):
        """Check that perl XML::Twig module is installed.
        Traffic summary depends on this module being installed.
        """
        line = "perl -MXML::Twig -e 1"
        p = subprocess.Popen(line, shell=True)
        retcode = p.wait()
        return (retcode == 0)

    def test_traffic_summary(self):
        if not self.check_twig():
            self.skipTest("Perl module XML::Twig is not installed")

        with self.mktemp() as output:
            command = "%s %s >%s" % (SCRIPT, INPUT, output)
            print(command)
            self.check_run(command)
            expected = open(EXPECTED_FN).readlines()
            actual = open(output).readlines()
            self.assertEqual(expected, actual)
