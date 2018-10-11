# -*- coding: utf-8 -*-
#
# Common functionality for all password change tests
#
# Copyright (C) Andrew Bartlett <abartlet@samba.org> 2018
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
#

import samba.tests


class PasswordCommon:

    @staticmethod
    def allow_password_changes(testcase, samdb):
        """Updates the DC to allow password changes during the current test"""

        # Get the old "dSHeuristics" if it was set
        dsheuristics = samdb.get_dsheuristics()

        # Reset the "dSHeuristics" as they were before
        testcase.addCleanup(samdb.set_dsheuristics, dsheuristics)

        # Set the "dSHeuristics" to activate the correct "userPassword" behaviour
        samdb.set_dsheuristics("000000001")

        # Get the old "minPwdAge"
        minPwdAge = samdb.get_minPwdAge()

        # Reset the "minPwdAge" as it was before
        testcase.addCleanup(samdb.set_minPwdAge, minPwdAge)

        # Set it temporarily to "0"
        samdb.set_minPwdAge("0")


class PasswordTestCase(samba.tests.TestCase):

    # this requires that an LDB connection has already been setup (so is not
    # part of the inherited setUp())
    def allow_password_changes(self, samdb=None):
        """Updates the DC to allow password changes during the current test"""

        if samdb is None:
            samdb = self.ldb

        PasswordCommon.allow_password_changes(self, samdb)
