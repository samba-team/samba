# -*- coding: utf-8 -*-

# Unix SMB/CIFS implementation.
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
#

"""Tests for the python wrapper of the check_password_quality function
"""

from samba import check_password_quality
from samba.tests import TestCase


class PasswordQualityTests(TestCase):
    def test_check_password_quality(self):
        self.assertFalse(check_password_quality(""),
                         "empty password")
        self.assertFalse(check_password_quality("a"),
                         "one char password")
        self.assertFalse(check_password_quality("aaaaaaaaaaaa"),
                         "same char password")
        self.assertFalse(check_password_quality("BLA"),
                         "multiple upcases password")
        self.assertFalse(check_password_quality("123"),
                         "digits only")
        self.assertFalse(check_password_quality("matthiéu"),
                         "not enough high symbols")
        self.assertFalse(check_password_quality("abcdééàçè"),
                         "only lower case")
        self.assertFalse(check_password_quality("abcdééàçè+"),
                         "only lower and symbols")
        self.assertTrue(check_password_quality("abcdééàçè+ढ"),
                        "valid")
        self.assertTrue(check_password_quality("ç+ढ"),
                        "valid")
        self.assertTrue(check_password_quality("A2e"),
                        "valid")
        self.assertTrue(check_password_quality("BA2eLi443"),
                        "valid")
