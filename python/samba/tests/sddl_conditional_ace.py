# Unix SMB/CIFS implementation.
# Copyright (C) Volker Lendecke <vl@samba.org> 2021
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

"""Tests for SDDL conditional ACES."""

from .sddl import SddlDecodeEncodeBase
from samba.tests import DynamicTestCase
from pathlib import Path

STRINGS_DIR = Path(__name__).parent.parent.parent / 'libcli/security/tests/data'

@DynamicTestCase
class SddlConditionalAces(SddlDecodeEncodeBase):
    strings_dir = STRINGS_DIR
    name = "conditional_aces"
    should_succeed = True


@DynamicTestCase
class SddlConditionalAcesShouldFail(SddlDecodeEncodeBase):
    strings_dir = STRINGS_DIR
    name = "conditional_aces_should_fail"
    should_succeed = False


@DynamicTestCase
class SddlConditionalAcesWindowsOnly(SddlDecodeEncodeBase):
    strings_dir = STRINGS_DIR
    name = "conditional_aces_windows_only"
    should_succeed = False


@DynamicTestCase
class SddlConditionalAcesCaseInsensitive(SddlDecodeEncodeBase):
    strings_dir = STRINGS_DIR
    name = "conditional_aces_case_insensitive"
    should_succeed = True
    case_insensitive = True
