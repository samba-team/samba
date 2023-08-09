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

"""These tests compare Windows security descriptors with Samba
descriptors derived from the same SDDL.

They use json and json.gz files in libcli/security/tests/data.
"""

from samba.dcerpc import security
from samba.ndr import ndr_pack, ndr_unpack, ndr_print
from samba.tests import TestCase, DynamicTestCase
from samba.colour import colourdiff
from hashlib import md5
import gzip

import json
from pathlib import Path

TEST_DIR = Path(__name__).parent.parent.parent / 'libcli/security/tests/data'


class SDDLvsDescriptorBase(TestCase):
    """These tests have no explicit cases and no inline data. The actual
    data is kept in JSON files in libcli/security/tests/data, so that
    it easy to share those files with Windows. To control what tests
    are run, set the `json_file` attribute in subclasses, and/or add a
    filter_test_cases class method.
    """
    maxDiff = 10000
    json_file = TEST_DIR / 'conditional_aces.txt.json'
    munge_to_v4 = True
    domain_sid = security.dom_sid("S-1-5-21-2457507606-2709100691-398136650")

    @classmethod
    def filter_test_cases(cls, data):
        """Filter out some cases before running the tests.
        Like this, for example:
            return {k:v for k, v in data.items() if len(k) < 200 and
                    '(D;;;;;MP)(D;;;;;MP)(D;;;;;MP)' in k}
        """
        return data

    @classmethod
    def setUpDynamicTestCases(cls):
        try:
            with gzip.open(cls.json_file, 'rt') as f:
                data = json.load(f)
        except Exception:
            with open(cls.json_file) as f:
                data = json.load(f)

        data = cls.filter_test_cases(data)

        for sddl, sdl in data.items():
            name = sddl
            if len(name) > 130:
                tag = md5(sddl.encode()).hexdigest()[:10]
                name = f"{name[:100]}+{len(name) - 100}-more-characters-{tag}"
            cls.generate_dynamic_test('test_sddl_vs_sd', name, sddl, sdl)

    def _test_sddl_vs_sd_with_args(self, sddl, sdl):
        sdb_win = bytes(sdl)
        try:
            sd_sam = security.descriptor.from_sddl(sddl, self.domain_sid)
        except (TypeError, ValueError) as e:
            self.fail(f"failed to parse {sddl} into SD: {e}")

        try:
            sdb_sam = ndr_pack(sd_sam)
        except RuntimeError as e:
            self.fail(f"failed to pack samba SD from {sddl} into bytes: {e}\n"
                      f"{ndr_print(sd_sam)}")

        try:
            sd_win = ndr_unpack(security.descriptor, sdb_win)
        except RuntimeError as e:
            self.fail(f"could not unpack windows descriptor for {sddl}: {e}")

        if self.munge_to_v4:
            # Force the ACL revisions to match Samba. Windows seems to
            # use the lowest possible revision, while Samba uses
            # ACL_REVISION_DS when generating from SDDL. The _DS
            # version allows more ACE types, but is otherwise the same.
            #
            # MS-DTYP 2.4.5 ACL:
            #
            # ACL_REVISION 0x02
            #
            # When set to 0x02, only AceTypes 0x00, 0x01,
            # 0x02, 0x03, 0x11, 0x12, and 0x13 can be present in the ACL.
            # An AceType of 0x11 is used for SACLs but not for DACLs. For
            # more information about ACE types, see section 2.4.4.1.
            #
            # ACL_REVISION_DS 0x04
            #
            # When set to 0x04, AceTypes 0x05, 0x06, 0x07, 0x08, and 0x11
            # are allowed. ACLs of revision 0x04 are applicable only to
            # directory service objects. An AceType of 0x11 is used for
            # SACLs but not for DACLs.
            #
            # 5, 6, 7, 8 are object ACES.
            if sd_win.dacl:
                sd_win.dacl.revision = 4
            if sd_win.sacl:
                sd_win.sacl.revision = 4

        if (sd_win != sd_sam):
            self.fail(f"Descriptors differ for {sddl}")


@DynamicTestCase
class SDDLvsDescriptorShortOrdinaryAcls(SDDLvsDescriptorBase):
    """These are not conditional ACEs or resource attribute aces, the SDDL
    is less than 1000 characters long, and success is expected.
    """
    json_file = TEST_DIR / 'short-ordinary-acls.json.gz'


@DynamicTestCase
class SDDLvsDescriptorRegistryObjectRights(SDDLvsDescriptorBase):
    """We'll fail these because we don't recognise 'KA' and related object
    rights strings that are used for registry objects."""
    json_file = TEST_DIR / 'registry-object-rights.json'
