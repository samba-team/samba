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
    json_file = None
    munge_to_v4 = True
    domain_sid = security.dom_sid("S-1-5-21-2457507606-2709100691-398136650")
    failure_json = None
    success_json = None

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
        i = 0
        for sddl, sdl in data.items():
            i += 1
            name = f'{i:03}-{sddl}'
            if len(name) > 130:
                tag = md5(sddl.encode()).hexdigest()[:10]
                name = f"{name[:100]}+{len(name) - 100}-more-characters-{tag}"
            cls.generate_dynamic_test('test_sddl_vs_sd', name, sddl, sdl)

        if cls.failure_json:
            cls.failures = {}
            cls.failure_file = open(cls.failure_json, 'w')
            cls.addClassCleanup(json.dump, cls.failures, cls.failure_file)
        if cls.success_json:
            cls.successes = {}
            cls.success_file = open(cls.success_json, 'w')
            cls.addClassCleanup(json.dump, cls.successes, cls.success_file)

    def _test_sddl_vs_sd_with_args(self, sddl, sdl):
        sdb_win = bytes(sdl)
        try:
            sd_sam = security.descriptor.from_sddl(sddl, self.domain_sid)
        except (TypeError, ValueError, security.SDDLValueError) as e:
            try:
                sd_win = ndr_unpack(security.descriptor, sdb_win)
                win_ndr_print = ndr_print(sd_win)
            except RuntimeError as e2:
                win_ndr_print = f"not parseable: {e2}"
            if self.failure_json:
                self.failures[sddl] = sdl

            self.fail(f"failed to parse {sddl} into SD: {e}")

        try:
            sdb_sam = ndr_pack(sd_sam)
        except RuntimeError as e:
            if self.failure_json:
                self.failures[sddl] = sdl
            self.fail(f"failed to pack samba SD from {sddl} into bytes: {e}\n"
                      f"{ndr_print(sd_sam)}")

        try:
            sd_win = ndr_unpack(security.descriptor, sdb_win)
        except RuntimeError as e:
            if self.failure_json:
                self.failures[sddl] = sdl
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
            if self.failure_json:
                self.failures[sddl] = sdl
            self.fail(f"Descriptors differ for {sddl}")

        if self.success_json:
            self.successes[sddl] = sdl


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


@DynamicTestCase
class SDDLvsDescriptorOverSizeAcls(SDDLvsDescriptorBase):
    """These are ordinary ACLs that contain duplicate ACEs (e.g.
    'D:P(D;;;;;MP)(D;;;;;MP)(D;;;;;MP)(D;;;;;MP)'). Due to a
    peculiarity in Windows, the ACL structures generated have extra
    trailing zero bytes. Due to a peculiarity in the way Samba reads
    an ACL (namely, it assumes an ACL will be just big enough for its
    ACEs), these cannot currently be parsed by Samba.
    """
    json_file = TEST_DIR / 'oversize-acls.json'


@DynamicTestCase
class SDDLvsDescriptorShortConditionalAndResourceAceSuccesses(SDDLvsDescriptorBase):
    """These contain conditional ACEs or resource attribute aces, the SDDL
    is less than 1000 characters long, and success is expected.
    """
    json_file = TEST_DIR / 'short-conditional-and-resource-aces-successes.json.gz'


@DynamicTestCase
class SDDLvsDescriptorShortConditionalAndResourceAcesTxIntegers(SDDLvsDescriptorBase):
    """These contain resource attribute aces in the form

          (RA;;;;;WD;("foo",TX,0x0,0077,00,...))

    where the numbers after the 0x0 flags like "0077" are interpreted
    by Windows as if they are octet strings. This is not documented
    and not supported by Samba.
    """
    json_file = TEST_DIR / 'short-conditional-and-resource-aces-tx-int.json.gz'


@DynamicTestCase
class SDDLvsDescriptorShortOrdinaryAclsNoMungeV4(SDDLvsDescriptorBase):
    """These ones have revision 2 ACLs (NT4), but Samba's SDDL only writes
    revision 4 ACLs (which are otherwise identical).
    """
    munge_to_v4 = False
    json_file = TEST_DIR / 'short-ordinary-acls-v2.json.gz'


@DynamicTestCase
class SDDLvsDescriptorCollectedConditionalAces(SDDLvsDescriptorBase):
    """Some conditional ACE strings that have collected up.
    """
    json_file = TEST_DIR / 'conditional_aces.txt.json'
