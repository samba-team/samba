# Unix SMB/CIFS implementation.
# Copyright © Catalyst IT 2023
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
"""Fine-grained control over conditional ACE contents.

This deliberately allows you to do broken things that SDDL doesn't.

- token sequences that make no real sense
- sequences that make sense which SDDL can't encode
- strings that aren't proper utf-16
- etc.
"""

from samba.tests import DynamicTestCase, TestCase
from samba.tests import conditional_ace_assembler as caa
from samba.tests.token_factory import token as Token
from samba.dcerpc import security
from samba.ndr import ndr_pack
from samba import NTSTATUSError
from samba.ntstatus import NT_STATUS_ACCESS_DENIED
from samba.colour import colourdiff


class ConditionalAceBytesBase(TestCase):
    maxDiff = 0
    @classmethod
    def setUpClass(cls):
        cls.domain_sid = security.dom_sid("S-1-2-3")
        cls.token = Token(sids=['WD', 'AA'],
                          device_claims={"colour": ["orange", "blue"]})

    @classmethod
    def setUpDynamicTestCases(cls):
        for i, row in enumerate(cls.data):
            assembly, sddl, access_desired, name = row
            if name is None:
                name = sddl
            name = f'{i+1:03}-{name}'
            if len(name) > 150:
                name = f"{name[:125]}+{len(name) - 125}-more-characters"

            cls.generate_dynamic_test('test_assembly',
                                      name, assembly, sddl, access_desired)

    def _test_assembly_with_args(self, assembly, sddl_ref, access_desired):
        sd_bytes = caa.assemble(*assembly)
        if sddl_ref is None:
            raise ValueError("for this test we need reference SDDL")

        sddl_ref_full = f'D:(XA;;;;;WD;{sddl_ref})'
        sd_ref = security.descriptor.from_sddl(sddl_ref_full, self.domain_sid)
        sd_ref_bytes = ndr_pack(sd_ref)
        header, artx, conditions = sd_ref_bytes.partition(b'artx')
        ref_bytes = artx + conditions
        print(colourdiff(sd_bytes, ref_bytes))

        self.assertEqual(sd_bytes, ref_bytes)

        if access_desired is not None:
            try:
                granted = security.access_check(sd, self.token, access_desired)
            except NTSTATUSError as e:
                if e.args[0] != NT_STATUS_ACCESS_DENIED:
                    raise
                if self.allow:
                    self.fail(f"{assembly}: access was denied")
                    self.assertEqual(granted, access_desired)

            else:
                if not self.allow:
                    self.fail(f"{assembly}: unexpected access")

@DynamicTestCase
class ConditionalAceAssemblySDDL(ConditionalAceBytesBase):
    allow = True
    data = [
        ((caa.LocalAttr("x"), 41, caa.EQUAL,
          caa.LocalAttr("x"), caa.DeviceAttr("x"), caa.GREATER_THAN,
          caa.AND),
         "((x == 41) && (x > @device.x))",
         None, None),
    ]
