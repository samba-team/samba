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

"""Tests for samba.dcerpc.security"""

from samba.dcerpc import security
from samba.tests import TestCase, DynamicTestCase
from samba.colour import c_RED, c_GREEN


class SddlDecodeEncodeBase(TestCase):
    maxDiff = 10000
    @classmethod
    def setUpDynamicTestCases(cls):
        cls.domain_sid = security.dom_sid("S-1-2-3-4")
        seen = set()
        for pair in cls.strings:
            if isinstance(pair, str):
                pair = (pair, pair)

            if pair in seen:
                print(f"seen {pair} after {len(seen)}")
            seen.add(pair)
            sddl, canonical = pair

            name = sddl
            if len(name) > 120:
                name = f"{name[:100]}+{len(name) - 100}-more-characters"

            if cls.should_succeed:
                cls.generate_dynamic_test('test_sddl', name, sddl, canonical)
            else:
                cls.generate_dynamic_test('test_sddl_should_fail',
                                          name, sddl, canonical)

    def _test_sddl_with_args(self, s, canonical):
        try:
            sd1 = security.descriptor.from_sddl(s, self.domain_sid)
        except (TypeError, ValueError) as e:
            self.fail(f"raised {e}")

        sddl = sd1.as_sddl(self.domain_sid)
        sd2 = security.descriptor.from_sddl(sddl, self.domain_sid)
        self.assertEqual(sd1, sd2)
        if '0X' in canonical.upper():
            # let's chill out about case in hex numbers.
            self.assertEqual(sddl.upper(), canonical.upper())
        else:
            self.assertEqual(sddl, canonical)

    def _test_sddl_should_fail_with_args(self, s, canonical):
        with self.assertRaises(ValueError):
            sd = security.descriptor.from_sddl(s, self.domain_sid)
            print(sd.as_sddl(self.domain_sid))

    def _test_write_test_strings(self):
        """The file libcli/security/tests/windows/windows-sddl-tests.c, if
        compiled on Windows under Cygwin or MSYS64, can run SDDL
        parsing tests using the Windows API. This allows us to run the
        same tests here and on Windows, to ensure we get the same
        results.

        That test program can read examples in a bespoke text format,
        in which each line looks like:

           original sddl -> returned sddl

        That is, the separator consists of the 4 bytes " -> ".
        Multi-line examples are not possible.

        If you rename this method to start with 'test_' and run these
        tests, the examples here will be written in this format in
        files in /tmp. If you then copy them to Windows and run them
        in your POSIX-y shell with

          windows-sddl-tests -i path/to/*.txt

        the results on Windows will be shown.
        """
        if getattr(self, 'name', None) is None:
            print(f"not reading changes in {c_RED(self)} with no name "
                  "(it is probably the base class)")
            return

        name = f"/tmp/{self.name}.txt"
        with open(name, 'w') as f:
            for p in self.strings:
                if isinstance(p, str):
                    p = (p, p)
                print(f"{p[0]} -> {p[1]}", file=f)

    def _test_00_read_test_strings(self):
        """This is a complementary non-test to _test_write_test_strings, which
        writes these tests in a format usable on Windows. In this
        case, if the method is enabled as a test by removing the
        leading '_', examples will be read. Unlike the write function,
        this reads from 'libcli/security/tests/windows/' in the source
        tree, and will replace the examples here with the ones there.
        Along the way it allerts you to the changes.

        If run, this test should run first, hence the 00 in its name.
        """
        if getattr(self, 'name', None) is None:
            print(f"not reading changes in {c_RED(self)} with no name "
                  "(it is probably the base class)")
            return

        from pathlib import Path
        p = Path(__file__).parent
        while not (p / 'libcli').is_dir():
            q = p.parent
            self.assertNotEqual(p, q)
            p = q

        filename = p / f"libcli/security/tests/windows/{self.name}.txt"

        old_pairs = set()
        for s in self.strings:
            if isinstance(s, str):
                s = (s, s)
            old_pairs.add(s)

        new_pairs = set()
        with open(filename) as f:
            for line in f:
                o, _, c = line.rstrip().partition(' -> ')
                new_pairs.add((o, c))

        if old_pairs == new_pairs:
            print(f"no change in {c_GREEN(self.name)}")
            # nothing to do
            return

        print(f"change in {c_RED(self.name)}")
        print("added:")
        for x in sorted(new_pairs - old_pairs):
            print(x)
        print("removed:")
        for x in sorted(old_pairs - new_pairs):
            print(x)

        self.strings[:] = sorted(new_pairs)
        self.fail("test cases out of sync")

@DynamicTestCase
class SddlNonCanonical(SddlDecodeEncodeBase):
    """These ones are transformed in the round trip into a preferred
    synonym. For example "S:D:" is accepted as input, but only "D:S:
    will be output.
    """
    name = "non_canonical"
    should_succeed = True
    strings = [
        # format is (original, canonical); after passing through an SD
        # object, the SDDL will look like the canonical version.
        ("D:(A;;CC;;;BA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)",
         "D:(A;;CC;;;BA)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)(A;;LCRPLORC;;;AU)"),

        (("D:(A;;RP;;;WD)"
          "(OA;;CR;1131f6aa-9c07-11d1-f79f-00c04fc2dcd2;;ED)"
          "(OA;;CR;1131f6ab-9c07-11d1-f79f-00c04fc2dcd2;;ED)"
          "(OA;;CR;1131f6ac-9c07-11d1-f79f-00c04fc2dcd2;;ED)"
          "(OA;;CR;1131f6aa-9c07-11d1-f79f-00c04fc2dcd2;;BA)"
          "(OA;;CR;1131f6ab-9c07-11d1-f79f-00c04fc2dcd2;;BA)"
          "(OA;;CR;1131f6ac-9c07-11d1-f79f-00c04fc2dcd2;;BA)"
          "(A;;RPLCLORC;;;AU)"
          "(A;;RPWPCRLCLOCCRCWDWOSW;;;BO)"
          "(A;CI;RPWPCRLCLOCCRCWDWOSDSW;;;BA)"
          "(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;SY)"
          "(A;CI;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;ES)"
          "(A;CI;LC;;;RU)"
          "(OA;CIIO;RP;037088f8-0ae1-11d2-b422-00a0c968f939;bf967aba-0de6-11d0-a285-00aa003049e2;RU)"
          "(OA;CIIO;RP;59ba2f42-79a2-11d0-9020-00c04fc2d3cf;bf967aba-0de6-11d0-a285-00aa003049e2;RU)"
          "(OA;CIIO;RP;bc0ac240-79a9-11d0-9020-00c04fc2d4cf;bf967aba-0de6-11d0-a285-00aa003049e2;RU)"
          "(OA;CIIO;RP;4c164200-20c0-11d0-a768-00aa006e0529;bf967aba-0de6-11d0-a285-00aa003049e2;RU)"
          "(OA;CIIO;RP;5f202010-79a5-11d0-9020-00c04fc2d4cf;bf967aba-0de6-11d0-a285-00aa003049e2;RU)"
          "(OA;;RP;c7407360-20bf-11d0-a768-00aa006e0529;;RU)"
          "(OA;CIIO;RPLCLORC;;bf967a9c-0de6-11d0-a285-00aa003049e2;RU)"
          "(A;;RPRC;;;RU)"
          "(OA;CIIO;RPLCLORC;;bf967aba-0de6-11d0-a285-00aa003049e2;RU)"
          "(A;;LCRPLORC;;;ED)"
          "(OA;CIIO;RP;037088f8-0ae1-11d2-b422-00a0c968f939;4828CC14-1437-45bc-9B07-AD6F015E5F28;RU)"
          "(OA;CIIO;RP;59ba2f42-79a2-11d0-9020-00c04fc2d3cf;4828CC14-1437-45bc-9B07-AD6F015E5F28;RU)"
          "(OA;CIIO;RP;bc0ac240-79a9-11d0-9020-00c04fc2d4cf;4828CC14-1437-45bc-9B07-AD6F015E5F28;RU)"
          "(OA;CIIO;RP;4c164200-20c0-11d0-a768-00aa006e0529;4828CC14-1437-45bc-9B07-AD6F015E5F28;RU)"
          "(OA;CIIO;RP;5f202010-79a5-11d0-9020-00c04fc2d4cf;4828CC14-1437-45bc-9B07-AD6F015E5F28;RU)"
          "(OA;CIIO;RPLCLORC;;4828CC14-1437-45bc-9B07-AD6F015E5F28;RU)"
          "(OA;;RP;b8119fd0-04f6-4762-ab7a-4986c76b3f9a;;RU)"
          "(OA;;RP;b8119fd0-04f6-4762-ab7a-4986c76b3f9a;;AU)"
          "(OA;CIIO;RP;b7c69e6d-2cc7-11d2-854e-00a0c983f608;bf967aba-0de6-11d0-a285-00aa003049e2;ED)"
          "(OA;CIIO;RP;b7c69e6d-2cc7-11d2-854e-00a0c983f608;bf967a9c-0de6-11d0-a285-00aa003049e2;ED)"
          "(OA;CIIO;RP;b7c69e6d-2cc7-11d2-854e-00a0c983f608;bf967a86-0de6-11d0-a285-00aa003049e2;ED)"
          "(OA;;CR;1131f6ad-9c07-11d1-f79f-00c04fc2dcd2;;NO)"
          "(OA;;CR;1131f6ad-9c07-11d1-f79f-00c04fc2dcd2;;BA)"
          "(OA;;CR;e2a36dc9-ae17-47c3-b58b-be34c55ba633;;SU)"
          "(OA;;CR;280f369c-67c7-438e-ae98-1d46f3c6f541;;AU)"
          "(OA;;CR;ccc2dc7d-a6ad-4a7a-8846-c04e3cc53501;;AU)"
          "(OA;;CR;05c74c5e-4deb-43b4-bd9f-86664c2a7fd5;;AU)"
          "S:(AU;SA;WDWOWP;;;WD)"),
         ("D:(A;;RP;;;WD)"
          "(OA;;CR;1131f6aa-9c07-11d1-f79f-00c04fc2dcd2;;ED)"
          "(OA;;CR;1131f6ab-9c07-11d1-f79f-00c04fc2dcd2;;ED)"
          "(OA;;CR;1131f6ac-9c07-11d1-f79f-00c04fc2dcd2;;ED)"
          "(OA;;CR;1131f6aa-9c07-11d1-f79f-00c04fc2dcd2;;BA)"
          "(OA;;CR;1131f6ab-9c07-11d1-f79f-00c04fc2dcd2;;BA)"
          "(OA;;CR;1131f6ac-9c07-11d1-f79f-00c04fc2dcd2;;BA)"
          "(A;;LCRPLORC;;;AU)"
          "(A;;CCLCSWRPWPLOCRRCWDWO;;;BO)"
          "(A;CI;CCLCSWRPWPLOCRSDRCWDWO;;;BA)"
          "(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)"
          "(A;CI;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;ES)"
          "(A;CI;LC;;;RU)"
          "(OA;CIIO;RP;037088f8-0ae1-11d2-b422-00a0c968f939;bf967aba-0de6-11d0-a285-00aa003049e2;RU)"
          "(OA;CIIO;RP;59ba2f42-79a2-11d0-9020-00c04fc2d3cf;bf967aba-0de6-11d0-a285-00aa003049e2;RU)"
          "(OA;CIIO;RP;bc0ac240-79a9-11d0-9020-00c04fc2d4cf;bf967aba-0de6-11d0-a285-00aa003049e2;RU)"
          "(OA;CIIO;RP;4c164200-20c0-11d0-a768-00aa006e0529;bf967aba-0de6-11d0-a285-00aa003049e2;RU)"
          "(OA;CIIO;RP;5f202010-79a5-11d0-9020-00c04fc2d4cf;bf967aba-0de6-11d0-a285-00aa003049e2;RU)"
          "(OA;;RP;c7407360-20bf-11d0-a768-00aa006e0529;;RU)"
          "(OA;CIIO;LCRPLORC;;bf967a9c-0de6-11d0-a285-00aa003049e2;RU)"
          "(A;;RPRC;;;RU)"
          "(OA;CIIO;LCRPLORC;;bf967aba-0de6-11d0-a285-00aa003049e2;RU)"
          "(A;;LCRPLORC;;;ED)"
          "(OA;CIIO;RP;037088f8-0ae1-11d2-b422-00a0c968f939;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)"
          "(OA;CIIO;RP;59ba2f42-79a2-11d0-9020-00c04fc2d3cf;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)"
          "(OA;CIIO;RP;bc0ac240-79a9-11d0-9020-00c04fc2d4cf;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)"
          "(OA;CIIO;RP;4c164200-20c0-11d0-a768-00aa006e0529;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)"
          "(OA;CIIO;RP;5f202010-79a5-11d0-9020-00c04fc2d4cf;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)"
          "(OA;CIIO;LCRPLORC;;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)"
          "(OA;;RP;b8119fd0-04f6-4762-ab7a-4986c76b3f9a;;RU)"
          "(OA;;RP;b8119fd0-04f6-4762-ab7a-4986c76b3f9a;;AU)"
          "(OA;CIIO;RP;b7c69e6d-2cc7-11d2-854e-00a0c983f608;bf967aba-0de6-11d0-a285-00aa003049e2;ED)"
          "(OA;CIIO;RP;b7c69e6d-2cc7-11d2-854e-00a0c983f608;bf967a9c-0de6-11d0-a285-00aa003049e2;ED)"
          "(OA;CIIO;RP;b7c69e6d-2cc7-11d2-854e-00a0c983f608;bf967a86-0de6-11d0-a285-00aa003049e2;ED)"
          "(OA;;CR;1131f6ad-9c07-11d1-f79f-00c04fc2dcd2;;NO)"
          "(OA;;CR;1131f6ad-9c07-11d1-f79f-00c04fc2dcd2;;BA)"
          "(OA;;CR;e2a36dc9-ae17-47c3-b58b-be34c55ba633;;SU)"
          "(OA;;CR;280f369c-67c7-438e-ae98-1d46f3c6f541;;AU)"
          "(OA;;CR;ccc2dc7d-a6ad-4a7a-8846-c04e3cc53501;;AU)"
          "(OA;;CR;05c74c5e-4deb-43b4-bd9f-86664c2a7fd5;;AU)"
          "S:(AU;SA;WPWDWO;;;WD)")),

         (("D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;BO)"
           "(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;AO)"
           "(A;;WPRPCRCCDCLCLORCWOWDSDDTSW;;;SY)"
           "(A;;RPCRLCLORCSDDT;;;CO)"
           "(OA;;WP;4c164200-20c0-11d0-a768-00aa006e0529;;CO)"
           "(A;;RPLCLORC;;;AU)"
           "(OA;;CR;ab721a53-1e2f-11d0-9819-00aa0040529b;;WD)"
           "(A;;CCDC;;;PS)"
           "(OA;;CCDC;bf967aa8-0de6-11d0-a285-00aa003049e2;;PO)"
           "(OA;;RPWP;bf967a7f-0de6-11d0-a285-00aa003049e2;;SY)"
           "(OA;;SW;f3a64788-5306-11d1-a9c5-0000f80367c1;;PS)"
           "(OA;;RPWP;77B5B886-944A-11d1-AEBD-0000F80367C1;;PS)"
           "(OA;;SW;72e39547-7b18-11d1-adef-00c04fd8d5cd;;PS)"
           "(OA;;SW;72e39547-7b18-11d1-adef-00c04fd8d5cd;;CO)"
           "(OA;;SW;f3a64788-5306-11d1-a9c5-0000f80367c1;;CO)"
           "(OA;;WP;3e0abfd0-126a-11d0-a060-00aa006c33ed;bf967a86-0de6-11d0-a285-00aa003049e2;CO)"
           "(OA;;WP;5f202010-79a5-11d0-9020-00c04fc2d4cf;bf967a86-0de6-11d0-a285-00aa003049e2;CO)"
           "(OA;;WP;bf967950-0de6-11d0-a285-00aa003049e2;bf967a86-0de6-11d0-a285-00aa003049e2;CO)"
           "(OA;;WP;bf967953-0de6-11d0-a285-00aa003049e2;bf967a86-0de6-11d0-a285-00aa003049e2;CO)"
           "(OA;;RP;46a9b11d-60ae-405a-b7e8-ff8a58d456d2;;S-1-5-32-560)"),
          ("D:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BO)"
           "(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;AO)"
           "(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)"
           "(A;;LCRPDTLOCRSDRC;;;CO)"
           "(OA;;WP;4c164200-20c0-11d0-a768-00aa006e0529;;CO)"
           "(A;;LCRPLORC;;;AU)"
           "(OA;;CR;ab721a53-1e2f-11d0-9819-00aa0040529b;;WD)"
           "(A;;CCDC;;;PS)"
           "(OA;;CCDC;bf967aa8-0de6-11d0-a285-00aa003049e2;;PO)"
           "(OA;;RPWP;bf967a7f-0de6-11d0-a285-00aa003049e2;;SY)"
           "(OA;;SW;f3a64788-5306-11d1-a9c5-0000f80367c1;;PS)"
           "(OA;;RPWP;77b5b886-944a-11d1-aebd-0000f80367c1;;PS)"
           "(OA;;SW;72e39547-7b18-11d1-adef-00c04fd8d5cd;;PS)"
           "(OA;;SW;72e39547-7b18-11d1-adef-00c04fd8d5cd;;CO)"
           "(OA;;SW;f3a64788-5306-11d1-a9c5-0000f80367c1;;CO)"
           "(OA;;WP;3e0abfd0-126a-11d0-a060-00aa006c33ed;bf967a86-0de6-11d0-a285-00aa003049e2;CO)"
           "(OA;;WP;5f202010-79a5-11d0-9020-00c04fc2d4cf;bf967a86-0de6-11d0-a285-00aa003049e2;CO)"
           "(OA;;WP;bf967950-0de6-11d0-a285-00aa003049e2;bf967a86-0de6-11d0-a285-00aa003049e2;CO)"
           "(OA;;WP;bf967953-0de6-11d0-a285-00aa003049e2;bf967a86-0de6-11d0-a285-00aa003049e2;CO)"
           "(OA;;RP;46a9b11d-60ae-405a-b7e8-ff8a58d456d2;;S-1-5-32-560)")),

         ("D:(A;;RPLCLORC;;;BO)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)",
          "D:(A;;LCRPLORC;;;BO)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)(A;;LCRPLORC;;;AU)"),

        (("D:(A;;WPCRCCDCLCLORCWOWDSDDTSWRP;;;BO)"
          "(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;AO)"
          "(A;;RPWPCRCCDCLCLORCWOWDSDSWDT;;;SY)"
          "(A;;RPCRLCLORCSDDT;;;CO)"
          "(OA;;WP;4c164200-20c0-11d0-a768-00aa006e0529;;CO)"
          "(A;;RPLCLORC;;;AU)"
          "(OA;;CR;ab721a53-1e2f-11d0-9819-00aa0040529b;;WD)"
          "(A;;CCDC;;;PS)"
          "(OA;;CCDC;bf967aa8-0de6-11d0-a285-00aa003049e2;;PO)"
          "(OA;;RPWP;bf967a7f-0de6-11d0-a285-00aa003049e2;;SY)"
          "(OA;;SW;f3a64788-5306-11d1-a9c5-0000f80367c1;;PS)"
          "(OA;;RPWP;77B5B886-944A-11d1-AEBD-0000F80367C1;;PS)"
          "(OA;;SW;72e39547-7b18-11d1-adef-00c04fd8d5cd;;PS)"
          "(OA;;SW;72e39547-7b18-11d1-adef-00c04fd8d5cd;;CO)"
          "(OA;;SW;f3a64788-5306-11d1-a9c5-0000f80367c1;;CO)"
          "(OA;;WP;3e0abfd0-126a-11d0-a060-00aa006c33ed;bf967a86-0de6-11d0-a285-00aa003049e2;CO)"
          "(OA;;WP;5f202010-79a5-11d0-9020-00c04fc2d4cf;bf967a86-0de6-11d0-a285-00aa003049e2;CO)"
          "(OA;;WP;bf967950-0de6-11d0-a285-00aa003049e2;bf967a86-0de6-11d0-a285-00aa003049e2;CO)"
          "(OA;;WP;bf967953-0de6-11d0-a285-00aa003049e2;bf967a86-0de6-11d0-a285-00aa003049e2;CO)"
          "(OA;;RP;46a9b11d-60ae-405a-b7e8-ff8a58d456d2;;SU)"),
         ("D:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BO)"
          "(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;AO)"
          "(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)"
          "(A;;LCRPDTLOCRSDRC;;;CO)"
          "(OA;;WP;4c164200-20c0-11d0-a768-00aa006e0529;;CO)"
          "(A;;LCRPLORC;;;AU)"
          "(OA;;CR;ab721a53-1e2f-11d0-9819-00aa0040529b;;WD)"
          "(A;;CCDC;;;PS)"
          "(OA;;CCDC;bf967aa8-0de6-11d0-a285-00aa003049e2;;PO)"
          "(OA;;RPWP;bf967a7f-0de6-11d0-a285-00aa003049e2;;SY)"
          "(OA;;SW;f3a64788-5306-11d1-a9c5-0000f80367c1;;PS)"
          "(OA;;RPWP;77b5b886-944a-11d1-aebd-0000f80367c1;;PS)"
          "(OA;;SW;72e39547-7b18-11d1-adef-00c04fd8d5cd;;PS)"
          "(OA;;SW;72e39547-7b18-11d1-adef-00c04fd8d5cd;;CO)"
          "(OA;;SW;f3a64788-5306-11d1-a9c5-0000f80367c1;;CO)"
          "(OA;;WP;3e0abfd0-126a-11d0-a060-00aa006c33ed;bf967a86-0de6-11d0-a285-00aa003049e2;CO)"
          "(OA;;WP;5f202010-79a5-11d0-9020-00c04fc2d4cf;bf967a86-0de6-11d0-a285-00aa003049e2;CO)"
          "(OA;;WP;bf967950-0de6-11d0-a285-00aa003049e2;bf967a86-0de6-11d0-a285-00aa003049e2;CO)"
          "(OA;;WP;bf967953-0de6-11d0-a285-00aa003049e2;bf967a86-0de6-11d0-a285-00aa003049e2;CO)"
          "(OA;;RP;46a9b11d-60ae-405a-b7e8-ff8a58d456d2;;SU)")),

        (("D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;BO)"
          "(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)"
          "(A;;RPLCLORC;;;AU)",
          "D:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BO)"
          "(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)"
          "(A;;LCRPLORC;;;AU)")),

        (("D:(A;;;;;BO)"
          "(A;;;;;AO)"
          "(A;;;;;SY)"
          "(A;;RPCRLCLORCSDDT;;;CO)"
          "(OA;;WP;4c164200-20c0-11d0-a768-00aa006e0529;;CO)"
          "(A;;RPLCLORC;;;AU)"
          "(OA;;CR;ab721a53-1e2f-11d0-9819-00aa0040529b;;WD)"
          "(A;;CCDC;;;PS)"
          "(OA;;CCDC;bf967aa8-0de6-11d0-a285-00aa003049e2;;PO)"
          "(OA;;RPWP;bf967a7f-0de6-11d0-a285-00aa003049e2;;SY)"
          "(OA;;SW;f3a64788-5306-11d1-a9c5-0000f80367c1;;PS)"
          "(OA;;RPWP;77B5B886-944A-11d1-AEBD-0000F80367C1;;PS)"
          "(OA;;SW;72e39547-7b18-11d1-adef-00c04fd8d5cd;;PS)"
          "(OA;;SW;72e39547-7b18-11d1-adef-00c04fd8d5cd;;CO)"
          "(OA;;SW;f3a64788-5306-11d1-a9c5-0000f80367c1;;CO)"
          "(OA;;WP;3e0abfd0-126a-11d0-a060-00aa006c33ed;bf967a86-0de6-11d0-a285-00aa003049e2;CO)"
          "(OA;;WP;5f202010-79a5-11d0-9020-00c04fc2d4cf;bf967a86-0de6-11d0-a285-00aa003049e2;CO)"
          "(OA;;WP;bf967950-0de6-11d0-a285-00aa003049e2;bf967a86-0de6-11d0-a285-00aa003049e2;CO)"
          "(OA;;WP;bf967953-0de6-11d0-a285-00aa003049e2;bf967a86-0de6-11d0-a285-00aa003049e2;CO)"
          "(OA;;RP;46a9b11d-60ae-405a-b7e8-ff8a58d456d2;;SU)"),
         ("D:(A;;;;;BO)"
          "(A;;;;;AO)"
          "(A;;;;;SY)"
          "(A;;LCRPDTLOCRSDRC;;;CO)"
          "(OA;;WP;4c164200-20c0-11d0-a768-00aa006e0529;;CO)"
          "(A;;LCRPLORC;;;AU)"
          "(OA;;CR;ab721a53-1e2f-11d0-9819-00aa0040529b;;WD)"
          "(A;;CCDC;;;PS)"
          "(OA;;CCDC;bf967aa8-0de6-11d0-a285-00aa003049e2;;PO)"
          "(OA;;RPWP;bf967a7f-0de6-11d0-a285-00aa003049e2;;SY)"
          "(OA;;SW;f3a64788-5306-11d1-a9c5-0000f80367c1;;PS)"
          "(OA;;RPWP;77b5b886-944a-11d1-aebd-0000f80367c1;;PS)"
          "(OA;;SW;72e39547-7b18-11d1-adef-00c04fd8d5cd;;PS)"
          "(OA;;SW;72e39547-7b18-11d1-adef-00c04fd8d5cd;;CO)"
          "(OA;;SW;f3a64788-5306-11d1-a9c5-0000f80367c1;;CO)"
          "(OA;;WP;3e0abfd0-126a-11d0-a060-00aa006c33ed;bf967a86-0de6-11d0-a285-00aa003049e2;CO)"
          "(OA;;WP;5f202010-79a5-11d0-9020-00c04fc2d4cf;bf967a86-0de6-11d0-a285-00aa003049e2;CO)"
          "(OA;;WP;bf967950-0de6-11d0-a285-00aa003049e2;bf967a86-0de6-11d0-a285-00aa003049e2;CO)"
          "(OA;;WP;bf967953-0de6-11d0-a285-00aa003049e2;bf967a86-0de6-11d0-a285-00aa003049e2;CO)"
          "(OA;;RP;46a9b11d-60ae-405a-b7e8-ff8a58d456d2;;SU)")),

        ("D:(A;;RPLCLORC;;;AU)",
         "D:(A;;LCRPLORC;;;AU)"),

        (("D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;BO)"
          "(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)"
          "(A;;RPLCLORC;;;AU)"
          "(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;AO)"
          "(A;;RPLCLORC;;;PS)"
          "(OA;;CR;ab721a55-1e2f-11d0-9819-00aa0040529b;;AU)"
          "(OA;;RP;46a9b11d-60ae-405a-b7e8-ff8a58d456d2;;SU)"),
         ("D:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BO)"
          "(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)"
          "(A;;LCRPLORC;;;AU)"
          "(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;AO)"
          "(A;;LCRPLORC;;;PS)"
          "(OA;;CR;ab721a55-1e2f-11d0-9819-00aa0040529b;;AU)"
          "(OA;;RP;46a9b11d-60ae-405a-b7e8-ff8a58d456d2;;SU)")),

        (("D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;BO)"
          "(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)"
          "(A;;RPLCLORC;;;AU)"
          "(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;CO)"),
         ("D:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BO)"
          "(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)"
          "(A;;LCRPLORC;;;AU)"
          "(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;CO)")),

        (("D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;BO)"
          "(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)"
          "(A;;RPLCLORC;;;AU)S:(AU;SA;CRWP;;;WD)"),
         ("D:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BO)"
          "(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)"
          "(A;;LCRPLORC;;;AU)S:(AU;SA;WPCR;;;WD)")),

        (("D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSWRP;;;BO)"
          "(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)"
          "(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;AO)"
          "(A;;RPLCLORC;;;PS)"
          "(OA;;CR;ab721a53-1e2f-11d0-9819-00aa0040529b;;PS)"
          "(OA;;CR;ab721a54-1e2f-11d0-9819-00aa0040529b;;PS)"
          "(OA;;CR;ab721a56-1e2f-11d0-9819-00aa0040529b;;PS)"
          "(OA;;RPWP;77B5B886-944A-11d1-AEBD-0000F80367C1;;PS)"
          "(OA;;RPWP;E45795B2-9455-11d1-AEBD-0000F80367C1;;PS)"
          "(OA;;RPWP;E45795B3-9455-11d1-AEBD-0000F80367C1;;PS)"
          "(OA;;RP;037088f8-0ae1-11d2-b422-00a0c968f939;;RD)"
          "(OA;;RP;4c164200-20c0-11d0-a768-00aa006e0529;;RD)"
          "(OA;;RP;bc0ac240-79a9-11d0-9020-00c04fc2d4cf;;RD)"
          "(A;;RC;;;AU)"
          "(OA;;RP;59ba2f42-79a2-11d0-9020-00c04fc2d3cf;;AU)"
          "(OA;;RP;77B5B886-944A-11d1-AEBD-0000F80367C1;;AU)"
          "(OA;;RP;E45795B3-9455-11d1-AEBD-0000F80367C1;;AU)"
          "(OA;;RP;e48d0154-bcf8-11d1-8702-00c04fb96050;;AU)"
          "(OA;;CR;ab721a53-1e2f-11d0-9819-00aa0040529b;;WD)"
          "(OA;;RP;5f202010-79a5-11d0-9020-00c04fc2d4cf;;RD)"
          "(OA;;RPWP;bf967a7f-0de6-11d0-a285-00aa003049e2;;SY)"
          "(OA;;RP;46a9b11d-60ae-405a-b7e8-ff8a58d456d2;;SU)"
          "(OA;;WPRP;6db69a1c-9422-11d1-aebd-0000f80367c1;;SU)"),
         ("D:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BO)"
          "(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)"
          "(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;AO)"
          "(A;;LCRPLORC;;;PS)"
          "(OA;;CR;ab721a53-1e2f-11d0-9819-00aa0040529b;;PS)"
          "(OA;;CR;ab721a54-1e2f-11d0-9819-00aa0040529b;;PS)"
          "(OA;;CR;ab721a56-1e2f-11d0-9819-00aa0040529b;;PS)"
          "(OA;;RPWP;77b5b886-944a-11d1-aebd-0000f80367c1;;PS)"
          "(OA;;RPWP;e45795b2-9455-11d1-aebd-0000f80367c1;;PS)"
          "(OA;;RPWP;e45795b3-9455-11d1-aebd-0000f80367c1;;PS)"
          "(OA;;RP;037088f8-0ae1-11d2-b422-00a0c968f939;;RD)"
          "(OA;;RP;4c164200-20c0-11d0-a768-00aa006e0529;;RD)"
          "(OA;;RP;bc0ac240-79a9-11d0-9020-00c04fc2d4cf;;RD)"
          "(A;;RC;;;AU)"
          "(OA;;RP;59ba2f42-79a2-11d0-9020-00c04fc2d3cf;;AU)"
          "(OA;;RP;77b5b886-944a-11d1-aebd-0000f80367c1;;AU)"
          "(OA;;RP;e45795b3-9455-11d1-aebd-0000f80367c1;;AU)"
          "(OA;;RP;e48d0154-bcf8-11d1-8702-00c04fb96050;;AU)"
          "(OA;;CR;ab721a53-1e2f-11d0-9819-00aa0040529b;;WD)"
          "(OA;;RP;5f202010-79a5-11d0-9020-00c04fc2d4cf;;RD)"
          "(OA;;RPWP;bf967a7f-0de6-11d0-a285-00aa003049e2;;SY)"
          "(OA;;RP;46a9b11d-60ae-405a-b7e8-ff8a58d456d2;;SU)"
          "(OA;;RPWP;6db69a1c-9422-11d1-aebd-0000f80367c1;;SU)")),

        (("D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)"),
         ("D:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)")),

        (("D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)"
          "(A;;RPLCLORC;;;AU)"
          "(A;;LCRPLORC;;;ED)"),
         ("D:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)"
          "(A;;LCRPLORC;;;AU)"
          "(A;;LCRPLORC;;;ED)")),

        (("D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)"
          "(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;BO)"
          "(OA;;CCDC;bf967a86-0de6-11d0-a285-00aa003049e2;;AO)"
          "(OA;;CCDC;bf967aba-0de6-11d0-a285-00aa003049e2;;AO)"
          "(OA;;CCDC;bf967a9c-0de6-11d0-a285-00aa003049e2;;AO)"
          "(OA;;CCDC;bf967aa8-0de6-11d0-a285-00aa003049e2;;PO)"
          "(A;;RPLCLORC;;;AU)"
          "(A;;LCRPLORC;;;ED)"
          "(OA;;CCDC;4828CC14-1437-45bc-9B07-AD6F015E5F28;;AO)"),
         ("D:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)"
          "(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BO)"
          "(OA;;CCDC;bf967a86-0de6-11d0-a285-00aa003049e2;;AO)"
          "(OA;;CCDC;bf967aba-0de6-11d0-a285-00aa003049e2;;AO)"
          "(OA;;CCDC;bf967a9c-0de6-11d0-a285-00aa003049e2;;AO)"
          "(OA;;CCDC;bf967aa8-0de6-11d0-a285-00aa003049e2;;PO)"
          "(A;;LCRPLORC;;;AU)"
          "(A;;LCRPLORC;;;ED)"
          "(OA;;CCDC;4828cc14-1437-45bc-9b07-ad6f015e5f28;;AO)")),

        (("D:(A;;RPWPCRCCDCLCLORCWOWDSW;;;BO)"
          "(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)"
          "(A;;RPLCLORC;;;AU)"),
         ("D:(A;;CCDCLCSWRPWPLOCRRCWDWO;;;BO)"
          "(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)"
          "(A;;LCRPLORC;;;AU)")),

        (("D:(A;CI;RPWPCRCCDCLCLORCWOWDSDDTSW;;;BO)"
          "(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)"
          "(A;;RPLCLORC;;;AU)"),
         ("D:(A;CI;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BO)"
          "(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)"
          "(A;;LCRPLORC;;;AU)")),

        ("S:D:P", "D:PS:"),
        ("S:D:", "D:S:"),

        # decimal to hex
        ("D:(A;;123456789;;;LG)",
         "D:(A;;0x75bcd15;;;LG)"),

        # octal to hex
        ("D:(A;;01234567;;;LG)",
         "D:(A;;0x53977;;;LG)"),

        # numbers to flags
        ("D:(A;;16;;;LG)",
         "D:(A;;RP;;;LG)"),
        ("D:(A;;17;;;LG)",
         "D:(A;;CCRP;;;LG)"),
        ("D:(A;;0xff;;;LG)",
         "D:(A;;CCDCLCSWRPWPDTLO;;;LG)"),
        ("D:(A;;0xf01ff;;;LG)",
         "D:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;LG)"),
        ("D:(A;;0xe00f0000;;;LG)",
         "D:(A;;SDRCWDWOGXGWGR;;;LG)"),

        # ACL flags
        ("D:ARPAI(A;;GA;;;SY)", "D:PARAI(A;;GA;;;SY)"),
        ("D:AIPAR(A;;GA;;;SY)", "D:PARAI(A;;GA;;;SY)"),
        ("D:PARP(A;;GA;;;SY)", "D:PAR(A;;GA;;;SY)"),
        ("D:PPPPPPPPPPPP(A;;GA;;;SY)", "D:P(A;;GA;;;SY)"),

        # hex vs decimal
        ('D:(A;;CC;;;S-1-21474836480-32-579)',
         'D:(A;;CC;;;S-1-0x500000000-32-579)'),
        ("D:(A;;GA;;;S-1-5000000000-30-40)",
         "D:(A;;GA;;;S-1-0x12A05F200-30-40)"),
        ("D:(A;;GA;;;S-1-0x2-3-4)",
         "D:(A;;GA;;;S-1-2-3-4)"),
        ("D:(A;;GA;;;S-1-0x20-3-4)",
         "D:(A;;GA;;;S-1-32-3-4)"),
        ("D:(A;;GA;;;S-1-3-0x00000002-3-4)",
         "D:(A;;GA;;;S-1-3-2-3-4)"),
        ("D:(A;;GA;;;S-1-3-0xffffffff-3-4)",
         "D:(A;;GA;;;S-1-3-4294967295-3-4)"),
        ("D:(A;;GA;;;S-1-5-21-0x1-0x2-0x3-513)",
         "D:(A;;GA;;;S-1-5-21-1-2-3-513)"),
        ("D:(A;;GA;;;S-1-5-21-2447931902-1787058256-3961074038-0x4b1)",
         "D:(A;;GA;;;S-1-5-21-2447931902-1787058256-3961074038-1201)"),

        # ambiguous 'D', looks like part of the SID but isn't
        ("O:S-1-2-0x200D:", "O:S-1-2-512D:"),
        ("O:S-1-2-0x2D:(A;;GA;;;LG)", "O:S-1-2-2D:(A;;GA;;;LG)"),

        # like the 'samba3.blackbox.large_acl.NT1' test in
        # WindowsFlagsAreDifferent below, except using numeric flags
        # that can't easily be turned into symbolic flags. Also it is
        # longer, and uses different flags for each ACE.
        (("D:(A;;0x00654321;;;WD)" +
          ''.join(f"(A;;0x00abc{i:03};;;S-1-5-21-11111111-22222222-33333333-{i})"
                  for i in range(101, 601))),
         ("D:(A;;0x654321;;;WD)" +
          ''.join(f"(A;;0xabc{i:03};;;S-1-5-21-11111111-22222222-33333333-{i})"
                  for i in range(101, 601)))
         ),

        # Windows allows a space in the middle of access flags
        ("D:AI(A;CI;RP LCLORC;;;AU)", "D:AI(A;CI;LCRPLORC;;;AU)"),
        ("D:AI(A;CI;RP LCLO  RC;;;AU)", "D:AI(A;CI;LCRPLORC;;;AU)"),
        # space before string flags is ignored.
        ("D:(A;; GA;;;LG)", "D:(A;;GA;;;LG)"),

        # from 'samba3.blackbox.large_acl.NT1.able to retrieve a large ACL if VFS supports it'
        (("D:(A;;0x001f01ff;;;WD)" +
          ''.join(f"(A;;0x001f01ff;;;S-1-5-21-11111111-22222222-33333333-{i})"
                  for i in range(1001, 1201))),
         ("D:(A;;FA;;;WD)" +
          ''.join(f"(A;;FA;;;S-1-5-21-11111111-22222222-33333333-{i})"
                  for i in range(1001, 1201)))
         ),

        # from samba4.blackbox.samba-tool_ntacl, but using 0x1f01ff in place of FA (which it will become)
        (("O:S-1-5-21-2212615479-2695158682-2101375468-512"
          "G:S-1-5-21-2212615479-2695158682-2101375468-513"
          "D:P(A;OICI;0x001f01ff;;;S-1-5-21-2212615479-2695158682-2101375468-512)"
          "(A;OICI;0x001f01ff;;;S-1-5-21-2212615479-2695158682-2101375468-519)"
          "(A;OICIIO;0x001f01ff;;;CO)"
          "(A;OICI;0x001f01ff;;;S-1-5-21-2212615479-2695158682-2101375468-512)"
          "(A;OICI;0x001f01ff;;;SY)"
          "(A;OICI;0x001200a9;;;AU)"
          "(A;OICI;0x001200a9;;;ED)"
          "S:AI(OU;CIIDSA;WP;f30e3bbe-9ff0-11d1-b603-0000f80367c1;"
          "bf967aa5-0de6-11d0-a285-00aa003049e2;WD)"
          "(OU;CIIDSA;WP;f30e3bbf-9ff0-11d1-b603-0000f80367c1;"
          "bf967aa5-0de6-11d0-a285-00aa003049e2;WD)"),
         ("O:S-1-5-21-2212615479-2695158682-2101375468-512"
          "G:S-1-5-21-2212615479-2695158682-2101375468-513"
          "D:P(A;OICI;FA;;;S-1-5-21-2212615479-2695158682-2101375468-512)"
          "(A;OICI;FA;;;S-1-5-21-2212615479-2695158682-2101375468-519)"
          "(A;OICIIO;FA;;;CO)"
          "(A;OICI;FA;;;S-1-5-21-2212615479-2695158682-2101375468-512)"
          "(A;OICI;FA;;;SY)"
          "(A;OICI;0x1200a9;;;AU)"
          "(A;OICI;0x1200a9;;;ED)"
          "S:AI(OU;CIIDSA;WP;f30e3bbe-9ff0-11d1-b603-0000f80367c1;"
          "bf967aa5-0de6-11d0-a285-00aa003049e2;WD)"
          "(OU;CIIDSA;WP;f30e3bbf-9ff0-11d1-b603-0000f80367c1;"
          "bf967aa5-0de6-11d0-a285-00aa003049e2;WD)")),

    ]


@DynamicTestCase
class SddlCanonical(SddlDecodeEncodeBase):
    """These ones are expected to be returned in exactly the form they
    start in. Hence we only have one string for each example.
    """
    name = "canonical"
    should_succeed = True
    strings = [
        # derived from GPO acl in provision, "-512D" could be misinterpreted
        ("O:S-1-5-21-1225132014-296224811-2507946102-512"
         "G:S-1-5-21-1225132014-296224811-2507946102-512"
         "D:P"),
        "D:(A;;GA;;;SY)",
        "D:(A;;GA;;;RU)",
        "D:(A;;GA;;;LG)",
        "D:(A;;0x401200a0;;;LG)",
        "D:S:",
        "D:PS:",
        'D:(A;;GA;;;RS)',
        "S:(AU;SA;CR;;;WD)(AU;SA;CR;;;WD)",

        ("S:(OU;CISA;WP;f30e3bbe-9ff0-11d1-b603-0000f80367c1;bf967aa5-0de6-11d0-a285-00aa003049e2;WD)"
         "(OU;CISA;WP;f30e3bbf-9ff0-11d1-b603-0000f80367c1;bf967aa5-0de6-11d0-a285-00aa003049e2;WD)"),

        "D:(A;;GA;;;S-1-3-4294967295-3-4)",
        "D:(A;;GA;;;S-1-5-21-1-2-3-513)",
        "D:(A;;GA;;;S-1-5-21-2447931902-1787058256-3961074038-1201)",
        "O:S-1-2-512D:",
        "D:PARAI(A;;GA;;;SY)",
        "D:P(A;;GA;;;LG)(A;;GX;;;AA)",
        "D:(A;;FA;;;WD)"
    ]


@DynamicTestCase
class SddlShouldFail(SddlDecodeEncodeBase):
    """These ones should be rejected.
    """
    name = "should_fail"
    should_succeed = False
    strings = [
        "Z:(A;;GA;;;SY)",
        "D:(Antlers;;GA;;;SY)",
        "Q:(A;;GA;;;RU)",
        "d:(A;;GA;;;LG)",
        "D:((A;;GA;;;LG))",
        "D:(A;;GA;;)",
        "D :S:",
        "S:(AU;SA;CROOO;;;WD)(AU;SA;CR;;;WD)",
        "D:(A;;GA;;;S-1-0x1313131313131-513)",
        "D:(A;;GA;a;;S-1-5-21-2447931902-1787058256-0x3961074038-1201)",
        "D:(A;;GA;a;;S-1-5-21-2447931902-1787058256-0xec193176-1201)",
        ("S:(OOU;CISA;WP;f30e3bbe-9ff0-11d1-b603-0000f80367c1;bf967aa5-0de6-11d0-a285-00aa003049e2;WD)"
         "(OU;CISA;WP;f30e3bbf-9ff0-11d1-b603-0000f80367c1;bf967aa5-0de6-11d0-a285-00aa003049e2;WD)"),
        ("S:(OU;CISA;WP;f30e3bbe-9ff0-11d1-b603-00potato7c1;bf967aa5-0de6-11d0-a285-00aa003049e2;WD)"
         "(OU;CISA;WP;f30e3bbf-9ff0-11d1-b603-00chips7c1;bf967aa5-0de6-11d0-a285-00aa003049e2;WD)"),
        "D:P:S:",
        "D:(Ā;;GA;;;LG)", # macron on Ā

        # whitespace around flags
        "D:(A;;123456789 ;;;LG)",
        "D:(A;;0x75bcd15\t;;;LG)",
        "D:(A;; 0x75bcd15;;;LG",
        "D:(A;;0x 75bcd15;;;LG)",
        # Windows accepts space before string flags, not after.
        "D:(A;;GA ;;;LG)",
        "D:(A;;RP ;;;LG)",

        # space after SID is bad
        # but Windows accepts space before SID, after 2-letter SID
        "D:(A;;GA;;;S-1-3-4 )",

        "D:(A;;GA; f30e3bbf-9ff0-11d1-b603-0000f80367c1;;WD)",
        "D:(A;;GA;f30e3bbf-9ff0-11d1-b603-0000f80367c1 ;;WD)",
        "D:(A;;GA;; f30e3bbf-9ff0-11d1-b603-0000f80367c1;WD)",
        "D:(A;;GA;;f30e3bbf-9ff0-11d1-b603-0000f80367c1 ;WD)",

        # Samba used to use GUID_from_string(), which would take
        # anything GUID-ish, including {}-wrapped GUIDs, hyphen-less
        # hexstrings, and 16 raw bytes. But we only want one kind.
        "D:(A;;GA;;{f30e3bbf-9ff0-11d1-b603-0000f80367c1};WD)",
        # would have been treated as raw bytes.
        "D:(A;;GA;;0123456789abcdef;WD)",
        # would have been 16 hex pairs.
        "D:(A;;GA;;0123456789abcdef0123456789abcdef;WD)",

        # space splits a flag in half.
        "D:AI(A;CI;RP LCLOR C;;;AU)",
        # tabs in flags
        "D:AI(A;CI;RP LC\tLORC;;;AU)",
        "D:AI(A;CI;RP LC\t LORC;;;AU)",

        # incomplete SIDs
        "O:S",
        "O:S-",
        "O:S-1",
        "O:S-10",
        "O:S-0",
        "O:S-1-",
        "O:S-0x1",
        "O:S-0x1-",

        "O:",
        "O:XX",
    ]


@DynamicTestCase
class SddlWindowsIsFussy(SddlDecodeEncodeBase):
    """Windows won't accept these strings, seemingly for semantic rather than
    syntactic reasons.
    """
    name = "windows_is_fussy"
    should_succeed = True
    strings = [
        # Windows doesn't seem to want AU type in DACL.
        ("D:(A;;RP;;;WD)"
         "(AU;SA;CR;;;BA)"
         "(AU;SA;CR;;;DU)"),
    ]


@DynamicTestCase
class SddlWindowsIsLessFussy(SddlDecodeEncodeBase):
    """Windows will accept these seemingly malformed strings, but Samba
    won't.
    """
    name = "windows_is_less_fussy"
    should_succeed = False
    strings = [
        # whitespace is ignored, repaired on return
        ("D:(A;;GA;;; LG)", "D:(A;;GA;;;LG)"),
        ("D: (A;;GA;;;LG)", "D:(A;;GA;;;LG)"),
        # whitespace before ACL string flags is ignored.
        ("D: AI(A;;GA;;;LG)", "D:AI(A;;GA;;;LG)"),
        # wrong case on type is ignored, fixed
        ("D:(a;;GA;;;LG)", "D:(A;;GA;;;LG)"),
        ("D:(A;;GA;;;lg)", "D:(A;;GA;;;LG)"),
        ("D:(A;;ga;;;LG)", "D:(A;;GA;;;LG)"),
        ("D: S:","D:S:"),

        # whitespace around ACL flags
        ("D: P(A;;GA;;;LG)", "D:P(A;;GA;;;LG)"),
        ("D:P (A;;GA;;;LG)", "D:P(A;;GA;;;LG)"),

        # whitespace between ACES
        ("D:P(A;;GA;;;LG) (A;;GX;;;AA)",
         "D:P(A;;GA;;;LG)(A;;GX;;;AA)"),

        # whitespace in absent ace flags
        ("D:(A; ;GA;;;LG)","D:(A;;GA;;;LG)"),

        # space after ACL flags
        ("D:AI (A;;GA;;;LG)", "D:AI(A;;GA;;;LG)"),

        # and more whitespace.
        ("D:(A;;GA;;; WD)", "D:(A;;GA;;;WD)"),
        ("D:(A;;GA;;;WD )", "D:(A;;GA;;;WD)"),
        ("D:(A;;GA;;; S-1-3-4)", "D:(A;;GA;;;OW)"),
        ("D:(A;;GA;; ;S-1-3-4)", "D:(A;;GA;;;OW)"),
        ("D:(A;;GA; ;;S-1-3-4)", "D:(A;;GA;;;OW)"),
        ("D:(A;;GA;;; S-1-333-4)", "D:(A;;GA;;;S-1-333-4)"),
        ("D:(A;;GA; ;;S-1-333-4)", "D:(A;;GA;;;S-1-333-4)"),
        (" O:AA", "O:AA"),
        ("  O:AA  ", "O:AA"),
        ("  O:AA G:WD ", "O:AAG:WD"),

        # spaces in some parts of the SID (not subauth)
        ("O:S- 1- 2-3", "O:S-1-2-3"),
    ]


@DynamicTestCase
class SddlWindowsIsWeird(SddlDecodeEncodeBase):
    """Windows will accept some very misleading SDDL strings.
    """
    name = "windows_is_weird"
    should_succeed = False
    strings = [
        # overflow of hex turns on all flags
        ("D:(A;;0x123456789;;;LG)",
         "D:(A;;0xffffffff;;;LG)"),
        # S-Ox1- makes all the rest of the SID hex.
        ('D:(A;;CC;;;S-0x1-0-0-579)',
         'D:(A;;CC;;;S-1-0-0-1401)'),
        ('O:S-0x1-20-0-579', 'O:S-1-32-0-1401'),
        ("D:(A;;GA;;;S-1-3-4294967296-3-4)",
         "D:(A;;GA;;;S-1-3-4294967295-3-4)"),
        # sid overflow
        ("D:(A;;GA;;;S-1-3-0x100000000-3-4)",
         "D:(A;;GA;;;S-1-3-4294967295-3-4)"),
        ("D:(A;;GA;;;S-1-5-21-0x1313131313131-513)",
         "D:(A;;GA;;;S-1-5-21-4294967295-513)"),
        # negative numbers for access flags
        ("D:(A;;-99;;;LG)",
         "D:(A;;0xffffff9d;;;LG)"),
        ("D:(A;;-0xffffff55;;;LG)",
         "D:(A;;CCDCSWWPLO;;;LG)"),
        # combine overflow with negatives
        # -9876543210 == -0xffffffff  ==  -(-1)  ==  0x1  ==  CC flag
        ("D:(A;;-9876543210;;;LG)",
         "D:(A;;CC;;;LG)"),
        # overflow of hex turns on all flags
        ("D:(A;;100000000000000000000000;;;LG)",
         "D:(A;;0xffffffff;;;LG)"),
    ]
