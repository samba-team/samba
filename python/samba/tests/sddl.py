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
from samba.ndr import ndr_pack, ndr_unpack
from samba.tests import TestCase
from samba.colour import c_RED, c_GREEN


class SddlDecodeEncode(TestCase):
    strings = [
        "D:(A;;CC;;;BA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)",

        "D:(A;;GA;;;SY)",

        "D:(A;;GA;;;RS)",

        ("D:(A;;RP;;;WD)"
         "(OA;;CR;1131f6aa-9c07-11d1-f79f-00c04fc2dcd2;;ED)"
         "(OA;;CR;1131f6ab-9c07-11d1-f79f-00c04fc2dcd2;;ED)"
         "(OA;;CR;1131f6ac-9c07-11d1-f79f-00c04fc2dcd2;;ED)"
         "(OA;;CR;1131f6aa-9c07-11d1-f79f-00c04fc2dcd2;;BA)"
         "(OA;;CR;1131f6ab-9c07-11d1-f79f-00c04fc2dcd2;;BA)"
         "(OA;;CR;1131f6ac-9c07-11d1-f79f-00c04fc2dcd2;;BA)"
         "(A;;RPLCLORC;;;AU)"
         "(A;;RPWPCRLCLOCCRCWDWOSW;;;DA)"
         "(A;CI;RPWPCRLCLOCCRCWDWOSDSW;;;BA)"
         "(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;SY)"
         "(A;CI;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;EA)"
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
         "(OA;;CR;1131f6ad-9c07-11d1-f79f-00c04fc2dcd2;;DD)"
         "(OA;;CR;1131f6ad-9c07-11d1-f79f-00c04fc2dcd2;;BA)"
         "(OA;;CR;e2a36dc9-ae17-47c3-b58b-be34c55ba633;;S-1-5-32-557)"
         "(OA;;CR;280f369c-67c7-438e-ae98-1d46f3c6f541;;AU)"
         "(OA;;CR;ccc2dc7d-a6ad-4a7a-8846-c04e3cc53501;;AU)"
         "(OA;;CR;05c74c5e-4deb-43b4-bd9f-86664c2a7fd5;;AU)S:(AU;SA;WDWOWP;;;WD)"
         "(AU;SA;CR;;;BA)"
         "(AU;SA;CR;;;DU)"
         "(OU;CISA;WP;f30e3bbe-9ff0-11d1-b603-0000f80367c1;bf967aa5-0de6-11d0-a285-00aa003049e2;WD)"
         "(OU;CISA;WP;f30e3bbf-9ff0-11d1-b603-0000f80367c1;bf967aa5-0de6-11d0-a285-00aa003049e2;WD)"),

        ("D:(A;;RPLCLORC;;;DA)"
         "(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)"
         "(A;;RPLCLORC;;;AU)"),

        ("D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)"
         "(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;AO)"
         "(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)"
         "(A;;RPCRLCLORCSDDT;;;CO)"
         "(OA;;WP;4c164200-20c0-11d0-a768-00aa006e0529;;CO)"
         "(A;;RPLCLORC;;;AU)"
         "(OA;;CR;ab721a53-1e2f-11d0-9819-00aa0040529b;;WD)"
         "(A;;CCDC;;;PS)"
         "(OA;;CCDC;bf967aa8-0de6-11d0-a285-00aa003049e2;;PO)"
         "(OA;;RPWP;bf967a7f-0de6-11d0-a285-00aa003049e2;;CA)"
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

        ("D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)"
         "(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)"
         "(A;;RPLCLORC;;;AU)"),

        ("D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)"
         "(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)"
         "(A;;RPLCLORC;;;AU)"
         "(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;AO)"
         "(A;;RPLCLORC;;;PS)"
         "(OA;;CR;ab721a55-1e2f-11d0-9819-00aa0040529b;;AU)"
         "(OA;;RP;46a9b11d-60ae-405a-b7e8-ff8a58d456d2;;S-1-5-32-560)"),

        ("D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)"
         "(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)"
         "(A;;RPLCLORC;;;AU)"
         "(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;CO)"),

        ("D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)"
         "(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)"
         "(A;;RPLCLORC;;;AU)S:(AU;SA;CRWP;;;WD)"),

        ("D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)"
         "(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)"
         "(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;AO)"
         "(A;;RPLCLORC;;;PS)"
         "(OA;;CR;ab721a53-1e2f-11d0-9819-00aa0040529b;;PS)"
         "(OA;;CR;ab721a54-1e2f-11d0-9819-00aa0040529b;;PS)"
         "(OA;;CR;ab721a56-1e2f-11d0-9819-00aa0040529b;;PS)"
         "(OA;;RPWP;77B5B886-944A-11d1-AEBD-0000F80367C1;;PS)"
         "(OA;;RPWP;E45795B2-9455-11d1-AEBD-0000F80367C1;;PS)"
         "(OA;;RPWP;E45795B3-9455-11d1-AEBD-0000F80367C1;;PS)"
         "(OA;;RP;037088f8-0ae1-11d2-b422-00a0c968f939;;RS)"
         "(OA;;RP;4c164200-20c0-11d0-a768-00aa006e0529;;RS)"
         "(OA;;RP;bc0ac240-79a9-11d0-9020-00c04fc2d4cf;;RS)"
         "(A;;RC;;;AU)"
         "(OA;;RP;59ba2f42-79a2-11d0-9020-00c04fc2d3cf;;AU)"
         "(OA;;RP;77B5B886-944A-11d1-AEBD-0000F80367C1;;AU)"
         "(OA;;RP;E45795B3-9455-11d1-AEBD-0000F80367C1;;AU)"
         "(OA;;RP;e48d0154-bcf8-11d1-8702-00c04fb96050;;AU)"
         "(OA;;CR;ab721a53-1e2f-11d0-9819-00aa0040529b;;WD)"
         "(OA;;RP;5f202010-79a5-11d0-9020-00c04fc2d4cf;;RS)"
         "(OA;;RPWP;bf967a7f-0de6-11d0-a285-00aa003049e2;;CA)"
         "(OA;;RP;46a9b11d-60ae-405a-b7e8-ff8a58d456d2;;S-1-5-32-560)"
         "(OA;;WPRP;6db69a1c-9422-11d1-aebd-0000f80367c1;;S-1-5-32-561)"),

        "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)",

        ("D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)"
         "(A;;RPLCLORC;;;AU)"
         "(A;;LCRPLORC;;;ED)"),

        ("D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)"
         "(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)"
         "(OA;;CCDC;bf967a86-0de6-11d0-a285-00aa003049e2;;AO)"
         "(OA;;CCDC;bf967aba-0de6-11d0-a285-00aa003049e2;;AO)"
         "(OA;;CCDC;bf967a9c-0de6-11d0-a285-00aa003049e2;;AO)"
         "(OA;;CCDC;bf967aa8-0de6-11d0-a285-00aa003049e2;;PO)"
         "(A;;RPLCLORC;;;AU)"
         "(A;;LCRPLORC;;;ED)"
         "(OA;;CCDC;4828CC14-1437-45bc-9B07-AD6F015E5F28;;AO)"),

        ("D:(A;;RPWPCRCCDCLCLORCWOWDSW;;;DA)"
         "(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)"
         "(A;;RPLCLORC;;;AU)"),

        ("D:(A;CI;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)"
         "(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)"
         "(A;;RPLCLORC;;;AU)"),

        "D:S:",
        "D:PS:",
    ]

    def _test_sddl_pair(self, sid, s, canonical):
        try:
            sd1 = security.descriptor.from_sddl(s, sid)
        except TypeError as e:
            self.fail()

        sddl = sd1.as_sddl(sid)
        sd2 = security.descriptor.from_sddl(sddl, sid)
        self.assertEqual(sd1, sd2)
        self.assertEqual(sddl, canonical)

    def _test_list(self, strings):
        sid = security.dom_sid("S-1-2-3-4")
        failed = []
        for x in strings:
            if isinstance(x, str):
                original, canonical = (x, x)
            else:
                original, canonical = x
            try:
                self._test_sddl_pair(sid, original, canonical)
            except AssertionError:
                failed.append((original, canonical))

        for o, c in failed:
            print(f"{c_RED(o)} -> {c} failed")
        self.assertEqual(failed, [])

    def test_sddl(self):
        self._test_list(self.strings)

    def test_multiflag(self):
        sid = security.dom_sid("S-1-2-3-4")
        raised = False
        sd = security.descriptor.from_sddl("D:(A;;GWFX;;;DA)", sid)
        sddl = sd.as_sddl(sid)
        self.assertEqual(sd, security.descriptor.from_sddl(sddl, sid))
