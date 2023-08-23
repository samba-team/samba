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

"""Tests for Conditional ACEs, claims, and security tokens."""

from samba.dcerpc import security
from samba.security import access_check
from samba.tests.token_factory import token as Token
from samba.tests import TestCase, DynamicTestCase, get_env_dir
from samba.colour import c_RED, c_GREEN
import os
from samba import NTSTATUSError
from samba.ntstatus import NT_STATUS_ACCESS_DENIED

DEFAULT_ACCESS = security.SEC_FILE_ALL
DEFAULT_ACCESS2 = (security.SEC_STD_READ_CONTROL |
                   security.SEC_ADS_LIST |
                   security.SEC_ADS_READ_PROP)


def write_c_test_on_failure(f):
    """This is a function decorator that writes a function for
    /libcli/security/tests/test_run_conditional_ace.c that runs the
    equivalent test. Why?! Because iterating over a test to debug the
    failure is slower in Python tests, but adding new tests is faster
    in Python. So the flow goes like this:

    1. add python tests, run them
    2. if nothing fails, goto 1
    3. copy the test_something() text into test_run_conditional_ace.c,
       rename it, and add it to main().
    4. `make bin/test_run_conditional_ace && rr bin/test_run_conditional_ace`
    5. `rr replay`

    and you're away. You can also just work from the Python, but a few
    runs of `make -j` after touching something in libcli/security will
    make you see why this exists.

    You might be thinking that this surely took longer to write than
    waiting 100 times for a 30 second compile, but that misses the
    point that debugging needs to be ergonomic and fun.
    """
    from json import dumps as q  # JSON quoting is C quoting, more or less

    def wrapper(name, token, sddl, access_desired):
        try:
            f(name, token, sddl, access_desired)
        except Exception:
            print()
            print('static void test_something(void **state)')
            print('{')
            print('\tINIT();')
            for s in ('sids', 'device_sids'):
                if s in token:
                    macro = ('user_sids' if s == 'sids' else s).upper()
                    v = ', '.join(q(x) for x in token[s])
                    print(f'\t{macro}({v});')
            for s in ('user_claims', 'device_claims'):
                if s in token:
                    macro = s.upper()
                    for name, values in token[s].items():
                        if not isinstance(values, (list, tuple)):
                            values = [values]
                        v = ', '.join(q(x) for x in values)
                        v = q(f"{v}")
                        print(f'\t{macro}({q(name)}, {v});')
            print(f'\tSD({q(sddl)});')
            if 'allow' in f.__name__:
                print(f'\tALLOW_CHECK({access_desired:#x});')
            else:
                print(f'\tDENY_CHECK({access_desired:#x});')
            print('}')
            print()
            raise
    return wrapper


class ConditionalAceClaimsBase(TestCase):
    maxDiff = 0

    @classmethod
    def setUpDynamicTestCases(cls):
        cls.domain_sid = security.dom_sid("S-1-22-333-4444")
        seen = set()

        for i, row in enumerate(cls.data):
            token, sddl, access_desired = row
            name = f'{i+1:03}-{token}-{sddl}-{access_desired}'
            if len(name) > 150:
                name = f"{name[:125]}+{len(name) - 125}-more-characters"

            if name in seen:
                print(f"seen {row} after {len(seen)}")
            seen.add(name)

            if cls.allow:
                cls.generate_dynamic_test('test_allow',
                                          name, token, sddl, access_desired)
            else:
                cls.generate_dynamic_test('test_deny',
                                          name, token, sddl, access_desired)

        fuzz_seed_dir = get_env_dir('SAMBA_WRITE_FUZZ_STRINGS_DIR')
        if fuzz_seed_dir is not None:
            cls._write_sddl_strings_for_fuzz_seeds(fuzz_seed_dir)

    @classmethod
    def _write_sddl_strings_for_fuzz_seeds(cls, fuzz_seed_dir):
        """write all the SDDL strings we have into a directory as individual
        files, using a naming convention beloved of fuzzing engines.

        To run this set an environment variable; see
        cls.setUpDynamicTestCases(), below.

        Note this will only run in subclasses annotated with @DynamicTestCase.
        """
        from hashlib import md5
        for _, sddl, _ in cls.data:
            name = md5(sddl.encode()).hexdigest()
            with open(os.path.join(fuzz_seed_dir, name), 'w') as f:
                f.write(sddl)

    @write_c_test_on_failure
    def _test_allow_with_args(self, _token, sddl, access_desired):
        if isinstance(_token, dict):
            token = Token(**_token)
        else:
            token = _token
        sd = security.descriptor.from_sddl(sddl, self.domain_sid)
        try:
            granted = access_check(sd, token, access_desired)
        except NTSTATUSError as e:
            print(c_RED(sddl))
            print(c_RED(_token))
            if e.args[0] != NT_STATUS_ACCESS_DENIED:
                raise
            self.fail("access was denied")

        self.assertEqual(granted, access_desired)

    @write_c_test_on_failure
    def _test_deny_with_args(self, token, sddl, access_desired):
        if isinstance(token, dict):
            token = Token(**token)
        sd = security.descriptor.from_sddl(sddl, self.domain_sid)
        try:
            granted = access_check(sd, token, access_desired)
        except NTSTATUSError as e:
            if e.args[0] == NT_STATUS_ACCESS_DENIED:
                return
            self.fail(f"failed with {e}, not access denied")

        self.fail("access allowed")


@DynamicTestCase
class AllowTests(ConditionalAceClaimsBase):
    name = "allow"
    allow = True
    data = [
        (  # device_claims
            {'sids': ['WD', 'AA'],
             'device_claims': {"colour":["orange", "blue"]}},
            ('D:(XA;;0x1f;;;AA;'
             '(@Device.colour == {"orange", "blue"}))'),
            0x10),
        (  # device_claims, int >=
            {'sids': ['WD', 'AA'],
             'device_claims': {"legs": 4}},
            ('D:(XA;;0x1f;;;AA;(@Device.legs >= 1))'),
            0x10),
        (  # device_claims, int
            {'sids': ['WD', 'AA'],
             'device_claims': {"legs": 1}},
            ('D:(XA;;0x1f;;;AA;(@Device.legs == 1))'),
            0x10),
        (  # device_member_of && member_of
            {'sids': ['WD', 'AA'],
             'device_sids': ['BA', 'BG']},
            ("D:(XA;;0x1f;;;AA;"
             "(Device_Member_of{SID(BA)} && Member_of{SID(WD)}))"),
            0x10),
        (  # device_member_of || member_of, both true
            {'sids': ['WD', 'AA'],
             'device_sids': ['BA', 'BG']},
            ("D:(XA;;0x1f;;;AA;"
             "(Device_Member_of{SID(AA)} || Member_of{SID(WD)}))"),
            0x10),
        (  # device_member_of || member_of, second true
            {'sids': ['WD', 'AA'],
             'device_sids': ['BA', 'BG']},
            ("D:(XA;;0x1f;;;AA;"
             "(Device_Member_of{SID(AA)} || Member_of{SID(WD)}))"),
            0x10),
        (  # device_member_of || member_of, first true
            {'sids': ['WD', 'AA'],
             'device_sids': ['BA', 'BG']},
            ("D:(XA;;0x1f;;;AA;"
             "(Device_Member_of{SID(BG)} || Member_of{SID(WR)}))"),
            0x10),
        (  # single SID, Member_of_Any
            {'sids': ['S-1-222-333']},
            ("D:(XA;;0x1ff;;;S-1-222-333;(Member_of_Any{SID(S-1-222-333)}))"),
            0x1),
        ({'sids': ['S-1-1-0']}, "O:S-1-1-0D:(A;;0x1ff;;;WD)", DEFAULT_ACCESS),
        ({'sids': ['S-1-1-0']},
         "O:S-1-1-0D:(XA;;0x1ff;;;WD;(Member_of{SID(S-1-1-0)}))",
         DEFAULT_ACCESS),
        ({'sids': ['S-1-1-0', 'S-1-222-333']},
         "O:S-1-1-0D:(XA;;0x1ff;;;WD;(Member_of{SID(S-1-1-0)}))",
         DEFAULT_ACCESS),
        ({'sids': ['WD', 'S-1-222-333']},
         "O:S-1-1-0D:(XA;;0x1ff;;;WD;(Member_of{SID(S-1-1-0)}))",
         DEFAULT_ACCESS),
        (  # a single SID, not a composite
            {'sids': ['S-1-1-0', 'S-1-222-333']},
            "O:S-1-1-0D:(XA;;0x1ff;;;WD;(Member_of SID(S-1-1-0)))",
            DEFAULT_ACCESS),
        (  # a single SID, not a composite, without space after Member_of
            {'sids': ['S-1-1-0', 'S-1-222-333']},
            "O:S-1-1-0D:(XA;;0x1ff;;;WD;(Member_of\nSID(S-1-1-0)))",
            DEFAULT_ACCESS),
        (  # a single SID, not a composite, Member_of_Any
            {'sids': ['S-1-1-0', 'S-1-222-333']},
            "O:S-1-1-0D:(XA;;0x1ff;;;WD;(Member_of_Any SID(S-1-1-0)))",
            DEFAULT_ACCESS),
        (  # Member_of_Any
            {'sids': ['S-1-1-0', 'S-1-222-333']},
            "O:S-1-1-0D:(XA;;0x1;;;WD;(Member_of_Any{SID(AS),SID(WD)}))",
            0x1),
        ({'sids': ['S-1-1-0', 'S-1-222-333']},
         ("O:S-1-1-0D:"
          "(XA;;0x1ff;;;WD;(Member_of_Any{SID(S-1-1-0), SID(S-1-222-333)}))"),
         DEFAULT_ACCESS),
        ({'sids': ['S-1-1-0', 'S-1-222-333']},
         ("O:S-1-1-0D:"
          "(XA;;0x1ff;;;WD;(Member_of_Any{SID(S-1-1-334), SID(S-1-222-333)}))"),
         DEFAULT_ACCESS),
        ({'sids': ['S-1-1-0', 'S-1-222-333']},
         ("D:(XA;;0x1ff;;;WD;(Member_of_Any{SID(S-1-222-333)}))"),
         DEFAULT_ACCESS),
        ({'sids': ['S-1-77-88-99', 'AA']},
         "D:(XA;;0x1f;;;AA;(Member_of{SID(S-1-77-88-99)}))",
         0x10),
        (  # device_member_of
            {'sids': ['WD', 'AA'],
             'device_sids': ['BA', 'BG']},
            "D:(XA;;0x1f;;;AA;(Device_Member_of{SID(BA)}))",
            0x10),
        (  # device_member_of
            {'sids': ['WD', 'AA'],
             'device_sids': ['BA', 'BG']},
            "D:(XA;;0x1f;;;AA;(Device_Member_of{SID(BA)}))",
            0x10),
        (  # not (!) member_of
            {'sids': ['WD', 'AA'],
             'device_sids': ['BA', 'BG']},
            "D:(XA;;0x1f;;;AA;(! (Member_of{SID(BA)})))",
            0x10),
        (  # not not (!!) member_of
            {'sids': ['WD', 'AA'],
             'device_sids': ['BA', 'BG']},
            "D:(XA;;0x1f;;;AA;(!(! (Member_of{SID(AA)}))))",
            0x10),
        (  # not * 8 (!!!! !!!!) member_of
            {'sids': ['WD', 'AA'],
             'device_sids': ['BA', 'BG']},
            "D:(XA;;0x1f;;;AA;(!(!(!(!(!(!(!(!( Member_of{SID(AA)}))))))))))",
            0x10),
        (  # not * 9 (!!! !!! !!!) member_of
            {'sids': ['WD', 'AA'],
             'device_sids': ['BA', 'BG']},
            "D:(XA;;0x1f;;;AA;(!(!(!( !(!(!( !(!(!(Member_of{SID(BA)})))))))))))",
            0x10),
        (  # not * 9 (!!! !!! !!!) Not_Member_of
            {'sids': ['WD', 'AA'],
             'device_sids': ['BA', 'BG']},
            ("D:(XA;;0x1f;;;AA;"
             "(!(!(!(  !(!(!(  !(!(!(  Not_Member_of{SID(AA)})))))))))))"),
            0x10),
        (  #resource ACE
            {'sids': ['WD', 'AA'],
             'device_claims': {"colour": ["blue"]}},
            ('D:(XA;;0x1f;;;AA;(@Device.colour Contains @Resource.colour))'
             'S:(RA;;;;;WD;("colour",TS,0,"blue"))'),
            0x10),
        (  #resource ACE ==
            {'sids': ['WD', 'AA'],
             'device_claims': {"colour": ["blue"]}},
            ('D:(XA;;0x1f;;;AA;(@Device.colour == @Resource.colour))'
             'S:(RA;;;;;WD;("colour",TS,0,"blue"))'),
            0x10),
        (  # device_claims, comparing single to single
            {'sids': ['WD', 'AA'],
             'device_claims': {"colour": "blue"}},
            ('D:(XA;;0x1f;;;AA;(@Device.colour == "blue"))'),
            0x10),
        (  # device_claims == user_claims
            {'sids': ['WD', 'AA'],
             'user_claims': {"colour": "blue"},
             'device_claims': {"colour": "blue"}},
            ('D:(XA;;0x1f;;;AA;(@User.colour == @Device.colour))'),
            0x10),
        (  #resource ACE multi
            {'sids': ['WD', 'AA'],
             'device_claims': {"colour": ["blue", "red"]}},
            ('D:(XA;;0x1f;;;AA;(@Device.colour Contains @Resource.colour))'
             'S:(RA;;;;;WD;("colour",TS,0,"blue", "red"))'),
            0x10),
    ]


@DynamicTestCase
class DenyTests(ConditionalAceClaimsBase):
    name = "allow"
    allow = False
    data = [
        ({}, "", DEFAULT_ACCESS),
        ({'sids': ['S-1-1-0']}, "O:S-1-1-0D:(A;;0x1fe;;;WD)", DEFAULT_ACCESS),
        ({}, "O:WDD:(A;;GACR;;;CO)", DEFAULT_ACCESS),
        ({'sids': ['S-1-1-0', 'S-1-222-444']},
         ("D:(XA;;0x1ff;;;WD;(Member_of_Any{SID(S-1-222-333)}))"),
         0x1),
        (  # Without explicit 'everyone' SID in list of SIDs, this is
           # denied because the ACE SID 'WD' doesn't match.
            {'sids': ['S-1-222-333']},
         ("D:(XA;;0x1ff;;;WD;(Member_of_Any{SID(S-1-222-333)}))"),
         0x1),
        (  # device_member_of && member_of, both false
            {'sids': ['WD', 'AA'],
             'device_sids': ['BA', 'BG']},
            ("D:(XA;;0x1f;;;AA;"
             "(Device_Member_of{SID(AA)} && Member_of{SID(WR)}))"),
            0x10),
        (  # device_member_of && member_of, first false
            {'sids': ['WD', 'AA'],
             'device_sids': ['BA', 'BG']},
            ("D:(XA;;0x1f;;;AA;"
             "(Device_Member_of{SID(AA)} && Member_of{SID(WD)}))"),
            0x10),
        (  # device_member_of && member_of, second false
            {'sids': ['WD', 'AA'],
             'device_sids': ['BA', 'BG']},
            ("D:(XA;;0x1f;;;AA;"
             "(Device_Member_of{SID(BA)} && Member_of{SID(BA)}))"),
            0x10),
        (  # device_member_of || member_of, both false
            {'sids': ['WD', 'AA'],
             'device_sids': ['BA', 'BG']},
            ("D:(XA;;0x1f;;;AA;"
             "(Device_Member_of{SID(AA)} || Member_of{SID(WR)}))"),
            0x10),
        (  # device_claims, comparing composite to single
            {'sids': ['WD', 'AA'],
             'device_claims': {"colour": ["orange", "blue"]}},
            ('D:(XA;;0x1f;;;AA;(@Device.colour == "blue"))'),
            0x10),
        (  # not (!) member_of
            {'sids': ['WD', 'AA'],
             'device_sids': ['BA', 'BG']},
            "D:(XA;;0x1f;;;AA;(! (Member_of{SID(AA)})))",
            0x10),
        (  # not not (!!) member_of
            {'sids': ['WD', 'AA'],
             'device_sids': ['BA', 'BG']},
            "D:(XA;;0x1f;;;AA;(!(!( Member_of{SID(BA)}))))",
            0x10),
        (  # not * 8 (!!!! !!!!) member_of
            {'sids': ['WD', 'AA'],
             'device_sids': ['BA', 'BG']},
            "D:(XA;;0x1f;;;AA;(!(!( !(!( !(!( !(!(Member_of{SID(BA)}))))))))))",
            0x10),
        (  # not * 3 (!!!) member_of
            {'sids': ['WD', 'AA'],
             'device_sids': ['BA', 'BG']},
            "D:(XA;;0x1f;;;AA;(!(!(!(Member_of{SID(AA)})))))",
            0x10),
        (  # not * 3 (!!!) Not_Member_of
            {'sids': ['WD', 'AA'],
             'device_sids': ['BA', 'BG']},
            "D:(XA;;0x1f;;;AA;(!(!(!(Not_Member_of{SID(BA)})))))",
            0x10),
    ]
