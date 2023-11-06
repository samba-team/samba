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

import random
from samba.dcerpc import security
from samba.security import access_check
from samba.tests.token_factory import token as Token
from samba.tests.token_factory import list_to_claim
from samba.dcerpc.security import CLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1
from samba.tests import TestCase, DynamicTestCase, get_env_dir
from samba.colour import c_RED
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
                        if isinstance(values,
                                      CLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1):
                            v = '...'
                        else:
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


def _int_range(n, n_dupes=0, random_seed=None):
    """Makes a list of stringified integers.

    If n_unique is specified and less than n, there will be that many unique
    values (and hence some duplicates). If random_seed is set, the list will be
    shuffled.
    """
    claims = [str(x) for x in range(n)]

    if random_seed is None:
        if n_dupes:
            claims *= 1 + (n + n_dupes) // n
        return claims[:n + n_dupes]

    random.seed(random_seed)
    for i in range(n_dupes):
        # this purposefully skews the distribution.
        claims.append(random.choice(claims))

    random.shuffle(claims)
    return claims


def _str_range(n, n_dupes=0, random_seed=None, mix_case=False):
    """Create a list of strings with somewhat controllable disorder.
    """
    ints = _int_range(n, n_dupes, random_seed)
    claims = [f'a{i}' for i in ints]

    if mix_case:
        if random_seed is None:
            random.seed(0)
        for i in range(len(claims)):
            if random.random() < 0.5:
                claims[i] = claims[i].upper()

    return claims


def claim_str_range(*args, name="foo", case_sensitive=False, **kwargs):
    """String value range as a CLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1"""
    vals = _str_range(*args, **kwargs)
    claim = list_to_claim(name, vals, case_sensitive=case_sensitive)
    return claim


def claim_int_range(*args, name="foo", case_sensitive=False, **kwargs):
    """Int value range as a CLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1"""
    vals = _int_range(*args, **kwargs)
    claim = list_to_claim(name, vals, case_sensitive=case_sensitive)
    return claim


def ra_str_range(*args, name="foo", case_sensitive=False, **kwargs):
    """Make a string claim as a resource attribute"""
    claim = _str_range(*args, **kwargs)
    values = '","'.join(claim)
    c = (2 if case_sensitive else 0)
    return f'(RA;;;;;WD;("{name}",TS,{c},"{values}"))'


def ra_int_range(*args, name="foo", unsigned=False, **kwargs):
    """Return an integer claim range as a resource attribute."""
    ints = _int_range(*args, **kwargs)
    values = ','.join(str(x) for x in ints)
    return f'(RA;;;;;WD;("{name}",T{"U" if unsigned else "I"},0,{values}))'


def composite_int(*args, **kwargs):
    """Integer conditional ACE composite"""
    claim = _int_range(*args, **kwargs)
    values = ', '.join(claim)
    return '{' + values + '}'


def composite_str(*args, **kwargs):
    """String conditional ACE composite"""
    claim = _str_range(*args, **kwargs)
    values = '", "'.join(claim)
    return '{"' + values + '"}'


@DynamicTestCase
class ConditionalAceLargeComposites(ConditionalAceClaimsBase):
    """Here we are dynamically generating claims and composites with large numbers
    of members, and using them in comparisons. Sometimes the comparisons are
    meant to fail, and sometimes not.
    """
    maxDiff = 0

    @classmethod
    def setUpDynamicTestCases(cls):
        cls.domain_sid = security.dom_sid("S-1-22-333-4444")
        for i, row in enumerate(cls.data):
            name, allow, token, sddl = row
            name = f'{i+1:03}-{name}'
            if 'sids' not in token:
                token['sids'] = ['AU', 'WD']
            if allow:
                cls.generate_dynamic_test('test_allow',
                                          name, token, sddl, 0x10)
            else:
                cls.generate_dynamic_test('test_deny',
                                          name, token, sddl, 0x10)

        fuzz_seed_dir = get_env_dir('SAMBA_WRITE_FUZZ_STRINGS_DIR')
        if fuzz_seed_dir is not None:
            cls._write_sddl_strings_for_fuzz_seeds(fuzz_seed_dir)


    data = [
        (
            "90-disorderly-strings-claim-vs-claim-case-sensitive-with-dupes",
            False,
            {'user_claims': {"c": claim_str_range(90,
                                                  random_seed=2),
                             "d": claim_str_range(90, 90,
                                                  case_sensitive=True,
                                                  random_seed=3)}},
            ('D:(XA;;FA;;;WD;(@USER.c == @USER.d))')
        ),
        (
            # this one currently fails before we get to compare_composites()
            "0-vs-0",
            True,
            {'user_claims': {"c": claim_str_range(0)}},
            ('D:(XA;;FA;;;WD;(@USER.c == @USER.c))')
        ),
        (
            "50-orderly-strings",
            True,
            {'user_claims': {"c": claim_str_range(50)}},
            (f'D:(XA;;FA;;;WD;(@USER.c == {composite_str(50)}))')
        ),
        (
            "50-disorderly-strings-same-disorder",
            True,
            {'user_claims': {"c": claim_str_range(50, random_seed=1)}},
            (f'D:(XA;;FA;;;WD;(@USER.c == {composite_str(50, random_seed=1)}))')
        ),
        (
            "200-disorderly-strings",
            True,
            {'user_claims': {"c": claim_str_range(200, random_seed=1)}},
            (f'D:(XA;;FA;;;WD;(@USER.c == {composite_str(200, random_seed=2)}))')
        ),
        (
            "50-orderly-vs-disorderly-strings",
            True,
            {'user_claims': {"c": claim_str_range(50)}},
            (f'D:(XA;;FA;;;WD;(@USER.c == {composite_str(50, random_seed=1)}))')
        ),
        (
            "50-disorderly-vs-orderly-strings",
            True,
            {'user_claims': {"c": claim_str_range(50, random_seed=1)}},
            (f'D:(XA;;FA;;;WD;(@USER.c == {composite_str(50)}))')
        ),
        (
            "99-orderly-strings",
            True,
            {'user_claims': {"c": claim_str_range(99)}},
            (f'D:(XA;;FA;;;WD;(@USER.c == {composite_str(99)}))')
        ),
        (
            "99-disorderly-strings",
            True,
            {'user_claims': {"c": claim_str_range(99, random_seed=1)}},
            (f'D:(XA;;FA;;;WD;(@USER.c == {composite_str(99, random_seed=2)}))')
        ),
        (
            "99-orderly-vs-disorderly-strings",
            True,
            {'user_claims': {"c": claim_str_range(99)}},
            (f'D:(XA;;FA;;;WD;(@USER.c == {composite_str(99, random_seed=1)}))')
        ),
        (
            "99-disorderly-vs-orderly-strings",
            True,
            {'user_claims': {"c": claim_str_range(99, random_seed=1)}},
            (f'D:(XA;;FA;;;WD;(@USER.c == {composite_str(99)}))')
        ),
        (
            "39-orderly-strings-vs-39+60-dupes",
            True,
            {'user_claims': {"c": claim_str_range(39)}},
            (f'D:(XA;;FA;;;WD;(@USER.c == {composite_str(39, 60)}))')
        ),
        (
            "39-disorderly-strings-vs-39+60-dupes",
            True,
            {'user_claims': {"c": claim_str_range(39, random_seed=1)}},
            (f'D:(XA;;FA;;;WD;(@USER.c == {composite_str(39, 60, random_seed=1)}))')
        ),
        (
            "39-orderly-vs-disorderly-strings-vs-39+60-dupes",
            True,
            {'user_claims': {"c": claim_str_range(39)}},
            (f'D:(XA;;FA;;;WD;(@USER.c == {composite_str(39, 60, random_seed=1)}))')
        ),
        (
            "39-disorderly-vs-orderly-strings-vs-39+60-dupes",
            True,
            {'user_claims': {"c": claim_str_range(39, random_seed=1)}},
            (f'D:(XA;;FA;;;WD;(@USER.c == {composite_str(39, 60)}))')
        ),
        (
            "3-orderly-strings-vs-3+60-dupes",
            True,
            {'user_claims': {"c": claim_str_range(3)}},
            (f'D:(XA;;FA;;;WD;(@USER.c == {composite_str(3, 60)}))')
        ),
        (
            "3-disorderly-strings-vs-3+60-dupes",
            True,
            {'user_claims': {"c": claim_str_range(3, random_seed=1)}},
            (f'D:(XA;;FA;;;WD;(@USER.c == {composite_str(3, 60, random_seed=1)}))')
        ),
        (
            "3-orderly-vs-disorderly-strings-vs-3+60-dupes",
            True,
            {'user_claims': {"c": claim_str_range(3)}},
            (f'D:(XA;;FA;;;WD;(@USER.c == {composite_str(3, 60, random_seed=1)}))')
        ),
        (
            "3-disorderly-vs-orderly-strings-vs-3+60-dupes",
            True,
            {'user_claims': {"c": claim_str_range(3, random_seed=1)}},
            (f'D:(XA;;FA;;;WD;(@USER.c == {composite_str(3, 60)}))')
        ),
        (
            "3-orderly-strings-vs-3+61-dupes",
            True,
            {'user_claims': {"c": claim_str_range(3)}},
            (f'D:(XA;;FA;;;WD;(@USER.c == {composite_str(3, 61)}))')
        ),

        (
            "63-orderly-strings-vs-62+1-dupe",
            False,
            {'user_claims': {"c": claim_str_range(63)}},
            (f'D:(XA;;FA;;;WD;(@USER.c == {composite_str(62, 1)}))')
        ),
        (
            "102+1-dupe-vs-102+1-dupe",
            False,
            # this is an invalid claim
            {'user_claims': {"c": claim_str_range(102, 1)}},
            (f'D:(XA;;FA;;;WD;(@USER.c == {composite_str(102, 1)}))')
        ),
        (
            "0-vs-1",
            False,
            {'user_claims': {"c": claim_str_range(0),
                             "d": claim_str_range(1)}},
            ('D:(XA;;FA;;;WD;(@USER.c == @USER.d))')
        ),
        (
            "2+1-dupe-vs-2+1-dupe",
            False,
            {'user_claims': {"c": claim_str_range(2, 1)}},
            (f'D:(XA;;FA;;;WD;(@USER.c == {composite_str(2, 1)}))')
        ),
        (
            "63-disorderly-strings-vs-62+1-dupe",
            False,
            {'user_claims': {"c": claim_str_range(63, random_seed=1)}},
            (f'D:(XA;;FA;;;WD;(@USER.c == {composite_str(62, 1, random_seed=1)}))')
        ),
        (
            "63-disorderly-strings-vs-63+800-dupe",
            True,
            {'user_claims': {"c": claim_str_range(63, random_seed=1)}},
            (f'D:(XA;;FA;;;WD;(@USER.c == {composite_str(63, 800, random_seed=1)}))')
        ),
        (
            "63-disorderly-strings-vs-62+800-dupe",
            False,
            {'user_claims': {"c": claim_str_range(63, random_seed=1)}},
            (f'D:(XA;;FA;;;WD;(@USER.c == {composite_str(62, 800, random_seed=1)}))')
        ),
        (
            "9-orderly-strings",
            True,
            {'user_claims': {"c": claim_str_range(9)}},
            (f'D:(XA;;FA;;;WD;(@USER.c == {composite_str(9)}))')
        ),
        (
            "9-orderly-strings-claim-vs-itself",
            True,
            {'user_claims': {"c": claim_str_range(9)}},
            ('D:(XA;;FA;;;WD;(@USER.c == @USER.c))')
        ),
        (
            "300-orderly-strings-claim-vs-itself",
            True,
            {'user_claims': {"c": claim_str_range(300)}},
            ('D:(XA;;FA;;;WD;(@USER.c == @USER.c))')
        ),
        (
            "900-disorderly-strings-claim-vs-claim",
            True,
            {'user_claims': {"c": claim_str_range(900, random_seed=1),
                             "d": claim_str_range(900, random_seed=1)}},
            ('D:(XA;;FA;;;WD;(@USER.c == @USER.d))')
        ),
        (
            "9-orderly-strings-claim-mixed-case-vs-claim-case-sensitive",
            False,
            {'user_claims': {"c": claim_str_range(9, mix_case=True),
                             "d": claim_str_range(9, case_sensitive=True)}},
            ('D:(XA;;FA;;;WD;(@USER.c == @USER.d))')
        ),
        (
            "9-disorderly-strings-claim-vs-claim-case-sensitive-mixed-case",
            False,
            {'user_claims': {"c": claim_str_range(9,random_seed=1),
                             "d": claim_str_range(9,
                                                  mix_case=True,
                                                  case_sensitive=True)}},
            ('D:(XA;;FA;;;WD;(@USER.c == @USER.d))')
        ),
        (
            "9-disorderly-strings-claim-vs-claim-case-sensitive-both-mixed-case",
            False,
            {'user_claims': {"c": claim_str_range(9,
                                                  mix_case=True,
                                                  random_seed=1),
                             "d": claim_str_range(9,
                                                  mix_case=True,
                                                  case_sensitive=True)}},
            ('D:(XA;;FA;;;WD;(@USER.c == @USER.d))')
        ),
        (
            "9-disorderly-strings-claim-vs-claim-case-sensitive-ne",
            True,
            {'user_claims': {"c": claim_str_range(9,random_seed=1),
                             "d": claim_str_range(9,
                                                  mix_case=True,
                                                  case_sensitive=True)}},
            ('D:(XA;;FA;;;WD;(@USER.c != @USER.d))')
        ),

        (
            "5-disorderly-strings-claim-vs-claim-case-sensitive-with-dupes-all-mixed-case",
            False,
            {'user_claims': {"c": claim_str_range(5,
                                                  mix_case=True,
                                                  random_seed=2),
                             "d": claim_str_range(5, 5,
                                                  mix_case=True,
                                                  random_seed=3,
                                                  case_sensitive=True)}},
            ('D:(XA;;FA;;;WD;(@USER.c == @USER.d))')
        ),
        (
            "90-disorderly-strings-claim-vs-int-claim",
            False,
            {'user_claims': {"c": claim_str_range(90,
                                                  random_seed=2),
                             "d": claim_int_range(90,
                                                  random_seed=3)}},
            ('D:(XA;;FA;;;WD;(@USER.c == @USER.d))')
        ),
        (
            "90-disorderly-ints-claim-vs-string-claim",
            False,
            {'user_claims': {"c": claim_int_range(90,
                                                  random_seed=2),
                             "d": claim_str_range(90,
                                                  random_seed=3)}},
            ('D:(XA;;FA;;;WD;(@USER.c == @USER.d))')
        ),
        (
            "9-disorderly-strings-vs-9+90-dupes",
            True,
            {'user_claims': {"c": claim_str_range(9, random_seed=1)}},
            (f'D:(XA;;FA;;;WD;(@USER.c == {composite_str(9, 90, random_seed=1)}))')
        ),
        (
            "9-disorderly-strings-vs-9+90-dupes-case-sensitive",
            True,
            {'user_claims': {"c": claim_str_range(9, random_seed=1, case_sensitive=True)}},
            (f'D:(XA;;FA;;;WD;(@USER.c == {composite_str(9, 90, random_seed=2)}))')
        ),
        (
            "9-disorderly-strings-vs-9+90-dupes-mixed-case",
            True,
            {'user_claims': {"c": claim_str_range(9, random_seed=1, mix_case=True)}},
            (f'D:(XA;;FA;;;WD;(@USER.c == {composite_str(9, 90, random_seed=2, mix_case=True)}))')
        ),
        (
            "9-disorderly-strings-vs-9+90-dupes-mixed-case-case-sensitive",
            False,
            {'user_claims': {"c": claim_str_range(9, random_seed=1, mix_case=True,
                                                  case_sensitive=True)}},
            (f'D:(XA;;FA;;;WD;(@USER.c == {composite_str(9, 90, random_seed=2, mix_case=True)}))')
        ),
        (
            "99-disorderly-strings-vs-9+90-dupes-mixed-case",
            False,
            {'user_claims': {"c": claim_str_range(99, random_seed=1, mix_case=True)}},
            (f'D:(XA;;FA;;;WD;(@USER.c == {composite_str(9, 90, random_seed=2, mix_case=True)}))')
        ),

        (
            "RA-99-disorderly-strings-vs-9+90-dupes-mixed-case",
            False,
            {},
            ('D:(XA;;FA;;;WD;(@RESOURCE.c == '
             f'{composite_str(9, 90, random_seed=1, mix_case=True)}))'
             f'S:{ra_str_range(99, random_seed=2, mix_case=True)}'
             )
        ),
        (
            "RA-9+90-dupes-disorderly-strings-vs-9+90-dupes-mixed-case",
            False,
            {},
            ('D:(XA;;FA;;;WD;(@RESOURCE.c == '
             f'{composite_str(9, 90, random_seed=1, mix_case=True)}))'
             f'S:{ra_str_range(9, 90, random_seed=2, mix_case=True)}'
             )
        ),
        (
            "90-disorderly-strings-claim-vs-missing-claim",
            False,
            {'user_claims': {"c": claim_str_range(90,
                                                  random_seed=2)}},
            ('D:(XA;;FA;;;WD;(@USER.c == @USER.d))')
        ),
        (
            "missing-claim-vs-90-disorderly-strings",
            False,
            {'user_claims': {"c": claim_str_range(90,
                                                  random_seed=2)}},
            ('D:(XA;;FA;;;WD;(@USER.z == @USER.c))')
        ),

        (
            "RA-9-disorderly-strings-vs-9-mixed-case",
            False,
            {'user_claims': {"c": claim_str_range(9,
                                                  random_seed=1,
                                                  mix_case=True),
                             }
             },
            ('D:(XA;;FA;;;WD;(@RESOURCE.c == @User.c))'
             f'S:{ra_str_range(9, random_seed=2, mix_case=True)}'
             )
        ),

        (
            "9-disorderly-strings-vs-9-RA-mixed-case",
            False,
            {'user_claims': {"c": claim_str_range(9,
                                                  random_seed=1,
                                                  mix_case=True),
                             }
             },
            ('D:(XA;;FA;;;WD;(@user.c == @resource.c))'
             f'S:{ra_str_range(9, random_seed=2, mix_case=True)}'
             )
        ),

        (
            "RA-29-disorderly-strings-vs-29-mixed-case",
            False,
            {'user_claims': {"c": claim_str_range(29,
                                                  random_seed=1,
                                                  mix_case=True),
                             }
             },
            ('D:(XA;;FA;;;WD;(@RESOURCE.c == @User.c))'
             f'S:{ra_str_range(29, random_seed=2, mix_case=True)}'
             )
        ),
        (
            "0-vs-0-ne",
            False,
            {'user_claims': {"c": claim_str_range(0)}},
            ('D:(XA;;FA;;;WD;(@USER.c != @USER.c))')
        ),
        (
            "1-vs-1",
            True,
            {'user_claims': {"c": claim_str_range(1)}},
            ('D:(XA;;FA;;;WD;(@USER.c == @USER.c))')
        ),
        (
            "1-vs-1-ne",
            False,
            {'user_claims': {"c": claim_str_range(1)}},
            ('D:(XA;;FA;;;WD;(@USER.c != @USER.c))')
        ),
    ]
