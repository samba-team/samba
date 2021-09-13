# Unix SMB/CIFS implementation.
#
# Copyright 2021 (C) Catalyst IT Ltd
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


import os
import sys
from samba.samdb import SamDB
from samba.auth import system_session
import ldb
from samba.tests.subunitrun import SubunitOptions, TestProgram
from samba.tests import TestCase, ldb_err
from samba.tests import DynamicTestCase
import samba.getopt as options
import optparse
from samba.colour import c_RED, c_GREEN, c_DARK_YELLOW
import re
import pprint
from samba.dsdb import (
    UF_SERVER_TRUST_ACCOUNT,
    UF_TRUSTED_FOR_DELEGATION,
)


# bad sAMAccountName characters from [MS-SAMR]
# "3.1.1.6 Attribute Constraints for Originating Updates"
BAD_SAM_CHARS = (''.join(chr(x) for x in range(0, 32)) +
                 '"/\\[]:|<>+=;?,*')

# 0x7f is *said* to be bad, but turns out to be fine.
ALLEGED_BAD_SAM_CHARS = chr(127)

LATIN1_BAD_CHARS = set([chr(x) for x in range(129, 160)] +
                       list("ªºÿ") +
                       [chr(x) for x in range(0xc0, 0xc6)] +
                       [chr(x) for x in range(0xc7, 0xd7)] +
                       [chr(x) for x in range(0xd8, 0xde)] +
                       [chr(x) for x in range(0xe0, 0xe6)] +
                       [chr(x) for x in range(0xe7, 0xf7)] +
                       [chr(x) for x in range(0xf8, 0xfe)])


LATIN_EXTENDED_A_NO_CLASH = {306, 307, 330, 331, 338, 339, 358, 359, 383}

#XXX does '\x00' just truncate the string though?
#XXX elsewhere we see "[\\\"|,/:<>+=;?*']" with "'"


## UPN limits
# max length 1024 UTF-8 bytes, following "rfc822"
# for o365 sync https://docs.microsoft.com/en-us/microsoft-365/enterprise/prepare-for-directory-synchronization?view=o365-worldwide
# max length is 113 [64 before @] "@" [48 after @]
# invalid chars: '\\%&*+/=?{}|<>();:,[]"'
# allowed chars: A – Z, a - z, 0 – 9, ' . - _ ! # ^ ~
# "Letters with diacritical marks, such as umlauts, accents, and tildes, are invalid characters."
#
# "@" can't be first
# "The username cannot end with a period (.), an ampersand (&), a space, or an at sign (@)."
#

# per RFC 822, «"a b" @ example.org» is


ok = True
bad = False
report = 'report'
exists = ldb.ERR_ENTRY_ALREADY_EXISTS


if sys.stdout.isatty():
    c_doc = c_DARK_YELLOW
else:
    c_doc = lambda x: x


def get_samdb():
    return SamDB(url=f"ldap://{SERVER}",
                 lp=LP,
                 session_info=system_session(),
                 credentials=CREDS)


def format(s):
    if type(s) is str:
        s = s.format(realm=REALM.upper(),
                     lrealm=REALM.lower(),
                     other_realm=(REALM + ".another.example.net"))
    return s


class LdapUpnSamTestBase(TestCase):
    """Make sure we can't add userPrincipalNames or sAMAccountNames that
    implicitly collide.
    """
    _disabled = False

    @classmethod
    def setUpDynamicTestCases(cls):
        if getattr(cls, '_disabled', False):
            return
        for doc, *rows in cls.cases:
            name = re.sub(r'\W+', '_', doc)
            cls.generate_dynamic_test("test_upn_sam", name, rows, doc)

    def setup_objects(self, rows):
        objects = set(r[0] for r in rows)
        for name in objects:
            if ':' in name:
                objtype, name = name.split(':', 1)
            else:
                objtype = 'user'
            getattr(self, f'add_{objtype}')(name)
            self.addCleanup(self.remove_object, name)

    def _test_upn_sam_with_args(self, rows, doc):
        self.setup_objects(rows)
        cdoc = c_doc(doc)

        for i, row in enumerate(rows):
            if len(row) == 4:
                obj, data, expected, op = row
            else:
                obj, data, expected = row
                op = ldb.FLAG_MOD_REPLACE

            dn, dnsname = self.objects[obj]
            sam, upn = None, None
            if isinstance(data, dict):
                sam = data.get('sam')
                upn = data.get('upn')
            elif isinstance(data, str):
                if '@' in data:
                    upn = data
                else:
                    sam = data
            else:  # bytes
                if b'@' in data:
                    upn = data
                else:
                    sam = data

            m = {"dn": dn}

            if upn is not None:
                m["userPrincipalName"] = format(upn)

            if sam is not None:
                m["sAMAccountName"] = format(sam)

            msg = ldb.Message.from_dict(self.samdb, m, op)

            if expected is bad:
                try:
                    self.samdb.modify(msg)
                except ldb.LdbError as e:
                    print(f"row {i+1} of '{cdoc}' failed as expected with "
                          f"{ldb_err(e)}\n")
                    continue
                self.fail(f"row {i+1} of '{cdoc}' should have failed:\n"
                          f"{pprint.pformat(m)} on {obj}")
            elif expected is ok:
                try:
                    self.samdb.modify(msg)
                except ldb.LdbError as e:
                    raise AssertionError(
                        f"row {i+1} of '{cdoc}' failed with {ldb_err(e)}:\n"
                        f"{pprint.pformat(m)} on {obj}") from None
            elif expected is report:
                try:
                    self.samdb.modify(msg)
                    print(f"row {i+1} of '{cdoc}' SUCCEEDED:\n"
                          f"{pprint.pformat(m)} on {obj}")
                except ldb.LdbError as e:
                    print(f"row {i+1} of '{cdoc}' FAILED "
                          f"with {ldb_err(e)}:\n"
                          f"{pprint.pformat(m)} on {obj}")

            else:
                try:
                    self.samdb.modify(msg)
                except ldb.LdbError as e:
                    if hasattr(expected, '__contains__'):
                        if e.args[0] in expected:
                            continue

                    if e.args[0] == expected:
                        continue

                    self.fail(f"row {i+1} of '{cdoc}' "
                              f"should have failed with {ldb_err(expected)} "
                              f"but instead failed with {ldb_err(e)}:\n"
                              f"{pprint.pformat(m)} on {obj}")
                self.fail(f"row {i+1} of '{cdoc}' "
                          f"should have failed with {ldb_err(expected)}:\n"
                          f"{pprint.pformat(m)} on {obj}")

    def add_dc(self, name):
        dn = f"CN={name},OU=Domain Controllers,{self.base_dn}"
        dnsname = f"{name}.{REALM}".lower()
        self.samdb.add({
            "dn": dn,
            "objectclass": "computer",
            "userAccountControl": str(UF_SERVER_TRUST_ACCOUNT |
                                      UF_TRUSTED_FOR_DELEGATION),
            "dnsHostName": dnsname,
            "carLicense": self.id()
        })
        self.objects[name] = (dn, dnsname)

    def add_user(self, name):
        dn = f"CN={name},{self.ou}"
        self.samdb.add({
            "dn": dn,
            "name": name,
            "objectclass": "user",
            "carLicense": self.id()
        })
        self.objects[name] = (dn, None)

    def remove_object(self, name):
        dn, dnsname = self.objects.pop(name)
        self.samdb.delete(dn)

    def setUp(self):
        super().setUp()
        self.samdb = get_samdb()
        self.base_dn = self.samdb.get_default_basedn()
        self.short_id = self.id().rsplit('.', 1)[1][:63]
        self.objects = {}
        self.ou = f"OU={ self.short_id },{ self.base_dn }"
        self.addCleanup(self.samdb.delete, self.ou, ["tree_delete:1"])
        self.samdb.add({"dn": self.ou, "objectclass": "organizationalUnit"})


@DynamicTestCase
class LdapUpnSamTest(LdapUpnSamTestBase):
    cases = [
        # The structure is
        # ( «documentation/message that becomes test name»,
        #    («short object id», «upn or sam or mapping», «expected»),
        #    («short object id», «upn or sam or mapping», «expected»),
        #    ...,
        # )
        #
        # where the first item is a one line string explaining the
        # test, and subsequent items describe database modifications,
        # to be applied in series.
        #
        # First is a short ID, which maps to an object DN. Second is
        # either a string or a dictionary.
        #
        # * If a string, if it contains '@', it is a UPN, otherwise a
        #   samaccountname.
        #
        # * If a dictionary, it is a mapping of some of ['sam', 'upn']
        #   to strings (in this way, you can add two attributes in one
        #   mesage, or attempt a samaccountname with '@').
        #
        # expected can be «ok», «bad» (mapped to True and False,
        # respectively), or a specific LDB error code, if that exact
        # exception is wanted.
        ("add good UPN",
         ('A', 'a@{realm}', ok),
        ),
        ("add the same upn to different objects",
         ('A', 'a@{realm}', ok),
         ('B', 'a@{realm}', ldb.ERR_CONSTRAINT_VIOLATION),
         ('B', 'a@{lrealm}', ldb.ERR_CONSTRAINT_VIOLATION),  # lowercase realm
        ),
        ("replace UPN with itself",
         ('A', 'a@{realm}', ok),
         ('A', 'a@{realm}', ok),
         ('A', 'a@{lrealm}', ok),
        ),
        ("replace SAM with itself",
         ('A', 'a', ok),
         ('A', 'a', ok),
        ),
        ("replace UPN realm",
         ('A', 'a@{realm}', ok),
         ('A', 'a@{other_realm}', ok),
        ),
        ("matching SAM and UPN",
         ('A', 'a', ok),
         ('A', 'a@{realm}', ok),
        ),
        ("matching SAM and UPN, other realm",
         ('A', 'a', ok),
         ('A', 'a@{other_realm}', ok),
        ),
        ("matching SAM and UPN, single message",
         ('A', {'sam': 'a', 'upn': 'a@{realm}'}, ok),
         ('A', {'sam': 'a', 'upn': 'a@{other_realm}'}, ok),
        ),
        ("different objects, different realms",
         ('A', 'a@{realm}', ok),
         ('B', 'a@{other_realm}', ok),
        ),
        ("different objects, same UPN, different case",
         ('A', 'a@{realm}', ok),
         ('B', 'A@{realm}', ldb.ERR_CONSTRAINT_VIOLATION),
        ),
        ("different objects, SAM after UPN",
         ('A', 'a@{realm}', ok),
         ('B', 'a', ldb.ERR_CONSTRAINT_VIOLATION),
        ),
        ("different objects, SAM before UPN",
         ('A', 'a', ok),
         ('B', 'a@{realm}', exists),
        ),
        ("different objects, SAM account clash",
         ('A', 'a', ok),
         ('B', 'a', exists),
        ),
        ("different objects, SAM account clash, different case",
         ('A', 'a', ok),
         ('B', 'A', exists),
        ),
        ("two way clash",
         ('A', {'sam': 'x', 'upn': 'y@{realm}'}, ok),
         # The sam account raises EXISTS while the UPN raises
         # CONSTRAINT_VIOLATION. We don't really care in which order
         # they are checked, so either error is ok.
         ('B', {'sam': 'y', 'upn': 'x@{realm}'},
          (exists, ldb.ERR_CONSTRAINT_VIOLATION)),
        ),
        ("two way clash, other realm",
         ('A', {'sam': 'x', 'upn': 'y@{other_realm}'}, ok),
         ('B', {'sam': 'y', 'upn': 'x@{other_realm}'}, ok),
        ),
        # UPN versions of bad sam account names
        ("UPN clash on other realm",
         ('A', 'a@x.x', ok),
         ('B', 'a@x.x', ldb.ERR_CONSTRAINT_VIOLATION),
        ),
        ("UPN same but for trailing spaces",
         ('A', 'a@{realm}', ok),
         ('B', 'a @{realm}', ok),
        ),
        # UPN has no at
        ("UPN has no at",
         ('A', {'upn': 'noat'}, ok),
         ('B', {'upn': 'noat'}, ldb.ERR_CONSTRAINT_VIOLATION),
         ('C', {'upn': 'NOAT'}, ldb.ERR_CONSTRAINT_VIOLATION),
        ),
        # UPN has non-ascii at, followed by real at.
        ("UPN with non-ascii at vs real at",
         ('A', {'upn': 'smallat﹫{realm}'}, ok),
         ('B', {'upn': 'smallat@{realm}'}, ok),
         ('C', {'upn': 'tagat\U000e0040{realm}'}, ok),
         ('D', {'upn': 'tagat@{realm}'}, ok),
        ),
        ("UPN with unicode at vs real at, real at first",
         ('B', {'upn': 'smallat@{realm}'}, ok),
         ('A', {'upn': 'smallat﹫{realm}'}, ok),
         ('D', {'upn': 'tagat@{realm}'}, ok),
         ('C', {'upn': 'tagat\U000e0040{realm}'}, ok),
        ),
        ("UPN username too long",
         #  SPN soft limit 20; hard limit 256, overall UPN 1024
         ('A', 'a' * 25 + '@b.c', ok),
         ('A', 'a' * 65 + '@b.c', ok),   # Azure AD limit is 64
         ('A', 'a' * 257 + '@b.c', ok),  # 256 is sam account name limit
        ),
        ("sam account name 20 long",
         #  SPN soft limit 20
         ('A', 'a' * 20, ok),
        ),
        ("UPN has two at signs",
         ('A', 'a@{realm}', ok),
         ('A', 'a@{realm}@{realm}', ok),
         ('A', 'a@a.b', ok),
         ('A', 'a@a@a.b', ok),
        ),
        ("SAM has at signs clashing upn second, non-realm",
         ('A', {'sam': 'a@a.b'}, ok),
         ('B', 'a@a.b@a.b', ok),  # UPN won't clash with SAM, because realm
        ),
        ("SAM has at signs clashing upn second",
         ('A', {'sam': 'a@{realm}'}, ok),
         ('B', 'a@{realm}@{realm}', bad),  # UPN would clashes with SAM
        ),
        ("SAM has at signs clashing upn first",
         ('B', 'a@{realm}@{realm}', ok),
         ('A', {'sam': 'a@{realm}'}, bad),
        ),
        ("spaces around at",
         ('A', 'a name @ {realm}', ok),
         ('B', 'a name @ {realm}', ldb.ERR_CONSTRAINT_VIOLATION),
         ('B', 'a name @{realm}', ok),  # because realm looks different
         ('C', 'a name@{realm}', ok),
         ('D', 'a name', ldb.ERR_CONSTRAINT_VIOLATION),
         ('D', 'a name ', (exists, ldb.ERR_CONSTRAINT_VIOLATION)),  # matches B
        ),
        ("SAM starts with at",
         ('A', {'sam': '@{realm}'}, ok),
         ('B', {'sam': '@a'}, ok),
         ('C', {'sam': '@{realm}'}, exists),
         ('C', {'sam': '@a'}, exists),
         ('C', {'upn': '@{realm}@{realm}'}, bad),
         ('C', {'upn': '@a@{realm}'}, bad),
        ),
        ("UPN starts with at",
         ('A', {'upn': '@{realm}'}, ok),
         ('B', {'upn': '@a@{realm}'}, ok),
         ('C', {'upn': '@{realm}'}, bad),
         ('C', {'sam': '@a'}, bad),
        ),
        ("SAM ends with at",
         ('A', {'sam': '{realm}@'}, ok),
         ('B', {'sam': 'a@'}, ok),
         ('C', {'sam': '{realm}@'}, exists),
         ('C', {'sam': 'a@'}, exists),
         ('C', {'upn': 'a@@{realm}'}, bad),
         ('C', {'upn': '{realm}@@{realm}'}, bad),
        ),
        ("UPN ends with at",
         ('A', {'upn': '{realm}@'}, ok),
         ('B', {'upn': '@a@{realm}@'}, ok),
         ('C', {'upn': '{realm}@'}, bad),
         ('C', {'sam': '@a@{realm}'}, ok),  # not like B, because other realm
        ),
    ]


@DynamicTestCase
class LdapUpnSamSambaOnlyTest(LdapUpnSamTestBase):
    # We don't run these ones outside of selftest, where we are
    # probably testing against Windows and these are known failures.
    _disabled = 'SAMBA_SELFTEST' not in os.environ
    cases = [
        ("sam account name too long",
         # SPN soft limit 20
         ('A', 'a' * 19, ok),
         ('A', 'a' * 20, ok),
         ('A', 'a' * 65, ok),
         ('A', 'a' * 255, ok),
         ('A', 'a' * 256, ok),
         ('A', 'a' * 257, ldb.ERR_INVALID_ATTRIBUTE_SYNTAX),
        ),
        ("UPN username too long",
         ('A', 'a' * 254 + '@' + 'b.c' * 257,
          ldb.ERR_INVALID_ATTRIBUTE_SYNTAX),  # 1024 is alleged UPN limit
        ),
        ("UPN same but for internal spaces",
         ('A', 'a b@x.x', ok),
         ('B', 'a  b@x.x', ldb.ERR_CONSTRAINT_VIOLATION),
        ),
        ("SAM contains delete",
         # forbidden according to documentation, but works in practice on Windows
         ('A', 'a\x7f', ldb.ERR_CONSTRAINT_VIOLATION),
         ('A', 'a\x7f'.encode(), ldb.ERR_CONSTRAINT_VIOLATION),
         ('A', 'a\x7fb', ldb.ERR_CONSTRAINT_VIOLATION),
         ('A', 'a\x7fb'.encode(), ldb.ERR_CONSTRAINT_VIOLATION),
         ('A', '\x7fb', ldb.ERR_CONSTRAINT_VIOLATION),
         ('A', '\x7fb'.encode(), ldb.ERR_CONSTRAINT_VIOLATION),
         ),
        # The wide at symbol ('＠' U+FF20) does not count as '@' for Samba
        # so it will look like a string with no @s.
        ("UPN with unicode wide at vs real at",
         ('A', {'upn': 'wideat＠{realm}'}, ok),
         ('B', {'upn': 'wideat@{realm}'}, ok),
        ),
        ("UPN with real at vs wide at",
         ('B', {'upn': 'wideat@{realm}'}, ok),
         ('A', {'upn': 'wideat＠{realm}'}, ok)
        ),
    ]


def main():
    global LP, CREDS, SERVER, REALM

    parser = optparse.OptionParser(
        "python3 ldap_upn_sam_account_name.py <server> [options]")
    sambaopts = options.SambaOptions(parser)
    parser.add_option_group(sambaopts)

    # use command line creds if available
    credopts = options.CredentialsOptions(parser)
    parser.add_option_group(credopts)
    subunitopts = SubunitOptions(parser)
    parser.add_option_group(subunitopts)

    opts, args = parser.parse_args()
    if len(args) != 1:
        parser.print_usage()
        sys.exit(1)

    LP = sambaopts.get_loadparm()
    CREDS = credopts.get_credentials(LP)
    SERVER = args[0]
    REALM = CREDS.get_realm()

    TestProgram(module=__name__, opts=subunitopts)

main()
