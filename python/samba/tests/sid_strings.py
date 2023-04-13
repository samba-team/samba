# Unix SMB/CIFS implementation.
# Copyright (C) Catalyst.NET Ltd 2022
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

import os
import string
import sys
import time
from hashlib import blake2b

import ldb

from samba import param

from samba.auth import system_session
from samba.credentials import Credentials
from samba.dcerpc import security
from samba.ndr import ndr_unpack
from samba.samdb import SamDB
from samba.tests import (
    DynamicTestCase,
    TestCase,
    delete_force,
    env_get_var_value,
)

sys.path.insert(0, 'bin/python')
os.environ['PYTHONUNBUFFERED'] = '1'


late_ERR_CONSTRAINT_VIOLATION = b"a hack to allow Windows to sometimes fail late"


class SidStringBase(TestCase):
    @classmethod
    def setUpDynamicTestCases(cls):
        if not hasattr(cls, 'skip_local'):
            cls.skip_local = env_get_var_value('SAMBA_SID_STRINGS_SKIP_LOCAL',
                                               allow_missing=True)

        if env_get_var_value('CHECK_ALL_COMBINATIONS',
                             allow_missing=True):
            for x in string.ascii_uppercase:
                for y in string.ascii_uppercase:
                    code = x + y
                    if code not in cls.cases:
                        cls.cases[code] = None

        for code, expected_sid in cls.cases.items():
            name = code

            cls.generate_dynamic_test('test_sid_string', name,
                                      code, expected_sid)
            if not cls.skip_local:
                cls.generate_dynamic_test('test_sid_string_internal', name,
                                          code, expected_sid)

    @classmethod
    def setUpClass(cls):
        super().setUpClass()

        server = os.environ['DC_SERVER']
        host = f'ldap://{server}'

        lp = param.LoadParm()
        lp.load(os.environ['SMB_CONF_PATH'])

        creds = Credentials()
        creds.guess(lp)
        creds.set_username(env_get_var_value('DC_USERNAME'))
        creds.set_password(env_get_var_value('DC_PASSWORD'))

        cls.ldb = SamDB(host, credentials=creds,
                        session_info=system_session(lp), lp=lp)
        cls.base_dn = cls.ldb.domain_dn()
        cls.schema_dn = cls.ldb.get_schema_basedn().get_linearized()
        cls.timestamp = str(int(time.time()))
        cls.domain_sid = cls.ldb.get_domain_sid()

    def _test_sid_string_with_args(self, code, expected_sid):
        suffix = int(blake2b(code.encode(), digest_size=3).hexdigest(), 16)

        class_name = f'my-Sid-String-Class-{self.timestamp}-{suffix}'
        class_ldap_display_name = class_name.replace('-', '')

        class_dn = f'CN={class_name},{self.schema_dn}'

        governs_id = f'1.3.6.1.4.1.7165.4.6.2.9.{self.timestamp[-8:]}.{suffix}'

        # expected_sid can be a SID string, an error code, None, or a
        # special value indicating a deferred error, as follows:
        #
        #  * a number represents the expected error code at the *first*
        #    hurdle, creating the classSchema object.
        #
        #  * late_ERR_CONSTRAINT_VIOLATION means an error when
        #    creating an object based on the class schema.
        #
        #  * None means a somewhat unspecified error or failure to set
        #    the object owner sid.
        #
        #  * a string is the expected owner sid. The rid is borrowed
        #  * and tacked onto the governs-id.

        if expected_sid is None:
            expected_err = ldb.ERR_UNWILLING_TO_PERFORM
        elif isinstance(expected_sid, int):
            expected_err = expected_sid
        elif expected_sid is late_ERR_CONSTRAINT_VIOLATION:
            expected_err = None
        else:
            expected_err = None
            # Append the RID to our OID to ensure more uniqueness.
            rid = expected_sid.rsplit('-', 1)[1]
            governs_id += f'.{rid}'

        ldif = f'''
dn: {class_dn}
objectClass: classSchema
cn: {class_name}
governsId: {governs_id}
subClassOf: top
possSuperiors: domainDNS
defaultSecurityDescriptor: O:{code}
'''
        try:
            self.ldb.add_ldif(ldif)
        except ldb.LdbError as err:
            num, _ = err.args
            self.assertEqual(num, expected_err)
            return
        else:
            if isinstance(expected_sid, int):
                self.fail("should have failed")

        # Search for created objectclass
        res = self.ldb.search(class_dn, scope=ldb.SCOPE_BASE,
                              attrs=['defaultSecurityDescriptor'])
        self.assertEqual(1, len(res))
        self.assertEqual(res[0].get('defaultSecurityDescriptor', idx=0),
                         f'O:{code}'.encode('utf-8'))

        ldif = '''
dn:
changetype: modify
add: schemaUpdateNow
schemaUpdateNow: 1
'''
        self.ldb.modify_ldif(ldif)

        object_name = f'sddl_{self.timestamp}_{suffix}'
        object_dn = f'CN={object_name},{self.base_dn}'

        ldif = f'''
dn: {object_dn}
objectClass: {class_ldap_display_name}
cn: {object_name}
'''
        if expected_sid is late_ERR_CONSTRAINT_VIOLATION:
            expected_err = ldb.ERR_CONSTRAINT_VIOLATION

        try:
            self.ldb.add_ldif(ldif)
        except ldb.LdbError as err:
            num, _ = err.args
            self.assertEqual(num, expected_err)
            return

        if expected_sid is not None:
            self.assertIsNone(expected_err)

        # Search for created object
        res = self.ldb.search(object_dn, scope=ldb.SCOPE_BASE,
                              attrs=['nTSecurityDescriptor'])
        self.assertEqual(1, len(res))

        # Delete the object
        delete_force(self.ldb, object_dn)

        data = res[0].get('nTSecurityDescriptor', idx=0)
        descriptor = ndr_unpack(security.descriptor, data)

        expected_sid = self.format_expected_sid(expected_sid)
        owner_sid = str(descriptor.owner_sid)
        self.assertEqual(expected_sid, owner_sid)

    def format_expected_sid(self, expected_sid):
        if expected_sid is None:
            return f'{self.domain_sid}-{security.DOMAIN_RID_ADMINS}'

        if not isinstance(expected_sid, str):
            # never going to match, should have failed already
            return None

        return expected_sid.format(domain_sid=self.domain_sid)

    def _test_sid_string_internal_with_args(self, code, expected_sid):
        """We just want to test the SIDs, which Samba can't really do because
        it doesn't parse them until creating an object using the
        schema class, at which time it doesn't distinguish between a
        missing value and a nonsense value.

        So let's also run the test using libcli/security/sddl.c and
        see what we *would* have done.
        """
        sddl = f"O:{code}"
        domsid = security.dom_sid(self.domain_sid)

        try:
            sd = security.descriptor.from_sddl(sddl, domsid)
        except ValueError:
            # we don't have detail as to what went wrong
            self.assertNotIsInstance(expected_sid, str)
        else:
            expected_sid = self.format_expected_sid(expected_sid)
            self.assertEqual(expected_sid, str(sd.owner_sid))


@DynamicTestCase
class SidStringTests(SidStringBase):
    """Testing two letter aliases."""
    cases = {
        'AA': 'S-1-5-32-579',
        'AC': 'S-1-15-2-1',
        'AN': 'S-1-5-7',
        'AO': 'S-1-5-32-548',
        'AP': '{domain_sid}-525',
        'AS': 'S-1-18-1',
        'AU': 'S-1-5-11',
        'BA': 'S-1-5-32-544',
        'BG': 'S-1-5-32-546',
        'BO': 'S-1-5-32-551',
        'BU': 'S-1-5-32-545',
        'CA': '{domain_sid}-517',
        'CD': 'S-1-5-32-574',
        'CG': 'S-1-3-1',
        'CN': '{domain_sid}-522',
        'CO': 'S-1-3-0',
        'CY': 'S-1-5-32-569',
        'DC': '{domain_sid}-515',
        'DD': '{domain_sid}-516',
        'DG': '{domain_sid}-514',
        'DU': '{domain_sid}-513',
        'EA': '{domain_sid}-519',
        'ED': 'S-1-5-9',
        'EK': '{domain_sid}-527',
        'ER': 'S-1-5-32-573',
        'ES': 'S-1-5-32-576',
        'HA': 'S-1-5-32-578',
        'HI': 'S-1-16-12288',
        'IS': 'S-1-5-32-568',
        'IU': 'S-1-5-4',
        'KA': '{domain_sid}-526',
        'LA': '{domain_sid}-500',
        'LG': '{domain_sid}-501',
        'LS': 'S-1-5-19',
        'LU': 'S-1-5-32-559',
        'LW': 'S-1-16-4096',
        'ME': 'S-1-16-8192',
        'MP': 'S-1-16-8448',
        'MS': 'S-1-5-32-577',
        'MU': 'S-1-5-32-558',
        'NO': 'S-1-5-32-556',
        'NS': 'S-1-5-20',
        'NU': 'S-1-5-2',
        'OW': 'S-1-3-4',
        'PA': '{domain_sid}-520',
        'PO': 'S-1-5-32-550',
        'PS': 'S-1-5-10',
        'PU': 'S-1-5-32-547',
        'RA': 'S-1-5-32-575',
        'RC': 'S-1-5-12',
        'RD': 'S-1-5-32-555',
        'RE': 'S-1-5-32-552',
        'RM': 'S-1-5-32-580',
        'RO': '{domain_sid}-498',
        'RS': '{domain_sid}-553',
        'RU': 'S-1-5-32-554',
        'SA': '{domain_sid}-518',
        'SI': 'S-1-16-16384',
        'SO': 'S-1-5-32-549',
        'SS': 'S-1-18-2',
        'SU': 'S-1-5-6',
        'SY': 'S-1-5-18',
        # Not tested, as it always gives us an OPERATIONS_ERROR with Windows.
        # 'UD': 'S-1-5-84-0-0-0-0-0',
        'WD': 'S-1-1-0',
        'WR': 'S-1-5-33',
        'aa': 'S-1-5-32-579',
        'Aa': 'S-1-5-32-579',
        'aA': 'S-1-5-32-579',
        'BR': None,
        'IF': None,
        'LK': None,
    }


@DynamicTestCase
class SidStringsThatStartWithS(SidStringBase):
    """Testing normal or normal-adjacent SIDs"""
    cases = {
        # testing explicit string to string round trips.
        'S-1-5-32-579': 'S-1-5-32-579',
        'S-1-5-0x20-579': 'S-1-5-32-579',  # hex
        'S-1-0x05-32-579': 'S-1-5-32-579',
        'S-1-5-040-579': 'S-1-5-40-579',   # no octal
        'S-1-0x50000000-32-579': 'S-1-1342177280-32-579',
        'S-1-0x500000000-32-579': 'S-1-0x500000000-32-579',
        'S-1-21474836480-32-579': 'S-1-0x500000000-32-579',  # >32 bit is hex
        f'S-1-5-{(1 << 32) - 1}-579': 'S-1-5-4294967295-579',
        f'S-1-{(1 << 48) - 1}-579': 'S-1-0xffffffffffff-579',
        f'S-1-{(1 << 48)}-579': ldb.ERR_UNWILLING_TO_PERFORM,
        'S-1-99999999999999999999999999999999999999-32-11111111111': ldb.ERR_UNWILLING_TO_PERFORM,
        'S-1-5-0-579': 'S-1-5-0-579',
        'S-1-0-0-579': 'S-1-0-0-579',
        'S-1-0x5-0x20-0x243': 'S-1-5-32-579',
        'S-1-5-32--579': ldb.ERR_UNWILLING_TO_PERFORM,
        'S-1-5-32- 579': ldb.ERR_UNWILLING_TO_PERFORM,
        'S-1-5-32 -579': ldb.ERR_UNWILLING_TO_PERFORM,
        'S-1-5-3 2-579': ldb.ERR_UNWILLING_TO_PERFORM,
        ' S-1-1-1-1-1-1-1': ldb.ERR_UNWILLING_TO_PERFORM,
        # go to lower case in hex.
        'S-1-0xABcDef123-0xABCDef-579': 'S-1-0xabcdef123-11259375-579',
        'S-1-1-1-1-1-1-1': 'S-1-1-1-1-1-1-1',
        's-1-5-32-579': 'S-1-5-32-579',
        'S-01-5-32-579': 'S-1-5-32-579',
        'S-000000001-5-32-579': 'S-1-5-32-579',
        # some strings from https://bugzilla.samba.org/show_bug.cgi?id=14213
        'S-1-0': ldb.ERR_UNWILLING_TO_PERFORM,
        'S-1-22': ldb.ERR_UNWILLING_TO_PERFORM,
        'S-1-22-1': 'S-1-22-1',
        'S-1-22-1-0': 'S-1-22-1-0',
        'S-1-3-0': 'S-1-3-0',
        'S-1-3-99': 'S-1-3-99',
        'S-01-05-020-0243': 'S-1-5-20-243',
        'S-000000000001-5-20-243': 'S-1-5-20-243',
        'S-1-000000000000000005-20-243': 'S-1-5-20-243',
        'S-1-5-20-00000000000243': 'S-1-5-20-243',
    }


@DynamicTestCase
class SidStringBehavioursThatWindowsAllows(SidStringBase):
    """Windows interpretations that we probably don't want to follow"""
    cases = {
        # saturating sub-auth values at 32 bits
        'S-1-5-9999999999-579': 'S-1-5-4294967295-579',
        'S-1-0x500000000-0x500000000-579': 'S-1-0x500000000-4294967295-579',
        'S-1-5-11111111111111111111111111111111111-579': 'S-1-5-4294967295-579',
        f'S-1-5-{(1 << 64) - 1}-579': 'S-1-5-4294967295-579',
        f'S-1-5-{1 << 64}-579': 'S-1-5-4294967295-579',
        # S-0x1- ?! on Windows this makes everything else a hex number.
        'S-0x1-5-40-579': 'S-1-5-64-1401',
        'S-0x1-0-0-579': 'S-1-0-0-1401',
        'S-0x1-500000000-20-243': 'S-1-0x500000000-32-579',
        'S-0x1-5-20-243': 'S-1-5-32-579',
        'S-0x1-0x5-020-0243': 'S-1-5-32-579',
        'S-1-0xABcDef123-0xABCDef123-579': 'S-1-0xabcdef123-4294967295-579',

        'S-0-5-32-579': late_ERR_CONSTRAINT_VIOLATION,
        'S-2-5-32-579': late_ERR_CONSTRAINT_VIOLATION,
        'S-10-5-32-579': late_ERR_CONSTRAINT_VIOLATION,
    }


@DynamicTestCase
class SidStringBehavioursThatSambaPrefers(SidStringBase):
    """Aspirational alternative answers to the
    SidStringBehavioursThatWindowsAllows cases."""
    cases = {
        'S-1-5-9999999999-579': ldb.ERR_UNWILLING_TO_PERFORM,
        'S-1-0x500000000-0x500000000-579': ldb.ERR_UNWILLING_TO_PERFORM,
        'S-1-5-11111111111111111111111111111111111-579': ldb.ERR_UNWILLING_TO_PERFORM,
        f'S-1-5-{(1 << 64) - 1}-579': ldb.ERR_UNWILLING_TO_PERFORM,
        f'S-1-5-{1 << 64}-579': ldb.ERR_UNWILLING_TO_PERFORM,
        'S-0x1-5-40-579': ldb.ERR_UNWILLING_TO_PERFORM,
        'S-0x1-0-0-579': ldb.ERR_UNWILLING_TO_PERFORM,
        'S-0x1-500000000-20-243': ldb.ERR_UNWILLING_TO_PERFORM,
        'S-0x1-5-20-243': ldb.ERR_UNWILLING_TO_PERFORM,
        'S-0x1-0x5-020-0243': ldb.ERR_UNWILLING_TO_PERFORM,
        'S-1-0xABcDef123-0xABCDef123-579': ldb.ERR_UNWILLING_TO_PERFORM,

        'S-0-5-32-579': ldb.ERR_UNWILLING_TO_PERFORM,
        'S-2-5-32-579': ldb.ERR_UNWILLING_TO_PERFORM,
        'S-10-5-32-579': ldb.ERR_UNWILLING_TO_PERFORM,
    }


@DynamicTestCase
class SidStringsAsDnInSearchBase(SidStringBase):
    """How does a bad <SID=x> dn work as a search base, if at all?

    This suggests that Windows does the SID parsing
    (INVALID_DN_SYNTAX) before starting the search (NO_SUCH_OBJECT).

    Currently Samba does not.
    """
    skip_local = True
    cases = {' S-1-1-1-1-1-1-1': ldb.ERR_INVALID_DN_SYNTAX,
             'S-0-5-32-579': ldb.ERR_INVALID_DN_SYNTAX,
             'S-000000000001-5-20-243': ldb.ERR_INVALID_DN_SYNTAX,
             'S-000000001-5-32-579': ldb.ERR_INVALID_DN_SYNTAX,
             'S-01-05-020-0243': ldb.ERR_NO_SUCH_OBJECT,
             'S-01-5-32-11579': ldb.ERR_NO_SUCH_OBJECT,
             'S-0x1-0-0-579': ldb.ERR_INVALID_DN_SYNTAX,
             'S-0x1-0x5-020-0243': ldb.ERR_INVALID_DN_SYNTAX,
             'S-0x1-5-20-243': ldb.ERR_INVALID_DN_SYNTAX,
             'S-0x1-5-40-579': ldb.ERR_INVALID_DN_SYNTAX,
             'S-0x1-500000000-20-243': ldb.ERR_INVALID_DN_SYNTAX,
             'S-1-0': ldb.ERR_NO_SUCH_OBJECT,
             'S-1-0-0-579': ldb.ERR_NO_SUCH_OBJECT,
             'S-1-0x05-32-11579': ldb.ERR_NO_SUCH_OBJECT,
             'S-1-0x5-0x20-0x243': ldb.ERR_NO_SUCH_OBJECT,
             'S-1-0x50000000-32-579': ldb.ERR_NO_SUCH_OBJECT,
             'S-1-0x500000000-0x500000000-579': ldb.ERR_NO_SUCH_OBJECT,
             'S-1-0x500000000-32-579': ldb.ERR_NO_SUCH_OBJECT,
             'S-1-0xABcDef123-0xABCDef123-579': ldb.ERR_NO_SUCH_OBJECT,
             'S-1-1-1-1-1-1-1': ldb.ERR_NO_SUCH_OBJECT,
             'S-1-21474836480-32-579': ldb.ERR_NO_SUCH_OBJECT,
             'S-1-22': ldb.ERR_NO_SUCH_OBJECT,
             'S-1-22-1': ldb.ERR_NO_SUCH_OBJECT,
             'S-1-22-1-0': ldb.ERR_NO_SUCH_OBJECT,
             'S-1-281474976710655-579': ldb.ERR_NO_SUCH_OBJECT,
             'S-1-281474976710656-579': ldb.ERR_INVALID_DN_SYNTAX,
             'S-1-3-0': ldb.ERR_NO_SUCH_OBJECT,
             'S-1-3-99': ldb.ERR_NO_SUCH_OBJECT,
             'S-1-5-0-579': ldb.ERR_NO_SUCH_OBJECT,
             'S-1-5-040-579': ldb.ERR_NO_SUCH_OBJECT,
             'S-1-5-0x20-579': ldb.ERR_NO_SUCH_OBJECT,
             'S-1-5-11111111111111111111111111111111111-579': ldb.ERR_INVALID_DN_SYNTAX,
             'S-1-5-18446744073709551615-579': ldb.ERR_INVALID_DN_SYNTAX,
             'S-1-5-18446744073709551616-579': ldb.ERR_INVALID_DN_SYNTAX,
             'S-1-5-3 2-579': ldb.ERR_NO_SUCH_OBJECT,
             'S-1-5-32 -11111579': None,
             'S-1-5-32- 579': ldb.ERR_INVALID_DN_SYNTAX,
             'S-1-5-32--579': ldb.ERR_INVALID_DN_SYNTAX,
             'S-1-5-32-11579': ldb.ERR_NO_SUCH_OBJECT,
             'S-1-5-4294967295-579': ldb.ERR_NO_SUCH_OBJECT,
             'S-1-5-9999999999-579': ldb.ERR_INVALID_DN_SYNTAX,
             'S-1-99999999999999999999999999999999999999-32-11111111111': ldb.ERR_INVALID_DN_SYNTAX,
             'S-10-5-32-579': ldb.ERR_INVALID_DN_SYNTAX,
             'S-2-5-32-579': ldb.ERR_INVALID_DN_SYNTAX,
             's-1-5-32-579': ldb.ERR_INVALID_DN_SYNTAX,
             'AA': ldb.ERR_INVALID_DN_SYNTAX,
        }

    def _test_sid_string_with_args(self, code, expected):
        try:
            self.ldb.search(base=f"<SID={code}>",
                            scope=ldb.SCOPE_BASE,
                            attrs=[])
        except ldb.LdbError as e:
            self.assertEqual(e.args[0], expected)
        else:
            self.assertIsNone(expected)


@DynamicTestCase
class SidStringsAsDnSearchWithDnObject(SidStringBase):
    """How does a bad <SID=x> dn work as a search base, if at all?

    This time we parse the DN in ldb first.
    """
    skip_local = True
    cases = {' S-1-1-1-1-1-1-1': ('parse error', None),
             'S-0-5-32-579': (None, ldb.ERR_INVALID_DN_SYNTAX),
             'S-000000000001-5-20-243': ('parse error', None),
             'S-000000001-5-32-579': ('parse error', None),
             'S-01-05-020-0243': (None, ldb.ERR_NO_SUCH_OBJECT),
             'S-0x1-0-0-579': ('parse error', None),
             'S-0x1-0x5-020-0243': ('parse error', None),
             'S-0x1-5-20-243': ('parse error', None),
             'S-0x1-5-40-579': ('parse error', None),
             'S-0x1-500000000-20-243': ('parse error', None),
             'S-1-0': (None, ldb.ERR_NO_SUCH_OBJECT),
             'S-1-0-0-579': (None, ldb.ERR_NO_SUCH_OBJECT),
             'S-1-0x05-32-579': (None, None),
             'S-1-0x5-0x20-0x243': (None, ldb.ERR_NO_SUCH_OBJECT),
             'S-1-0x50000000-32-579': (None, ldb.ERR_NO_SUCH_OBJECT),
             'S-1-0x500000000-0x500000000-579': (None, ldb.ERR_NO_SUCH_OBJECT),
             'S-1-0x500000000-32-579': (None, ldb.ERR_NO_SUCH_OBJECT),
             'S-1-0xABcDef123-0xABCDef123-579': (None, ldb.ERR_NO_SUCH_OBJECT),
             'S-1-1-1-1-1-1-1': (None, ldb.ERR_NO_SUCH_OBJECT),
             'S-1-21474836480-32-579': (None, ldb.ERR_NO_SUCH_OBJECT),
             'S-1-22': (None, ldb.ERR_NO_SUCH_OBJECT),
             'S-1-22-1': (None, ldb.ERR_NO_SUCH_OBJECT),
             'S-1-22-1-0': (None, ldb.ERR_NO_SUCH_OBJECT),
             'S-1-281474976710655-579': (None, ldb.ERR_NO_SUCH_OBJECT),
             'S-1-281474976710656-579': ('parse error', None),
             'S-1-3-0': (None, ldb.ERR_NO_SUCH_OBJECT),
             'S-1-3-99': (None, ldb.ERR_NO_SUCH_OBJECT),
             'S-1-5-0-579': (None, ldb.ERR_NO_SUCH_OBJECT),
             'S-1-5-040-579': (None, ldb.ERR_NO_SUCH_OBJECT),
             'S-1-5-0x20-579': (None, ldb.ERR_NO_SUCH_OBJECT),
             'S-1-5-11111111111111111111111111111111111-579': ('parse error', None),
             'S-1-5-18446744073709551615-579': ('parse error', None),
             'S-1-5-18446744073709551616-579': ('parse error', None),
             'S-1-5-3 2-579': (None, ldb.ERR_NO_SUCH_OBJECT),
             'S-1-5-32- 579': ('parse error', None),
             'S-1-5-32--579': ('parse error', None),
             'S-1-5-4294967295-579': (None, ldb.ERR_NO_SUCH_OBJECT),
             'S-1-5-9999999999-579': ('parse error', None),
             'S-1-99999999999999999999999999999999999999-32-11111111111': ('parse error',
                                                                           None),
             'S-10-5-32-579': (None, ldb.ERR_INVALID_DN_SYNTAX),
             'S-2-5-32-579': (None, ldb.ERR_INVALID_DN_SYNTAX),
             's-1-5-32-579': ('parse error', None),
            }

    def _test_sid_string_with_args(self, code, expected):
        dn_err, search_err = expected
        dn_str = f"<SID={code}>"
        try:
            dn = ldb.Dn(self.ldb, dn_str)
        except ValueError:
            self.assertEqual(dn_err, 'parse error')
            return
        except ldb.LdbError as e:
            self.assertEqual(dn_err, e.args[0])
            return

        self.assertIsNone(dn_err)

        try:
            self.ldb.search(dn, scope=ldb.SCOPE_BASE, attrs=['*'])
        except ldb.LdbError as e:
            self.assertEqual(search_err, e.args[0])
            return

        self.assertIsNone(search_err)


@DynamicTestCase
class SidStringsAsDnInSearchFilter(SidStringBase):
    """How does a bad <SID=x> dn work is a search filter?

    Answer: on Windows it always works.
    """
    skip_local = True
    cases = {}
    cases.update(SidStringTests.cases)
    cases.update(SidStringsThatStartWithS.cases)
    cases.update(SidStringBehavioursThatSambaPrefers.cases)

    def _test_sid_string_with_args(self, code, _dummy):
        basedn = self.ldb.get_default_basedn()
        try:
            self.ldb.search(base=basedn,
                            scope=ldb.SCOPE_ONELEVEL,
                            expression="(distinguishedName=<SID={code}>)")
        except ldb.LdbError as e:
            self.fail(f"expected no failure, got {e}")


if __name__ == '__main__':
    global_asn1_print = False
    global_hexdump = False
    import unittest
    unittest.main()
