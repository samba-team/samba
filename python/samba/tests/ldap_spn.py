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


import sys
import os
import pprint
import re
from samba.samdb import SamDB
from samba.auth import system_session
import ldb
from samba.sd_utils import SDUtils
from samba.credentials import DONT_USE_KERBEROS, Credentials
from samba.gensec import FEATURE_SEAL
from samba.tests.subunitrun import SubunitOptions, TestProgram
from samba.tests import TestCase, ldb_err
from samba.tests import DynamicTestCase
import samba.getopt as options
import optparse
from samba.colour import c_RED, c_GREEN, c_DARK_YELLOW
from samba.dsdb import (
    UF_SERVER_TRUST_ACCOUNT,
    UF_TRUSTED_FOR_DELEGATION,
)


SPN_GUID = 'f3a64788-5306-11d1-a9c5-0000f80367c1'

RELEVANT_ATTRS = {'dNSHostName',
                  'servicePrincipalName',
                  'sAMAccountName',
                  'dn'}

ok = True
bad = False
report = 'report'

operr = ldb.ERR_OPERATIONS_ERROR
denied = ldb.ERR_INSUFFICIENT_ACCESS_RIGHTS
constraint = ldb.ERR_CONSTRAINT_VIOLATION
exists = ldb.ERR_ENTRY_ALREADY_EXISTS

add = ldb.FLAG_MOD_ADD
replace = ldb.FLAG_MOD_REPLACE
delete = ldb.FLAG_MOD_DELETE

try:
    breakpoint
except NameError:
    # for python <= 3.6
    def breakpoint():
        import pdb
        pdb.set_trace()


def init():
    # This needs to happen before the class definition, and we put it
    # in a function to keep the namespace clean.
    global LP, CREDS, SERVER, REALM, COLOUR_TEXT, subunitopts, FILTER

    parser = optparse.OptionParser(
        "python3 ldap_spn.py <server> [options]")
    sambaopts = options.SambaOptions(parser)
    parser.add_option_group(sambaopts)

    # use command line creds if available
    credopts = options.CredentialsOptions(parser)
    parser.add_option_group(credopts)
    subunitopts = SubunitOptions(parser)
    parser.add_option_group(subunitopts)

    parser.add_option('--colour', action="store_true",
                      help="use colour text",
                      default=sys.stdout.isatty())

    parser.add_option('--filter', help="only run tests matching this regex")

    opts, args = parser.parse_args()
    if len(args) != 1:
        parser.print_usage()
        sys.exit(1)

    LP = sambaopts.get_loadparm()
    CREDS = credopts.get_credentials(LP)
    SERVER = args[0]
    REALM = CREDS.get_realm()
    COLOUR_TEXT = opts.colour
    FILTER = opts.filter


init()


def colour_text(x, state=None):
    if not COLOUR_TEXT:
        return x
    if state == 'error':
        return c_RED(x)
    if state == 'pass':
        return c_GREEN(x)

    return c_DARK_YELLOW(x)


def get_samdb(creds=None):
    if creds is None:
        creds = CREDS
        session = system_session()
    else:
        session = None

    return SamDB(url=f"ldap://{SERVER}",
                 lp=LP,
                 session_info=session,
                 credentials=creds)


def add_unpriv_user(samdb, ou, username,
                    writeable_objects=None,
                    password="samba123@"):
    creds = Credentials()
    creds.set_username(username)
    creds.set_password(password)
    creds.set_domain(CREDS.get_domain())
    creds.set_realm(CREDS.get_realm())
    creds.set_workstation(CREDS.get_workstation())
    creds.set_gensec_features(CREDS.get_gensec_features() | FEATURE_SEAL)
    creds.set_kerberos_state(DONT_USE_KERBEROS)
    dnstr = f"CN={username},{ou}"

    # like, WTF, samdb.newuser(), this is what you make us do.
    short_ou = ou.split(',', 1)[0]

    samdb.newuser(username, password, userou=short_ou)

    if writeable_objects:
        sd_utils = SDUtils(samdb)
        sid = sd_utils.get_object_sid(dnstr)
        for obj in writeable_objects:
            mod = f"(OA;CI;WP;{ SPN_GUID };;{ sid })"
            sd_utils.dacl_add_ace(obj, mod)

    unpriv_samdb = get_samdb(creds=creds)
    return unpriv_samdb


class LdapSpnTestBase(TestCase):
    _disabled = False

    @classmethod
    def setUpDynamicTestCases(cls):
        if getattr(cls, '_disabled', False):
            return
        for doc, *rows in cls.cases:
            if FILTER:
                if not re.search(FILTER, doc):
                    continue
            name = re.sub(r'\W+', '_', doc)
            cls.generate_dynamic_test("test_spn", name, rows, doc)

    def setup_objects(self, rows):
        objects = set(r[0] for r in rows)
        for name in objects:
            if ':' in name:
                objtype, name = name.split(':', 1)
            else:
                objtype = 'dc'
            getattr(self, f'add_{objtype}')(name)

    def setup_users(self, rows):
        # When you are adding an SPN that aliases (or would be aliased
        # by) another SPN on another object, you need to have write
        # permission on that other object too.
        #
        # To test this negatively and positively, we need to have
        # users with various combinations of write permission, which
        # means fiddling with SDs on the objects.
        #
        # The syntax is:
        #   ''    :  user with no special permissions
        #   '*'   :  admin user
        #   'A'   :  user can write to A only
        #   'A,C' :  user can write to A and C
        #   'C,A' :  same, but makes another user
        self.userdbs = {
            '*': self.samdb
        }

        permissions = set(r[2] for r in rows)
        for p in permissions:
            if p == '*':
                continue
            if p == '':
                user = 'nobody'
                writeable_objects = None
            else:
                user = 'writes_' + p.replace(",", '_')
                writeable_objects = [self.objects[x][0] for x in p.split(',')]

            self.userdbs[p] = add_unpriv_user(self.samdb, self.ou, user,
                                              writeable_objects)

    def _test_spn_with_args(self, rows, doc):
        cdoc = colour_text(doc)
        edoc = colour_text(doc, 'error')
        pdoc = colour_text(doc, 'pass')

        if COLOUR_TEXT:
            sys.stderr.flush()
            print('\n', c_DARK_YELLOW('#' * 10), f'starting «{cdoc}»\n')
            sys.stdout.flush()

        self.samdb = get_samdb()
        self.base_dn = self.samdb.get_default_basedn()
        self.short_id = self.id().rsplit('.', 1)[1][:63]
        self.objects = {}
        self.ou = f"OU={ self.short_id },{ self.base_dn }"
        self.addCleanup(self.samdb.delete, self.ou, ["tree_delete:1"])
        self.samdb.create_ou(self.ou)

        self.setup_objects(rows)
        self.setup_users(rows)

        for i, row in enumerate(rows):
            if len(row) == 5:
                obj, data, rights, expected, op = row
            else:
                obj, data, rights, expected = row
                op = ldb.FLAG_MOD_REPLACE

            # We use this DB with possibly restricted rights for this row
            samdb = self.userdbs[rights]

            if ':' in obj:
                objtype, obj = obj.split(':', 1)
            else:
                objtype = 'dc'

            dn, dnsname = self.objects[obj]
            m = {"dn": dn}

            if isinstance(data, dict):
                m.update(data)
            else:
                m['servicePrincipalName'] = data

            # for python's sake (and our sanity) we try to ensure we
            # have consistent canonical case in our attributes
            keys = set(m.keys())
            if not keys.issubset(RELEVANT_ATTRS):
                raise ValueError(f"unexpected attr {keys - RELEVANT_ATTRS}. "
                                 "Casefold typo?")

            for k in ('dNSHostName', 'servicePrincipalName'):
                if isinstance(m.get(k), str):
                    m[k] = m[k].format(dnsname=f"x.{REALM}")
                elif isinstance(m.get(k), list):
                    m[k] = [x.format(dnsname=f"x.{REALM}") for x in m[k]]

            msg = ldb.Message.from_dict(samdb, m, op)

            if expected is bad:
                try:
                    samdb.modify(msg)
                except ldb.LdbError as e:
                    print(f"row {i+1} of '{pdoc}' failed as expected with "
                          f"{ldb_err(e)}\n")
                    continue
                self.fail(f"row {i+1}: "
                          f"{rights} {pprint.pformat(m)} on {objtype} {obj} "
                          f"should fail ({edoc})")

            elif expected is ok:
                try:
                    samdb.modify(msg)
                except ldb.LdbError as e:
                    self.fail(f"row {i+1} of {edoc} failed with {ldb_err(e)}:\n"
                              f"{rights} {pprint.pformat(m)} on {objtype} {obj}")

            elif expected is report:
                try:
                    self.samdb.modify(msg)
                    print(f"row {i+1} "
                          f"of '{cdoc}' {colour_text('SUCCEEDED', 'pass')}:\n"
                          f"{pprint.pformat(m)} on {obj}")
                except ldb.LdbError as e:
                    print(f"row {i+1} "
                          f"of '{cdoc}' {colour_text('FAILED', 'error')} "
                          f"with {ldb_err(e)}:\n{pprint.pformat(m)} on {obj}")

            elif expected is breakpoint:
                try:
                    breakpoint()
                    samdb.modify(msg)
                except ldb.LdbError as e:
                    print(f"row {i+1} of '{pdoc}' FAILED with {ldb_err(e)}\n")

            else:  # an ldb error number
                try:
                    samdb.modify(msg)
                except ldb.LdbError as e:
                    if e.args[0] == expected:
                        continue
                    self.fail(f"row {i+1} of '{edoc}' "
                              f"should have failed with {ldb_err(expected)}:\n"
                              f"not {ldb_err(e)}:\n"
                              f"{rights} {pprint.pformat(m)} on {objtype} {obj}")
                self.fail(f"row {i+1} of '{edoc}' "
                          f"should have failed with {ldb_err(expected)}:\n"
                          f"{rights} {pprint.pformat(m)} on {objtype} {obj}")

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
        self.addCleanup(self.remove_object, name)
        self.objects[name] = (dn, dnsname)

    def add_user(self, name):
        dn = f"CN={name},{self.ou}"
        self.samdb.add({
            "dn": dn,
            "name": name,
            "samAccountName": name,
            "objectclass": "user",
            "carLicense": self.id()
        })
        self.addCleanup(self.remove_object, name)
        self.objects[name] = (dn, None)

    def remove_object(self, name):
        dn, dnsname = self.objects.pop(name)
        self.samdb.delete(dn)


@DynamicTestCase
class LdapSpnTest(LdapSpnTestBase):
    """Make sure we can't add clashing servicePrincipalNames.

    This would be possible using sPNMappings aliases — for example, if
    the mapping maps host/ to cifs/, we should not be able to add
    different addresses for each.
    """

    # default sPNMappings: host=alerter, appmgmt, cisvc, clipsrv,
    # browser, dhcp, dnscache, replicator, eventlog, eventsystem,
    # policyagent, oakley, dmserver, dns, mcsvc, fax, msiserver, ias,
    # messenger, netlogon, netman, netdde, netddedsm, nmagent,
    # plugplay, protectedstorage, rasman, rpclocator, rpc, rpcss,
    # remoteaccess, rsvp, samss, scardsvr, scesrv, seclogon, scm,
    # dcom, cifs, spooler, snmp, schedule, tapisrv, trksvr, trkwks,
    # ups, time, wins, www, http, w3svc, iisadmin, msdtc
    #
    # I think in practice this is rarely if ever changed or added to.

    cases = [
        ("add one as admin",
         ('A', 'host/{dnsname}', '*', ok),
        ),
        ("add one as rightful user",
         ('A', 'host/{dnsname}', 'A', ok),
        ),
        ("attempt to add one as nobody",
         ('A', 'host/{dnsname}', '', denied),
        ),

        ("add and replace as admin",
         ('A', 'host/{dnsname}', '*', ok),
         ('A', 'host/x.{dnsname}', '*', ok),
        ),
        ("replace as rightful user",
         ('A', 'host/{dnsname}', 'A', ok),
         ('A', 'host/x.{dnsname}', 'A', ok),
        ),
        ("attempt to replace one as nobody",
         ('A', 'host/{dnsname}', '*', ok),
         ('A', 'host/x.{dnsname}', '', denied),
        ),

        ("add second as admin",
         ('A', 'host/{dnsname}', '*', ok),
         ('A', 'host/x.{dnsname}', '*', ok, add),
        ),
        ("add second as rightful user",
         ('A', 'host/{dnsname}', 'A', ok),
         ('A', 'host/x.{dnsname}', 'A', ok, add),
        ),
        ("attempt to add second as nobody",
         ('A', 'host/{dnsname}', '*', ok),
         ('A', 'host/x.{dnsname}', '', denied, add),
        ),

        ("add the same one twice, simple duplicate error",
         ('A', 'host/{dnsname}', '*', ok),
         ('A', 'host/{dnsname}', '*', bad, add),
        ),
        ("simple duplicate attributes, as non-admin",
         ('A', 'host/{dnsname}', '*', ok),
         ('A', 'host/{dnsname}', 'A', bad, add),
        ),

        ("add the same one twice, identical duplicate",
         ('A', 'host/{dnsname}', '*', ok),
         ('A', 'host/{dnsname}', '*', bad, add),
        ),

        ("add a conflict, host first, as nobody",
         ('A', 'host/z.{dnsname}', '*', ok),
         ('B', 'cifs/z.{dnsname}', '', denied),
        ),

        ("add a conflict, service first, as nobody",
         ('A', 'cifs/{dnsname}', '*', ok),
         ('B', 'host/{dnsname}', '', denied),
        ),


        ("three way conflict, host first, as admin",
         ('A', 'host/z.{dnsname}', '*', ok),
         ('B', 'cifs/z.{dnsname}', '*', ok),
         ('C', 'www/z.{dnsname}', '*', ok),
        ),
        ("three way conflict, host first, with sufficient rights",
         ('A', 'host/z.{dnsname}', 'A', ok),
         ('B', 'cifs/z.{dnsname}', 'B,A', ok),
         ('C', 'www/z.{dnsname}', 'C,A', ok),
        ),
        ("three way conflict, host first, adding duplicate",
         ('A', 'host/z.{dnsname}', 'A', ok),
         ('B', 'cifs/z.{dnsname}', 'B,A', ok),
         ('C', 'cifs/z.{dnsname}', 'C,A', bad),
        ),
        ("three way conflict, host first, adding duplicate, full rights",
         ('A', 'host/z.{dnsname}', 'A', ok),
         ('B', 'cifs/z.{dnsname}', 'B,A', ok),
         ('C', 'cifs/z.{dnsname}', 'C,B,A', bad),
        ),

        ("three way conflict, host first, with other write rights",
         ('A', 'host/z.{dnsname}', '*', ok),
         ('B', 'cifs/z.{dnsname}', 'A,B', ok),
         ('C', 'cifs/z.{dnsname}', 'A,B', bad),

        ),
        ("three way conflict, host first, as nobody",
         ('A', 'host/z.{dnsname}', '*', ok),
         ('B', 'cifs/z.{dnsname}', '*', ok),
         ('C', 'www/z.{dnsname}', '', denied),
        ),

        ("three way conflict, services first, as admin",
         ('A', 'cifs/{dnsname}', '*', ok),
         ('B', 'www/{dnsname}', '*', ok),
         ('C', 'host/{dnsname}', '*', constraint),
        ),
        ("three way conflict, services first, with service write rights",
         ('A', 'cifs/{dnsname}', '*', ok),
         ('B', 'www/{dnsname}', '*', ok),
         ('C', 'host/{dnsname}', 'A,B', bad),
        ),

        ("three way conflict, service first, as nobody",
         ('A', 'cifs/{dnsname}', '*', ok),
         ('B', 'www/{dnsname}', '*', ok),
         ('C', 'host/{dnsname}', '', denied),
        ),
        ("replace host before specific",
         ('A', 'host/{dnsname}', '*', ok),
         ('A', 'cifs/{dnsname}', '*', ok),
        ),
        ("replace host after specific, as nobody",
         ('A', 'cifs/{dnsname}', '*', ok),
         ('A', 'host/{dnsname}', '', denied),
        ),

        ("non-conflict host before specific",
         ('A', 'host/{dnsname}', '*', ok),
         ('A', 'cifs/{dnsname}', '*', ok, add),
        ),
        ("non-conflict host after specific",
         ('A', 'cifs/{dnsname}', '*', ok),
         ('A', 'host/{dnsname}', '*', ok, add),
        ),
        ("non-conflict host before specific, non-admin",
         ('A', 'host/{dnsname}', 'A', ok),
         ('A', 'cifs/{dnsname}', 'A', ok, add),
        ),
        ("non-conflict host after specific, as nobody",
         ('A', 'cifs/{dnsname}', '*', ok),
         ('A', 'host/{dnsname}', '', denied, add),
        ),

        ("add a conflict, host first on user, as admin",
         ('user:C', 'host/{dnsname}', '*', ok),
         ('B', 'cifs/{dnsname}', '*', ok),
        ),
        ("add a conflict, host first on user, host rights",
         ('user:C', 'host/{dnsname}', '*', ok),
         ('B', 'cifs/{dnsname}', 'C', denied),
        ),
        ("add a conflict, host first on user, both rights",
         ('user:C', 'host/{dnsname}', '*', ok),
         ('B', 'cifs/{dnsname}', 'B,C', ok),
        ),
        ("add a conflict, host first both on user",
         ('user:C', 'host/{dnsname}', '*', ok),
         ('user:D', 'www/{dnsname}', '*', ok),
        ),
        ("add a conflict, host first both on user, host rights",
         ('user:C', 'host/{dnsname}', '*', ok),
         ('user:D', 'www/{dnsname}', 'C', denied),
         ),
        ("add a conflict, host first both on user, both rights",
         ('user:C', 'host/{dnsname}', '*', ok),
         ('user:D', 'www/{dnsname}', 'C,D', ok),
        ),
        ("add a conflict, host first both on user, as nobody",
         ('user:C', 'host/{dnsname}', '*', ok),
         ('user:D', 'www/{dnsname}', '', denied),
        ),
        ("add a conflict, host first, with both write rights",
         ('A', 'host/z.{dnsname}', '*', ok),
         ('B', 'cifs/z.{dnsname}', 'A,B', ok),
        ),

        ("add a conflict, host first, second on user, as admin",
         ('A', 'host/{dnsname}', '*', ok),
         ('user:D', 'cifs/{dnsname}', '*', ok),
        ),
        ("add a conflict, host first, second on user, with rights",
         ('A', 'host/{dnsname}', '*', ok),
         ('user:D', 'cifs/{dnsname}', 'A,D', ok),
        ),

        ("nonsense SPNs, part 1, as admin",
         ('A', 'a-b-c/{dnsname}', '*', ok),
         ('A', 'rrrrrrrrrrrrr /{dnsname}', '*', ok),
        ),
        ("nonsense SPNs, part 1, as user",
         ('A', 'a-b-c/{dnsname}', 'A', ok),
         ('A', 'rrrrrrrrrrrrr /{dnsname}', 'A', ok),
        ),
        ("nonsense SPNs, part 1, as nobody",
         ('A', 'a-b-c/{dnsname}', '', denied),
         ('A', 'rrrrrrrrrrrrr /{dnsname}', '', denied),
        ),

        ("add a conflict, using port",
         ('A', 'dns/{dnsname}', '*', ok),
         ('B', 'dns/{dnsname}:53', '*', ok),
        ),
        ("add a conflict, using port, port first",
         ('user:C', 'dns/{dnsname}:53', '*', ok),
         ('user:D', 'dns/{dnsname}', '*', ok),
        ),
        ("three part spns",
         ('A', {'dNSHostName': '{dnsname}'}, '*', ok),
         ('A', 'cifs/{dnsname}/DomainDNSZones.{dnsname}', '*', ok),
         ('B', 'cifs/{dnsname}/DomainDNSZones.{dnsname}', '*', constraint),
         ('A', {'dNSHostName': 'y.{dnsname}'}, '*', ok),
         ('B', 'cifs/{dnsname}/DomainDNSZones.{dnsname}', '*', ok),
         ('B', 'cifs/y.{dnsname}/DomainDNSZones.{dnsname}', '*', constraint),
        ),
        ("three part nonsense spns",
         ('A', {'dNSHostName': 'bean'}, '*', ok),
         ('A', 'cifs/bean/DomainDNSZones.bean', '*', ok),
         ('B', 'cifs/bean/DomainDNSZones.bean', '*', constraint),
         ('A', {'dNSHostName': 'y.bean'}, '*', ok),
         ('B', 'cifs/bean/DomainDNSZones.bean', '*', ok),
         ('B', 'cifs/y.bean/DomainDNSZones.bean', '*', constraint),
         ('C', 'host/bean/bean', '*', ok),
        ),

        ("one part spns (no slashes)",
         ('A', '{dnsname}', '*', constraint),
         ('B', 'cifs', '*', constraint),
         ('B', 'cifs/', '*', ok),
         ('B', ' ', '*', constraint),
         ('user:C', 'host', '*', constraint),
        ),

        ("dodgy spns",
         # These tests pass on Windows. An SPN must have one or two
         # slashes, with at least one character before the first one,
         # UNLESS the first slash is followed by a good enough service
         # name (e.g. "/host/x.y" rather than "sdfsd/x.y").
         ('A', '\\/{dnsname}', '*', ok),
         ('B', 'cifs/\\\\{dnsname}', '*', ok),
         ('B', r'cifs/\\\{dnsname}', '*', ok),
         ('B', r'cifs/\\\{dnsname}/', '*', ok),
         ('A', r'cīfs/\\\{dnsname}/', '*', constraint),  # 'ī' maps to 'i'
         # on the next two, full-width solidus (U+FF0F) does not work
         # as '/'.
         ('A', 'cifs／sfic', '*', constraint, add),
         ('A', r'cifs／\\\{dnsname}', '*', constraint, add),
         ('B', '\n', '*', constraint),
         ('B', '\n/\n', '*', ok),
         ('B', '\n/\n/\n', '*', ok),
         ('B', '\n/\n/\n/\n', '*', constraint),
         ('B', ' /* and so on */ ', '*', ok, add),
         ('B', r'¯\_(ツ)_/¯', '*', ok, add),      # ¯\_(ツ)_/¯
         # つ is hiragana for katakana ツ, so the next one fails for
         # something analogous to casefold reasons.
         ('A', r'¯\_(つ)_/¯', '*', constraint),
         ('A', r'¯\_(㋡)_/¯', '*', constraint),   # circled ツ
         ('B', '//', '*', constraint),           # all can't be empty,
         ('B', ' //', '*', ok),                  # service can be space
         ('B', '/host/{dnsname}', '*', ok),      # or empty if others aren't
         ('B', '/host/x.y.z', '*', ok),
         ('B', '/ /x.y.z', '*', ok),
         ('B', ' / / ', '*', ok),
         ('user:C', b'host/', '*', ok),
         ('user:C', ' /host', '*', ok),          # service is ' ' (space)
         ('B', ' /host', '*', constraint),       # already on C
         ('B', ' /HōST', '*', constraint),       # ō equiv to O
         ('B', ' /ħØşt', '*', constraint),       # maps to ' /host'
         ('B', ' /H0ST', '*', ok),               # 0 is zero
         ('B', ' /НoST', '*', ok),               # Cyrillic Н (~N)
         ('B', '  /host', '*', ok),              # two space
         ('B', '\u00a0/host', '*', ok),          # non-breaking space
         ('B', ' 2/HōST/⌷[ ][]¨(', '*', ok),
         ('B', ' (//)', '*', ok, add),
         ('B', ' ///', '*', constraint),
         ('B', r' /\//', '*', constraint),        # escape doesn't help
         ('B', ' /\\//', '*', constraint),       # double escape doesn't help
         ('B', r'\//', '*', ok),
         ('A', r'\\/\\/', '*', ok),
         ('B', '|//|', '*', ok, add),
         ('B', r'\/\/\\', '*', ok, add),

         ('A', ':', '*', constraint),
         ('A', ':/:', '*', ok),
         ('A', ':/:80', '*', ok),   # port number syntax is not special
         ('A', ':/:( ツ', '*', ok),
         ('A', ':/:/:', '*', ok),
         ('B', b'cifs/\x11\xaa\xbb\xcc\\example.com', '*', ok),
         ('A', b':/\xcc\xcc\xcc\xcc', '*', ok),
         ('A', b':/b\x00/b/b/b', '*', ok),  # string handlng truncates at \x00
         ('A', b'a@b/a@b/a@b', '*', ok),
         ('A', b'a/a@b/a@b', '*', ok),
        ),
        ("empty part spns (consecutive slashes)",
         ('A', 'cifs//{dnsname}', '*', ok),
         ('B', 'cifs//{dnsname}', '*', bad),  # should clash with line 1
         ('B', 'cifs/zzzy.{dnsname}/', '*', ok),
         ('B', '/host/zzzy.{dnsname}', '*', ok),
        ),
        ("too many spn parts",
         ('A', 'cifs/{dnsname}/{dnsname}/{dnsname}', '*', bad),
         ('A', {'dNSHostName': 'y.{dnsname}'}, '*', ok),
         ('B', 'cifs/{dnsname}/{dnsname}/', '*', bad),
         ('B', 'cifs/y.{dnsname}/{dnsname}/toop', '*', bad),
         ('B', 'host/{dnsname}/a/b/c', '*', bad),
        ),
        ("add a conflict, host first, as admin",
         ('A', 'host/z.{dnsname}', '*', ok),
         ('B', 'cifs/z.{dnsname}', '*', ok),
        ),
        ("add a conflict, host first, with host write rights",
         ('A', 'host/z.{dnsname}', '*', ok),
         ('B', 'cifs/z.{dnsname}', 'A', denied),
        ),
        ("add a conflict, service first, with service write rights",
         ('A', 'cifs/{dnsname}', '*', ok),
         ('B', 'host/{dnsname}', 'A', denied),
        ),
        ("adding dNSHostName after cifs with no old dNSHostName",
         ('A', 'cifs/{dnsname}', '*', ok),
         ('A', {'dNSHostName': 'y.{dnsname}'}, '*', ok),
         ('B', 'cifs/{dnsname}', '*', constraint),
         ('B', 'cifs/y.{dnsname}', '*', ok),
         ('B', 'host/y.{dnsname}', '*', ok),
        ),
        ("changing dNSHostName after cifs",
         ('A', {'dNSHostName': '{dnsname}'}, '*', ok),
         ('A', 'cifs/{dnsname}', '*', ok),
         ('A', {'dNSHostName': 'y.{dnsname}'}, '*', ok),
         ('B', 'cifs/{dnsname}', '*', ok),
         ('B', 'cifs/y.{dnsname}', '*', bad),
         ('B', 'host/y.{dnsname}', '*', bad),
        ),
    ]


@DynamicTestCase
class LdapSpnSambaOnlyTest(LdapSpnTestBase):
    # We don't run these ones outside of selftest, where we are
    # probably testing against Windows and these are known failures.
    _disabled = 'SAMBA_SELFTEST' not in os.environ
    cases = [
        ("add a conflict, host first, with service write rights",
         ('A', 'host/z.{dnsname}', '*', ok),
         ('B', 'cifs/z.{dnsname}', 'B', denied),
        ),
        ("add a conflict, service first, with host write rights",
         ('A', 'cifs/{dnsname}', '*', ok),
         ('B', 'host/{dnsname}', 'B', constraint),
        ),
        ("add a conflict, service first, as admin",
         ('A', 'cifs/{dnsname}', '*', ok),
         ('B', 'host/{dnsname}', '*', constraint),
        ),
        ("add a conflict, service first, with both write rights",
         ('A', 'cifs/{dnsname}', '*', ok),
         ('B', 'host/{dnsname}', 'A,B', constraint),
        ),
        ("add a conflict, host first both on user, service rights",
         ('user:C', 'host/{dnsname}', '*', ok),
         ('user:D', 'www/{dnsname}', 'D', denied),
        ),
        ("add a conflict, along with a re-added SPN",
         ('A', 'cifs/{dnsname}', '*', ok),
         ('B', 'cifs/heeble.example.net', 'B', ok),
         ('B', ['cifs/heeble.example.net', 'host/{dnsname}'], 'B', constraint),
        ),

        ("changing dNSHostName after host",
         ('A', {'dNSHostName': '{dnsname}'}, '*', ok),
         ('A', 'host/{dnsname}', '*', ok),
         ('A', {'dNSHostName': 'y.{dnsname}'}, '*', ok),
         ('B', 'cifs/{dnsname}', 'B', ok),     # no clash with A
         ('B', 'cifs/y.{dnsname}', 'B', bad),  # should clash with A
         ('B', 'host/y.{dnsname}', '*', bad),
        ),

        ("mystery dnsname clash, host first",
         ('user:C', 'host/heeble.example.net', '*', ok),
         ('user:D', 'www/heeble.example.net', '*', ok),
        ),
        ("mystery dnsname clash, www first",
         ('user:D', 'www/heeble.example.net', '*', ok),
         ('user:C', 'host/heeble.example.net', '*', constraint),
        ),
        ("replace as admin",
         ('A', 'cifs/{dnsname}', '*', ok),
         ('A', 'host/{dnsname}', '*', ok),
         ('A', 'cifs/{dnsname}', '*', ok),
        ),
        ("replace as non-admin with rights",
         ('A', 'cifs/{dnsname}', '*', ok),
         ('A', 'host/{dnsname}', 'A', ok),
         ('A', 'cifs/{dnsname}', 'A', ok),
        ),
        ("replace vial delete as non-admin with rights",
         ('A', 'cifs/{dnsname}', '*', ok),
         ('A', 'host/{dnsname}', 'A', ok),
         ('A', 'host/{dnsname}', 'A', ok, delete),
         ('A', 'cifs/{dnsname}', 'A', ok, add),
        ),
        ("replace as non-admin without rights",
         ('B', 'cifs/b', '*', ok),
         ('A', 'cifs/{dnsname}', '*', ok),
         ('A', 'host/{dnsname}', 'B', denied),
         ('A', 'cifs/{dnsname}', 'B', denied),
        ),
        ("replace as nobody",
         ('B', 'cifs/b', '*', ok),
         ('A', 'cifs/{dnsname}', '*', ok),
         ('A', 'host/{dnsname}', '', denied),
         ('A', 'cifs/{dnsname}', '', denied),
        ),
        ("accumulate and delete as admin",
         ('A', 'cifs/{dnsname}', '*', ok),
         ('A', 'host/{dnsname}', '*', ok, add),
         ('A', 'www/{dnsname}', '*', ok, add),
         ('A', 'www/...', '*', ok, add),
         ('A', 'host/...', '*', ok, add),
         ('A', 'www/{dnsname}', '*', ok, delete),
         ('A', 'host/{dnsname}', '*', ok, delete),
         ('A', 'host/{dnsname}', '*', ok, add),
         ('A', 'www/{dnsname}', '*', ok, add),
         ('A', 'host/...', '*', ok, delete),
        ),
        ("accumulate and delete with user rights",
         ('A', 'cifs/{dnsname}', '*', ok),
         ('A', 'host/{dnsname}', 'A', ok, add),
         ('A', 'www/{dnsname}', 'A', ok, add),
         ('A', 'www/...', 'A', ok, add),
         ('A', 'host/...', 'A', ok, add),
         ('A', 'www/{dnsname}', 'A', ok, delete),
         ('A', 'host/{dnsname}', 'A', ok, delete),
         ('A', 'host/{dnsname}', 'A', ok, add),
         ('A', 'www/{dnsname}', 'A', ok, add),
         ('A', 'host/...', 'A', ok, delete),
        ),
        ("three way conflict, host first, with partial write rights",
         ('A', 'host/z.{dnsname}', 'A', ok),
         ('B', 'cifs/z.{dnsname}', 'B', denied),
         ('C', 'www/z.{dnsname}', 'C', denied),
        ),
        ("three way conflict, host first, with partial write rights 2",
         ('A', 'host/z.{dnsname}', 'A', ok),
         ('B', 'cifs/z.{dnsname}', 'B', bad),
         ('C', 'www/z.{dnsname}', 'C,A', ok),
        ),

        ("three way conflict sandwich, sufficient rights",
         ('B', 'host/{dnsname}', 'B', ok),
         ('A', 'cifs/{dnsname}', 'A,B', ok),
         # the replaces don't fail even though they appear to affect A
         # and B, because they are effectively no-ops, leaving
         # everything as it was before.
         ('A', 'cifs/{dnsname}', 'A', ok),
         ('B', 'host/{dnsname}', 'B', ok),
         ('C', 'www/{dnsname}', 'A,B,C', ok),
         ('C', 'www/{dnsname}', 'B,C', ok),
         # because B already has host/, C doesn't matter
         ('B', 'host/{dnsname}', 'A,B', ok),
         # removing host (via replace) frees others, needs B only
         ('B', 'ldap/{dnsname}', 'B', ok),
         ('C', 'www/{dnsname}', 'C', ok),
         ('A', 'cifs/{dnsname}', 'A', ok),

         # re-adding host is now impossible while A and C have {dnsname} spns
         ('B', 'host/{dnsname}', '*', bad),
         ('B', 'host/{dnsname}', 'A,B,C', bad),
         # so let's remove those... (not needing B rights)
         ('C', 'www/{dnsname}', 'C', ok, delete),
         ('A', 'cifs/{dnsname}', 'A', ok, delete),
         # and now we can add host/ again
         ('B', 'host/{dnsname}', 'B', ok),
         ('C', 'www/{dnsname}', 'B,C', ok, add),
         ('A', 'cifs/{dnsname}', 'A,B', ok),
        ),
        ("three way conflict, service first, with all write rights",
         ('A', 'cifs/{dnsname}', '*', ok),
         ('B', 'www/{dnsname}', 'A,B,C', ok),
         ('C', 'host/{dnsname}', 'A,B,C', bad),
        ),
        ("three way conflict, service first, just sufficient rights",
         ('A', 'cifs/{dnsname}', 'A', ok),
         ('B', 'www/{dnsname}', 'B', ok),
         ('C', 'host/{dnsname}', 'A,B,C', bad),
        ),

        ("three way conflict, service first, with host write rights",
         ('A', 'cifs/{dnsname}', '*', ok),
         ('B', 'www/{dnsname}', '*', ok),
         ('C', 'host/{dnsname}', 'C', bad),
        ),
        ("three way conflict, service first, with both write rights",
         ('A', 'cifs/{dnsname}', '*', ok),
         ('A', 'cifs/{dnsname}', '*', ok, delete),
         ('A', 'www/{dnsname}', 'A,B,C', ok),
         ('B', 'host/{dnsname}', 'A,B', bad),
         ('A', 'www/{dnsname}', 'A', ok, delete),
         ('B', 'host/{dnsname}', 'A,B', ok),
         ('C', 'cifs/{dnsname}', 'C', bad),
         ('C', 'cifs/{dnsname}', 'B,C', ok),
        ),
        ("three way conflict, services first, with partial rights",
         ('A', 'cifs/{dnsname}', 'A,C', ok),
         ('B', 'www/{dnsname}', '*', ok),
         ('C', 'host/{dnsname}', 'A,C', bad),
        ),
    ]


@DynamicTestCase
class LdapSpnAmbitiousTest(LdapSpnTestBase):
    _disabled = True
    cases = [
        ("add a conflict with port, host first both on user",
         ('user:C', 'host/{dnsname}', '*', ok),
         ('user:D', 'www/{dnsname}:80', '*', bad),
        ),
        # see https://bugzilla.samba.org/show_bug.cgi?id=8929
        ("add the same one twice, case-insensitive duplicate",
         ('A', 'host/{dnsname}', '*', ok),
         ('A', 'Host/{dnsname}', '*', bad, add),
        ),
        ("special SPN",
         # should fail because we don't have all the DSA infrastructure
         ('A', ("E3514235-4B06-11D1-AB04-00C04FC2DCD2/"
                "75b84f00-a81b-4a19-8ef2-8e483cccff11/"
                "{dnsname}"), '*', constraint)
         ),
        ("single part SPNs matching sAMAccountName",
         # setting them both together is allegedly a MacOS behaviour,
         # but all we get from Windows is a mysterious NO_SUCH_OBJECT.
         ('user:A', {'sAMAccountName': 'A',
                     'servicePrincipalName': 'A'}, '*', ldb.ERR_NO_SUCH_OBJECT),
         ('user:B', {'sAMAccountName': 'B'}, '*', ok),
         ('user:B', {'servicePrincipalName': 'B'}, '*', constraint),
         ('user:C', {'servicePrincipalName': 'C'}, '*', constraint),
         ('user:C', {'sAMAccountName': 'C'}, '*', ok),
        ),
        ("three part spns with dnsHostName",
         ('A', {'dNSHostName': '{dnsname}'}, '*', ok),
         ('A', 'cifs/{dnsname}/DomainDNSZones.{dnsname}', '*', ok),
         ('A', {'dNSHostName': 'y.{dnsname}'}, '*', ok),
         ('B', 'cifs/{dnsname}/DomainDNSZones.{dnsname}', '*', ok),
         ('B', 'cifs/y.{dnsname}/DomainDNSZones.{dnsname}', '*', constraint),
         ('C', 'host/{y.dnsname}/{y.dnsname}', '*', constraint),
         ('A', 'host/y.{dnsname}/{dnsname}', '*', constraint),
        ),
    ]


def main():
    TestProgram(module=__name__, opts=subunitopts)

main()
