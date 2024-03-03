# Unix SMB/CIFS implementation.
#
# Tests for samba-tool commands for Key Distribution Services
#
# Copyright © Catalyst.Net Ltd. 2024
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

import json
import os
import re
from datetime import datetime, timezone

from .base import SambaToolCmdTest
from samba.dcerpc import misc

from samba.nt_time import (nt_now,
                           NT_TICKS_PER_SEC,
                           nt_time_from_string,
                           string_from_nt_time)

from ldb import SCOPE_SUBTREE, Dn

from samba.tests.gkdi import create_root_key


HOST = "ldap://{DC_SERVER}".format(**os.environ)
CREDS = "-U{DC_USERNAME}%{DC_PASSWORD}".format(**os.environ)
SMBCONF = os.environ['SERVERCONFFILE']

# alice%Secret007
NON_ADMIN_CREDS = "-U{DOMAIN_USER}%{DOMAIN_USER_PASSWORD}".format(**os.environ)

TIMESTAMP_RE = r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}\+00:00'

NOWISH = 'about now'


class KdsRootKeyTestsBase(SambaToolCmdTest):
    @classmethod
    def setUpClass(cls):
        cls.samdb = cls.getSamDB("-H", HOST, CREDS)
        dn = cls.samdb.get_config_basedn()
        dn.add_child("CN=Master Root Keys,CN=Group Key Distribution Service,CN=Services")
        cls.root_key_base_dn = dn

        # we'll add one for all tests to rely on -- but most will add
        # their own.
        super().setUpClass()

    @classmethod
    def _create_root_key_timediff(cls, create_diff=0, use_diff=0):
        now = nt_now()
        nt_create = now + create_diff * NT_TICKS_PER_SEC
        nt_use = now + use_diff * NT_TICKS_PER_SEC
        guid, dn = create_root_key(cls.samdb,
                                   cls.root_key_base_dn,
                                   current_nt_time=nt_create,
                                   use_start_time=nt_use)

        return guid, dn, nt_create, nt_use

    def _create_root_key_timediff_cleanup(self, create_diff=0, use_diff=0):
        """create a root key that will disappear when the test ends."""
        guid, dn, nt_create, nt_use = self._create_root_key_timediff(
            create_diff,
            use_diff)
        self.addCleanup(self.samdb.delete, dn)
        return guid, dn, nt_create, nt_use

    def _check_timestamp(self, isotimestamp, expected, range=10000):
        """Check that a timestamp string matches an nt-time.

        By default we give a millisecond of leeway, because the ISO
        timestamp has less resolution than NT time (at most 6 decimal
        digits for seconds).
        """

        t = nt_time_from_string(isotimestamp)

        if expected is None:
            # we don't know what we want, but at least it's a time!
            return

        if expected is NOWISH:
            expected = nt_now()
            range = 2.0 * NT_TICKS_PER_SEC

        self.assertGreaterEqual(t, expected - range)
        self.assertLessEqual(t, expected + range)

    def _test_list_output_snippet(self, output,
                                  guid=r'\b[0-9a-fA-F-]{36}\b',
                                  created=None,
                                  used_from=None,
                                  verbose=False):
        # name 1146a853-b604-75ac-5acc-4ef4f0530584
        #    created        2024-02-15T22:55:47.865576+00:00 (about 4 days ago)
        #    usable from    2024-02-15T22:55:47.865576+00:00 (about 4 days ago)
        self.assertRegex(output, f"(?m)^name {guid}$")

        m = re.search(f' created +({TIMESTAMP_RE})', output)
        self.assertIsNotNone(m, "create timestamp not found")
        create_timestamp = m.group(1)
        self._check_timestamp(create_timestamp, created)

        m = re.search(f' usable from +({TIMESTAMP_RE})', output)
        self.assertIsNotNone(m, "usable from timestamp not found")
        used_from_timestamp = m.group(1)
        self._check_timestamp(used_from_timestamp, used_from)

        if verbose:
            dn = f"CN={guid},{self.root_key_base_dn}"
            self.assertRegex(output, f"(?m)^ +dn +{dn}$")
            self.assertRegex(output, r"(?m)^ +whenCreated +\d{14}.0Z$")
            self.assertRegex(output, r"(?m)^ +whenChanged +\d{14}.0Z$")
            self.assertRegex(output, r"(?m)^ +objectGUID +[0-9a-fA-F-]{36}$")
            self.assertRegex(output, r"(?m)^ +msKds-KDFAlgorithmID \w+$")
            self.assertRegex(output, r"(?m)^ +msKds-KDFParam \w+$")
            self.assertRegex(output, r"(?m)^ +msKds-SecretAgreementAlgorithmID \w+$")
            self.assertRegex(output, r"(?m)^ +msKds-PublicKeyLength \d+$")
            self.assertRegex(output, r"(?m)^ +msKds-PrivateKeyLength \d+$")
            self.assertRegex(output, r"(?m)^ +msKds-Version  1$")
            self.assertRegex(output, rf"(?m)^ +msKds-DomainID [\w=, ]+{self.samdb.domain_dn()}$",
                             re.MULTILINE)
            self.assertRegex(output, f"(?m)^ +cn +{guid}$")  # same guid as name

    def _test_list_output_json_snippet(self, snippet,
                                       guid=r'\b[0-9a-fA-F-]{36}\b',
                                       created=None,
                                       used_from=None,
                                       verbose=False):

        _guid = lambda x: re.fullmatch(str(guid), x)
        _hexstr = lambda x: re.fullmatch('[0-9a-fA-F]+', x)
        _str = lambda x: isinstance(x, str)
        _int = lambda x: isinstance(x, int)

        # these next 2 will raise an assertion error on failure
        def _used_from(x):
            self._check_timestamp(x, used_from)
            return True

        def _created(x):
            self._check_timestamp(x, used_from)
            return True

        validators = {
            "cn": _guid,
            "dn": _str,
            "msKds-CreateTime": _created,
            "msKds-DomainID": _str,
            "msKds-KDFAlgorithmID": _str,
            "msKds-KDFParam": _hexstr,
            "msKds-PrivateKeyLength": _int,
            "msKds-PublicKeyLength": _int,
            "msKds-SecretAgreementAlgorithmID": _str,
            "msKds-UseStartTime": _used_from,
            "msKds-Version": _int,
            "name": _guid,
            "objectGUID": _str,
            "whenChanged": _str,
            "whenCreated": _str,
        }
        if verbose:
            keys = validators
        else:
            keys = ["name", "msKds-UseStartTime", "msKds-CreateTime", "dn"]

        self.assertEqual(len(keys), len(snippet), f"keys: {keys}, json: {snippet}")

        for k in keys:
            f = validators.get(k)
            v = snippet.get(k)
            self.assertTrue(f(v), f"{k} value {v} is wrong or malformed")

    def _get_root_key_guids(self):
        """Get the current list of GUIDs."""
        result, out, err = self.runcmd("domain", "kds", "root-key", "list", "--json",
                                       "-H", HOST, CREDS)
        return [x['name'] for x in json.loads(out)]

    def _delete_root_key(self, guid):
        dn = Dn(self.samdb, str(self.root_key_base_dn))
        dn.add_child(f"CN={guid}")
        self.samdb.delete(dn)

class KdsRootKeyTests(KdsRootKeyTestsBase):

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        # we'll add one for all tests to rely on.
        cls.common_guid, cls.common_dn, cls.common_time, _ = cls._create_root_key_timediff()
        cls.addClassCleanup(cls.samdb.delete, cls.common_dn)

    def test_list(self):

        """Do we list root keys with the expected info?"""
        # For this test we also need to create some root keys.
        guid, dn, _created, _used = self._create_root_key_timediff_cleanup()

        result, out, err = self.runcmd("domain", "kds", "root-key", "list",
                                       "-H", HOST, CREDS)
        self.assertCmdSuccess(result, out, err)
        self.assertEqual(err, "", "not expecting error messages")

        # the output looks something like
        #
        #------------------------------------------------------------------------
        # 2 root keys found.
        #
        # name d58e85d7-ffc4-d118-9c43-46fac38dea05
        #   created        2024-02-27T09:09:21.065486+00:00 (about 1 seconds ago)
        #   usable from    2024-02-27T09:09:21.065486+00:00 (about 1 seconds ago)
        #
        # name 8f3e6557-3ec9-cb84-2ecd-9e258df68e79
        #   created        2024-02-27T09:09:10.853494+00:00 (about 12 seconds ago)
        #   usable from    2024-02-27T09:09:10.853494+00:00 (about 12 seconds ago)
        #-------------------------------------------------------------------------
        #
        # we want to check the various bits.

        parts = out.rstrip().split("\n\n")

        self.assertEqual(parts[0], f"{len(parts) - 1} root keys found.")

        self._test_list_output_snippet(parts[1], guid,
                                       created=NOWISH,
                                       used_from=NOWISH)

        guid2, dn2, _created2, _used2 = self._create_root_key_timediff_cleanup()

        result, out, err = self.runcmd("domain", "kds", "root-key", "list",
                                       "-H", HOST, CREDS)
        self.assertCmdSuccess(result, out, err)
        self.assertEqual(err, "", "not expecting error messages")

        parts2 = out.rstrip().split("\n\n")
        self.assertEqual(parts2[0], f"{len(parts)} root keys found.")
        self.assertEqual(len(parts2), len(parts) + 1)

        # we want to check that both of them are still there, in the
        # right order, which is newest first.
        self._test_list_output_snippet(parts2[1], guid2,
                                       created=_created2,
                                       used_from=_used2)
        self._test_list_output_snippet(parts2[2], guid,
                                       created=_created,
                                       used_from=_used)

    def test_list_verbose(self):
        """Do we list root keys with the expected info?"""
        guid, dn, _created, _used = self._create_root_key_timediff_cleanup()

        result, out, err = self.runcmd("domain", "kds", "root-key", "list", "-v",
                                       "-H", HOST, CREDS)

        self.assertCmdSuccess(result, out, err)
        self.assertEqual(err, "", "not expecting error messages")

        self._test_list_output_snippet(out, guid, verbose=True)

        guid2, dn2, _created2, _used2 = self._create_root_key_timediff_cleanup()

        result, out, err = self.runcmd("domain", "kds", "root-key", "list", "-v",
                                       "-H", HOST, CREDS)
        self.assertCmdSuccess(result, out, err)
        self.assertEqual(err, "", "not expecting error messages")

        self._test_list_output_snippet(out, guid2, verbose=True)

        # in case there are other root keys, we will test each piece
        # using the default '[0-9a-fA-F-]{36}' guid-ish assertion.

        pieces = out.rstrip().split('\n\n')
        self.assertRegex(pieces[0], f'{len(pieces) - 1} root keys found.')

        for piece in pieces[1:]:
            self._test_list_output_snippet(piece, verbose=True)

    def test_list_json(self):
        """The JSON should be a list of dicts, containing the right things"""
        guid, dn, _created, _used = self._create_root_key_timediff_cleanup()

        result, out, err = self.runcmd("domain", "kds", "root-key", "list", "-v", "--json",
                                       "-H", HOST, CREDS)
        self.assertCmdSuccess(result, out, err)
        self.assertEqual(err, "", "not expecting error messages")
        data = json.loads(out)
        for snippet in data:
            self._test_list_output_json_snippet(snippet, verbose=True)

        # non-verbose
        result, out, err = self.runcmd("domain", "kds", "root-key", "list", "--json",
                                       "-H", HOST, CREDS)
        self.assertCmdSuccess(result, out, err)
        self.assertEqual(err, "", "not expecting error messages")
        data = json.loads(out)
        for snippet in data:
            self._test_list_output_json_snippet(snippet)

    def test_view_key_that_exists(self):
        guid, dn, _created, _used = self._create_root_key_timediff_cleanup()
        cmd = ["domain", "kds", "root-key", "view",
               "-H", HOST, CREDS,
               "--name", str(guid)]

        result, out, err = self.runcmd(*cmd)
        self.assertCmdSuccess(result, out, err)
        self.assertEqual(err, "", "not expecting error messages")

        self._test_list_output_snippet(out, guid,
                                       created=NOWISH,
                                       used_from=NOWISH,
                                       verbose=True)

    def test_view_key_that_exists_json(self):
        guid, dn, _created, _used = self._create_root_key_timediff_cleanup()

        result, out, err = self.runcmd("domain", "kds", "root-key", "view",
                                       "--json",
                                       "--name", str(guid),
                                       "-H", HOST, CREDS)
        self.assertCmdSuccess(result, out, err)
        self.assertEqual(err, "", "not expecting error messages")
        data = json.loads(out)
        self._test_list_output_json_snippet(data, guid,
                                            created=_created,
                                            used_from=_used,
                                            verbose=True)


    def test_view_key_latest_json(self):
        guid, dn, _created, _used = self._create_root_key_timediff_cleanup()

        result, out, err = self.runcmd("domain", "kds", "root-key", "view",
                                       "--json",
                                       "--latest",
                                       "-H", HOST, CREDS)
        self.assertCmdSuccess(result, out, err)
        self.assertEqual(err, "", "not expecting error messages")
        data = json.loads(out)
        self._test_list_output_json_snippet(data, guid,
                                            created=_created,
                                            used_from=_used,
                                            verbose=True)

        # if we make a new now-ish key, it will be shown with
        # --latest, forgetting the old one.
        guid2, dn2, _created2, _used2 = self._create_root_key_timediff_cleanup()

        result, out, err = self.runcmd("domain", "kds", "root-key", "view",
                                       "--json",
                                       "--latest",
                                       "-H", HOST, CREDS)
        self.assertCmdSuccess(result, out, err)
        self.assertEqual(err, "", "not expecting error messages")
        data = json.loads(out)
        self._test_list_output_json_snippet(data, guid2,
                                            created=_created2,
                                            used_from=_used2,
                                            verbose=True)

        # if we make a new backdated key, it will not be shown as
        # latest, even though it was the most recently created.

        self._create_root_key_timediff_cleanup(use_diff=-600)

        result, out, err = self.runcmd("domain", "kds", "root-key", "view",
                                       "--json",
                                       "--latest",
                                       "-H", HOST, CREDS)
        self.assertCmdSuccess(result, out, err)
        self.assertEqual(err, "", "not expecting error messages")
        data = json.loads(out)
        self._test_list_output_json_snippet(data, guid2,
                                            created=_created2,
                                            used_from=_used2,
                                            verbose=True)

        # if we make a future-dated key, it will be shown as
        # latest, even though it doesn't work yet.

        guid3, dn3, _created3, _used3 = self._create_root_key_timediff_cleanup()

        result, out, err = self.runcmd("domain", "kds", "root-key", "view",
                                       "--json",
                                       "--latest",
                                       "-H", HOST, CREDS)
        self.assertCmdSuccess(result, out, err)
        self.assertEqual(err, "", "not expecting error messages")
        data = json.loads(out)
        self._test_list_output_json_snippet(data, guid3,
                                            created=_created3,
                                            used_from=_used3,
                                            verbose=True)

    def test_view_non_existent(self):
        """Viewing a non-existent GUID should fail, regardless of what exists."""
        guid = misc.GUID(b'a' * 16)

        result, out, err = self.runcmd("domain", "kds", "root-key", "view",
                                       "-H", HOST, CREDS,
                                       "--name", str(guid))
        self.assertCmdFail(result)

        self.assertIn("ERROR: no such root key: 61616161-6161-6161-6161-616161616161",
                      err)

    def test_view_non_existent_json(self):
        guid = misc.GUID(b'a' * 16)

        result, out, err = self.runcmd("domain", "kds", "root-key", "view",
                                       "-H", HOST, CREDS,
                                       "--name", str(guid),
                                       "--json")
        self.assertCmdFail(result)
        data = json.loads(out)
        self.assertEqual(
            data,
            {
                "message": f"no such root key: {guid}",
                "status": "error"
            })

    def test_delete_non_existent(self):
        """Deletion of non-existent guid should fail"""
        guid = 'eeeeeeee-1111-eeee-1111-000000000000'
        result, out, err = self.runcmd("domain", "kds", "root-key", "delete",
                                       "-H", HOST, CREDS,
                                       "--name", guid)
        self.assertCmdFail(result)
        self.assertIn(f"ERROR: no such root key: {guid}", err)

    def test_delete_non_existent_json(self):
        """Deletion of non-existent guids should fail"""
        for guid in ('eeeeeeee-1111-eeee-1111-000000000000',
                     'foo',
                     ''):
            result, out, err = self.runcmd("domain", "kds", "root-key", "delete",
                                           "-H", HOST, CREDS,
                                           "--name", guid,
                                           "--json")
            self.assertCmdFail(result)
            data = json.loads(out)
            self.assertEqual(
                data,
                {
                    "message": f"no such root key: {guid}",
                    "status": "error"
                })

    def test_create(self):
        """does create work?"""
        pre_create = self._get_root_key_guids()

        result, out, err = self.runcmd("domain", "kds", "root-key", "create",
                                       "-H", HOST, CREDS)
        self.assertCmdSuccess(result, out, err)
        self.assertEqual(err, "", "not expecting error messages")

        post_create = self._get_root_key_guids()

        new_guids = list(set(post_create) - set(pre_create))
        gone_guids = set(pre_create) - set(post_create)
        self.assertEqual(len(gone_guids), 0)
        self.assertEqual(len(new_guids), 1)
        self.assertRegex(out,
                         f"created root key {new_guids[0]}, usable from {TIMESTAMP_RE}")
        self._delete_root_key(new_guids[0])

    def test_create_json(self):
        """does create work?"""
        pre_create = self._get_root_key_guids()

        result, out, err = self.runcmd("domain", "kds", "root-key", "create",
                                       "-H", HOST, CREDS, "--json")
        self.assertCmdSuccess(result, out, err)
        self.assertEqual(err, "", "not expecting error messages")

        post_create = self._get_root_key_guids()

        new_guids = list(set(post_create) - set(pre_create))
        gone_guids = set(pre_create) - set(post_create)
        self.assertEqual(len(gone_guids), 0)
        self.assertEqual(len(new_guids), 1)
        data = json.loads(out)
        self.assertEqual(data['dn'], f"CN={new_guids[0]},{self.root_key_base_dn}")
        self.assertEqual(data['status'], 'OK')
        self.assertRegex(data['message'],
                         f"created root key {new_guids[0]}, usable from {TIMESTAMP_RE}")
        self._delete_root_key(new_guids[0])

    def test_create_json_non_admin(self):
        """can you create a root-key without being admin?"""
        pre_create = self._get_root_key_guids()

        result, out, err = self.runcmd("domain", "kds", "root-key", "create",
                                       "-H", HOST, NON_ADMIN_CREDS, "--json")
        self.assertCmdFail(result)

        post_create = self._get_root_key_guids()

        self.assertEqual(set(pre_create), set(post_create))
        data = json.loads(out)
        self.assertEqual(data['status'], 'error')
        self.assertEqual(data['message'], 'User has insufficient access rights')
        self.assertEqual(err, "", "not expecting stderr messages")

    def test_create_json_1997(self):
        """does create work?"""
        pre_create = self._get_root_key_guids()

        result, out, err = self.runcmd("domain", "kds", "root-key", "create",
                                       "-H", HOST, CREDS, "--json",
                                       "--use-start-time",
                                       "1997-11-11T23:18:00.259810+00:00")
        self.assertCmdSuccess(result, out, err)
        self.assertEqual(err, "", "not expecting error messages")

        post_create = self._get_root_key_guids()

        new_guids = list(set(post_create) - set(pre_create))
        gone_guids = set(pre_create) - set(post_create)
        self.assertEqual(len(gone_guids), 0)
        self.assertEqual(len(new_guids), 1)
        data = json.loads(out)
        self.assertEqual(data['dn'], f"CN={new_guids[0]},{self.root_key_base_dn}")
        self.assertEqual(data['status'], 'OK')
        self.assertRegex(data['message'],
                         f"created root key {new_guids[0]}, usable from 1997-11-1")
        self._delete_root_key(new_guids[0])

    def test_create_json_2197(self):
        """does create work?"""
        pre_create = self._get_root_key_guids()

        result, out, err = self.runcmd("domain", "kds", "root-key", "create",
                                       "-H", HOST, CREDS, "--json",
                                       "--use-start-time",
                                       "2197-11-11T23:18:00")
        self.assertCmdSuccess(result, out, err)
        self.assertEqual(err, "", "not expecting error messages")

        post_create = self._get_root_key_guids()

        new_guids = list(set(post_create) - set(pre_create))
        gone_guids = set(pre_create) - set(post_create)
        self.assertEqual(len(gone_guids), 0)
        self.assertEqual(len(new_guids), 1)
        data = json.loads(out)
        self.assertEqual(data['dn'], f"CN={new_guids[0]},{self.root_key_base_dn}")
        self.assertEqual(data['status'], 'OK')
        self.assertRegex(data['message'],
                         f"created root key {new_guids[0]}, usable from 2197-11-1")
        self._delete_root_key(new_guids[0])

    def test_create_future(self):
        """does create work, with a use-start-time 500 seconds in the
        future?"""
        pre_create = self._get_root_key_guids()
        now = nt_now()
        later = now + 500 * NT_TICKS_PER_SEC
        timestamp = string_from_nt_time(later)

        result, out, err = self.runcmd("domain", "kds", "root-key", "create",
                                       "-H", HOST, CREDS, "--json",
                                       "--use-start-time", timestamp)

        self.assertCmdSuccess(result, out, err)
        self.assertEqual(err, "", "not expecting error messages")

        post_create = self._get_root_key_guids()

        new_guids = list(set(post_create) - set(pre_create))
        gone_guids = set(pre_create) - set(post_create)
        self.assertEqual(len(gone_guids), 0)
        self.assertEqual(len(new_guids), 1)
        data = json.loads(out)
        self.assertEqual(data['dn'], f"CN={new_guids[0]},{self.root_key_base_dn}")
        self.assertEqual(data['status'], 'OK')
        self.assertRegex(data['message'],
                         f"created root key {new_guids[0]}, usable from {timestamp[:-10]}")
        self._delete_root_key(new_guids[0])

    def test_delete(self):
        """does delete work?"""
        # make one to delete, and get the list as JSON
        _guid, dn, _created, _used = self._create_root_key_timediff()
        guid = str(_guid)

        result, out, err = self.runcmd("domain", "kds", "root-key", "list", "--json",
                                       "-H", HOST, CREDS)
        pre_delete = json.loads(out)

        result, out, err = self.runcmd("domain", "kds", "root-key", "delete",
                                       "-H", HOST, CREDS,
                                       "--name", guid)
        self.assertCmdSuccess(result, out, err)
        self.assertEqual(err, "", "not expecting error messages")
        self.assertEqual(out, f"deleted root key {guid}\n")

        result, out, err = self.runcmd("domain", "kds", "root-key", "list", "--json",
                                       "-H", HOST, CREDS)
        post_delete = json.loads(out)

        self.assertEqual(len(pre_delete), len(post_delete) + 1)

        post_names = [x['name'] for x in post_delete]
        pre_names = [x['name'] for x in pre_delete]

        self.assertIn(guid, pre_names)
        self.assertNotIn(guid, post_names)

    def test_delete_json(self):
        """does delete --json work?"""
        _guid, dn, _created, _used = self._create_root_key_timediff()
        guid = str(_guid)

        result, out, err = self.runcmd("domain", "kds", "root-key", "list", "--json",
                                       "-H", HOST, CREDS)
        pre_delete = json.loads(out)

        result, out, err = self.runcmd("domain", "kds", "root-key", "delete",
                                       "-H", HOST, CREDS, "--json",
                                       "--name", guid)

        self.assertCmdSuccess(result, out, err)
        self.assertEqual(err, "", "not expecting error messages")
        data = json.loads(out)
        self.assertEqual(
            data,
            {
                "message": f"deleted root key {guid}",
                "status": "error"
            })

        result, out, err = self.runcmd("domain", "kds", "root-key", "list", "--json",
                                       "-H", HOST, CREDS)
        post_delete = json.loads(out)

        self.assertEqual(len(pre_delete), len(post_delete) + 1)

        post_names = [x['name'] for x in post_delete]
        pre_names = [x['name'] for x in pre_delete]

        self.assertIn(guid, pre_names)
        self.assertNotIn(guid, post_names)

    def test_delete_non_admin(self):
        """does delete as non-admin fail?"""
        # make one to delete, and get the list as JSON
        _guid, dn, _created, _used = self._create_root_key_timediff()
        guid = str(_guid)

        result, out, err = self.runcmd("domain", "kds", "root-key", "list", "--json",
                                       "-H", HOST, CREDS)
        pre_delete = json.loads(out)

        result, out, err = self.runcmd("domain", "kds", "root-key", "delete",
                                       "-H", HOST, NON_ADMIN_CREDS,
                                       "--name", guid)
        self.assertCmdFail(result)
        self.assertIn(f"ERROR: no such root key: {guid}", err)

        # a bad guid should be just like a good guid
        guid2 = 'eeeeeeee-1111-eeee-1111-000000000000'
        result, out2, err2 = self.runcmd("domain", "kds", "root-key", "delete",
                                         "-H", HOST, NON_ADMIN_CREDS,
                                         "--name", guid2)
        self.assertCmdFail(result)
        self.assertIn(f"ERROR: no such root key: {guid2}", err2)

        result, out, err = self.runcmd("domain", "kds", "root-key", "list", "--json",
                                       "-H", HOST, CREDS)
        post_delete = json.loads(out)

        self.assertEqual(len(pre_delete), len(post_delete))

        post_names = [x['name'] for x in post_delete]
        pre_names = [x['name'] for x in pre_delete]

        self.assertIn(guid, pre_names)
        self.assertIn(guid, post_names)

    def test_list_non_admin(self):
        """There are root keys, but non-admins can't see them"""
        result, out, err = self.runcmd("domain", "kds", "root-key", "list",
                                       "-H", HOST, NON_ADMIN_CREDS)
        self.assertCmdSuccess(result, out, err)
        self.assertEqual(err, "", "not expecting error messages")
        self.assertEqual(out, "no root keys found.\n")

    def test_list_json_non_admin(self):
        """Insufficient rights should look like an empty list."""
        # this is a copy of the KdsNoRootKeyTests test below --
        # non-admin should look exactly like an empty list.
        for extra in ([], ["-v"]):
            result, out, err = self.runcmd("domain", "kds", "root-key", "list",
                                           "-H", HOST, NON_ADMIN_CREDS, "--json", *extra)
            self.assertCmdSuccess(result, out, err)
            self.assertEqual(err, "", "not expecting error messages")
            data = json.loads(out)
            self.assertEqual(data, [])

    def test_view_key_non_admin(self):
        """should not appear to non-admin"""
        guid, dn, _created, _used = self._create_root_key_timediff_cleanup()

        result, out, err = self.runcmd("domain", "kds", "root-key", "view",
                                       "--json",
                                       "--name", str(guid),
                                       "-H", HOST, NON_ADMIN_CREDS)
        self.assertCmdFail(result)
        self.assertEqual(err, "", "not expecting error messages")
        data = json.loads(out)
        data = json.loads(out)
        self.assertEqual(
            data,
            {
                "message": f"no such root key: {guid}",
                "status": "error"
            })


class KdsNoRootKeyTests(KdsRootKeyTestsBase):
    """Here we test the case were there are no root keys, which we need to
    ensure by deleting any that are there.
    """

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        # We delete all the root keys, and add one back at the end,
        # in case other tests want there to be one.
        res = cls.samdb.search(cls.root_key_base_dn,
                               scope=SCOPE_SUBTREE,
                               expression="(objectClass = msKds-ProvRootKey)")

        for msg in res:
            cls.samdb.delete(msg.dn)

        cls.addClassCleanup(cls.samdb.new_gkdi_root_key)

    def test_list_empty(self):
        """Check the message when there are no root keys"""
        result, out, err = self.runcmd("domain", "kds", "root-key", "list",
                                       "-H", HOST, CREDS)
        self.assertCmdSuccess(result, out, err)
        self.assertEqual(err, "", "not expecting error messages")
        self.assertEqual(out, "no root keys found.\n")

    def test_list_empty_json(self):
        """The JSON should be an empty list when there are no root keys"""
        # verbose flag makes no difference here.
        for extra in ([], ["-v"]):
            result, out, err = self.runcmd("domain", "kds", "root-key", "list",
                                           "-H", HOST, CREDS, "--json", *extra)
            self.assertCmdSuccess(result, out, err)
            self.assertEqual(err, "", "not expecting error messages")
            data = json.loads(out)
            self.assertEqual(data, [])

    def test_list_empty_json_non_admin(self):
        """Insufficient rights should look like an empty list."""
        # verbose flag makes no difference here.
        for extra in ([], ["-v"]):
            result, out, err = self.runcmd("domain", "kds", "root-key", "list",
                                           "-H", HOST, NON_ADMIN_CREDS, "--json", *extra)
            self.assertCmdSuccess(result, out, err)
            self.assertEqual(err, "", "not expecting error messages")
            data = json.loads(out)
            self.assertEqual(data, [])

    def test_view_latest_non_existent(self):
        """With no root keys, --latest should return an error"""

        result, out, err = self.runcmd("domain", "kds", "root-key", "view",
                                       "-H", HOST, CREDS,
                                       "--latest")

        self.assertEqual(err, "ERROR: no root keys found\n")
        self.assertCmdFail(result)

    def test_view_latest_non_existent_json(self):
        """With no root keys, --latest should return an error"""

        result, out, err = self.runcmd("domain", "kds", "root-key", "view",
                                       "-H", HOST, CREDS,
                                       "--json", "--latest")
        self.assertCmdFail(result)
        data = json.loads(out)
        self.assertEqual(
            data,
            {
                "message": "no root keys found",
                "status": "error"
            })

    def test_view_non_existent(self):
        """Viewing a non-existent GUID should fail, regardless of what exists."""
        guid = misc.GUID(b'b' * 16)

        result, out, err = self.runcmd("domain", "kds", "root-key", "view",
                                       "-H", HOST, CREDS,
                                       "--name", str(guid))
        self.assertCmdFail(result)

        self.assertIn("ERROR: no such root key: 62626262-6262-6262-6262-626262626262",
                      err)
