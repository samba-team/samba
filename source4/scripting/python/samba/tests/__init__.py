#!/usr/bin/env python

# Unix SMB/CIFS implementation.
# Copyright (C) Jelmer Vernooij <jelmer@samba.org> 2007-2008
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

"""Samba Python tests."""

import os
import ldb
import samba
import samba.auth
from samba import param
import subprocess
import tempfile

# Other modules import these two classes from here, for convenience:
from testtools.testcase import TestCase, TestSkipped


class LdbTestCase(TestCase):
    """Trivial test case for running tests against a LDB."""

    def setUp(self):
        super(LdbTestCase, self).setUp()
        self.filename = os.tempnam()
        self.ldb = samba.Ldb(self.filename)

    def set_modules(self, modules=[]):
        """Change the modules for this Ldb."""
        m = ldb.Message()
        m.dn = ldb.Dn(self.ldb, "@MODULES")
        m["@LIST"] = ",".join(modules)
        self.ldb.add(m)
        self.ldb = samba.Ldb(self.filename)


class TestCaseInTempDir(TestCase):

    def setUp(self):
        super(TestCaseInTempDir, self).setUp()
        self.tempdir = tempfile.mkdtemp()

    def tearDown(self):
        super(TestCaseInTempDir, self).tearDown()
        self.assertEquals([], os.listdir(self.tempdir))
        os.rmdir(self.tempdir)


def env_loadparm():
    lp = param.LoadParm()
    try:
        lp.load(os.environ["SMB_CONF_PATH"])
    except KeyError:
        raise Exception("SMB_CONF_PATH not set")
    return lp

cmdline_credentials = None

class RpcInterfaceTestCase(TestCase):

    def get_loadparm(self):
        return env_loadparm()

    def get_credentials(self):
        return cmdline_credentials


class ValidNetbiosNameTests(TestCase):

    def test_valid(self):
        self.assertTrue(samba.valid_netbios_name("FOO"))

    def test_too_long(self):
        self.assertFalse(samba.valid_netbios_name("FOO"*10))

    def test_invalid_characters(self):
        self.assertFalse(samba.valid_netbios_name("*BLA"))


class BlackboxTestCase(TestCase):
    """Base test case for blackbox tests."""

    def check_run(self, line):
        bindir = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../../bin"))
        parts = line.split(" ")
        if os.path.exists(os.path.join(bindir, parts[0])):
            parts[0] = os.path.join(bindir, parts[0])
        line = " ".join(parts)
        subprocess.check_call(line, shell=True)


def connect_samdb(samdb_url, lp=None, session_info=None,
                  credentials=None, flags=0, ldb_options=None, ldap_only=False):
    """Creates SamDB instance and connects to samdb_url database.

    :param samdb_url: Url for database to connect to.
    :param lp: Optional loadparm object
    :param session_info: Optional session information
    :param credentials: Optional credentials, defaults to anonymous.
    :param flags: Optional LDB flags
    :param ldap_only: If set, only remote LDAP connection will be created.

    Added value for tests is that we have a shorthand function
    to make proper URL for ldb.connect() while using default
    parameters for connection based on test environment
    """
    samdb_url = samdb_url.lower()
    if not "://" in samdb_url:
        if not ldap_only and os.path.isfile(samdb_url):
            samdb_url = "tdb://%s" % samdb_url
        else:
            samdb_url = "ldap://%s" % samdb_url
    # use 'paged_search' module when connecting remotely
    if samdb_url.startswith("ldap://"):
        ldb_options = ["modules:paged_searches"]
    else:
        assert not ldap_only, \
               "Trying to connect to %s while remote connection is required" % samdb_url

    # set defaults for test environment
    if not lp:
        lp=env_loadparm()
    if not session_info:
        session_info=samba.auth.system_session()
    if not credentials:
        credentials=cmdline_credentials

    from samba.samdb import SamDB
    return SamDB(url=samdb_url,
                 lp=lp,
                 session_info=session_info,
                 credentials=credentials,
                 flags=flags,
                 options=ldb_options)
