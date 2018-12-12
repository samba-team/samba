#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import optparse
import sys
sys.path.insert(0, 'bin/python')

import os
import samba
import samba.getopt as options
import random
import tempfile
import shutil
import subprocess

from samba.netcmd.main import cmd_sambatool

# We try to use the test infrastructure of Samba 4.3+, but if it
# doesn't work, we are probably in a back-ported patch and trying to
# run on 4.1 or something.
#
# Don't copy this horror into ordinary tests -- it is special for
# performance tests that want to apply to old versions.
try:
    from samba.tests.subunitrun import SubunitOptions, TestProgram
    ANCIENT_SAMBA = False
except ImportError:
    ANCIENT_SAMBA = True
    samba.ensure_external_module("testtools", "testtools")
    samba.ensure_external_module("subunit", "subunit/python")
    from subunit.run import SubunitTestRunner
    import unittest

parser = optparse.OptionParser("ad_dc_provision_performance.py [options] <host>")
sambaopts = options.SambaOptions(parser)
parser.add_option_group(sambaopts)
parser.add_option_group(options.VersionOptions(parser))

if not ANCIENT_SAMBA:
    subunitopts = SubunitOptions(parser)
    parser.add_option_group(subunitopts)

# use command line creds if available
credopts = options.CredentialsOptions(parser)
parser.add_option_group(credopts)
opts, args = parser.parse_args()


if len(args) < 1:
    parser.print_usage()
    sys.exit(1)

host = args[0]

lp = sambaopts.get_loadparm()
creds = credopts.get_credentials(lp)

random.seed(1)


class PerfTestException(Exception):
    pass


class UserTests(samba.tests.TestCase):

    def setUp(self):
        super(UserTests, self).setUp()
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmpdir)

    def test_00_00_do_nothing(self):
        # this gives us an idea of the overhead
        pass

    def _test_provision_subprocess(self, options=None, subdir=None):
        if subdir is None:
            d = self.tmpdir
        else:
            d = os.path.join(self.tmpdir, str(subdir))
            os.mkdir(d)

        cmd = ['bin/samba-tool', 'domain', 'provision', '--targetdir',
               d, '--realm=realm.com', '--use-ntvfs', '--domain=dom']

        if options:
            options.extend(options)
        subprocess.check_call(cmd)

    test_01_00_provision_subprocess = _test_provision_subprocess

    def test_01_00_provision_subprocess_overwrite(self):
        for i in range(2):
            self._test_provision_subprocess()

    def test_02_00_provision_cmd_sambatool(self):
        cmd = cmd_sambatool.subcommands['domain'].subcommands['provision']
        result = cmd._run("samba-tool domain provision",
                          '--targetdir=%s' % self.tmpdir,
                          '--use-ntvfs')

    def test_03_00_provision_server_role(self):
        for role in ('member', 'server', 'member', 'standalone'):
            self._test_provision_subprocess(options=['--server-role', role],
                                            subdir=role)

    def test_04_00_provision_blank(self):
        for i in range(2):
            self._test_provision_subprocess(options=['--blank'],
                                            subdir=i)

    def test_05_00_provision_partitions_only(self):
        self._test_provision_subprocess(options=['--partitions-only'])


if "://" not in host:
    if os.path.isfile(host):
        host = "tdb://%s" % host
    else:
        host = "ldap://%s" % host


if ANCIENT_SAMBA:
    runner = SubunitTestRunner()
    if not runner.run(unittest.makeSuite(UserTests)).wasSuccessful():
        sys.exit(1)
    sys.exit(0)
else:
    TestProgram(module=__name__, opts=subunitopts)
