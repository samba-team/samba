# Unix SMB/CIFS implementation.
# Copyright (C) Andrew Bartlett 2012
#
# Based on user.py:
# Copyright (C) Sean Dague <sdague@linux.vnet.ibm.com> 2011
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
from samba.tests.samba_tool.base import SambaToolCmdTest
from samba.tests import env_loadparm
import random
import secrets


class NtACLCmdSysvolTestCase(SambaToolCmdTest):
    """Tests for samba-tool ntacl sysvol* subcommands"""

    def test_ntvfs(self):
        (result, out, err) = self.runsubcmd("ntacl", "sysvolreset",
                                            "--use-ntvfs")
        self.assertCmdSuccess(result, out, err)
        self.assertEqual(out, "", "Shouldn't be any output messages")
        self.assertIn("Please note that POSIX permissions have NOT been changed, only the stored NT ACL", err)

    def test_s3fs(self):
        (result, out, err) = self.runsubcmd("ntacl", "sysvolreset",
                                            "--use-s3fs")

        self.assertCmdSuccess(result, out, err)
        self.assertEqual(err, "", "Shouldn't be any error messages")
        self.assertEqual(out, "", "Shouldn't be any output messages")

    def test_ntvfs_check(self):
        (result, out, err) = self.runsubcmd("ntacl", "sysvolreset",
                                            "--use-ntvfs")
        self.assertCmdSuccess(result, out, err)
        self.assertEqual(out, "", "Shouldn't be any output messages")
        self.assertIn("Please note that POSIX permissions have NOT been changed, only the stored NT ACL", err)
        # Now check they were set correctly
        (result, out, err) = self.runsubcmd("ntacl", "sysvolcheck")
        self.assertCmdSuccess(result, out, err)
        self.assertEqual(err, "", "Shouldn't be any error messages")
        self.assertEqual(out, "", "Shouldn't be any output messages")

    def test_s3fs_check(self):
        (result, out, err) = self.runsubcmd("ntacl", "sysvolreset",
                                            "--use-s3fs")

        self.assertCmdSuccess(result, out, err)
        self.assertEqual(err, "", "Shouldn't be any error messages")
        self.assertEqual(out, "", "Shouldn't be any output messages")

        # Now check they were set correctly
        (result, out, err) = self.runsubcmd("ntacl", "sysvolcheck")
        self.assertCmdSuccess(result, out, err)
        self.assertEqual(err, "", "Shouldn't be any error messages")
        self.assertEqual(out, "", "Shouldn't be any output messages")

    def test_with_missing_files(self):
        lp = env_loadparm()
        sysvol = lp.get('path', 'sysvol')
        realm = lp.get('realm').lower()

        src = os.path.join(sysvol, realm, 'Policies')
        dest = os.path.join(sysvol, realm, 'Policies-NOT-IN-THE-EXPECTED-PLACE')
        try:
            os.rename(src, dest)

            for args in (["sysvolreset", "--use-s3fs"],
                         ["sysvolreset", "--use-ntvfs"],
                         ["sysvolreset"],
                         ["sysvolcheck"]
            ):

                (result, out, err) = self.runsubcmd("ntacl", *args)
                self.assertCmdFail(result, f"succeeded with {args} with missing dir")
                self.assertNotIn("uncaught exception", err,
                                 "Shouldn't be uncaught exception")
                self.assertNotRegex(err, r'^\s*File [^,]+, line \d+, in',
                                    "Shouldn't be lines of traceback")
                self.assertEqual(out, "", "Shouldn't be any output messages")
        finally:
            os.rename(dest, src)


class NtACLCmdGetSetTestCase(SambaToolCmdTest):
    """Tests for samba-tool ntacl get/set subcommands"""

    acl = "O:DAG:DUD:P(A;OICI;FA;;;DA)(A;OICI;FA;;;EA)(A;OICIIO;FA;;;CO)(A;OICI;FA;;;DA)(A;OICI;FA;;;SY)(A;OICI;0x1200a9;;;AU)(A;OICI;0x1200a9;;;ED)S:AI(OU;CIIDSA;WP;f30e3bbe-9ff0-11d1-b603-0000f80367c1;bf967aa5-0de6-11d0-a285-00aa003049e2;WD)(OU;CIIDSA;WP;f30e3bbf-9ff0-11d1-b603-0000f80367c1;bf967aa5-0de6-11d0-a285-00aa003049e2;WD)"

    def test_ntvfs(self):
        path = os.environ['SELFTEST_PREFIX']
        tempf = os.path.join(path, "pytests" + str(int(100000 * random.random())))
        open(tempf, 'w').write("empty")

        (result, out, err) = self.runsubcmd("ntacl", "set", self.acl, tempf,
                                            "--use-ntvfs")
        self.assertCmdSuccess(result, out, err)
        self.assertEqual(out, "", "Shouldn't be any output messages")
        self.assertIn("Please note that POSIX permissions have NOT been changed, only the stored NT ACL", err)

    def test_s3fs(self):
        path = os.environ['SELFTEST_PREFIX']
        tempf = os.path.join(path, "pytests" + str(int(100000 * random.random())))
        open(tempf, 'w').write("empty")

        (result, out, err) = self.runsubcmd("ntacl", "set", self.acl, tempf,
                                            "--use-s3fs")

        self.assertCmdSuccess(result, out, err)
        self.assertEqual(err, "", "Shouldn't be any error messages")
        self.assertEqual(out, "", "Shouldn't be any output messages")

    def test_set_expect_file_not_found(self):
        path = os.environ['SELFTEST_PREFIX']
        tempf_basename = f"{self.unique_name()}-{secrets.token_hex(10)}"
        tempf = os.path.join(path, tempf_basename)

        for fs_arg in ["--use-s3fs", "--use-ntvfs"]:
            (result, out, err) = self.runsubcmd("ntacl",
                                                "set",
                                                self.acl,
                                                tempf_basename,
                                                fs_arg)

            self.assertCmdFail(result, "succeeded with non-existent file")
            self.assertIn("No such file or directory",
                          err,
                          "No such file or directory expected")
            self.assertEqual(out, "", "Shouldn't be any output messages")

    def test_set_with_relative_path(self):
        path = os.environ['SELFTEST_PREFIX']
        tempf_basename = f"{self.unique_name()}-{secrets.token_hex(10)}"
        tempf = os.path.join(path, tempf_basename)
        workdir = os.getcwd()

        open(tempf, 'w').write("empty")

        os.chdir(path)

        for fs_arg in ["--use-s3fs", "--use-ntvfs"]:
            (result, out, err) = self.runsubcmd("ntacl",
                                                "set",
                                                self.acl,
                                                tempf_basename,
                                                fs_arg)

            self.assertCmdSuccess(result, out, err)
            if fs_arg == "--use-s3fs":
                self.assertEqual(err, "", "Shouldn't be any error messages")
            elif fs_arg == "--use-ntvfs":
                self.assertIn("only the stored NT ACL",
                              err,
                              "only the stored NT ACL warning expected")
            self.assertEqual(out, "", "Shouldn't be any output messages")

        os.chdir(workdir)

    def test_set_with_relative_parent_path(self):
        path = os.environ['SELFTEST_PREFIX']
        tempf_basename = f"{self.unique_name()}-{secrets.token_hex(10)}"
        tempf = os.path.join(path, tempf_basename)
        subdir_basename = f"{self.unique_name()}-subdir-{secrets.token_hex(10)}"
        subdir_path = os.path.join(path, subdir_basename)
        workdir = os.getcwd()

        os.mkdir(subdir_path)
        open(tempf, 'w').write("empty")

        tempf_relative_path = os.path.join("../", tempf_basename)

        os.chdir(subdir_path)

        for fs_arg in ["--use-s3fs", "--use-ntvfs"]:
            (result, out, err) = self.runsubcmd("ntacl",
                                                "set",
                                                self.acl,
                                                tempf_relative_path,
                                                fs_arg)

            self.assertCmdSuccess(result, out, err)
            if fs_arg == "--use-s3fs":
                self.assertEqual(err, "", "Shouldn't be any error messages")
            elif fs_arg == "--use-ntvfs":
                self.assertIn("only the stored NT ACL",
                              err,
                              "only the stored NT ACL warning expected")
            self.assertEqual(out, "", "Shouldn't be any output messages")

        os.chdir(workdir)

    def test_ntvfs_check(self):
        path = os.environ['SELFTEST_PREFIX']
        tempf = os.path.join(path, "pytests" + str(int(100000 * random.random())))
        open(tempf, 'w').write("empty")

        (result, out, err) = self.runsubcmd("ntacl", "set", self.acl, tempf,
                                            "--use-ntvfs")
        self.assertCmdSuccess(result, out, err)
        self.assertEqual(out, "", "Shouldn't be any output messages")
        self.assertIn("Please note that POSIX permissions have NOT been changed, only the stored NT ACL", err)

        # Now check they were set correctly
        (result, out, err) = self.runsubcmd("ntacl", "get", tempf,
                                            "--use-ntvfs", "--as-sddl")
        self.assertCmdSuccess(result, out, err)
        self.assertEqual(err, "", "Shouldn't be any error messages")
        self.assertEqual(self.acl + "\n", out, "Output should be the ACL")

    def test_s3fs_check(self):
        path = os.environ['SELFTEST_PREFIX']
        tempf = os.path.join(path, "pytests" + str(int(100000 * random.random())))
        open(tempf, 'w').write("empty")

        (result, out, err) = self.runsubcmd("ntacl", "set", self.acl, tempf,
                                            "--use-s3fs")
        self.assertCmdSuccess(result, out, err)
        self.assertEqual(out, "", "Shouldn't be any output messages")
        self.assertEqual(err, "", "Shouldn't be any error messages")

        # Now check they were set correctly
        (result, out, err) = self.runsubcmd("ntacl", "get", tempf,
                                            "--use-s3fs", "--as-sddl")
        self.assertCmdSuccess(result, out, err)
        self.assertEqual(err, "", "Shouldn't be any error messages")
        self.assertEqual(self.acl + "\n", out, "Output should be the ACL")

class NtACLCmdChangedomsidTestCase(SambaToolCmdTest):
    """Tests for samba-tool ntacl changedomsid subcommand"""
    maxDiff = 10000
    acl = "O:DAG:DUD:P(A;OICI;0x001f01ff;;;DA)(A;OICI;0x001f01ff;;;EA)(A;OICIIO;0x001f01ff;;;CO)(A;OICI;0x001f01ff;;;DA)(A;OICI;0x001f01ff;;;SY)(A;OICI;0x001200a9;;;AU)(A;OICI;0x001200a9;;;ED)S:AI(OU;CIIDSA;WP;f30e3bbe-9ff0-11d1-b603-0000f80367c1;bf967aa5-0de6-11d0-a285-00aa003049e2;WD)(OU;CIIDSA;WP;f30e3bbf-9ff0-11d1-b603-0000f80367c1;bf967aa5-0de6-11d0-a285-00aa003049e2;WD)"
    new_acl="O:S-1-5-21-2212615479-2695158682-2101375468-512G:S-1-5-21-2212615479-2695158682-2101375468-513D:P(A;OICI;FA;;;S-1-5-21-2212615479-2695158682-2101375468-512)(A;OICI;FA;;;S-1-5-21-2212615479-2695158682-2101375468-519)(A;OICIIO;FA;;;CO)(A;OICI;FA;;;S-1-5-21-2212615479-2695158682-2101375468-512)(A;OICI;FA;;;SY)(A;OICI;0x1200a9;;;AU)(A;OICI;0x1200a9;;;ED)S:AI(OU;CIIDSA;WP;f30e3bbe-9ff0-11d1-b603-0000f80367c1;bf967aa5-0de6-11d0-a285-00aa003049e2;WD)(OU;CIIDSA;WP;f30e3bbf-9ff0-11d1-b603-0000f80367c1;bf967aa5-0de6-11d0-a285-00aa003049e2;WD)"
    domain_sid=os.environ['DOMSID']
    new_domain_sid="S-1-5-21-2212615479-2695158682-2101375468"

    def test_ntvfs_check(self):
        path = os.environ['SELFTEST_PREFIX']
        tempf = os.path.join(
            path, "pytests" + str(int(100000 * random.random())))
        open(tempf, 'w').write("empty")

        print("DOMSID: %s", self.domain_sid)

        (result, out, err) = self.runsubcmd("ntacl",
                                            "set",
                                            self.acl,
                                            tempf,
                                            "--use-ntvfs")
        self.assertCmdSuccess(result, out, err)
        self.assertEqual(out, "", "Shouldn't be any output messages")
        self.assertIn("Please note that POSIX permissions have NOT been "
                      "changed, only the stored NT ACL", err)

        (result, out, err) = self.runsubcmd("ntacl",
                                            "changedomsid",
                                            self.domain_sid,
                                            self.new_domain_sid,
                                            tempf,
                                            "--use-ntvfs")
        self.assertCmdSuccess(result, out, err)
        self.assertEqual(out, "", "Shouldn't be any output messages")
        self.assertIn("Please note that POSIX permissions have NOT been "
                      "changed, only the stored NT ACL.", err)

        # Now check they were set correctly
        (result, out, err) = self.runsubcmd("ntacl",
                                            "get",
                                            tempf,
                                            "--use-ntvfs",
                                            "--as-sddl")
        self.assertCmdSuccess(result, out, err)
        self.assertEqual(err, "", "Shouldn't be any error messages")
        self.assertEqual(self.new_acl + "\n", out, "Output should be the ACL")

    def test_s3fs_check(self):
        path = os.environ['SELFTEST_PREFIX']
        tempf = os.path.join(
            path, "pytests" + str(int(100000 * random.random())))
        open(tempf, 'w').write("empty")

        print("DOMSID: %s" % self.domain_sid)

        (result, out, err) = self.runsubcmd("ntacl",
                                            "set",
                                            self.acl,
                                            tempf,
                                            "--use-s3fs",
                                            "--service=sysvol")
        self.assertCmdSuccess(result, out, err)
        self.assertEqual(out, "", "Shouldn't be any output messages")
        self.assertEqual(err, "", "Shouldn't be any error messages")

        (result, out, err) = self.runsubcmd("ntacl",
                                            "changedomsid",
                                            self.domain_sid,
                                            self.new_domain_sid,
                                            tempf,
                                            "--use-s3fs",
                                            "--service=sysvol")
        self.assertCmdSuccess(result, out, err)
        self.assertEqual(out, "", "Shouldn't be any output messages")
        self.assertEqual(err, "", "Shouldn't be any error messages")

        # Now check they were set correctly
        (result, out, err) = self.runsubcmd("ntacl",
                                            "get",
                                            tempf,
                                            "--use-s3fs",
                                            "--as-sddl",
                                            "--service=sysvol")
        self.assertCmdSuccess(result, out, err)
        self.assertEqual(err, "", "Shouldn't be any error messages")
        self.assertEqual(self.new_acl + "\n", out, "Output should be the ACL")
