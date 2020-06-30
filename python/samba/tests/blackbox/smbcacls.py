# Blackbox tests for smbcaclcs
#
# Copyright (C) Noel Power noel.power@suse.com
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
from __future__ import print_function
from samba.tests import BlackboxTestCase, BlackboxProcessError
from samba.samba3 import param as s3param

from samba.credentials import Credentials

import os

class SmbCaclsBlockboxTestBase(BlackboxTestCase):

    def setUp(self):
        super(SmbCaclsBlockboxTestBase, self).setUp()
        self.lp = s3param.get_context()
        self.server = os.environ["SERVER"]
        self.user = os.environ["USER"]
        self.passwd = os.environ["PASSWORD"]
        self.creds = Credentials()
        self.creds.guess(self.lp)
        self.creds.set_username(self.user)
        self.creds.set_password(self.passwd)
        self.testdir = os.getenv("TESTDIR", "smbcacls")
        self.share = os.getenv("SHARE", "tmp")

    def tearDown(self):
        try:
            # remote removal doesn't seem to work with dfs share(s)
            # #TODO find out if this is intentional (it very well might be)
            # so if we fail with remote remove perform local remove
            # (of remote files) instead
            smbclient_args = self.build_test_cmd("smbclient", ["//%s/%s" % (self.server, self.share), "-c", "deltree %s/*" % self.testdir])
            self.check_output(smbclient_args)
        except Exception as e:
            print("remote remove failed: %s" % str(e))
            dirpath = os.path.join(os.environ["LOCAL_PATH"],self.testdir)
            print("falling back to removing contents of local dir: %s" % dirpath)
            if os.path.exists(dirpath):
                for entry in os.listdir(dirpath):
                    fullpath = os.path.join(dirpath, entry)
                if os.path.isdir(fullpath):
                    import shutil
                    shutil.rmtree(fullpath)
                else:
                    os.unlink(fullpath)

    def ace_dump(self, ace):
        for key, value in ace.items():
            print ("%s=%s," % (key, value), end="")
            print ("")

    def ace_cmp(self, left, right):
        for key, value in left.items():
            if key == "user_dom":
                continue
            if not key in right:
                print ("no entry for: %s" % key)
                return False
            if value != right[key]:
                print ("mismatch: %s:%s != %s:%s" % (key, value, key, right[key]))
                return False
        return True

    def ace_parse_str(self, ace):
        parts = ace.split(':')
        result = {}
        if parts[0] != "ACL":
            raise Exception("invalid ace string:%" % ace)
        if "\\" in parts[1]:
            result["user_dom"], result["user"] = parts[1].split("\\")
        elif "/" in parts[1]:
            result["user_dom"], result["user"] = parts[1].split("/")
        else:
            result["user"] = parts[1]
        result["type"], result["inherit"], result["permissions"] = parts[2].split('/')
        return result

    def build_test_cmd(self, cmd, args):
        cmd = [cmd, "-U%s%%%s" % (self.user, self.passwd)]
        cmd.extend(args)
        return cmd

    def smb_cacls(self, args):
        cacls_args = ["//%s/%s" % (self.server, self.share)]
        cacls_args.extend(args)
        out = self.check_output(self.build_test_cmd("smbcacls", cacls_args))
        return out

    def create_remote_test_file(self, remotepath):
        with self.mktemp() as tmpfile:
            filepath = os.path.join(self.testdir, remotepath)
            (dirpath, filename) = os.path.split(remotepath)
            remote_path = ""
            if len(dirpath):
                remote_path = self.testdir.replace("/", "\\", 10)
                for seg in dirpath.split(os.sep):
                    remote_path = remote_path + "\\" + seg
                    smbclient_args = self.build_test_cmd("smbclient", ["//%s/%s" % (self.server, self.share), "-c", "mkdir %s" % remote_path])
                    self.check_output(smbclient_args)
            smbclient_args = self.build_test_cmd("smbclient", ["//%s/%s" % (self.server, self.share), "-c", "put  %s %s" % (tmpfile, filepath)])
            out = self.check_output(smbclient_args)
        return filepath


    def file_ace_check(self, remotepath, ace):
        smbcacls_args = self.build_test_cmd("smbcacls",
                            ["//%s/%s" % (self.server, self.share), "--get",
                            remotepath])
        try:
            output = self.check_output(smbcacls_args)
        except BlackboxProcessError as e:
            print(str(e))
            return False
        out_str = output.decode()
        aces = []
        for line in out_str.split("\n"):
            if line.startswith("ACL"):
                aces.append(line)
        for acl in aces:
            acl_ace = self.ace_parse_str(acl)
            if ace["user"] == acl_ace["user"] and ace["type"] ==  acl_ace["type"]:
                print ("found ACE for %s" % acl_ace["user"])
                if not self.ace_cmp(acl_ace, ace):
                    print ("differences between file ACE: ")
                    self.ace_dump(acl_ace)
                    print ("and expected ACE: ")
                    self.ace_dump(ace)
                else:
                    print ("matched ACE for %s" % acl_ace["user"])
                    self.ace_dump(ace)
                    return True
        return False
