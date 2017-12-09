# Unix SMB/CIFS implementation.
# A test for the ntlm_auth tool
# Copyright (C) Kai Blin <kai@samba.org> 2008
# Copyright (C) Samuel Cabrero <scabrero@suse.de> 2018
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
"""Test ntlm_auth
This test program will start ntlm_auth with the given command line switches and
see if it will get the expected results.
"""

import os
import samba
import subprocess
from samba.tests import BlackboxTestCase

class NTLMAuthTestCase(BlackboxTestCase):

    def setUp(self):
        super(NTLMAuthTestCase, self).setUp()
        bindir = os.path.normpath(os.getenv("BINDIR", "./bin"))
        self.ntlm_auth_path = os.path.join(bindir, 'ntlm_auth')
        self.lp = samba.tests.env_loadparm()
        self.winbind_separator = self.lp.get('winbind separator')

    def readLine(self, text_stream):
        buf = text_stream.readline()
        newline = buf.find('\n')
        if newline == -1:
            raise Exception("Failed to read line")
        return buf[:newline]

    def writeLine(self, text_stream, buf):
        text_stream.write(buf)
        text_stream.write("\n")

    def run_helper(self,
                   client_username=None,
                   client_password=None,
                   client_domain=None,
                   client_use_cached_creds=False,
                   server_username=None,
                   server_password=None,
                   server_domain=None,
                   client_helper="ntlmssp-client-1",
                   server_helper="squid-2.5-ntlmssp",
                   server_use_winbind=False,
                   require_membership=None,
                   target_hostname=None,
                   target_service=None):
        self.assertTrue(os.access(self.ntlm_auth_path, os.X_OK))

        if client_username is None:
            raise Exception("client_username required")

        # Client helper args
        client_args = []
        client_args.append(self.ntlm_auth_path)
        client_args.append("--helper-protocol=%s" % client_helper)
        client_args.append("--username=%s" % client_username)
        if client_domain:
            client_args.append("--domain=%s" % client_domain)
        if client_use_cached_creds:
            client_args.append("--use-cached-creds")
        else:
            if client_password is None:
                raise Exception("client_password required")
            client_args.append("--password=%s" % client_password)
        if target_service:
            client_args.append("--target-service=%s" % target_service)
        if target_hostname:
            client_args.append("--target-hostname=%s" % target_hostname)
        client_args.append("--configfile=%s" % self.lp.configfile)

        # Server helper args
        server_args = []
        server_args.append(self.ntlm_auth_path)
        server_args.append("--helper-protocol=%s" % server_helper)
        server_args.append("--configfile=%s" % self.lp.configfile)
        if not server_use_winbind:
            if server_username is None or server_password is None or server_domain is None:
                raise Exception("Server credentials required if not using winbind")
            server_args.append("--username=%s" % server_username)
            server_args.append("--password=%s" % server_password)
            server_args.append("--domain=%s" % server_domain)
            if require_membership is not None:
                raise Exception("Server must be using winbind for require-membership-of")
        else:
            if require_membership is not None:
                server_args.append("--require-membership-of=%s" % require_membership)

        # Run helpers
        result = False
        server_proc = subprocess.Popen(server_args, stdout=subprocess.PIPE, stdin=subprocess.PIPE, bufsize=0, universal_newlines=True)
        client_proc = subprocess.Popen(client_args, stdout=subprocess.PIPE, stdin=subprocess.PIPE, bufsize=0, universal_newlines=True)

        try:
            if client_helper == "ntlmssp-client-1" and server_helper == "squid-2.5-ntlmssp":
                self.writeLine(client_proc.stdin, "YR")
                buf = self.readLine(client_proc.stdout)
                self.assertTrue(buf.startswith("YR "))

                self.writeLine(server_proc.stdin, buf)
                buf = self.readLine(server_proc.stdout)
                self.assertTrue(buf.startswith("TT "))

                self.writeLine(client_proc.stdin, buf)
                buf = self.readLine(client_proc.stdout)
                self.assertTrue(buf.startswith("AF "))

                # Client sends 'AF <base64 blob>' but server
                # expects 'KK <base64 blob>'
                buf = buf.replace("AF", "KK", 1)

                self.writeLine(server_proc.stdin, buf)
                buf = self.readLine(server_proc.stdout)
                result = buf.startswith("AF ")
            elif client_helper == "ntlmssp-client-1" and server_helper == "gss-spnego":
                self.writeLine(client_proc.stdin, "YR")
                buf = self.readLine(client_proc.stdout)
                self.assertTrue(buf.startswith("YR "))

                self.writeLine(server_proc.stdin, buf)
                buf = self.readLine(server_proc.stdout)
                self.assertTrue(buf.startswith("TT "))

                self.writeLine(client_proc.stdin, buf)
                buf = self.readLine(client_proc.stdout)
                self.assertTrue(buf.startswith("AF "))

                # Client sends 'AF <base64 blob>' but server expects 'KK <abse64 blob>'
                buf = buf.replace("AF", "KK", 1)

                self.writeLine(server_proc.stdin, buf)
                buf = self.readLine(server_proc.stdout)
                result = buf.startswith("AF * ")
            elif client_helper == "gss-spnego-client" and server_helper == "gss-spnego":
                self.writeLine(server_proc.stdin, "YR")
                buf = self.readLine(server_proc.stdout)

                while True:
                    if (buf.startswith("NA * ")):
                        result = False
                        break

                    self.assertTrue(buf.startswith("AF ") or buf.startswith("TT "))

                    self.writeLine(client_proc.stdin, buf)
                    buf = self.readLine(client_proc.stdout)

                    if buf.startswith("AF"):
                        result = True
                        break

                    self.assertTrue(buf.startswith("AF ") or buf.startswith("KK ") or buf.startswith("TT "))

                    self.writeLine(server_proc.stdin, buf)
                    buf = self.readLine(server_proc.stdout)

                    if buf.startswith("AF * "):
                        result = True
                        break
            else:
                self.fail("Helper protocols not handled")

            if result is True and client_helper == "ntlmssp-client-1":
                self.writeLine(client_proc.stdin, "GK")
                buf = self.readLine(client_proc.stdout)
                self.assertTrue(buf.startswith("GK "))

                self.writeLine(client_proc.stdin, "GF")
                buf = self.readLine(client_proc.stdout)
                self.assertTrue(buf.startswith("GF "))

            if result is True and server_helper == "squid-2.5-ntlmssp":
                self.writeLine(server_proc.stdin, "GK")
                buf = self.readLine(server_proc.stdout)
                self.assertTrue(buf.startswith("GK "))

                self.writeLine(server_proc.stdin, "GF")
                buf = self.readLine(server_proc.stdout)
                self.assertTrue(buf.startswith("GF "))

            client_proc.stdin.close()
            client_proc.wait()
            self.assertEqual(client_proc.returncode, 0)

            server_proc.stdin.close()
            server_proc.wait()
            self.assertEqual(server_proc.returncode, 0)

            return result
        except:
            client_proc.kill()
            client_proc.wait()
            server_proc.kill()
            server_proc.wait()
            raise
