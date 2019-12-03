# Unix SMB/CIFS implementation. Tests for smbd fuzzing.
# Copyright (C) Jeremy Allison 2019.
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

import sys
import samba
import os
import binascii
import socket

class fuzzsmbd(samba.tests.TestCase):
    def test_bug_14205(self):
        #
        # badblob consists of an incorrectly
        # terminated SMB1 Negprot, with a valid SessionSetup after.
        # BUG: #14205 causes the smbd server to crash.
        #
        state = True;
        badblob = binascii.a2b_base64("AAAA1P9TTUJyAAAAABhDyAAAAAAAAAAAAAAAACcA/v8AAAAAALEAAlBDIE5F"
                                      "VFdPUksgUFJPR1JBTSD//jAAAk1JQ1JPU09GVCBOR1RXT1JLUyAxLjANDAJN"
                                      "SR3hkXOl0mb+QXW4Da/jp0f+AAAA1P9TTUJyAAAAABgDyAAABDQAAAAAAAAA"
                                      "ACcA/v8AAAAAALEAAlBDIE5FVFdPUksgUFJPR1JBFBX//jAAAk1JQ1JPU09G"
                                      "VCBOR1RXT1JLUyAxLjANDAJNSR3hkUal0mb+QXW4Da/jp0f+AAAA1P9TTUJz"
                                      "LTE0OEF1uA2v46dH/gqAIIwiAoRiVHWgODu8OdksJQAAAAAnAP7/AAAAAACx"
                                      "AAJQQyBORVRXT1JLIFBST0dSQU0g//4wAAJNSUNST1NPRlQgTkdUV09SS1Mg"
                                      "MS4wDQwCTUkd4ZFGpdJm/kF1uA2v46dH/gAAANT/U01Ccy0xNDgyMTIyOTE3"
                                      "Nzk2MzIAAAAAGAPIAAAAAAAAAAAAAAAAJwD+/wAAAAAAsQACUEMgTkVUV09S"
                                      "SyBQUk9HUkFNIP/+MAACTUlDUk9TT0ZUIE5HVFdPUktTIDEuMA0GAAAAAAAA"
                                      "AKXSZv5BdbgNr+OnR/4AAADU/1NNQnMtMTQ4MjEyMjkxNzc5NjMyNDQ4NDNA"
                                      "ujcyNjgAsQACUEMgTkVUF09SSyAgAAAAAAAAAP/+MAACTUlDUk9TT0bAIE5H"
                                      "BwAtMjMxODIxMjE4MTM5OTU0ODA2OP5BdbgNr+OnR/4KgCCMIgKEYlR1oDg7"
                                      "vDnZLCWy")
        s = None
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect(("fileserver", 445))
            s.send(badblob)
            # Read the 39-byte SMB1 reply to the SMB1 Negprot.
            # This is an error message saying the Negprot was
            # invalid.
            rb = s.recv(1024)
            try:
                # Read again to wait for the server to exit.
                rb = s.recv(1024)
            except socket.error as e:
                # We expect a socket error here as
                # in both success and fail cases the
                # server just resets the connection.
                pass
            finally:
                pass
        finally:
            if s is not None:
                s.close()
        #
        # If the server crashed there is the
        # following message in the debug log.
        #
        for line in open(os.environ['SMBD_TEST_LOG']):
            if "INTERNAL ERROR: Signal 11 in pid" in line:
                print("Found crash in smbd log")
                state = False;
                break
        self.assertTrue(state)
