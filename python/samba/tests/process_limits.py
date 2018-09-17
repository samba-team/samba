# Tests for limiting processes forked on accept by the standard process model
#
# Copyright (C) Andrew Bartlett <abartlet@samba.org> 2018
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
"""Tests limits on processes forked by fork on accept in the standard process
   model.
   NOTE: This test runs in an environment with an artificially low setting for
         smbd max processes
"""


import os
from samba.tests import TestCase
from samba.samdb import SamDB
from ldb import LdbError, ERR_OPERATIONS_ERROR


class StandardModelProcessLimitTests(TestCase):

    def setUp(self):
        super(StandardModelProcessLimitTests, self).setUp()

    def tearDown(self):
        super(StandardModelProcessLimitTests, self).tearDown()

    def simple_bind(self):
        creds = self.insta_creds(template=self.get_credentials())
        creds.set_bind_dn("%s\\%s" % (creds.get_domain(),
                                      creds.get_username()))

        return SamDB(url="ldaps://%s" % os.environ["SERVER"],
                     lp=self.get_loadparm(),
                     credentials=creds)

    def test_process_limits(self):
        creds = self.insta_creds(template=self.get_credentials())
        creds.set_bind_dn("%s\\%s" % (creds.get_domain(),
                                      creds.get_username()))

        connections = []
        try:
            # Open a series of LDAP connections, the maximum number of
            # active connections should be 20, so the 21st should fail.
            # But as it is possible that there may be other processes holding
            # connections, need to allow for earlier connection failures.
            for _ in range(21):
                connections.append(self.simple_bind())
            self.fail(
                "Processes not limited, able to make more than 20 connections")
        except LdbError as e:
            (errno, estr) = e.args
            if errno != ERR_OPERATIONS_ERROR:
                raise
            if not (estr.endswith("NT_STATUS_CONNECTION_DISCONNECTED") or
                    estr.endswith("NT_STATUS_CONNECTION_RESET")):
                raise
            pass
        #
        # Clean up the connections we've just opened, by deleting the
        # connection in python. This should invoke the talloc destructor to
        # release any resources and close the actual connection to the server.
        for c in connections:
            del c
