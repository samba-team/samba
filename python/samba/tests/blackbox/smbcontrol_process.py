# Blackbox tests for the smbcontrol fault injection commands
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
# As the test terminates and sleeps samba processes these tests need to run
# in the preforkrestartdc test environment to prevent them impacting other
# tests.
#
from __future__ import print_function
import time
from samba.tests import BlackboxTestCase, BlackboxProcessError
from samba.messaging import Messaging

COMMAND = "bin/smbcontrol"
PING = "ping"


class SmbcontrolProcessBlockboxTests(BlackboxTestCase):

    def setUp(self):
        super(SmbcontrolProcessBlockboxTests, self).setUp()
        lp_ctx = self.get_loadparm()
        self.msg_ctx = Messaging(lp_ctx=lp_ctx)

    def get_process_data(self):
        services = self.msg_ctx.irpc_all_servers()

        processes = []
        for service in services:
            for id in service.ids:
                processes.append((service.name, id.pid))
        return processes

    def get_process(self, name):
        processes = self.get_process_data()
        for pname, pid in processes:
            if name == pname:
                return pid
        return None

    def test_inject_fault(self):
        INJECT = "inject"
        FAULT = "segv"
        #
        # Note that this process name needs to be different to the one used
        # in the sleep test to avoid a race condition
        #
        pid = self.get_process("rpc_server")

        #
        # Ensure we can ping the process before injecting a fault.
        #
        try:
            self.check_run("%s %s %s" % (COMMAND, pid, PING),
                           msg="trying to ping rpc_server")
        except BlackboxProcessError as e:
            self.fail("Unable to ping rpc_server process")

        #
        # Now inject a fault.
        #
        try:
            self.check_run("%s %s %s %s" % (COMMAND, pid, INJECT, FAULT),
                           msg="injecting fault into rpc_server")
        except BlackboxProcessError as e:
            print(e)
            self.fail("Unable to inject a fault into the rpc_server process")

        #
        # The process should have died, so we should not be able to ping it
        #
        try:
            self.check_run("%s %s %s" % (COMMAND, pid, PING),
                           msg="trying to ping rpc_server")
            self.fail("Could ping rpc_server process")
        except BlackboxProcessError as e:
            pass

    def test_sleep(self):
        SLEEP = "sleep"  # smbcontrol sleep command
        DURATION = 5     # duration to sleep server for
        DELTA = 1        # permitted error for the sleep duration

        #
        # Note that this process name needs to be different to the one used
        # in the inject fault test to avoid a race condition
        #
        pid = self.get_process("ldap_server")
        #
        # Ensure we can ping the process before getting it to sleep
        #
        try:
            self.check_run("%s %s %s" % (COMMAND, pid, PING),
                           msg="trying to ping rpc_server")
        except BlackboxProcessError as e:
            self.fail("Unable to ping rpc_server process")

        #
        # Now ask it to sleep
        #
        start = time.time()
        try:
            self.check_run("%s %s %s %s" % (COMMAND, pid, SLEEP, DURATION),
                           msg="putting rpc_server to sleep for %d" % DURATION)
        except BlackboxProcessError as e:
            print(e)
            self.fail("Failed to get rpc_server to sleep for %d" % DURATION)

        #
        # The process should be sleeping and not respond until it wakes
        #
        try:
            self.check_run("%s %s %s" % (COMMAND, pid, PING),
                           msg="trying to ping rpc_server")
            end = time.time()
            duration = end - start
            self.assertGreater(duration + DELTA, DURATION)
        except BlackboxProcessError as e:
            self.fail("Unable to ping rpc_server process")
