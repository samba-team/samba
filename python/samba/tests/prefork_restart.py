# Tests for process restarting in the pre-fork process model
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
"""Tests process restarting in the pre-fork process model.
   NOTE: As this test kills samba processes it won't play nicely with other
         tests, so needs to be run in it's own environment.
"""


import os
import signal
import time

import samba
from samba.tests import TestCase, delete_force
from samba.dcerpc import echo, netlogon
from samba.messaging import Messaging
from samba.samdb import SamDB
from samba.credentials import Credentials, DONT_USE_KERBEROS
from samba.compat import get_string
from samba.dsdb import (
    UF_WORKSTATION_TRUST_ACCOUNT,
    UF_PASSWD_NOTREQD)
from samba.dcerpc.misc import SEC_CHAN_WKSTA
from samba.auth import system_session

NUM_WORKERS = 4
MACHINE_NAME = "PFRS"


class PreforkProcessRestartTests(TestCase):

    def setUp(self):
        super(PreforkProcessRestartTests, self).setUp()
        lp_ctx = self.get_loadparm()
        self.msg_ctx = Messaging(lp_ctx=lp_ctx)

    def tearDown(self):
        super(PreforkProcessRestartTests, self).tearDown()

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

    def get_worker_pids(self, name, workers):
        pids = []
        for x in range(workers):
            process_name = "prefork-worker-{0}-{1}".format(name, x)
            pids.append(self.get_process(process_name))
            self.assertIsNotNone(pids[x])
        return pids

    def wait_for_workers(self, name, workers):
        num_workers = len(workers)
        for x in range(num_workers):
            process_name = "prefork-worker-{0}-{1}".format(name, x)
            self.wait_for_process(process_name, workers[x], 0, 1, 30)

    def wait_for_process(self, name, pid, initial_delay, wait, timeout):
        time.sleep(initial_delay)
        delay = initial_delay
        while delay < timeout:
            p = self.get_process(name)
            if p is not None and p != pid:
                # process has restarted
                return
            time.sleep(wait)
            delay += wait
        self.fail("Times out after {0} seconds waiting for {1} to restart".
                  format(delay, name))

    def check_for_duplicate_processes(self):
            processes = self.get_process_data()
            process_map = {}
            for name, p in processes:
                if (name.startswith("prefork-") or
                    name.endswith("_server") or
                    name.endswith("srv")):

                    if name in process_map:
                        if p != process_map[name]:
                            self.fail(
                                "Duplicate process for {0}, pids {1} and {2}".
                                format(name, p, process_map[name]))

    def simple_bind(self):
        creds = self.insta_creds(template=self.get_credentials())
        creds.set_bind_dn("%s\\%s" % (creds.get_domain(),
                                      creds.get_username()))

        self.samdb = SamDB(url="ldaps://%s" % os.environ["SERVER"],
                           lp=self.get_loadparm(),
                           credentials=creds)

    def rpc_echo(self):
        conn = echo.rpcecho("ncalrpc:", self.get_loadparm())
        self.assertEqual([1, 2, 3], conn.EchoData([1, 2, 3]))

    def netlogon(self):
        server = os.environ["SERVER"]
        host = os.environ["SERVER_IP"]
        lp = self.get_loadparm()

        credentials = self.get_credentials()

        session = system_session()
        ldb = SamDB(url="ldap://%s" % host,
                    session_info=session,
                    credentials=credentials,
                    lp=lp)
        machine_pass = samba.generate_random_password(32, 32)
        machine_name = MACHINE_NAME
        machine_dn = "cn=%s,%s" % (machine_name, ldb.domain_dn())

        delete_force(ldb, machine_dn)

        utf16pw = ('"%s"' % get_string(machine_pass)).encode('utf-16-le')
        ldb.add({
            "dn": machine_dn,
            "objectclass": "computer",
            "sAMAccountName": "%s$" % machine_name,
            "userAccountControl":
                str(UF_WORKSTATION_TRUST_ACCOUNT | UF_PASSWD_NOTREQD),
            "unicodePwd": utf16pw})

        machine_creds = Credentials()
        machine_creds.guess(lp)
        machine_creds.set_secure_channel_type(SEC_CHAN_WKSTA)
        machine_creds.set_kerberos_state(DONT_USE_KERBEROS)
        machine_creds.set_password(machine_pass)
        machine_creds.set_username(machine_name + "$")
        machine_creds.set_workstation(machine_name)

        netlogon.netlogon(
            "ncacn_ip_tcp:%s[schannel,seal]" % server,
            lp,
            machine_creds)

        delete_force(ldb, machine_dn)

    def test_ldap_master_restart(self):
        # check ldap connection, do a simple bind
        self.simple_bind()

        # get ldap master process
        pid = self.get_process("prefork-master-ldap")
        self.assertIsNotNone(pid)

        # Get the worker processes
        workers = self.get_worker_pids("ldap", NUM_WORKERS)

        # kill it
        os.kill(pid, signal.SIGTERM)

        # wait for the process to restart
        self.wait_for_process("prefork-master-ldap", pid, 1, 1, 30)

        # restarting the master restarts the workers as well, so make sure
        # they have finished restarting
        self.wait_for_workers("ldap", workers)

        # get ldap master process
        new_pid = self.get_process("prefork-master-ldap")
        self.assertIsNotNone(new_pid)

        # check that the pid has changed
        self.assertNotEquals(pid, new_pid)

        # check that the worker processes have restarted
        new_workers = self.get_worker_pids("ldap", NUM_WORKERS)
        for x in range(NUM_WORKERS):
            self.assertNotEquals(workers[x], new_workers[x])

        # check that the previous server entries have been removed.
        self.check_for_duplicate_processes()

        # check ldap connection, another simple bind
        self.simple_bind()

    def test_ldap_worker_restart(self):
        # check ldap connection, do a simple bind
        self.simple_bind()

        # get ldap master process
        pid = self.get_process("prefork-master-ldap")
        self.assertIsNotNone(pid)

        # Get the worker processes
        workers = self.get_worker_pids("ldap", NUM_WORKERS)

        # kill worker 0
        os.kill(workers[0], signal.SIGTERM)

        # wait for the process to restart
        self.wait_for_process("prefork-worker-ldap-0", pid, 1, 1, 30)

        # get ldap master process
        new_pid = self.get_process("prefork-master-ldap")
        self.assertIsNotNone(new_pid)

        # check that the pid has not changed
        self.assertEqual(pid, new_pid)

        # check that the worker processes have restarted
        new_workers = self.get_worker_pids("ldap", NUM_WORKERS)
        # process 0 should have a new pid the others should be unchanged
        self.assertNotEquals(workers[0], new_workers[0])
        self.assertEqual(workers[1], new_workers[1])
        self.assertEqual(workers[2], new_workers[2])
        self.assertEqual(workers[3], new_workers[3])

        # check that the previous server entries have been removed.
        self.check_for_duplicate_processes()

        # check ldap connection, another simple bind
        self.simple_bind()

    #
    # Kill all the ldap worker processes and ensure that they are restarted
    # correctly
    #
    def test_ldap_all_workers_restart(self):
        # check ldap connection, do a simple bind
        self.simple_bind()

        # get ldap master process
        pid = self.get_process("prefork-master-ldap")
        self.assertIsNotNone(pid)

        # Get the worker processes
        workers = self.get_worker_pids("ldap", NUM_WORKERS)

        # kill all the worker processes
        for x in workers:
            os.kill(x, signal.SIGTERM)

        # wait for the worker processes to restart
        self.wait_for_workers("ldap", workers)

        # get ldap master process
        new_pid = self.get_process("prefork-master-ldap")
        self.assertIsNotNone(new_pid)

        # check that the pid has not changed
        self.assertEqual(pid, new_pid)

        # check that the worker processes have restarted
        new_workers = self.get_worker_pids("ldap", NUM_WORKERS)
        for x in range(NUM_WORKERS):
            self.assertNotEquals(workers[x], new_workers[x])

        # check that the previous server entries have been removed.
        self.check_for_duplicate_processes()

        # check ldap connection, another simple bind
        self.simple_bind()

    def test_rpc_master_restart(self):
        # check rpc connection, make a rpc echo request
        self.rpc_echo()

        # get rpc master process
        pid = self.get_process("prefork-master-rpc")
        self.assertIsNotNone(pid)

        # Get the worker processes
        workers = self.get_worker_pids("rpc", NUM_WORKERS)

        # kill it
        os.kill(pid, signal.SIGTERM)

        # wait for the process to restart
        self.wait_for_process("prefork-master-rpc", pid, 1, 1, 30)

        # wait for workers to restart as well
        self.wait_for_workers("rpc", workers)

        # get ldap master process
        new_pid = self.get_process("prefork-master-rpc")
        self.assertIsNotNone(new_pid)

        # check that the pid has changed
        self.assertNotEquals(pid, new_pid)

        # check that the worker processes have restarted
        new_workers = self.get_worker_pids("rpc", NUM_WORKERS)
        for x in range(NUM_WORKERS):
            self.assertNotEquals(workers[x], new_workers[x])

        # check that the previous server entries have been removed.
        self.check_for_duplicate_processes()

        # check rpc connection, another rpc echo request
        self.rpc_echo()

    def test_rpc_worker_zero_restart(self):
        # check rpc connection, make a rpc echo request and a netlogon request
        self.rpc_echo()
        self.netlogon()

        # get rpc master process
        pid = self.get_process("prefork-master-rpc")
        self.assertIsNotNone(pid)

        # Get the worker processes
        workers = self.get_worker_pids("rpc", NUM_WORKERS)

        # kill worker 0
        os.kill(workers[0], signal.SIGTERM)

        # wait for the process to restart
        self.wait_for_process("prefork-worker-rpc-0", workers[0], 1, 1, 30)

        # get rpc master process
        new_pid = self.get_process("prefork-master-rpc")
        self.assertIsNotNone(new_pid)

        # check that the pid has not changed
        self.assertEqual(pid, new_pid)

        # check that the worker processes have restarted
        new_workers = self.get_worker_pids("rpc", NUM_WORKERS)
        # process 0 should have a new pid the others should be unchanged
        self.assertNotEquals(workers[0], new_workers[0])
        self.assertEqual(workers[1], new_workers[1])
        self.assertEqual(workers[2], new_workers[2])
        self.assertEqual(workers[3], new_workers[3])

        # check that the previous server entries have been removed.
        self.check_for_duplicate_processes()

        # check rpc connection, another rpc echo request, and netlogon request
        self.rpc_echo()
        self.netlogon()

    def test_rpc_all_workers_restart(self):
        # check rpc connection, make a rpc echo request, and a netlogon request
        self.rpc_echo()
        self.netlogon()

        # get rpc master process
        pid = self.get_process("prefork-master-rpc")
        self.assertIsNotNone(pid)

        # Get the worker processes
        workers = self.get_worker_pids("rpc", NUM_WORKERS)

        # kill all the worker processes
        for x in workers:
            os.kill(x, signal.SIGTERM)

        # wait for the worker processes to restart
        for x in range(NUM_WORKERS):
            self.wait_for_process(
                "prefork-worker-rpc-{0}".format(x), workers[x], 0, 1, 30)

        # get rpc master process
        new_pid = self.get_process("prefork-master-rpc")
        self.assertIsNotNone(new_pid)

        # check that the pid has not changed
        self.assertEqual(pid, new_pid)

        # check that the worker processes have restarted
        new_workers = self.get_worker_pids("rpc", NUM_WORKERS)
        for x in range(NUM_WORKERS):
            self.assertNotEquals(workers[x], new_workers[x])

        # check that the previous server entries have been removed.
        self.check_for_duplicate_processes()

        # check rpc connection, another rpc echo request and netlogon
        self.rpc_echo()
        self.netlogon()

    def test_master_restart_backoff(self):

        # get kdc master process
        pid = self.get_process("prefork-master-echo")
        self.assertIsNotNone(pid)

        #
        # Check that the processes get backed off as expected
        #
        # have prefork backoff increment = 5
        #      prefork maximum backoff   = 10
        backoff_increment = 5
        for expected in [0, 5, 10, 10]:
            # Get the worker processes
            workers = self.get_worker_pids("kdc", NUM_WORKERS)

            process = self.get_process("prefork-master-echo")
            os.kill(process, signal.SIGTERM)
            # wait for the process to restart
            start = time.time()
            self.wait_for_process("prefork-master-echo", process, 0, 1, 30)
            # wait for the workers to restart as well
            self.wait_for_workers("echo", workers)
            end = time.time()
            duration = end - start

            # process restart will take some time. Check that the elapsed
            # duration falls somewhere in the expected range, i.e. we haven't
            # taken longer than the backoff increment
            self.assertLess(duration, expected + backoff_increment)
            self.assertGreaterEqual(duration, expected)

        # check that the worker processes have restarted
        new_workers = self.get_worker_pids("echo", NUM_WORKERS)
        for x in range(NUM_WORKERS):
            self.assertNotEquals(workers[x], new_workers[x])

        # check that the previous server entries have been removed.
        self.check_for_duplicate_processes()

    def test_worker_restart_backoff(self):
        #
        # Check that the processes get backed off as expected
        #
        # have prefork backoff increment = 5
        #      prefork maximum backoff   = 10
        backoff_increment = 5
        for expected in [0, 5, 10, 10]:
            process = self.get_process("prefork-worker-echo-2")
            self.assertIsNotNone(process)
            os.kill(process, signal.SIGTERM)
            # wait for the process to restart
            start = time.time()
            self.wait_for_process("prefork-worker-echo-2", process, 0, 1, 30)
            end = time.time()
            duration = end - start

            # process restart will take some time. Check that the elapsed
            # duration falls somewhere in the expected range, i.e. we haven't
            # taken longer than the backoff increment
            self.assertLess(duration, expected + backoff_increment)
            self.assertGreaterEqual(duration, expected)

        self.check_for_duplicate_processes()
