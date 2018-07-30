# Unix SMB/CIFS implementation. Tests for DSDB locking
# Copyright (C) Andrew Bartlett <abartlet@samba.org> 2017
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

"""Tests for samba's dsdb modules"""

from samba.tests.samdb import SamDBTestCase
from samba.samdb import SamDB
import ldb
import os
import samba
import gc
import time


class DsdbLockTestCase(SamDBTestCase):
    def test_db_lock1(self):
        basedn = self.samdb.get_default_basedn()
        (r1, w1) = os.pipe()

        pid = os.fork()
        if pid == 0:
            # In the child, close the main DB, re-open just one DB
            del(self.samdb)
            gc.collect()
            self.samdb = SamDB(session_info=self.session,
                               lp=self.lp)

            self.samdb.transaction_start()

            dn = "cn=test_db_lock_user,cn=users," + str(basedn)
            self.samdb.add({
                 "dn": dn,
                 "objectclass": "user",
            })
            self.samdb.delete(dn)

            # Obtain a write lock
            self.samdb.transaction_prepare_commit()
            os.write(w1, b"prepared")
            time.sleep(2)

            # Drop the write lock
            self.samdb.transaction_cancel()
            os._exit(0)

        self.assertEqual(os.read(r1, 8), b"prepared")

        start = time.time()

        # We need to hold this iterator open to hold the all-record lock.
        res = self.samdb.search_iterator()

        # This should take at least 2 seconds because the transaction
        # has a write lock on one backend db open

        # Release the locks
        for l in res:
            pass

        end = time.time()
        self.assertGreater(end - start, 1.9)

        (got_pid, status) = os.waitpid(pid, 0)
        self.assertEqual(got_pid, pid)
        self.assertTrue(os.WIFEXITED(status))
        self.assertEqual(os.WEXITSTATUS(status), 0)

    def test_db_lock2(self):
        basedn = self.samdb.get_default_basedn()
        (r1, w1) = os.pipe()
        (r2, w2) = os.pipe()

        pid = os.fork()
        if pid == 0:
            # In the child, close the main DB, re-open
            del(self.samdb)
            gc.collect()
            self.samdb = SamDB(session_info=self.session,
                               lp=self.lp)

            # We need to hold this iterator open to hold the all-record lock.
            res = self.samdb.search_iterator()

            os.write(w2, b"start")
            if (os.read(r1, 7) != b"started"):
                os._exit(1)

            os.write(w2, b"add")
            if (os.read(r1, 5) != b"added"):
                os._exit(2)

            # Wait 2 seconds to block prepare_commit() in the child.
            os.write(w2, b"prepare")
            time.sleep(2)

            # Release the locks
            for l in res:
                pass

            if (os.read(r1, 8) != b"prepared"):
                os._exit(3)

            os._exit(0)

        # We can start the transaction during the search
        # because both just grab the all-record read lock.
        self.assertEqual(os.read(r2, 5), b"start")
        self.samdb.transaction_start()
        os.write(w1, b"started")

        self.assertEqual(os.read(r2, 3), b"add")
        dn = "cn=test_db_lock_user,cn=users," + str(basedn)
        self.samdb.add({
             "dn": dn,
             "objectclass": "user",
        })
        self.samdb.delete(dn)
        os.write(w1, b"added")

        # Obtain a write lock, this will block until
        # the parent releases the read lock.
        self.assertEqual(os.read(r2, 7), b"prepare")
        start = time.time()
        self.samdb.transaction_prepare_commit()
        end = time.time()
        try:
            self.assertGreater(end - start, 1.9)
        except:
            raise
        finally:
            os.write(w1, b"prepared")

            # Drop the write lock
            self.samdb.transaction_cancel()

            (got_pid, status) = os.waitpid(pid, 0)
            self.assertEqual(got_pid, pid)
            self.assertTrue(os.WIFEXITED(status))
            self.assertEqual(os.WEXITSTATUS(status), 0)

    def test_db_lock3(self):
        basedn = self.samdb.get_default_basedn()
        (r1, w1) = os.pipe()
        (r2, w2) = os.pipe()

        pid = os.fork()
        if pid == 0:
            # In the child, close the main DB, re-open
            del(self.samdb)
            gc.collect()
            self.samdb = SamDB(session_info=self.session,
                               lp=self.lp)

            # We need to hold this iterator open to hold the all-record lock.
            res = self.samdb.search_iterator()

            os.write(w2, b"start")
            if (os.read(r1, 7) != b"started"):
                os._exit(1)

            os.write(w2, b"add")
            if (os.read(r1, 5) != b"added"):
                os._exit(2)

            # Wait 2 seconds to block prepare_commit() in the child.
            os.write(w2, b"prepare")
            time.sleep(2)

            # Release the locks
            for l in res:
                pass

            if (os.read(r1, 8) != b"prepared"):
                os._exit(3)

            os._exit(0)

        # We can start the transaction during the search
        # because both just grab the all-record read lock.
        self.assertEqual(os.read(r2, 5), b"start")
        self.samdb.transaction_start()
        os.write(w1, b"started")

        self.assertEqual(os.read(r2, 3), b"add")

        # This will end up in the top level db
        dn = "@DSDB_LOCK_TEST"
        self.samdb.add({
             "dn": dn})
        self.samdb.delete(dn)
        os.write(w1, b"added")

        # Obtain a write lock, this will block until
        # the child releases the read lock.
        self.assertEqual(os.read(r2, 7), b"prepare")
        start = time.time()
        self.samdb.transaction_prepare_commit()
        end = time.time()
        self.assertGreater(end - start, 1.9)
        os.write(w1, b"prepared")

        # Drop the write lock
        self.samdb.transaction_cancel()

        (got_pid, status) = os.waitpid(pid, 0)
        self.assertTrue(os.WIFEXITED(status))
        self.assertEqual(os.WEXITSTATUS(status), 0)
        self.assertEqual(got_pid, pid)

    def _test_full_db_lock1(self, backend_path):
        (r1, w1) = os.pipe()

        pid = os.fork()
        if pid == 0:
            # In the child, close the main DB, re-open just one DB
            del(self.samdb)
            gc.collect()

            backenddb = ldb.Ldb(backend_path)

            backenddb.transaction_start()

            backenddb.add({"dn": "@DSDB_LOCK_TEST"})
            backenddb.delete("@DSDB_LOCK_TEST")

            # Obtain a write lock
            backenddb.transaction_prepare_commit()
            os.write(w1, b"prepared")
            time.sleep(2)

            # Drop the write lock
            backenddb.transaction_cancel()
            os._exit(0)

        self.assertEqual(os.read(r1, 8), b"prepared")

        start = time.time()

        # We need to hold this iterator open to hold the all-record lock.
        res = self.samdb.search_iterator()

        # This should take at least 2 seconds because the transaction
        # has a write lock on one backend db open

        end = time.time()
        self.assertGreater(end - start, 1.9)

        # Release the locks
        for l in res:
            pass

        (got_pid, status) = os.waitpid(pid, 0)
        self.assertEqual(got_pid, pid)
        self.assertTrue(os.WIFEXITED(status))
        self.assertEqual(os.WEXITSTATUS(status), 0)

    def test_full_db_lock1(self):
        basedn = self.samdb.get_default_basedn()
        backend_filename = "%s.ldb" % basedn.get_casefold()
        backend_subpath = os.path.join("sam.ldb.d",
                                       backend_filename)
        backend_path = self.lp.private_path(backend_subpath)
        self._test_full_db_lock1(backend_path)

    def test_full_db_lock1_config(self):
        basedn = self.samdb.get_config_basedn()
        backend_filename = "%s.ldb" % basedn.get_casefold()
        backend_subpath = os.path.join("sam.ldb.d",
                                       backend_filename)
        backend_path = self.lp.private_path(backend_subpath)
        self._test_full_db_lock1(backend_path)

    def _test_full_db_lock2(self, backend_path):
        (r1, w1) = os.pipe()
        (r2, w2) = os.pipe()

        pid = os.fork()
        if pid == 0:

            # In the child, close the main DB, re-open
            del(self.samdb)
            gc.collect()
            self.samdb = SamDB(session_info=self.session,
                               lp=self.lp)

            # We need to hold this iterator open to hold the all-record lock.
            res = self.samdb.search_iterator()

            os.write(w2, b"start")
            if (os.read(r1, 7) != b"started"):
                os._exit(1)
            os.write(w2, b"add")
            if (os.read(r1, 5) != b"added"):
                os._exit(2)

            # Wait 2 seconds to block prepare_commit() in the child.
            os.write(w2, b"prepare")
            time.sleep(2)

            # Release the locks
            for l in res:
                pass

            if (os.read(r1, 8) != b"prepared"):
                os._exit(3)

            os._exit(0)

        # In the parent, close the main DB, re-open just one DB
        del(self.samdb)
        gc.collect()
        backenddb = ldb.Ldb(backend_path)

        # We can start the transaction during the search
        # because both just grab the all-record read lock.
        self.assertEqual(os.read(r2, 5), b"start")
        backenddb.transaction_start()
        os.write(w1, b"started")

        self.assertEqual(os.read(r2, 3), b"add")
        backenddb.add({"dn": "@DSDB_LOCK_TEST"})
        backenddb.delete("@DSDB_LOCK_TEST")
        os.write(w1, b"added")

        # Obtain a write lock, this will block until
        # the child releases the read lock.
        self.assertEqual(os.read(r2, 7), b"prepare")
        start = time.time()
        backenddb.transaction_prepare_commit()
        end = time.time()

        try:
            self.assertGreater(end - start, 1.9)
        except:
            raise
        finally:
            os.write(w1, b"prepared")

            # Drop the write lock
            backenddb.transaction_cancel()

            (got_pid, status) = os.waitpid(pid, 0)
            self.assertEqual(got_pid, pid)
            self.assertTrue(os.WIFEXITED(status))
            self.assertEqual(os.WEXITSTATUS(status), 0)

    def test_full_db_lock2(self):
        basedn = self.samdb.get_default_basedn()
        backend_filename = "%s.ldb" % basedn.get_casefold()
        backend_subpath = os.path.join("sam.ldb.d",
                                       backend_filename)
        backend_path = self.lp.private_path(backend_subpath)
        self._test_full_db_lock2(backend_path)

    def test_full_db_lock2_config(self):
        basedn = self.samdb.get_config_basedn()
        backend_filename = "%s.ldb" % basedn.get_casefold()
        backend_subpath = os.path.join("sam.ldb.d",
                                       backend_filename)
        backend_path = self.lp.private_path(backend_subpath)
        self._test_full_db_lock2(backend_path)
