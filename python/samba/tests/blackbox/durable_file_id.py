# Blackbox test for the file id of a disconnected durable handle
#
# Copyright (C) Ralph Boehme <slow@samba.org> 2026
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

from contextlib import suppress
import os
from pathlib import Path
import shlex
import tempfile
import time
import uuid

import tdb
from samba.dcerpc import smbXsrv
from samba.ndr import ndr_unpack
from samba.tests import BINDIR, BlackboxTestCase


class DurableFileIdTests(BlackboxTestCase):
    def test_file_id(self):
        guid = str(uuid.uuid4())
        filename = "durable_v2_file_id.dat"
        path = Path(os.environ["LOCAL_PATH"]) / filename
        db_path = Path(os.environ["LOCK_DIR"]) / "smbXsrv_open_global.tdb"
        self.addCleanup(self.unlink_if_present, path)

        with tempfile.TemporaryDirectory(dir=self.tempdir) as basedir:
            self.check_run(shlex.split(os.getenv("VALGRIND", "")) + [
                os.path.join(BINDIR, "smbtorture"),
                f"--basedir={basedir}",
                f"//{os.environ['SERVER_IP']}/durable",
                f"-U{os.environ['USERNAME']}%{os.environ['PASSWORD']}",
                f"--option=torture:create_guid={guid}",
                "smb2.durable-v2-open.file-id-disconnect",
            ])

        st = path.stat()
        # The read-only TDB handle does not lock. Retry while smbd is
        # rewriting the record or has yet to mark it disconnected.
        for _ in range(10):
            try:
                record = self.find_disconnected_record(db_path, guid)
            except (OSError, RuntimeError):
                record = None
            if record is not None:
                break
            time.sleep(0.5)

        self.assertIsNotNone(record, f"no disconnected open record for {guid}")
        self.assertEqual(record.file_id.devid, st.st_dev)
        self.assertEqual(record.file_id.inode, st.st_ino)
        self.assertNotEqual(record.name_hash, 0)

    @staticmethod
    def unlink_if_present(path):
        with suppress(FileNotFoundError):
            path.unlink()

    @staticmethod
    def find_disconnected_record(db_path, guid):
        db = tdb.Tdb(str(db_path), 0, tdb.DEFAULT, os.O_RDONLY)
        try:
            for key in db.keys():
                # Replay-cache records have 32-byte keys, opens have 4.
                if len(key) != 4:
                    continue
                value = db.get(key)
                if value is None:
                    continue
                try:
                    record = ndr_unpack(smbXsrv.open_globalB, value).info
                except RuntimeError:
                    continue
                if (record is not None and str(record.create_guid) == guid
                        and record.server_id.pid == (1 << 64) - 1):
                    return record
        finally:
            db.close()
        return None
