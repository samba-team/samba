# Unix SMB/CIFS implementation.
# Copyright (C) Douglas Bagnall <douglas.bagnall@catalyst.net.nz>
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
import tarfile
from samba import safe_tarfile

import os
from samba.tests import TestCaseInTempDir


def filterer(prefix):
    def f(info):
        info.name = prefix + info.name
        return info
    return f


class SafeTarFileTestCase(TestCaseInTempDir):

    def test_dots(self):
        filename = os.path.join(self.tempdir, 'x')
        tarname = os.path.join(self.tempdir, 'tar.tar')
        f = open(filename, 'w')
        f.write('x')
        f.close()

        tf = tarfile.open(tarname, 'w')
        tf.add(filename, filter=filterer('../../'))
        tf.close()

        stf = safe_tarfile.open(tarname)

        # If we have data_filter, we have a patched python to address
        # CVE-2007-4559.
        if hasattr(tarfile, "data_filter"):
            self.assertRaises((tarfile.OutsideDestinationError,
                               NotADirectoryError),
                              stf.extractall,
                              tarname)
        else:
            self.assertRaises(tarfile.ExtractError,
                              stf.extractall,
                              tarname)
        self.rm_files('x', 'tar.tar')

    def test_slash(self):
        filename = os.path.join(self.tempdir, 'x')
        tarname = os.path.join(self.tempdir, 'tar.tar')
        f = open(filename, 'w')
        f.write('x')
        f.close()

        tf = tarfile.open(tarname, 'w')
        tf.add(filename, filter=filterer('/'))
        tf.close()

        stf = safe_tarfile.open(tarname)

        # If we have data_filter, we have a patched python to address
        # CVE-2007-4559.
        if hasattr(tarfile, "data_filter"):
            self.assertRaises(NotADirectoryError,
                              stf.extractall,
                              tarname)
        else:
            self.assertRaises(tarfile.ExtractError,
                              stf.extractall,
                              tarname)

        self.rm_files('x', 'tar.tar')
