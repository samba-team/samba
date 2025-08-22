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


import os
import tarfile
from pathlib import Path
from tarfile import ExtractError, TarFile as UnsafeTarFile


class TarFile(UnsafeTarFile):
    """This TarFile implementation is trying to ameliorate CVE-2007-4559,
    where tarfile.TarFiles can step outside of the target directory
    using '../../'.
    """

    try:
        # In 3.8.18 (the last 3.8) and post 2023-08-22 versions of
        # 3.9+ (including all of 3.12 and greater), Python's standard
        # tarfile module uses the extraction_filter method for
        # preventing path traversal. See:
        #
        # https://docs.python.org/3/library/tarfile.html#tarfile.TarFile.extraction_filter
        # https://peps.python.org/pep-0706/
        #
        # The default filter is 'fully_trusted', which allows
        # extraction outside the directory, but in Python 3.14 the
        # default is expected to change to the stricter 'data' filter.
        # The 'data' filter preserves no permissions so we select the
        # intermediate 'tar' filter here which prevents escape but
        # preserves permissions.
        #
        # When we no longer support versions less than 3.8 or 3.9, we
        # should remove this whole try...except and just have this
        # next line as the whole class body:
        extraction_filter = staticmethod(tarfile.tar_filter)
    except AttributeError:
        def extract(self, member, path="", set_attrs=True, *,
                    numeric_owner=False):
            self._safetarfile_check()
            super().extract(member, path, set_attrs=set_attrs,
                            numeric_owner=numeric_owner)

        def extractall(self, path, members=None, *, numeric_owner=False):
            self._safetarfile_check()
            super().extractall(path, members,
                               numeric_owner=numeric_owner)

        def _safetarfile_check(self):
            for tarinfo in self.__iter__():
                if self._is_traversal_attempt(tarinfo=tarinfo):
                    raise ExtractError(
                        "Attempted directory traversal for "
                        f"member: {tarinfo.name}")
                if self._is_unsafe_symlink(tarinfo=tarinfo):
                    raise ExtractError(
                        "Attempted directory traversal via symlink for "
                        f"member: {tarinfo.linkname}")
                if self._is_unsafe_link(tarinfo=tarinfo):
                    raise ExtractError(
                        "Attempted directory traversal via link for "
                        f"member: {tarinfo.linkname}")

        def _resolve_path(self, path):
            return os.path.realpath(os.path.abspath(path))

        def _is_path_in_dir(self, path, basedir):
            return self._resolve_path(os.path.join(basedir,
                                      path)).startswith(basedir)

        def _is_traversal_attempt(self, tarinfo):
            if (tarinfo.name.startswith(os.sep)
               or ".." + os.sep in tarinfo.name):
                return True
            return False

        def _is_unsafe_symlink(self, tarinfo):
            if tarinfo.issym():
                symlink_file = Path(
                    os.path.normpath(os.path.join(os.getcwd(),
                                     tarinfo.linkname)))
                if not self._is_path_in_dir(symlink_file, os.getcwd()):
                    return True
            return False

        def _is_unsafe_link(self, tarinfo):
            if tarinfo.islnk():
                link_file = Path(
                    os.path.normpath(os.path.join(os.getcwd(),
                                                  tarinfo.linkname)))
                if not self._is_path_in_dir(link_file, os.getcwd()):
                    return True
            return False


open = TarFile.open
