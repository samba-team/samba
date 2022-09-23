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


from tarfile import ExtractError, TarInfo, TarFile as UnsafeTarFile


class TarFile(UnsafeTarFile):
    """This TarFile implementation is trying to ameliorate CVE-2007-4559,
    where tarfile.TarFiles can step outside of the target directory
    using '../../'.
    """

    def extract(self, member, path="", set_attrs=True, *, numeric_owner=False):
        if isinstance(member, TarInfo):
            name = member.name
        else:
            name = member

        if '../' in name:
            raise ExtractError(f"'../' is not allowed in path '{name}'")

        if name.startswith('/'):
            raise ExtractError(f"path '{name}' should not start with '/'")

        super().extract(member, path, set_attrs=set_attrs,
                        numeric_owner=numeric_owner)


open = TarFile.open
