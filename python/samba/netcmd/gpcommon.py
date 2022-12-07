# Samba common group policy functions
#
# Copyright Andrew Tridgell 2010
# Copyright Amitay Isaacs 2011-2012 <amitay@gmail.com>
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

def create_directory_hier(conn, remotedir):
    elems = remotedir.replace('/', '\\').split('\\')
    path = ""
    for e in elems:
        path = path + '\\' + e
        if not conn.chkpath(path):
            conn.mkdir(path)
