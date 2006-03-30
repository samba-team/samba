"""Provide a more Pythonic and object-oriented interface to tdb."""

#
# Swig interface to Samba
#
# Copyright (C) Tim Potter 2006
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#   
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#   
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
#

import tdb, os, UserDict

class Tdb:

    def __init__(self, name, hash_size = 0, tdb_flags = tdb.TDB_DEFAULT,
                 open_flags = os.O_RDWR | os.O_CREAT, mode = 0600):

        self.tdb = tdb.open(name, hash_size, tdb_flags, open_flags, mode)

    def __del__(self):
        tdb.close(self.tdb)

    def __getitem__(self, key):
        pass

    def __setitem__(self, key, item):
        pass

    def __delitem__(self, key):
        pass

    def keys(self):
        pass
