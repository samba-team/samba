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

# Open flags

DEFAULT        = tdb.TDB_DEFAULT
CLEAR_IF_FIRST = tdb.TDB_CLEAR_IF_FIRST
INTERNAL       = tdb.TDB_INTERNAL
NOLOCK         = tdb.TDB_NOLOCK
NOMMAP         = tdb.TDB_NOMMAP

# Class representing a TDB file

class Tdb:

    # Create and destroy Tdb objects

    def __init__(self, name, hash_size = 0, flags = tdb.TDB_DEFAULT,
                 open_flags = os.O_RDWR | os.O_CREAT, mode = 0600):
        self.tdb = tdb.open(name, hash_size, flags, open_flags, mode)

    def __del__(self):
        if hasattr(self, 'tdb'):
            tdb.close(self.tdb)

    # Random access to keys, values

    def __getitem__(self, key):
        result = tdb.fetch(self.tdb, key)
        if result is None:
            raise KeyError, key
        return result

    def __setitem__(self, key, item):
        tdb.store(self.tdb, key, item)

    def __delitem__(self, key):
        if not tdb.exists(self.tdb, key):
            raise KeyError, key
        tdb.delete(self.tdb, key)

    def has_key(self, key):
        return tdb.exists(self.tdb, key)

    # Tdb iterator

    class TdbIterator:
        def __init__(self, tdb):
            self.tdb = tdb
            self.key = None

        def __iter__(self):
            return self
            
        def next(self):
            if self.key is None:
                self.key = tdb.firstkey(self.tdb)
                if self.key is None:
                    raise StopIteration
                return self.key
            else:
                self.key = tdb.nextkey(self.tdb, self.key)
                if self.key is None:
                    raise StopIteration
                return self.key

    def __iter__(self):
        return Tdb.TdbIterator(self.tdb)

    # Implement other dict functions using TdbIterator

    def keys(self):
        return [k for k in iter(self)]

    def values(self):
        return [self[k] for k in iter(self)]

    def items(self):
        return [(k, self[k]) for k in iter(self)]

    def __len__(self):
        return len(self.keys())

    def clear(self):
        for k in iter(self):
            del(self[k])
