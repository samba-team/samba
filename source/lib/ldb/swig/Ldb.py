"""Provide a more Pythonic and object-oriented interface to ldb."""

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

from ldb import *

ldb_global_init()

class LdbError(Exception):
    """An exception raised when a ldb error occurs."""
    pass

class LdbMessage:
    """A class representing a ldb message as a Python dictionary."""
    
    def __init__(self, msg = None):

        self._msg = msg
        if self._msg is None:
            self._msg = ldb_msg_new(None)

    def __del__(self):
        talloc_free(self._msg)

    def len(self):
        return self._msg.num_elements

    def __getitem__(self, key):
        elt = ldb_msg_find_element(self._msg, key)
        if elt is None:
            raise KeyError, "No such attribute '%s'" % key
        return [ldb_val_array_getitem(elt.values, i)
                for i in range(elt.num_values)]

    def __setitem__(self, key, value):
        result = ldb_msg_add_value(self._msg, key, str(value))
        if result != LDB_SUCCESS:
            raise LdbError, (result, ldb.strerror(result))
    
class Ldb:
    """A class representing a binding to a ldb file."""

    def __init__(self, url, flags = 0):
        """Initialise underlying ldb."""
    
        self.mem_ctx = talloc_init('mem_ctx for ldb 0x%x' % id(self))
        self.ldb_ctx = ldb_init(self.mem_ctx)

        result =  ldb_connect(self.ldb_ctx, url, flags, None)

        if result != LDB_SUCCESS:
            raise ldbError, (result, ldb.strerror(result))
        
    def __del__(self):
        ldb.talloc_free(self.mem_ctx)
        self.mem_ctx = None
        self.ldb_ctx = None

    def _ldb_call(self, fn, *args):
        """Call a ldb function with args.  Raise a LdbError exception
        if the function returns a non-zero return value."""
        
        result = fn(*args)

        if result != ldb.LDB_SUCCESS:
            raise LdbError, (result, ldb.strerror(result))

    def search(self, expression):
        """Search a ldb for a given expression."""

        self._ldb_call(ldb.search, self.ldb_ctx, None, ldb.LDB_SCOPE_DEFAULT,
                       expression, None);

        return [LdbMessage(ldb.ldb_message_ptr_array_getitem(result.msgs, ndx))
                for ndx in range(result.count)]

    def delete(self, dn):
        """Delete a dn."""

        _dn = ldb_dn_explode(self.ldb_ctx, dn)

        self._ldb_call(ldb.delete, self.ldb_ctx, _dn)

    def rename(self, olddn, newdn):
        """Rename a dn."""
        
        _olddn = ldb_dn_explode(self.ldb_ctx, olddn)
        _newdn = ldb_dn_explode(self.ldb_ctx, newdn)
        
        self._ldb_call(ldb.rename, self.ldb_ctx, _olddn, _newdn)

    def add(self, msg):
        self._ldb_call(ldb.add, self.ldb_ctx, msg)
