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

import ldb

class LdbElement:
    """A class representing a ldb element as an array of values."""
    
    def __init__(self, elt):
        self.name = elt.name
        self.flags = elt.flags
        self.values = [ldb.ldb_val_array_getitem(elt.values, x)
                       for x in range(elt.num_values)]

    def __repr__(self):
        return '<%s(name=%s) instance at 0x%x' % (self.__class__.__name__,
                                                  `self.name`, id(self))

    def __len__(self):
        return self.values.len()

    def __getitem__(self, key):
        return self.values[key]

class LdbMessage:
    """A class representing a ldb message as a dict of ldb elements."""
    
    def __init__(self, msg = None):

        self.dn = None
        self.private_data = None
        self.elements = []

        if msg is not None:
            self.dn = msg.dn
            self.private_data = msg.private_data
            eltlist = \
                [LdbElement(ldb.ldb_message_element_array_getitem(
                            msg.elements, x))
                 for x in range(msg.num_elements)]
            self.elements = dict([(x.name, x) for x in eltlist])

    def __repr__(self):
        return '<%s(dn=%s) instance at 0x%x>' % (self.__class__.__name__,
                                               `self.dn`, id(self))

    def __getitem__(self, key):
        return self.elements[key]

    def keys(self):
        return self.elements.keys()

class Ldb:
    """A class representing a binding to a ldb file."""

    def __init__(self):
        self.mem_ctx = ldb.talloc_init('python ldb')
        self.ldb_ctx = ldb.init(self.mem_ctx)
        
    def __del__(self):
        ldb.talloc_free(self.mem_ctx)

    def connect(self, url, flags = 0):
        ldb.connect(self.ldb_ctx, url, flags, None)

    def search(self, expression):

        result = ldb.search(self.ldb_ctx, None, ldb.LDB_SCOPE_DEFAULT,
                            expression, None);

        return [LdbMessage(ldb.ldb_message_ptr_array_getitem(result.msgs, ndx))
                for ndx in range(result.count)]

    def delete(self, dn):
        if ldb.delete(self.ldb_ctx, dn) != 0:
            raise IOError, ldb.errstring(self.ldb_ctx)

    def rename(self, olddn, newdn):
        if ldb.rename(self.ldb_ctx, olddn, newdn) != 0:
            raise IOError, ldb.errstring(self.ldb_ctx)

    def add(self, msg):
        ldb.add(self.ldb_ctx, msg)
