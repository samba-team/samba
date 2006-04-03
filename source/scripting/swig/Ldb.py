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

class Ldb:

    def __init__(self):
        self.mem_ctx = ldb.talloc_init('python ldb')
        self.ldb_ctx = ldb.init(self.mem_ctx)
        
    def __del__(self):
        ldb.talloc_free(self.mem_ctx)

    def connect(self, url, flags = 0):
        ldb.connect(self.ldb_ctx, url, flags, None)

    def search(self, expression):
        return ldb.search(self.ldb_ctx, None, ldb.LDB_SCOPE_DEFAULT,
                          expression, None);
