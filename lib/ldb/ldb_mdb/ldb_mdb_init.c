/*
   ldb database library using mdb back end

   Copyright (C) Jakub Hrozek 2014
   Copyright (C) Catalyst.Net Ltd 2017

     ** NOTE! The following LGPL license applies to the ldb
     ** library. This does NOT imply that all of Samba is released
     ** under the LGPL

   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 3 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with this library; if not, see <http://www.gnu.org/licenses/>.
*/

#include "ldb_mdb.h"

int ldb_mdb_init(const char *version)
{
	LDB_MODULE_CHECK_VERSION(version);
	return ldb_register_backend("mdb", lmdb_connect, false);
}
