/*
   Unix SMB/CIFS implementation.

   Compatibility layer for TDB1 vs TDB2.

   Copyright (C) Rusty Russell 2011

     ** NOTE! The following LGPL license applies to the tdb_compat
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
#ifndef TDB_COMPAT_H
#define TDB_COMPAT_H

#include "replace.h"
#include <ccan/typesafe_cb/typesafe_cb.h>
#include <tdb.h>

#define tdb_fetch_compat tdb_fetch

#endif /* TDB_COMPAT_H */
