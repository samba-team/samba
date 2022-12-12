 /*
   Unix SMB/CIFS implementation.

   trivial database library

   Copyright (C) Andrew Tridgell              1999-2005
   Copyright (C) Paul `Rusty' Russell		   2000
   Copyright (C) Jeremy Allison			   2000-2003

     ** NOTE! The following LGPL license applies to the tdb
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

#include "tdb_private.h"

_PUBLIC_ enum TDB_ERROR tdb_error(struct tdb_context *tdb)
{
	return tdb->ecode;
}

_PUBLIC_ const char *tdb_errorstr(struct tdb_context *tdb)
{
	switch (tdb->ecode) {
	case TDB_SUCCESS:
		return "Success";
		break;
	case TDB_ERR_CORRUPT:
		return "Corrupt database";
		break;
	case TDB_ERR_IO:
		return "IO Error";
		break;
	case TDB_ERR_LOCK:
		return "Locking error";
		break;
	case TDB_ERR_OOM:
		return "Out of memory";
		break;
	case TDB_ERR_EXISTS:
		return "Record exists";
		break;
	case TDB_ERR_NOLOCK:
		return "Lock exists on other keys";
		break;
	case TDB_ERR_EINVAL:
		return "Invalid parameter";
		break;
	case TDB_ERR_NOEXIST:
		return "Record does not exist";
		break;
	case TDB_ERR_RDONLY:
		return "write not permitted";
		break;
	default:
		break;
	}

	return "Invalid error code";
}

