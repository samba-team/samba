/*
   ldb database library

   Copyright (C) Andrew Tridgell 2004
   Copyright (C) Stefan Metzmacher 2004
   Copyright (C) Simo Sorce 2006-2008
   Copyright (C) Matthias Dieter Wallnöfer 2009-2010

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

/*
 *  Name: ldb_tdb
 *
 *  Component: ldb tdb backend
 *
 *  Description: core functions for tdb backend
 *
 *  Author: Andrew Tridgell
 *  Author: Stefan Metzmacher
 *
 *  Modifications:
 *
 *  - description: make the module use asynchronous calls
 *    date: Feb 2006
 *    Author: Simo Sorce
 *
 *  - description: make it possible to use event contexts
 *    date: Jan 2008
 *    Author: Simo Sorce
 *
 *  - description: fix up memory leaks and small bugs
 *    date: Oct 2009
 *    Author: Matthias Dieter Wallnöfer
 */

#include "ldb_tdb.h"
#include <tdb.h>

/*
  map a tdb error code to a ldb error code
*/
int ltdb_err_map(enum TDB_ERROR tdb_code)
{
	switch (tdb_code) {
	case TDB_SUCCESS:
		return LDB_SUCCESS;
	case TDB_ERR_CORRUPT:
	case TDB_ERR_OOM:
	case TDB_ERR_EINVAL:
		return LDB_ERR_OPERATIONS_ERROR;
	case TDB_ERR_IO:
		return LDB_ERR_PROTOCOL_ERROR;
	case TDB_ERR_LOCK:
	case TDB_ERR_NOLOCK:
		return LDB_ERR_BUSY;
	case TDB_ERR_LOCK_TIMEOUT:
		return LDB_ERR_TIME_LIMIT_EXCEEDED;
	case TDB_ERR_EXISTS:
		return LDB_ERR_ENTRY_ALREADY_EXISTS;
	case TDB_ERR_NOEXIST:
		return LDB_ERR_NO_SUCH_OBJECT;
	case TDB_ERR_RDONLY:
		return LDB_ERR_INSUFFICIENT_ACCESS_RIGHTS;
	default:
		break;
	}
	return LDB_ERR_OTHER;
}
