/*
 *  Unix SMB/CIFS implementation.
 *  RPC Pipe client / server routines
 *  Copyright (C) Andrew Tridgell              1992-2006,
 *  Copyright (C) Jean François Micouleau      1998-2001.
 *  Copyright (C) Volker Lendecke              2006.
 *  Copyright (C) Gerald Carter                2006.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#ifndef _GROUPDB_MAPPING_TDB_H_
#define _GROUPDB_MAPPING_TDB_H_

/* The following definitions come from groupdb/mapping_tdb.c  */

const struct mapping_backend *groupdb_tdb_init(void);

#endif /* _GROUPDB_MAPPING_TDB_H_ */
