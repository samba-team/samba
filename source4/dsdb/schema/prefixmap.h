/*
   Unix SMB/CIFS implementation.

   DRS::prefixMap data structures

   Copyright (C) Kamen Mazdrashki <kamen.mazdrashki@postpath.com> 2009

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef _DSDB_PREFIXMAP_H
#define _DSDB_PREFIXMAP_H

/**
 * oid-prefix in prefixmap
 */
struct dsdb_schema_prefixmap_oid {
	uint32_t id;
	DATA_BLOB *bin_oid; /* partial binary-oid prefix */
};

/**
 * DSDB prefixMap internal presentation
 */
struct dsdb_schema_prefixmap {
	uint32_t length;
	struct dsdb_schema_prefixmap_oid *prefixes;
};


#include "dsdb/schema/proto.h"


#endif /* _DSDB_PREFIXMAP_H */
