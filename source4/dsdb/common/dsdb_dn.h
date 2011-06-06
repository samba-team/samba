#ifndef __DSDB_COMMON_DSDB_DN_H__
#define __DSDB_COMMON_DSDB_DN_H__
/*
   Unix SMB/CIFS implementation.

   (C) 2011 Samba Team.

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

enum dsdb_dn_format {
	DSDB_NORMAL_DN,
	DSDB_BINARY_DN,
	DSDB_STRING_DN,
	DSDB_INVALID_DN
};

struct dsdb_dn {
	struct ldb_dn *dn;
	DATA_BLOB extra_part;
	enum dsdb_dn_format dn_format;
	const char *oid;
};

#define DSDB_SYNTAX_BINARY_DN	"1.2.840.113556.1.4.903"
#define DSDB_SYNTAX_STRING_DN	"1.2.840.113556.1.4.904"
#define DSDB_SYNTAX_OR_NAME	"1.2.840.113556.1.4.1221"


/* RMD_FLAGS component in a DN */
#define DSDB_RMD_FLAG_DELETED     1
#define DSDB_RMD_FLAG_INVISIBLE   2
#endif
