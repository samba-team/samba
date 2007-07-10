/* 
   Unix SMB/CIFS implementation.

   database wrap headers

   Copyright (C) Andrew Tridgell 2004
   
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


struct tdb_wrap {
	struct tdb_context *tdb;

	const char *name;
	struct tdb_wrap *next, *prev;
};

struct auth_session_info;
struct ldb_message;
struct ldb_dn;
struct cli_credentials;

#include "lib/db_wrap_proto.h"
