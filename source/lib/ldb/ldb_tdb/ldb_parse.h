 /* 
   Unix SMB/CIFS implementation.

   parse a LDAP-like expression - header

   Copyright (C) Andrew Tridgell 2004
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

enum ldb_parse_op {LDB_OP_SIMPLE, LDB_OP_AND, LDB_OP_OR, LDB_OP_NOT};

struct ldb_parse_tree {
	enum ldb_parse_op operation;
	union {
		struct {
			char *attr;
			struct ldb_val value;
		} simple;
		struct {
			unsigned int num_elements;
			struct ldb_parse_tree **elements;
		} list;
		struct {
			struct ldb_parse_tree *child;
		} not;
	} u;
};
