/* 
   ldb database library

   Copyright (C) Andrew Tridgell  2004

     ** NOTE! The following LGPL license applies to the ldb
     ** library. This does NOT imply that all of Samba is released
     ** under the LGPL
   
   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with this library; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

/*
 *  Name: ldb
 *
 *  Component: ldb expression parse header
 *
 *  Description: structure for expression parsing
 *
 *  Author: Andrew Tridgell
 */

#ifndef _LDB_PARSE_H
#define _LDB_PARSE_H 1

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

struct ldb_parse_tree *ldb_parse_tree(struct ldb_context *ldb, const char *s);
void ldb_parse_tree_free(struct ldb_context *ldb, struct ldb_parse_tree *tree);

#endif
