/*
   ldb database library

   Copyright (C) Simo Sorce 2005

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

#ifndef _OLSCHEMA2LDIF_LIB_H
#define _OLSCHEMA2LDIF_LIB_H

#include "includes.h"
#include "ldb.h"
#include "dsdb/samdb/samdb.h"

struct schema_conv {
	int count;
	int failures;
};

struct conv_options {
	struct ldb_context *ldb_ctx;
	struct ldb_dn *basedn;
	FILE *in;
	FILE *out;
};

struct schema_conv process_file(TALLOC_CTX *mem_ctx, struct conv_options *opt);

#endif /* _OLSCHEMA2LDIF_LIB_H */
