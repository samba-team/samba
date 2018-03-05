/*
   ldb database library using mdb back end - transaction operations

   Copyright (C) Jakub Hrozek 2015
   Copyright (C) Catalyst.Net Ltd 2017

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

#ifndef _LDB_MDB_H_
#define _LDB_MDB_H_

#include "ldb_private.h"
#include <lmdb.h>

struct lmdb_private {
	struct ldb_context *ldb;
	MDB_env *env;

	struct lmdb_trans *txlist;

	struct ldb_mdb_metadata {
		struct ldb_message *attributes;
		unsigned seqnum;
	} *meta;
	int error;
	MDB_txn *read_txn;

	pid_t pid;

};

struct lmdb_trans {
	struct lmdb_trans *next;
	struct lmdb_trans *prev;

	MDB_txn *tx;
};

int ldb_mdb_err_map(int lmdb_err);
int lmdb_connect(struct ldb_context *ldb, const char *url,
		 unsigned int flags, const char *options[],
		 struct ldb_module **_module);

#endif /* _LDB_MDB_H_ */
