/* 
   Unix SMB/CIFS implementation.

   database wrapper code

   Copyright (C) Volker Lendecks 2005-2007
   Copyright (C) Andrew Tridgell 2007
   
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

struct db_record {
	TDB_DATA key, value;
	NTSTATUS (*store)(struct db_record *rec, TDB_DATA data, int flag);
	NTSTATUS (*delete_rec)(struct db_record *rec);
	void *private_data;
};

struct db_context {
	struct db_record *(*fetch_locked)(struct db_context *db,
					  TALLOC_CTX *mem_ctx,
					  TDB_DATA key);
	int (*fetch)(struct db_context *db, TALLOC_CTX *mem_ctx,
		     TDB_DATA key, TDB_DATA *data);
	int (*traverse)(struct db_context *db,
			int (*f)(struct db_record *db,
				 void *private_data),
			void *private_data);
	int (*traverse_read)(struct db_context *db,
			     int (*f)(struct db_record *db,
				      void *private_data),
			     void *private_data);
	int (*get_seqnum)(struct db_context *db);
	void *private_data;
};

struct db_context *db_tmp_open(TALLOC_CTX *mem_ctx, const char *name, int tdb_flags);


/* backends */
struct db_context *db_tmp_open_tdb(TALLOC_CTX *mem_ctx, const char *name, int tdb_flags);
struct db_context *db_tmp_open_ctdb(TALLOC_CTX *mem_ctx, const char *name, int tdb_flags);
