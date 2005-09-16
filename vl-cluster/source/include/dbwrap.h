/* 
   Unix SMB/CIFS implementation.
   Database interface wrapper around tdb
   Copyright (C) Volker Lendecke 2005
   
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

#ifndef __FILEDB_H__
#define __FILEDB_H__

struct db_record {
	DATA_BLOB key, value;
	int (*store)(struct db_record *rec, DATA_BLOB data, int flag);
	int (*delete_rec)(struct db_record *rec);
	void *private_data;
};

struct db_context {
	struct db_record *(*fetch_locked)(struct db_context *db,
					  TALLOC_CTX *mem_ctx,
					  DATA_BLOB key);
	int (*traverse)(struct db_context *db,
			int (*f)(DATA_BLOB key, DATA_BLOB data,
				 void *private_data),
			void *private_data);
	void *private_data;
};

struct db_context *db_open(TALLOC_CTX *mem_ctx, const char *name,
			   int hash_size, int tdb_flags,
			   int open_flags, mode_t mode);


#endif /* __FILEDB_H__ */
