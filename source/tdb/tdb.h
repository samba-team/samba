/* 
   Unix SMB/Netbios implementation.
   Version 3.0
   Samba database functions
   Copyright (C) Andrew Tridgell 1999
   
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

typedef unsigned tdb_len;
typedef unsigned tdb_off;

#define TDB_MAGIC_FOOD "TDB file\n"

/* this is stored at the front of every database */
struct tdb_header {
	char magic_food[32]; /* for /etc/magic */
	unsigned version; /* version of the code */
	unsigned hash_size; /* number of hash entries */
};

typedef struct {
	char *dptr;
	size_t dsize;
} TDB_DATA;

/* this is the context structure that is returned from a db open */
typedef struct {
	char *name; /* the name of the database */
	void *map_ptr; /* where it is currently mapped */
	int fd; /* open file descriptor for the database */
	tdb_len map_size; /* how much space has been mapped */
	int read_only; /* opened read-only */
	int *locked; /* set if we have a chain locked */
	int ecode; /* error code for last tdb error */
	struct tdb_header header; /* a cached copy of the header */
} TDB_CONTEXT;

/* flags to tdb_store() */
#define TDB_REPLACE 1
#define TDB_INSERT 2

/* flags for tdb_open() */
#define TDB_CLEAR_IF_FIRST 1

/* error codes */
enum TDB_ERROR {TDB_SUCCESS=0, TDB_ERR_CORRUPT, TDB_ERR_IO, TDB_ERR_LOCK, 
		TDB_ERR_OOM, TDB_ERR_EXISTS};

typedef int (*tdb_traverse_func)(TDB_CONTEXT *, TDB_DATA, TDB_DATA, void *);

#if STANDALONE
TDB_CONTEXT *tdb_open(char *name, int hash_size, int tdb_flags,
		      int open_flags, mode_t mode);
char *tdb_error(TDB_CONTEXT *tdb);
int tdb_writelock(TDB_CONTEXT *tdb);
int tdb_writeunlock(TDB_CONTEXT *tdb);
TDB_DATA tdb_fetch(TDB_CONTEXT *tdb, TDB_DATA key);
int tdb_delete(TDB_CONTEXT *tdb, TDB_DATA key);
int tdb_store(TDB_CONTEXT *tdb, TDB_DATA key, TDB_DATA dbuf, int flag);
int tdb_close(TDB_CONTEXT *tdb);
TDB_DATA tdb_firstkey(TDB_CONTEXT *tdb);
TDB_DATA tdb_nextkey(TDB_CONTEXT *tdb, TDB_DATA key);
int tdb_traverse(TDB_CONTEXT *tdb, 
	int (*fn)(TDB_CONTEXT *tdb, TDB_DATA key, TDB_DATA dbuf, void *state),
	void *state);
int tdb_exists(TDB_CONTEXT *tdb, TDB_DATA key);
#endif
