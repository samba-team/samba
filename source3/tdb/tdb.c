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

#if STANDALONE
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include "tdb.h"
#else
#include "includes.h"
#endif

#define TDB_VERSION (0x26011967 + 0)
#define TDB_ALIGN 32
#define MIN_REC_SIZE (2*sizeof(struct list_struct) + TDB_ALIGN)
#define DEFAULT_HASH_SIZE 512
#define TDB_PAGE_SIZE 0x1000
#define FREELIST_TOP (sizeof(struct tdb_header))

/* the body of the database is made of one list_struct for the free space
   plus a separate data list for each hash value */
struct list_struct {
	tdb_len rec_len; /* total byte length of record */
	tdb_off next; /* offset of the next record in the list */
	tdb_len key_len; /* byte length of key */
	tdb_len data_len; /* byte length of data */
	unsigned full_hash; /* the full 32 bit hash of the key */
	/*
	   the following union is implied 
	   union {
              char record[rec_len];
	      struct {
	        char key[key_len];
		char data[data_len];
	      }
           }
	*/
};

/* a null data record - useful for error returns */
static TDB_DATA null_data;

#if STANDALONE
/* like strdup but for memory */
static char *memdup(char *d, int size)
{
	char *ret;
	ret = (char *)malloc(size);
	if (!ret) return NULL;
	memcpy(ret, d, size);
	return ret;
}
#endif

/* the hash algorithm - turn a key into an integer
   This is based on the hash agorithm from gdbm */
static unsigned tdb_hash(TDB_DATA *key)
{
	unsigned value;	/* Used to compute the hash value.  */
	unsigned   i;	/* Used to cycle through random values. */

	/* Set the initial value from the key size. */
	value = 0x238F13AF * key->dsize;
	for (i=0; i < key->dsize; i++) {
		value = (value + (key->dptr[i] << (i*5 % 24)));
	}

	value = (1103515243 * value + 12345);  

	return value;
}

/* find the top of the hash chain for an open database */
static tdb_off tdb_hash_top(TDB_CONTEXT *tdb, unsigned hash)
{
	tdb_off ret;
	hash = hash % tdb->header.hash_size;
	ret = FREELIST_TOP + (hash+1)*sizeof(tdb_off);
	return ret;
}


/* check for an out of bounds access - if it is out of bounds then
   see if the database has been expanded by someone else and expand
   if necessary */
static int tdb_oob(TDB_CONTEXT *tdb, tdb_off offset)
{
	struct stat st;
	if (offset < tdb->map_size) return 0;

	fstat(tdb->fd, &st);
	if (st.st_size <= tdb->map_size) return -1;

#if HAVE_MMAP
	if (tdb->map_ptr) {
		munmap(tdb->map_ptr, tdb->map_size);
		tdb->map_ptr = NULL;
	}
#endif

	tdb->map_size = st.st_size;
#if HAVE_MMAP
	tdb->map_ptr = (void *)mmap(NULL, tdb->map_size, 
				    tdb->read_only?PROT_READ:PROT_READ|PROT_WRITE,
				    MAP_SHARED | MAP_FILE, tdb->fd, 0);
#endif	
	return 0;
}


/* write a lump of data at a specified offset */
static int tdb_write(TDB_CONTEXT *tdb, tdb_off offset, char *buf, tdb_len len)
{
	if (tdb_oob(tdb, offset + len) != 0) {
		/* oops - trying to write beyond the end of the database! */
#if TDB_DEBUG
		printf("write error of length %u at offset %u (max %u)\n",
		       len, offset, tdb->map_size);
#endif
		return -1;
	}

	if (tdb->map_ptr) {
		memcpy(offset + (char *)tdb->map_ptr, buf, len);
	} else {
		lseek(tdb->fd, offset, SEEK_SET);
		if (write(tdb->fd, buf, len) != (ssize_t)len) {
			return -1;
		}
	}
	return 0;
}

/* read a lump of data at a specified offset */
static int tdb_read(TDB_CONTEXT *tdb, tdb_off offset, char *buf, tdb_len len)
{
	if (tdb_oob(tdb, offset + len) != 0) {
		/* oops - trying to read beyond the end of the database! */
#if TDB_DEBUG
		printf("read error of length %u at offset %u (max %u)\n",
		       len, offset, tdb->map_size);
#endif
		return -1;
	}

	if (tdb->map_ptr) {
		memcpy(buf, offset + (char *)tdb->map_ptr, len);
	} else {
		lseek(tdb->fd, offset, SEEK_SET);
		if (read(tdb->fd, buf, len) != (ssize_t)len) {
			return -1;
		}
	}
	return 0;
}


/* read a lump of data, allocating the space for it */
static char *tdb_alloc_read(TDB_CONTEXT *tdb, tdb_off offset, tdb_len len)
{
	char *buf;

	buf = (char *)malloc(len);

	if (tdb_read(tdb, offset, buf, len) == -1) {
		free(buf);
		return NULL;
	}
	
	return buf;
}

/* expand the database at least length bytes by expanding the
   underlying file and doing the mmap again if necessary */
static int tdb_expand(TDB_CONTEXT *tdb, tdb_off length)
{
	struct list_struct rec;
	tdb_off offset, ptr;
	char b = 0;

	/* always make room for at least 10 more records */
	length *= 10;

	/* and round the database up to a multiple of TDB_PAGE_SIZE */
	length = ((tdb->map_size + length + TDB_PAGE_SIZE) & ~(TDB_PAGE_SIZE - 1)) - tdb->map_size;

	/* expand the file itself */
	lseek(tdb->fd, tdb->map_size + length - 1, SEEK_SET);
	if (write(tdb->fd, &b, 1) != 1) return -1;

	/* form a new freelist record */
	offset = FREELIST_TOP;
	rec.rec_len = length - sizeof(rec);
	if (tdb_read(tdb, offset, (char *)&rec.next, sizeof(rec.next)) == -1) return -1;

#if HAVE_MMAP
	if (tdb->map_ptr) {
		munmap(tdb->map_ptr, tdb->map_size);
		tdb->map_ptr = NULL;
	}
#endif

	tdb->map_size += length;

	/* write it out */
	if (tdb_write(tdb, tdb->map_size - length, (char *)&rec, sizeof(rec)) == -1) return -1;

	/* link it into the free list */
	ptr = tdb->map_size - length;
	if (tdb_write(tdb, offset, (char *)&ptr, sizeof(ptr)) == -1) return -1;

#if HAVE_MMAP
	tdb->map_ptr = (void *)mmap(NULL, tdb->map_size, 
				   PROT_READ|PROT_WRITE,
				   MAP_SHARED | MAP_FILE, tdb->fd, 0);
#endif

#if TDB_DEBUG
	printf("expanded database by %u bytes\n", length);
#endif

	return 0;
}

/* allocate some space from the free list. The offset returned points
   to a unconnected list_struct within the database with room for at
   least length bytes of total data

   0 is returned if the space could not be allocated
 */
static tdb_off tdb_allocate(TDB_CONTEXT *tdb, tdb_len length)
{
	tdb_off offset, rec_ptr, last_ptr;
	struct list_struct rec, lastrec, newrec;

 again:
	last_ptr = 0;
	offset = FREELIST_TOP;

	/* read in the freelist top */
	if (tdb_read(tdb, offset, (char *)&rec_ptr, sizeof(rec_ptr)) == -1) {
		goto fail;
	}

	/* keep looking until we find a freelist record that is big
           enough */
	while (rec_ptr) {
		if (tdb_read(tdb, rec_ptr, (char *)&rec, sizeof(rec)) == -1) {
			goto fail;
		}

		if (rec.rec_len >= length) {
			/* found it - now possibly split it up  */
			if (rec.rec_len > length + MIN_REC_SIZE) {
				length = (length + TDB_ALIGN) & ~(TDB_ALIGN-1);

				newrec.rec_len = rec.rec_len - (sizeof(rec) + length);
				newrec.next = rec.next;
				
				rec.rec_len = length;
				rec.next = rec_ptr + sizeof(rec) + rec.rec_len;
				
				if (tdb_write(tdb, rec.next, (char *)&newrec, 
					     sizeof(newrec)) == -1) {
					goto fail;
				}

				if (tdb_write(tdb, rec_ptr, (char *)&rec, 
					     sizeof(rec)) == -1) {
					goto fail;
				}
			}

			/* remove it from the list */
			if (last_ptr == 0) {
				offset = FREELIST_TOP;

				if (tdb_write(tdb, offset, (char *)&rec.next, 
					     sizeof(tdb_off)) == -1) {
					goto fail;
				}				
			} else {
				lastrec.next = rec.next;
				if (tdb_write(tdb, last_ptr, (char *)&lastrec, 
					     sizeof(lastrec)) == -1) {
					goto fail;
				}
			}

			/* all done - return the new record offset */
#if TDB_DEBUG
			printf("allocated %u bytes in database\n", rec.rec_len);
#endif
			return rec_ptr;
		}

		/* move to the next record */
		lastrec = rec;
		last_ptr = rec_ptr;
		rec_ptr = rec.next;
	}

	/* we didn't find enough space. See if we can expand the database and if we can
	   then try again */
	if (tdb_expand(tdb, length + sizeof(rec)) == 0) goto again;

 fail:
#if TDB_DEBUG
	printf("tdb_allocate failed for size %u\n", length);
#endif
	return 0;
}

/* initialise a new database with a specified hash size */
static int tdb_new_database(TDB_CONTEXT *tdb, int hash_size)
{
	struct tdb_header header;
	tdb_off offset;
	int i;

	/* create the header */
	header.version = TDB_VERSION;
	header.hash_size = hash_size;
	if (write(tdb->fd, &header, sizeof(header)) != sizeof(header)) return -1;

	/* the freelist and hash pointers */
	offset = 0;
	for (i=0;i<hash_size+1;i++) {
		if (write(tdb->fd, &offset, sizeof(tdb_off)) != sizeof(tdb_off)) return -1;
	}

#if TDB_DEBUG
	printf("initialised database of hash_size %u available space %u\n", 
	       hash_size, rec.rec_len);
#endif
	return 0;
}


/* update an entry in place - this only works if the new data size
   is <= the old data size and the key exists.
   on failure return -1
*/
int tdb_update(TDB_CONTEXT *tdb, TDB_DATA key, TDB_DATA dbuf)
{
	unsigned hash;
	tdb_off offset, rec_ptr;
	struct list_struct rec;
	char *data=NULL;

	/* find which hash bucket it is in */
	hash = tdb_hash(&key);

	/* find the top of the hash chain */
	offset = tdb_hash_top(tdb, hash);

	/* read in the hash top */
	if (tdb_read(tdb, offset, (char *)&rec_ptr, sizeof(rec_ptr)) == -1) {
		goto fail;
	}

	/* keep looking until we find the right record */
	while (rec_ptr) {
		if (tdb_read(tdb, rec_ptr, (char *)&rec, sizeof(rec)) == -1) {
			goto fail;
		}

		if (hash == rec.full_hash && key.dsize == rec.key_len) {
			/* a very likely hit - read the full key */
			data = tdb_alloc_read(tdb, rec_ptr + sizeof(rec), 
					     rec.key_len);
			if (!data) goto fail;

			if (memcmp(key.dptr, data, key.dsize) == 0) {
				/* definate hit */
				if (rec.rec_len < key.dsize + dbuf.dsize) {
					/* the update won't fit! */
					goto fail;
				}
				if (tdb_write(tdb, rec_ptr + sizeof(rec) + rec.key_len,
					     dbuf.dptr, dbuf.dsize) == -1) {
					goto fail;
				}
				if (dbuf.dsize != rec.data_len) {
					rec.data_len = dbuf.dsize;
					if (tdb_write(tdb, rec_ptr, (char *)&rec, sizeof(rec)) == -1) {
						goto fail;
					}
				}
				free(data);
				return 0;
			}

			/* a miss - drat */
			free(data);
			data = NULL;
		}

		/* move to the next record */
		rec_ptr = rec.next;
	}

	/* we didn't find it */
 fail:
	if (data) free(data);
	return -1;
}


/* find an entry in the database given a key */
TDB_DATA tdb_fetch(TDB_CONTEXT *tdb, TDB_DATA key)
{
	unsigned hash;
	tdb_off offset, rec_ptr;
	struct list_struct rec;
	char *data;
	TDB_DATA ret;

	/* find which hash bucket it is in */
	hash = tdb_hash(&key);

	/* find the top of the hash chain */
	offset = tdb_hash_top(tdb, hash);

	/* read in the hash top */
	if (tdb_read(tdb, offset, (char *)&rec_ptr, sizeof(rec_ptr)) == -1) {
		return null_data;
	}

	/* keep looking until we find the right record */
	while (rec_ptr) {
		if (tdb_read(tdb, rec_ptr, (char *)&rec, sizeof(rec)) == -1) {
			return null_data;
		}

		if (hash == rec.full_hash && key.dsize == rec.key_len) {
			/* a very likely hit - read the full record */
			data = tdb_alloc_read(tdb, rec_ptr + sizeof(rec), 
					     rec.key_len + rec.data_len);
			if (!data) {
				return null_data;
			}

			if (memcmp(key.dptr, data, key.dsize) == 0) {
				/* a definate match */
				ret.dptr = (char *)memdup(data + rec.key_len, rec.data_len);
				ret.dsize = rec.data_len;
				free(data);
				return ret;
			}

			/* a miss - drat */
			free(data);
		}

		/* move to the next record */
		rec_ptr = rec.next;
	}

	/* we didn't find it */
	return null_data;
}

/* check if an entry in the database exists 

   note that 1 is returned if the key is found and 0 is returned if not found
   this doesn't match the conventions in the rest of this module, but is
   compatible with gdbm
*/
int tdb_exists(TDB_CONTEXT *tdb, TDB_DATA key)
{
	unsigned hash;
	tdb_off offset, rec_ptr;
	struct list_struct rec;
	char *data;

	/* find which hash bucket it is in */
	hash = tdb_hash(&key);

	/* find the top of the hash chain */
	offset = tdb_hash_top(tdb, hash);

	/* read in the hash top */
	if (tdb_read(tdb, offset, (char *)&rec_ptr, sizeof(rec_ptr)) == -1) {
		return 0;
	}

	/* keep looking until we find the right record */
	while (rec_ptr) {
		if (tdb_read(tdb, rec_ptr, (char *)&rec, sizeof(rec)) == -1) {
			return 0;
		}

		if (hash == rec.full_hash && key.dsize == rec.key_len) {
			/* a very likely hit - read the full record */
			data = tdb_alloc_read(tdb, rec_ptr + sizeof(rec), 
					     rec.key_len + rec.data_len);
			if (!data) {
				return 0;
			}

			if (memcmp(key.dptr, data, key.dsize) == 0) {
				/* a definate match */
				free(data);
				return 1;
			}

			/* a miss - drat */
			free(data);
		}

		/* move to the next record */
		rec_ptr = rec.next;
	}

	/* we didn't find it */
	return 0;
}


/* traverse the entire database - calling fn(tdb, key, data) on each element.
   return -1 on error or the record count traversed
   if fn is NULL then it is not called
   a non-zero return value from fn() indicates that the traversal should stop
  */
int tdb_traverse(TDB_CONTEXT *tdb, int (*fn)(TDB_CONTEXT *tdb, TDB_DATA key, TDB_DATA dbuf))
{
	int count = 0;
	unsigned h;
	tdb_off offset, rec_ptr;
	struct list_struct rec;
	char *data;
	TDB_DATA key, dbuf;

	/* loop over all hash chains */
	for (h = 0; h < tdb->header.hash_size; h++) {
		/* read in the hash top */
		offset = tdb_hash_top(tdb, h);
		if (tdb_read(tdb, offset, (char *)&rec_ptr, sizeof(rec_ptr)) == -1) {
			return -1;
		}

		/* traverse all records for this hash */
		while (rec_ptr) {
			if (tdb_read(tdb, rec_ptr, (char *)&rec, sizeof(rec)) == -1) {
				return -1;
			}

			/* now read the full record */
			data = tdb_alloc_read(tdb, rec_ptr + sizeof(rec), 
					     rec.key_len + rec.data_len);
			if (!data) {
				return -1;
			}

			key.dptr = data;
			key.dsize = rec.key_len;
			dbuf.dptr = data + rec.key_len;
			dbuf.dsize = rec.data_len;
			count++;

			if (fn && fn(tdb, key, dbuf) != 0) {
				/* they want us to stop traversing */
				free(data);
				return count;
			}

			/* a miss - drat */
			free(data);

			/* move to the next record */
			rec_ptr = rec.next;
		}

	}

	/* return the number traversed */
	return count;
}


/* find the first entry in the database and return its key */
TDB_DATA tdb_firstkey(TDB_CONTEXT *tdb)
{
	tdb_off offset, rec_ptr;
	struct list_struct rec;
	unsigned hash;
	TDB_DATA ret;

	/* look for a non-empty hash chain */
	for (hash = 0, rec_ptr = 0; 
	     hash < tdb->header.hash_size && rec_ptr == 0;
	     hash++) {
		/* find the top of the hash chain */
		offset = tdb_hash_top(tdb, hash);

		/* read in the hash top */
		if (tdb_read(tdb, offset, (char *)&rec_ptr, sizeof(rec_ptr)) == -1) {
			return null_data;
		}
	}

	if (rec_ptr == 0) return null_data;

	/* we've found a non-empty chain, now read the record */
	if (tdb_read(tdb, rec_ptr, (char *)&rec, sizeof(rec)) == -1) {
		return null_data;
	}

	/* allocate and read the key space */
	ret.dptr = tdb_alloc_read(tdb, rec_ptr + sizeof(rec), rec.key_len);
	ret.dsize = rec.key_len;

	return ret;
}

/* find the next entry in the database, returning its key */
TDB_DATA tdb_nextkey(TDB_CONTEXT *tdb, TDB_DATA key)
{
	unsigned hash, h;
	tdb_off offset, rec_ptr;
	struct list_struct rec;
	char *data;
	TDB_DATA ret;

	/* find which hash bucket it is in */
	hash = tdb_hash(&key);

	/* find the top of the hash chain */
	offset = tdb_hash_top(tdb, hash);

	/* read in the hash top */
	if (tdb_read(tdb, offset, (char *)&rec_ptr, sizeof(rec_ptr)) == -1) {
		return null_data;
	}

	/* look until we find the right record */
	while (rec_ptr) {
		if (tdb_read(tdb, rec_ptr, (char *)&rec, sizeof(rec)) == -1) {
			return null_data;
		}

		if (hash == rec.full_hash && key.dsize == rec.key_len) {
			/* a very likely hit - read the full key */
			data = tdb_alloc_read(tdb, rec_ptr + sizeof(rec), 
					     rec.key_len);
			if (!data) {
				return null_data;
			}

			if (memcmp(key.dptr, data, key.dsize) == 0) {
				/* a definate match - we want the next
                                   record after this one */
				rec_ptr = rec.next;
				free(data);
				if (rec_ptr == 0) goto next_hash;
				goto found_record;
			}

			/* a miss - drat */
			free(data);
		}

		/* move to the next record */
		rec_ptr = rec.next;
	}

 next_hash:
#if TDB_DEBUG
	printf("tdb_nextkey trying next hash from %u\n",
	       hash % tdb->header.hash_size);
#endif

	h = hash % tdb->header.hash_size;
	if (h == tdb->header.hash_size - 1) return null_data;

	/* look for a non-empty hash chain */
	for (h = h+1, rec_ptr = 0; 
	     h < tdb->header.hash_size && rec_ptr == 0;
	     h++) {
#if TDB_DEBUG
		printf("tdb_nextkey trying bucket %u\n",h);
#endif
		/* find the top of the hash chain */
		offset = tdb_hash_top(tdb, h);

		/* read in the hash top */
		if (tdb_read(tdb, offset, (char *)&rec_ptr, sizeof(rec_ptr)) == -1) {
			return null_data;
		}
	}

	if (rec_ptr == 0) return null_data;

 found_record:

	/* we've found a non-empty chain, now read the record */
	if (tdb_read(tdb, rec_ptr, (char *)&rec, sizeof(rec)) == -1) {
		return null_data;
	}

#if TDB_DEBUG
	printf("tdb_nextkey found hash 0x%08x in bucket %u from bucket %u\n", 
	       rec.full_hash, rec.full_hash % tdb->header.hash_size,
	       hash % tdb->header.hash_size);
#endif
	/* allocate and read the key space */
	ret.dptr = tdb_alloc_read(tdb, rec_ptr + sizeof(rec), rec.key_len);
	ret.dsize = rec.key_len;

	return ret;
}

/* delete an entry in the database given a key */
int tdb_delete(TDB_CONTEXT *tdb, TDB_DATA key)
{
	unsigned hash;
	tdb_off offset, rec_ptr, last_ptr;
	struct list_struct rec, lastrec;
	char *data;

	tdb_writelock(tdb);

	/* find which hash bucket it is in */
	hash = tdb_hash(&key);

	/* find the top of the hash chain */
	offset = tdb_hash_top(tdb, hash);

	/* read in the hash top */
	if (tdb_read(tdb, offset, (char *)&rec_ptr, sizeof(rec_ptr)) == -1) {
		goto fail;
	}

	last_ptr = 0;

	/* keep looking until we find the right record */
	while (rec_ptr) {
		if (tdb_read(tdb, rec_ptr, (char *)&rec, sizeof(rec)) == -1) {
			goto fail;
		}

		if (hash == rec.full_hash && key.dsize == rec.key_len) {
			/* a very likely hit - read the record and full key */
			data = tdb_alloc_read(tdb, rec_ptr + sizeof(rec), 
					     rec.key_len);
			if (!data) {
				goto fail;
			}

			if (memcmp(key.dptr, data, key.dsize) == 0) {
				/* a definate match - delete it */
#if TDB_DEBUG
				printf("deleting record with hash 0x%08x in bucket %u\n", 
				       hash, hash % tdb->header.hash_size);
#endif
				if (last_ptr == 0) {
					offset = tdb_hash_top(tdb, hash);
					if (tdb_write(tdb, offset, (char *)&rec.next, sizeof(rec.next)) == -1) {
						goto fail;
					}
				} else {
					lastrec.next = rec.next;
					if (tdb_write(tdb, last_ptr, (char *)&lastrec, sizeof(lastrec)) == -1) {
						goto fail;
					}					
				}
				/* and recover the space */
				offset = FREELIST_TOP;
				if (tdb_read(tdb, offset, (char *)&rec.next, sizeof(rec.next)) == -1) {
					goto fail;
				}
				if (tdb_write(tdb, rec_ptr, (char *)&rec, sizeof(rec)) == -1) {
					goto fail;
				}
				if (tdb_write(tdb, offset, (char *)&rec_ptr, sizeof(rec_ptr)) == -1) {
					goto fail;
				}

				/* yipee - all done */
				free(data);
				tdb_writeunlock(tdb);
				return 0;
			}

			/* a miss - drat */
			free(data);
		}

		/* move to the next record */
		last_ptr = rec_ptr;
		lastrec = rec;
		rec_ptr = rec.next;
	}


 fail:
	tdb_writeunlock(tdb);
	return -1;
}


/* store an element in the database, replacing any existing element
   with the same key 

   return 0 on success, -1 on failure
*/
int tdb_store(TDB_CONTEXT *tdb, TDB_DATA key, TDB_DATA dbuf, int flag)
{
	struct list_struct rec;
	char *data = NULL;
	unsigned hash;
	tdb_off rec_ptr, offset;

	/* check for it existing */
	if (flag == TDB_INSERT && tdb_exists(tdb, key)) {
		return -1;
	}

	tdb_writelock(tdb);

	/* first try in-place update */
	if (flag != TDB_INSERT && tdb_update(tdb, key, dbuf) == 0) {
		tdb_writeunlock(tdb);
		return 0;
	}

	/* delete any existing record - if it doesn't exist we don't care */
	if (flag != TDB_INSERT) {
		tdb_delete(tdb, key);
	}

	/* find which hash bucket it is in */
	hash = tdb_hash(&key);

	rec_ptr = tdb_allocate(tdb, key.dsize + dbuf.dsize);
	if (rec_ptr == 0) {
		goto fail;
	}

	/* read the newly created record */
	if (tdb_read(tdb, rec_ptr, (char *)&rec, sizeof(rec)) == -1) {
		goto fail;
	}

	/* find the top of the hash chain */
	offset = tdb_hash_top(tdb, hash);

	/* read in the hash top diretcly into our next pointer */
	if (tdb_read(tdb, offset, (char *)&rec.next, sizeof(rec.next)) == -1) {
		goto fail;
	}

	rec.key_len = key.dsize;
	rec.data_len = dbuf.dsize;
	rec.full_hash = hash;

	/* write the new record */
	if (tdb_write(tdb, rec_ptr, (char *)&rec, sizeof(rec)) == -1) goto fail;
	if (tdb_write(tdb, rec_ptr + sizeof(rec), key.dptr, key.dsize) == -1) goto fail;
	if (tdb_write(tdb, rec_ptr + sizeof(rec) + key.dsize, dbuf.dptr, dbuf.dsize) == -1) goto fail;

	/* and point the top of the hash chain at it */
	if (tdb_write(tdb, offset, (char *)&rec_ptr, sizeof(rec_ptr)) == -1) goto fail;

	tdb_writeunlock(tdb);
#if TDB_DEBUG
	printf("added record with hash 0x%08x in bucket %u\n", hash, hash % tdb->header.hash_size);
#endif
	return 0;

 fail:
#if TDB_DEBUG
	printf("store failed for hash 0x%08x in bucket %u\n", hash, hash % tdb->header.hash_size);
#endif
	if (data) free(data);
	tdb_writeunlock(tdb);
	return -1;
}


/* open the database, creating it if necessary 

   The flags and mode are passed straight to the open call on the database
   file. A flags value of O_WRONLY is invalid

   The hash size is advisory, use zero for a default value. 

   return is NULL on error
*/
TDB_CONTEXT *tdb_open(char *name, int hash_size, int flags, mode_t mode)
{
	TDB_CONTEXT tdb, *ret;
	struct tdb_header header;
	struct stat st;

	tdb.fd = -1;
	tdb.name = NULL;
	tdb.map_ptr = NULL;

	if ((flags & O_ACCMODE) == O_WRONLY) goto fail;

	if (hash_size == 0) hash_size = DEFAULT_HASH_SIZE;

	tdb.fd = open(name, flags, mode);
	if (tdb.fd == -1) goto fail;

	if (read(tdb.fd, &header, sizeof(header)) != sizeof(header) ||
	    header.version != TDB_VERSION) {
		/* its not a valid database - possibly initialise it */
		if (!(flags & O_CREAT)) {
			goto fail;
		}
		if (tdb_new_database(&tdb, hash_size) == -1) goto fail;

		lseek(tdb.fd, 0, SEEK_SET);
		if (read(tdb.fd, &header, sizeof(header)) != sizeof(header)) goto fail;
	}

	fstat(tdb.fd, &st);

	/* map the database and fill in the return structure */
	tdb.name = (char *)strdup(name);
	tdb.map_size = st.st_size;
	tdb.read_only = ((flags & O_ACCMODE) == O_RDONLY);
#if HAVE_MMAP
	tdb.map_ptr = (void *)mmap(NULL, st.st_size, 
				  tdb.read_only? PROT_READ : PROT_READ|PROT_WRITE,
				  MAP_SHARED | MAP_FILE, tdb.fd, 0);
#endif
	tdb.header = header;

	ret = (TDB_CONTEXT *)malloc(sizeof(tdb));
	if (!ret) goto fail;

	*ret = tdb;

#if TDB_DEBUG
	printf("mapped database of hash_size %u map_size=%u\n", 
	       hash_size, db.map_size);
#endif

	return ret;

 fail:
	if (tdb.name) free(tdb.name);
	if (tdb.fd != -1) close(tdb.fd);
	if (tdb.map_ptr) munmap(tdb.map_ptr, tdb.map_size);

	return NULL;
}

/* close a database */
int tdb_close(TDB_CONTEXT *tdb)
{
	if (!tdb) return -1;

	if (tdb->name) free(tdb->name);
	if (tdb->fd != -1) close(tdb->fd);
	if (tdb->map_ptr) munmap(tdb->map_ptr, tdb->map_size);

	memset(tdb, 0, sizeof(*tdb));
	free(tdb);

	return 0;
}

/* lock the database. If we already have it locked then don't do anything */
int tdb_writelock(TDB_CONTEXT *tdb)
{
#if !NOLOCK
	struct flock fl;

	if (tdb->write_locked) return 0;

	fl.l_type = F_WRLCK;
	fl.l_whence = SEEK_SET;
	fl.l_start = 0;
	fl.l_len = 1;
	fl.l_pid = 0;

	if (fcntl(tdb->fd, F_SETLKW, &fl) != 0) return -1;

	tdb->write_locked = 1;
#endif
	return 0;
}

/* unlock the database. If we don't have it locked then return -1 */
int tdb_writeunlock(TDB_CONTEXT *tdb)
{
#if !NOLOCK
	struct flock fl;

	if (!tdb->write_locked) return -1;

	fl.l_type = F_UNLCK;
	fl.l_whence = SEEK_SET;
	fl.l_start = 0;
	fl.l_len = 1;
	fl.l_pid = 0;

	if (fcntl(tdb->fd, F_SETLK, &fl) != 0) return -1;

	tdb->write_locked = 0;
#endif
	return 0;
}

