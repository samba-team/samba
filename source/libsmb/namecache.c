/* 
   Unix SMB/CIFS implementation.

   NetBIOS name cache module.

   Copyright (C) Tim Potter, 2002-2003
   
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

#include "includes.h"

static BOOL done_namecache_init;
static BOOL enable_namecache;		/* full namecache enable; separate 
					   from marking WINS servers that died */
static TDB_CONTEXT *namecache_tdb;

struct nc_value {
	time_t expiry;		     /* When entry expires */
	int count;		     /* Number of addresses */
	struct in_addr ip_list[1];   /* Address list */
};

/* Initialise namecache system */

BOOL namecache_enable( BOOL full_cache_enable )
{
	/* Check if we have been here before, or name caching disabled
           by setting the name cache timeout to zero. */ 

	if (done_namecache_init)
		return False;

	done_namecache_init = True;

	if (lp_name_cache_timeout() == 0) {
		DEBUG(5, ("namecache_init: disabling netbios name cache\n"));
		return False;
	}

	/* Open namecache tdb in read/write or readonly mode */

	namecache_tdb = tdb_open_log(
		lock_path("namecache.tdb"), 0,
		TDB_DEFAULT, O_RDWR | O_CREAT, 0644);

	if (!namecache_tdb) {
		DEBUG(5, ("namecache_init: could not open %s\n",
			  lock_path("namecache.tdb")));
		return False;
	}

	DEBUG(5, ("namecache_init: enabling netbios namecache, timeout %d "
		  "seconds\n", lp_name_cache_timeout()));

	enable_namecache = full_cache_enable;

	return True;
}

/* Return a key for a name and name type.  The caller must free
   retval.dptr when finished. */

static TDB_DATA namecache_key(const char *name, int name_type)
{
	TDB_DATA retval;
	char *keystr;

	asprintf(&keystr, "%s#%02X", strupper_static(name), name_type);

	retval.dsize = strlen(keystr) + 1;
	retval.dptr = keystr;

	return retval;
}

/* Return a data value for an IP list.  The caller must free
   retval.dptr when finished. */

static TDB_DATA namecache_value(struct in_addr *ip_list, int num_names, 
				time_t expiry)
{
	TDB_DATA retval;
	struct nc_value *value;
	int size = sizeof(struct nc_value);

	if (num_names > 0)
		size += sizeof(struct in_addr) * (num_names-1);

	value = (struct nc_value *)malloc(size);

	memset(value, 0, size);

	value->expiry = expiry;
	value->count = num_names;

	if (ip_list)
		memcpy(value->ip_list, ip_list, sizeof(struct in_addr) * num_names);

	retval.dptr = (char *)value;
	retval.dsize = size;

	return retval;
}

/* Store a name in the name cache */

void namecache_store(const char *name, int name_type,
		     int num_names, struct in_addr *ip_list)
{
	TDB_DATA key, value;
	time_t expiry;
	int i;

	if (!enable_namecache)
		return;

	DEBUG(5, ("namecache_store: storing %d address%s for %s#%02x: ",
		  num_names, num_names == 1 ? "": "es", name, name_type));

	for (i = 0; i < num_names; i++) 
		DEBUGADD(5, ("%s%s", inet_ntoa(ip_list[i]),
			     i == (num_names - 1) ? "" : ", "));

	DEBUGADD(5, ("\n"));

	key = namecache_key(name, name_type);

	/* Cache pdc location or dc lists for only a little while
	   otherwise if we lock on to a bad DC we can potentially be
	   out of action for the entire cache timeout time! */

	if (name_type == 0x1b || name_type == 0x1c)
		expiry = time(NULL) + 15;
	else
		expiry = time(NULL) + lp_name_cache_timeout();

	value = namecache_value(ip_list, num_names, expiry);

	tdb_store(namecache_tdb, key, value, TDB_REPLACE);

	free(key.dptr);
	free(value.dptr);
}

/* Look up a name in the name cache.  Return a mallocated list of IP
   addresses if the name is contained in the cache. */

BOOL namecache_fetch(const char *name, int name_type, struct in_addr **ip_list,
		     int *num_names)
{
	TDB_DATA key, value;
	struct nc_value *data = NULL;
	time_t now;
	int i;

	*ip_list = NULL;
	*num_names = 0;

	if (!enable_namecache)
		return False;

	/* Read value */

	key = namecache_key(name, name_type);

	value = tdb_fetch(namecache_tdb, key);
	
	if (!value.dptr) {
		DEBUG(5, ("namecache_fetch: %s#%02x not found\n",
			  name, name_type));
		goto done;
	}

	data = (struct nc_value *)value.dptr;

	/* Check expiry time */

	now = time(NULL);

	if (now > data->expiry) {

		DEBUG(5, ("namecache_fetch: entry for %s#%02x expired\n",
			  name, name_type));

		tdb_delete(namecache_tdb, key);

		value = tdb_null;

		goto done;
	}

	if ((data->expiry - now) > lp_name_cache_timeout()) {

		/* Someone may have changed the system time on us */

		DEBUG(5, ("namecache_fetch: entry for %s#%02x has bad expiry\n",
			  name, name_type));

		tdb_delete(namecache_tdb, key);

		value = tdb_null;

		goto done;
	}

	/* Extract and return namelist */

	DEBUG(5, ("namecache_fetch: returning %d address%s for %s#%02x: ",
		  data->count, data->count == 1 ? "" : "es", name, name_type));

	if (data->count) {

		*ip_list = (struct in_addr *)malloc(
			sizeof(struct in_addr) * data->count);
		
		memcpy(*ip_list, data->ip_list, sizeof(struct in_addr) * data->count);
		
		*num_names = data->count;
		
		for (i = 0; i < *num_names; i++)
			DEBUGADD(5, ("%s%s", inet_ntoa((*ip_list)[i]),
				     i == (*num_names - 1) ? "" : ", "));

	}

	DEBUGADD(5, ("\n"));

done:
	SAFE_FREE(key.dptr);
	SAFE_FREE(data);

	return value.dsize > 0;
}

/* Flush all names from the name cache */

void namecache_flush(void)
{
	int result;

	if (!namecache_tdb)
		return;

	result = tdb_traverse(namecache_tdb, tdb_traverse_delete_fn, NULL);

	if (result == -1)
		DEBUG(5, ("namecache_flush: error deleting cache entries\n"));
	else
		DEBUG(5, ("namecache_flush: deleted %d cache entr%s\n", 
			  result, result == 1 ? "y" : "ies"));
}

/* Return true if a dead WINS server record is in the namecache */

BOOL namecache_wins_get(char *keystr)
{
	TDB_DATA key, value;
	time_t *timeout, now;
	BOOL result = False;

	if ( !done_namecache_init )
		return False;
		
	/* Look up key */

	key.dptr = keystr;
	key.dsize = strlen(keystr) + 1;

	value = tdb_fetch(namecache_tdb, key);

	if (!value.dptr)
		return False;	/* No key: WINS server is alive */

	/* Check timestamp on returned key */

	timeout = (time_t *)value.dptr;

	now = time(NULL);

	if (now > *timeout) {

		DEBUG(5, ("namecache_wins_get: entry for %s expired\n",
			  keystr));

		tdb_delete(namecache_tdb, key);

		goto done;
	}

	if ((*timeout - now) > lp_name_cache_timeout()) {

		DEBUG(5, ("namecache_wins_get: entry for %s has bad expiry %ld\n",
			  keystr, *timeout));

		tdb_delete(namecache_tdb, key);

		goto done;
	}

	/* WINS server is marked as dead */

	result = True;

done:
	SAFE_FREE(value.dptr);

	return result;
}

/* Delete a dead WINS server record */

void namecache_wins_del(char *keystr)
{
	TDB_DATA key;

	if ( !done_namecache_init )
		return;

	key.dptr = keystr;
	key.dsize = strlen(keystr) + 1;

	tdb_delete(namecache_tdb, key);
}

/* Set a dead WINS server record */

void namecache_wins_set(char *keystr, time_t timeout)
{
	TDB_DATA key, value;

	if ( !done_namecache_init )
		return;

	key.dptr = keystr;
	key.dsize = strlen(keystr) + 1;

	value.dptr = (char *)&timeout;
	value.dsize = sizeof(timeout);

	tdb_store(namecache_tdb, key, value, TDB_REPLACE);
}
