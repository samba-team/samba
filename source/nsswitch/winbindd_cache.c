/* 
   Unix SMB/Netbios implementation.
   Version 2.0

   Winbind daemon - caching related functions

   Copyright (C) Tim Potter 2000
   
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

#include "winbindd.h"

#define CACHE_TYPE_USER "USR"
#define CACHE_TYPE_GROUP "GRP"

/* Initialise caching system */

static TDB_CONTEXT *cache_tdb;

struct cache_rec {
	uint32 seq_num;
	time_t mod_time;
};

void winbindd_cache_init(void)
{
	/* Open tdb cache */
	unlink(lock_path("winbindd_cache.tdb"));
	if (!(cache_tdb = tdb_open(lock_path("winbindd_cache.tdb"), 0, 
				   TDB_NOLOCK, O_RDWR | O_CREAT, 0600))) {
		DEBUG(0, ("Unable to open tdb cache - user and group caching "
			  "disabled\n"));
	}
}

/* get the domain sequence number, possibly re-fetching */
static uint32 cached_sequence_number(char *domain_name)
{
	fstring keystr;
	TDB_DATA dbuf;
	struct cache_rec rec;
	time_t t = time(NULL);

	slprintf(keystr, sizeof(keystr), "CACHESEQ/%s", domain_name);
	dbuf = tdb_fetch_by_string(cache_tdb, keystr);
	if (!dbuf.dptr || dbuf.dsize != sizeof(rec)) {
		goto refetch;
	}
	memcpy(&rec, dbuf.dptr, sizeof(rec));
	free(dbuf.dptr);

	if (t < (rec.mod_time + lp_winbind_cache_time())) {
		DEBUG(4,("cached sequence number for %s is %u\n",
			 domain_name, (unsigned)rec.seq_num));
		return rec.seq_num;
	}

 refetch:	
	rec.seq_num = domain_sequence_number(domain_name);
	rec.mod_time = t;
	tdb_store_by_string(cache_tdb, keystr, &rec, sizeof(rec));

	return rec.seq_num;
}

/* Check whether a seq_num for a cached item has expired */
static BOOL cache_domain_expired(char *domain_name, uint32 seq_num)
{
	if (cached_sequence_number(domain_name) != seq_num) {
		DEBUG(4,("seq %u for %s has expired\n", (unsigned)seq_num, 
			 domain_name));
		return True;
	}
	return False;
}

static void set_cache_sequence_number(char *domain_name, char *cache_type, 
				      char *subkey)
{
	fstring keystr;

	slprintf(keystr,sizeof(keystr),"CACHESEQ %s/%s/%s",
		 domain_name, cache_type, subkey?subkey:"");

	tdb_store_int(cache_tdb, keystr, cached_sequence_number(domain_name));
}

static uint32 get_cache_sequence_number(char *domain_name, char *cache_type, 
					char *subkey)
{
	fstring keystr;
	uint32 seq_num;

	slprintf(keystr,sizeof(keystr),"CACHESEQ %s/%s/%s",
		 domain_name, cache_type, subkey?subkey:"");
	seq_num = (uint32)tdb_fetch_int(cache_tdb, keystr);

	DEBUG(4,("%s is %u\n", keystr, (unsigned)seq_num));

	return seq_num;
}

/* Fill the user or group cache with supplied data */

static void fill_cache(char *domain_name, char *cache_type,
                       struct acct_info *sam_entries, int num_sam_entries)
{
	fstring keystr;

	if (lp_winbind_cache_time() == 0) return;

	/* Error check */
	if (!sam_entries || (num_sam_entries == 0)) return;

	DEBUG(4, ("filling %s cache for domain %s with %d entries\n",
		  cache_type, domain_name, num_sam_entries));

	/* Store data as a mega-huge chunk in the tdb */
	slprintf(keystr, sizeof(keystr), "%s CACHE DATA/%s", cache_type,
		 domain_name);

	tdb_store_by_string(cache_tdb, keystr, sam_entries, 
			    sizeof(struct acct_info) * num_sam_entries);

	/* Stamp cache with current seq number */
	set_cache_sequence_number(domain_name, cache_type, NULL);
}

/* Fill the user cache with supplied data */

void winbindd_store_user_cache(char *domain_name, 
			       struct getpwent_user *sam_entries,
			       int num_sam_entries)
{
	fstring keystr;

	if (lp_winbind_cache_time() == 0) return;

	/* Error check */

	if (!sam_entries || (num_sam_entries == 0)) return;

	DEBUG(4, ("filling USER cache for domain %s with %d entries\n",
		  domain_name, num_sam_entries));

	slprintf(keystr, sizeof(keystr), "USR CACHE DATA/%s", domain_name);

	tdb_store_by_string(cache_tdb, keystr, sam_entries, 
			    sizeof(struct getpwent_user) * num_sam_entries);

	set_cache_sequence_number(domain_name, CACHE_TYPE_USER, NULL);

	return;
}

/* Fill the group cache with supplied data */

void winbindd_store_group_cache(char *domain_name,
				struct acct_info *sam_entries,
				int num_sam_entries)
{
	fill_cache(domain_name, CACHE_TYPE_GROUP, sam_entries, 
		   num_sam_entries);
}

static void fill_cache_entry(char *domain, char *cache_type, char *name, 
			     void *buf, int len)
{
	fstring keystr;

	/* Create key for store */
	slprintf(keystr, sizeof(keystr), "%s/%s/%s", cache_type, domain, name);

	DEBUG(4, ("filling cache entry %s\n", keystr));

	/* Store it */
	tdb_store_by_string(cache_tdb, keystr, buf, len);
}

/* Fill a user info cache entry */

void winbindd_store_user_cache_entry(char *domain, char *user_name, 
				     struct winbindd_pw *pw)
{
        if (lp_winbind_cache_time() == 0) return;

        fill_cache_entry(domain, CACHE_TYPE_USER, user_name, pw, 
			 sizeof(struct winbindd_pw));

	set_cache_sequence_number(domain, CACHE_TYPE_USER, user_name);
}

/* Fill a user uid cache entry */

void winbindd_store_uid_cache_entry(char *domain, uid_t uid, 
                                    struct winbindd_pw *pw)
{
        fstring uidstr;

        if (lp_winbind_cache_time() == 0) return;

        slprintf(uidstr, sizeof(uidstr), "#%u", (unsigned)uid);
        fill_cache_entry(domain, CACHE_TYPE_USER, uidstr, pw, 
			 sizeof(struct winbindd_pw));

        set_cache_sequence_number(domain, CACHE_TYPE_USER, uidstr);
}

/* Fill a group info cache entry */
void winbindd_store_group_cache_entry(char *domain, char *group_name, 
				      struct winbindd_gr *gr, void *extra_data,
				      int extra_data_len)
{
        fstring keystr;

        if (lp_winbind_cache_time() == 0) return;

        /* Fill group data */
        fill_cache_entry(domain, CACHE_TYPE_GROUP, group_name, gr, 
			 sizeof(struct winbindd_gr));

        /* Fill extra data */
        slprintf(keystr, sizeof(keystr), "%s/%s/%s DATA", CACHE_TYPE_GROUP, 
		 domain, group_name);
        tdb_store_by_string(cache_tdb, keystr, extra_data, extra_data_len);

	set_cache_sequence_number(domain, CACHE_TYPE_GROUP, group_name);
}

/* Fill a group info cache entry */

void winbindd_store_gid_cache_entry(char *domain, gid_t gid, 
				    struct winbindd_gr *gr, void *extra_data,
				    int extra_data_len)
{
        fstring keystr;
	fstring gidstr;

	slprintf(gidstr, sizeof(gidstr), "#%u", (unsigned)gid);

        if (lp_winbind_cache_time() == 0) return;

        /* Fill group data */
        fill_cache_entry(domain, CACHE_TYPE_GROUP, gidstr, gr, 
			 sizeof(struct winbindd_gr));

        /* Fill extra data */
        slprintf(keystr, sizeof(keystr), "%s/%s/%s DATA", CACHE_TYPE_GROUP, 
		 domain, gidstr);
        tdb_store_by_string(cache_tdb, keystr, extra_data, extra_data_len);

	set_cache_sequence_number(domain, CACHE_TYPE_GROUP, gidstr);
}

/* Fetch some cached user or group data */
static BOOL fetch_cache(char *domain_name, char *cache_type,
                        struct acct_info **sam_entries, int *num_sam_entries)
{
        TDB_DATA data;
        fstring keystr;

        if (lp_winbind_cache_time() == 0) return False;

	/* Parameter check */
	if (!sam_entries || !num_sam_entries) {
		return False;
	}

	/* Check cache data is current */
	if (cache_domain_expired(domain_name, 
				 get_cache_sequence_number(domain_name, 
							   cache_type, 
							   NULL))) {
		return False;
	}
	
        /* Create key */        
        slprintf(keystr, sizeof(keystr), "%s CACHE DATA/%s", cache_type,
                 domain_name);
	
        /* Fetch cache information */
	data = tdb_fetch_by_string(cache_tdb, keystr);
	
        if (!data.dptr) return False;

	/* Copy across cached data.  We can save a memcpy() by directly
	   assigning the data.dptr to the sam_entries pointer.  It will
	   be freed by the end{pw,gr}ent() function. */
	
	*sam_entries = (struct acct_info *)data.dptr;
	*num_sam_entries = data.dsize / sizeof(struct acct_info);
	
	DEBUG(4, ("fetched %d cached %s entries for domain %s\n",
		  *num_sam_entries, cache_type, domain_name));
	
	return True;
}

/* Return cached entries for a domain.  Return false if there are no cached
   entries, or the cached information has expired for the domain. */

BOOL winbindd_fetch_user_cache(char *domain_name, 
			       struct getpwent_user **sam_entries,
                               int *num_entries)
{
	fstring keystr;
	TDB_DATA data;

	if (!domain_name || !sam_entries || !num_entries) return False;

	if (lp_winbind_cache_time() == 0) return False;

	slprintf(keystr, sizeof(keystr), "USR CACHE DATA/%s", domain_name);
	data = tdb_fetch_by_string(cache_tdb, keystr);

	if (!data.dptr) return False;

	/* Copy across cached data.  We can save a memcpy() by directly
	   assigning the data.dptr to the sam_entries pointer.  It will
	   be freed by the end{pw,gr}ent() function. */
	
	*sam_entries = (struct getpwent_user *)data.dptr;
	*num_entries = data.dsize / sizeof(struct getpwent_user);

	DEBUG(4, ("fetched %d cached USR entries for domain %s\n",
		  *num_entries, domain_name));

	return True;
}

/* Return cached entries for a domain.  Return false if there are no cached
   entries, or the cached information has expired for the domain. */

BOOL winbindd_fetch_group_cache(char *domain_name, void **sam_entries,
                                int *num_entries)
{
	return fetch_cache(domain_name, CACHE_TYPE_GROUP, 
			   (struct acct_info **)sam_entries, num_entries);
}

static BOOL fetch_cache_entry(char *domain, char *cache_type, char *name, 
			      void *buf, int len)
{
	TDB_DATA data;
	fstring keystr;
    
	/* Create key for lookup */
	slprintf(keystr, sizeof(keystr), "%s/%s/%s", cache_type, domain, name);
    
	/* Look up cache entry */
	data = tdb_fetch_by_string(cache_tdb, keystr);
    	if (!data.dptr) return False;
        
        DEBUG(4, ("returning cached entry for %s\\%s\n", domain, name));

        /* Copy found entry into buffer */        
        memcpy((char *)buf, data.dptr, len < data.dsize ? len : data.dsize);
	free(data.dptr);
	return True;
}

/* Fetch an individual user cache entry */
BOOL winbindd_fetch_user_cache_entry(char *domain_name, char *user, 
                                     struct winbindd_pw *pw)
{
	uint32 seq_num;

	if (lp_winbind_cache_time() == 0) return False;

	seq_num = get_cache_sequence_number(domain_name, CACHE_TYPE_USER,
					    user);
	if (cache_domain_expired(domain_name, seq_num)) return False;

	return fetch_cache_entry(domain_name, CACHE_TYPE_USER, user, pw, 
				 sizeof(struct winbindd_pw));
}

/* Fetch an individual uid cache entry */
BOOL winbindd_fetch_uid_cache_entry(char *domain_name, uid_t uid, 
				    struct winbindd_pw *pw)
{
	fstring uidstr;
	uint32 seq_num;

        if (lp_winbind_cache_time() == 0) return False;

	slprintf(uidstr, sizeof(uidstr), "#%u", (unsigned)uid);
    	seq_num = get_cache_sequence_number(domain_name, CACHE_TYPE_USER, 
					    uidstr);
	if (cache_domain_expired(domain_name, seq_num)) return False;

	return fetch_cache_entry(domain_name, CACHE_TYPE_USER, uidstr, pw, 
				 sizeof(struct winbindd_pw));
}

/* Fetch an individual group cache entry.  This function differs from the
   user cache code as we need to store the group membership data. */

BOOL winbindd_fetch_group_cache_entry(char *domain_name, char *group, 
                                      struct winbindd_gr *gr,
                                      void **extra_data, int *extra_data_len)
{
        TDB_DATA data;
        fstring keystr;
	uint32 seq_num;

        if (lp_winbind_cache_time() == 0) return False;

    	seq_num = get_cache_sequence_number(domain_name, CACHE_TYPE_GROUP, 
					    group);

	if (cache_domain_expired(domain_name, seq_num)) return False;

        /* Fetch group data */
        if (!fetch_cache_entry(domain_name, CACHE_TYPE_GROUP, group, gr, 
			       sizeof(struct winbindd_gr))) {
		return False;
	}
	
        /* Fetch extra data */
        slprintf(keystr, sizeof(keystr), "%s/%s/%s DATA", CACHE_TYPE_GROUP, 
		 domain_name, group);

        data = tdb_fetch_by_string(cache_tdb, keystr);

        if (!data.dptr) return False;

	/* Extra data freed when data has been sent */
	if (extra_data) *extra_data = data.dptr;
	if (extra_data_len) *extra_data_len = data.dsize;
	
	return True;
}


/* Fetch an individual gid cache entry.  This function differs from the
   user cache code as we need to store the group membership data. */

BOOL winbindd_fetch_gid_cache_entry(char *domain_name, gid_t gid,
				    struct winbindd_gr *gr,
				    void **extra_data, int *extra_data_len)
{
        TDB_DATA data;
        fstring keystr;
	fstring gidstr;
	uint32 seq_num;

	slprintf(gidstr, sizeof(gidstr), "#%u", (unsigned)gid);
	
        if (lp_winbind_cache_time() == 0) return False;

    	seq_num = get_cache_sequence_number(domain_name, CACHE_TYPE_GROUP, 
					    gidstr);

	if (cache_domain_expired(domain_name, seq_num)) return False;

        /* Fetch group data */
        if (!fetch_cache_entry(domain_name, CACHE_TYPE_GROUP, 
			       gidstr, gr, sizeof(struct winbindd_gr))) {
		return False;
	}

        /* Fetch extra data */
        slprintf(keystr, sizeof(keystr), "%s/%s/%s DATA", CACHE_TYPE_GROUP, 
		 domain_name, gidstr);
        data = tdb_fetch_by_string(cache_tdb, keystr);
        if (!data.dptr) return False;

	/* Extra data freed when data has been sent */
	if (extra_data) *extra_data = data.dptr;
	if (extra_data_len) *extra_data_len = data.dsize;

	return True;
}

/* Flush cache data - easiest to just reopen the tdb */
void winbindd_flush_cache(void)
{
	tdb_close(cache_tdb);
	winbindd_cache_init();
}

/* Print cache status information */
void winbindd_cache_dump_status(void)
{
}
