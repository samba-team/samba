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

/* Cache types */

#define CACHE_TYPE_USER      "USER"
#define CACHE_TYPE_GROUP     "GROUP"

/* Initialise caching system */

static TDB_CONTEXT *cache_tdb;

void winbindd_cache_init(void)
{
    /* Open tdb cache */

    if (!(cache_tdb = tdb_open(lock_path("winbindd_cache.tdb"), 0, 
                               TDB_CLEAR_IF_FIRST | TDB_NOLOCK | TDB_NOMMAP,
                               O_RDWR | O_CREAT, 0600))) {
        DEBUG(0, ("Unable to open tdb cache - user and group caching "
                  "disabled\n"));
    }
}

/* Reset the timestamp for a cached domain */

static void set_cache_time(char *domain_name, char *cache_type, char *subkey)
{
    fstring keystr;

    /* Store timestamp for domain */

    slprintf(keystr, sizeof(keystr), "%s CACHE/%s/%s", 
	     cache_type, domain_name, subkey?subkey:"");
    tdb_store_int(cache_tdb, keystr, (int)time(NULL));
    
    DEBUG(3, ("cache set for %s %s [%s]\n",
	      domain_name, cache_type, 
	      subkey?subkey:""));
}

/* Check whether the timestamp for a cached domain has expired */

static BOOL cache_time_expired(char *domain_name, char *cache_type, 
			       char *subkey)
{
    fstring keystr;
    time_t stamp;
    time_t t = time(NULL);

    /* Get timestamp */

    slprintf(keystr, sizeof(keystr), "%s CACHE/%s/%s", 
	     cache_type, domain_name, subkey?subkey:"");
    stamp = (time_t)tdb_get_int(cache_tdb, keystr);
    
    /* Has it expired? */

    if (t > (stamp + lp_winbind_cache_time())) {
	    DEBUG(3, ("cache timeout for %s %s [%s] has expired (%d secs)\n",
		      domain_name, cache_type, 
		      subkey?subkey:"",
		      (int)(t - stamp)));
    }                

    return time(NULL) > (stamp + lp_winbind_cache_time());
}

/* Fill the user or group cache with supplied data */

static void fill_cache(char *domain_name, char *cache_type,
                       struct acct_info *sam_entries,
                       int num_sam_entries)
{
    TDB_DATA data, key;
    fstring keystr;

    if (lp_winbind_cache_time() == 0) return;

    /* Error check */

    if (!sam_entries || (num_sam_entries == 0)) return;

    DEBUG(4, ("filling %s cache for domain %s with %d entries\n",
              cache_type, domain_name, num_sam_entries));

    /* Store data as a mega-huge chunk in the tdb */

    data.dptr = (void *)sam_entries;
    data.dsize = sizeof(struct acct_info) * num_sam_entries;

    slprintf(keystr, sizeof(keystr), "%s CACHE DATA/%s", cache_type,
             domain_name);

    key.dptr = keystr;
    key.dsize = strlen(keystr);

    tdb_store(cache_tdb, key, data, TDB_REPLACE);

    /* Stamp cache with current time */

    set_cache_time(domain_name, cache_type, NULL);
}

/* Fill the user cache with supplied data */

void winbindd_fill_user_cache(char *domain_name, 
                              struct acct_info *sam_entries,
                              int num_sam_entries)
{
    fill_cache(domain_name, CACHE_TYPE_USER, sam_entries, num_sam_entries);
}

/* Fill the group cache with supplied data */

void winbindd_fill_group_cache(char *domain_name,
                               struct acct_info *sam_entries,
                               int num_sam_entries)
{
    fill_cache(domain_name, CACHE_TYPE_GROUP, sam_entries, num_sam_entries);
}

static void fill_cache_entry(char *domain, char *name, void *buf, int len)
{
    TDB_DATA key, data;
    fstring keystr;

    /* Create key for store */

    slprintf(keystr, sizeof(keystr), "%s/%s", domain, name);

    DEBUG(4, ("filling cache entry %s\n", keystr));

    key.dptr = keystr;
    key.dsize = strlen(keystr) + 1;

    data.dptr = buf;
    data.dsize = len;

    /* Store it */

    tdb_store(cache_tdb, key, data, TDB_REPLACE);
}

/* Fill a user info cache entry */
void winbindd_fill_user_cache_entry(char *domain, char *user_name, 
                                    struct winbindd_pw *pw)
{
        if (lp_winbind_cache_time() == 0) return;

        fill_cache_entry(domain, user_name, pw, sizeof(struct winbindd_pw));
	set_cache_time(domain, CACHE_TYPE_USER, user_name);
}

/* Fill a user uid cache entry */
void winbindd_fill_uid_cache_entry(char *domain, uid_t uid, 
                                    struct winbindd_pw *pw)
{
        fstring uidstr;

        if (lp_winbind_cache_time() == 0) return;

        slprintf(uidstr, sizeof(uidstr), "#%u", (unsigned)uid);
        fill_cache_entry(domain, uidstr, pw, sizeof(struct winbindd_pw));
        set_cache_time(domain, CACHE_TYPE_USER, uidstr);
}

/* Fill a group info cache entry */

void winbindd_fill_group_cache_entry(char *domain, char *group_name, 
                                     struct winbindd_gr *gr, void *extra_data,
                                     int extra_data_len)
{
        TDB_DATA key, data;
        fstring keystr;

        if (lp_winbind_cache_time() == 0) return;

        /* Fill group data */

        fill_cache_entry(domain, group_name, gr, sizeof(struct winbindd_gr));
	set_cache_time(domain, CACHE_TYPE_GROUP, group_name);

        /* Fill extra data */

        slprintf(keystr, sizeof(keystr), "%s/%s DATA", domain, group_name);

        key.dptr = keystr;
        key.dsize = strlen(keystr) + 1;

        data.dptr = extra_data;
        data.dsize = extra_data_len;

        tdb_store(cache_tdb, key, data, TDB_REPLACE);
}

/* Fill a group info cache entry */

void winbindd_fill_gid_cache_entry(char *domain, gid_t gid, 
                                     struct winbindd_gr *gr, void *extra_data,
                                     int extra_data_len)
{
        TDB_DATA key, data;
        fstring keystr;
	fstring gidstr;
	slprintf(gidstr, sizeof(gidstr), "#%u", (unsigned)gid);

        if (lp_winbind_cache_time() == 0) return;

        /* Fill group data */

        fill_cache_entry(domain, gidstr, gr, sizeof(struct winbindd_gr));
	set_cache_time(domain, CACHE_TYPE_GROUP, gidstr);

        /* Fill extra data */

        slprintf(keystr, sizeof(keystr), "%s/%s DATA", domain, gidstr);

        key.dptr = keystr;
        key.dsize = strlen(keystr) + 1;

        data.dptr = extra_data;
        data.dsize = extra_data_len;

        tdb_store(cache_tdb, key, data, TDB_REPLACE);
}

/* Expire information in cache */

void expire_cache(char *domain_name, char *cache_type)
{
    TDB_DATA key;
    fstring keystr;

    DEBUG(4, ("expiring cached %s data for domain %s\n", 
              cache_type, domain_name));

    slprintf(keystr, sizeof(keystr), "%s CACHE DATA/%s", cache_type,
             domain_name);

    key.dptr = keystr;
    key.dsize = strlen(keystr);

    tdb_delete(cache_tdb, key);
}

/* Fetch some cached user or group data */

static BOOL fetch_cache(char *domain_name, char *cache_type,
                        struct acct_info **sam_entries, int *num_sam_entries)
{
        TDB_DATA data, key;
        fstring keystr;

        if (lp_winbind_cache_time() == 0) return False;

	/* Parameter check */

	if (!sam_entries || !num_sam_entries) {
		return False;
	}

	/* Check cache data is current */
	if (cache_time_expired(domain_name, cache_type, NULL)) {
		expire_cache(domain_name, cache_type);
		return False;
	}
	
        /* Create key */        
        slprintf(keystr, sizeof(keystr), "%s CACHE DATA/%s", cache_type,
                 domain_name);
	
        key.dptr = keystr;
        key.dsize = strlen(keystr);
	
        /* Fetch cache information */
	
        data = tdb_fetch(cache_tdb, key);
	
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
                               struct acct_info **sam_entries,
                               int *num_entries)
{
    return fetch_cache(domain_name, CACHE_TYPE_USER, sam_entries,
                       num_entries);
}

/* Return cached entries for a domain.  Return false if there are no cached
   entries, or the cached information has expired for the domain. */

BOOL winbindd_fetch_group_cache(char *domain_name,
                                struct acct_info **sam_entries,
                                int *num_entries)
{
    return fetch_cache(domain_name, CACHE_TYPE_GROUP, sam_entries,
                       num_entries);
}

static BOOL fetch_cache_entry(char *domain, char *name, void *buf, int len)
{
    TDB_DATA key, data;
    fstring keystr;
    
    /* Create key for lookup */
    
    slprintf(keystr, sizeof(keystr), "%s/%s", domain, name);
    
    key.dptr = keystr;
    key.dsize = strlen(keystr) + 1;
    
    /* Look up cache entry */
    
    data = tdb_fetch(cache_tdb, key);
    
    if (data.dptr) {
        
        DEBUG(4, ("returning cached entry for %s/%s\n", domain, name));
    
        /* Copy found entry into buffer */
        
        memcpy((char *)buf, data.dptr, len < data.dsize ? len : data.dsize);
                free(data.dptr);
        
        return True;
    }
    
    return False;
}

/* Fetch an individual user cache entry */

BOOL winbindd_fetch_user_cache_entry(char *domain, char *user, 
                                     struct winbindd_pw *pw)
{
    if (lp_winbind_cache_time() == 0) return False;

    if (!cache_time_expired(domain, CACHE_TYPE_USER, user)) {
        return fetch_cache_entry(domain, user, pw, 
                                 sizeof(struct winbindd_pw));
    }
    return False;
}

/* Fetch an individual uid cache entry */

BOOL winbindd_fetch_uid_cache_entry(char *domain, uid_t uid, 
				    struct winbindd_pw *pw)
{
	fstring uidstr;

        if (lp_winbind_cache_time() == 0) return False;

	slprintf(uidstr, sizeof(uidstr), "#%u", (unsigned)uid);
    
	if (!cache_time_expired(domain, CACHE_TYPE_USER, uidstr)) {
		return fetch_cache_entry(domain, uidstr, pw, 
					 sizeof(struct winbindd_pw));
	}
	return False;
}

/* Fetch an individual group cache entry.  This function differs from the
   user cache code as we need to store the group membership data. */

BOOL winbindd_fetch_group_cache_entry(char *domain, char *group, 
                                      struct winbindd_gr *gr,
                                      void **extra_data, int *extra_data_len)
{
        TDB_DATA key, data;
        fstring keystr;

        if (lp_winbind_cache_time() == 0) return False;

	if (cache_time_expired(domain, CACHE_TYPE_GROUP, group)) return False;

        /* Fetch group data */
        fetch_cache_entry(domain, group, gr, 
                          sizeof(struct winbindd_gr));
	
        /* Fetch extra data */
        slprintf(keystr, sizeof(keystr), "%s/%s DATA", domain, group);

        key.dptr = keystr;
        key.dsize = strlen(keystr) + 1;

        data = tdb_fetch(cache_tdb, key);

        if (!data.dptr) return False;

	/* Extra data freed when data has been sent */
	if (extra_data) *extra_data = data.dptr;
	if (extra_data_len) *extra_data_len = data.dsize;
	
	return True;
}


/* Fetch an individual gid cache entry.  This function differs from the
   user cache code as we need to store the group membership data. */

BOOL winbindd_fetch_gid_cache_entry(char *domain, gid_t gid,
				    struct winbindd_gr *gr,
				    void **extra_data, int *extra_data_len)
{
        TDB_DATA key, data;
        fstring keystr;
	fstring gidstr;
	slprintf(gidstr, sizeof(gidstr), "#%u", (unsigned)gid);
	
        if (lp_winbind_cache_time() == 0) return False;

	if (cache_time_expired(domain, CACHE_TYPE_GROUP, gidstr)) return False;

        /* Fetch group data */
        fetch_cache_entry(domain, gidstr, gr, 
                          sizeof(struct winbindd_gr));

        /* Fetch extra data */
        slprintf(keystr, sizeof(keystr), "%s/%s DATA", domain, gidstr);

        key.dptr = keystr;
        key.dsize = strlen(keystr) + 1;

        data = tdb_fetch(cache_tdb, key);

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
