/* 
   Unix SMB/CIFS implementation.

   Winbind cache backend functions

   Copyright (C) Andrew Tridgell 2001
   
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

struct winbind_cache {
	struct winbindd_methods *backend;
	TDB_CONTEXT *tdb;
};

struct cache_entry {
	NTSTATUS status;
	uint32 sequence_number;
	uint8 *data;
	uint32 len, ofs;
};

#define WINBINDD_MAX_CACHE_SIZE (50*1024*1024)

static struct winbind_cache *wcache;

/* flush the cache */
void wcache_flush_cache(void)
{
	extern BOOL opt_nocache;

	if (!wcache) return;
	if (wcache->tdb) {
		tdb_close(wcache->tdb);
		wcache->tdb = NULL;
	}
	if (opt_nocache) return;

	wcache->tdb = tdb_open_log(lock_path("winbindd_cache.tdb"), 5000, 
				   TDB_DEFAULT, O_RDWR | O_CREAT | O_TRUNC, 0600);

	if (!wcache->tdb) {
		DEBUG(0,("Failed to open winbindd_cache.tdb!\n"));
	}
}

void winbindd_check_cache_size(time_t t)
{
	static time_t last_check_time;
	struct stat st;

	if (last_check_time == (time_t)0)
		last_check_time = t;

	if (t - last_check_time < 60 && t - last_check_time > 0)
		return;

	if (wcache == NULL || wcache->tdb == NULL) {
		DEBUG(0, ("Unable to check size of tdb cache - cache not open !\n"));
		return;
	}

	if (fstat(wcache->tdb->fd, &st) == -1) {
		DEBUG(0, ("Unable to check size of tdb cache %s!\n", strerror(errno) ));
		return;
	}

	if (st.st_size > WINBINDD_MAX_CACHE_SIZE) {
		DEBUG(10,("flushing cache due to size (%lu) > (%lu)\n",
			(unsigned long)st.st_size,
			(unsigned long)WINBINDD_MAX_CACHE_SIZE));
		wcache_flush_cache();
	}
}

/* get the winbind_cache structure */
static struct winbind_cache *get_cache(struct winbindd_domain *domain)
{
	extern struct winbindd_methods msrpc_methods;
	struct winbind_cache *ret = wcache;

	if (ret) return ret;
	
	ret = smb_xmalloc(sizeof(*ret));
	ZERO_STRUCTP(ret);
	switch (lp_security()) {
#ifdef HAVE_ADS
	case SEC_ADS: {
		extern struct winbindd_methods ads_methods;
		ret->backend = &ads_methods;
		break;
	}
#endif
	default:
		ret->backend = &msrpc_methods;
	}

	wcache = ret;
	wcache_flush_cache();

	return ret;
}

/*
  free a centry structure
*/
static void centry_free(struct cache_entry *centry)
{
	if (!centry) return;
	SAFE_FREE(centry->data);
	free(centry);
}


/*
  pull a uint32 from a cache entry 
*/
static uint32 centry_uint32(struct cache_entry *centry)
{
	uint32 ret;
	if (centry->len - centry->ofs < 4) {
		DEBUG(0,("centry corruption? needed 4 bytes, have %d\n", 
			 centry->len - centry->ofs));
		smb_panic("centry_uint32");
	}
	ret = IVAL(centry->data, centry->ofs);
	centry->ofs += 4;
	return ret;
}

/*
  pull a uint8 from a cache entry 
*/
static uint8 centry_uint8(struct cache_entry *centry)
{
	uint8 ret;
	if (centry->len - centry->ofs < 1) {
		DEBUG(0,("centry corruption? needed 1 bytes, have %d\n", 
			 centry->len - centry->ofs));
		smb_panic("centry_uint32");
	}
	ret = CVAL(centry->data, centry->ofs);
	centry->ofs += 1;
	return ret;
}

/* pull a string from a cache entry, using the supplied
   talloc context 
*/
static char *centry_string(struct cache_entry *centry, TALLOC_CTX *mem_ctx)
{
	uint32 len;
	char *ret;

	len = centry_uint8(centry);

	if (len == 0xFF) {
		/* a deliberate NULL string */
		return NULL;
	}

	if (centry->len - centry->ofs < len) {
		DEBUG(0,("centry corruption? needed %d bytes, have %d\n", 
			 len, centry->len - centry->ofs));
		smb_panic("centry_string");
	}

	ret = talloc(mem_ctx, len+1);
	if (!ret) {
		smb_panic("centry_string out of memory\n");
	}
	memcpy(ret,centry->data + centry->ofs, len);
	ret[len] = 0;
	centry->ofs += len;
	return ret;
}

/* the server is considered down if it can't give us a sequence number */
static BOOL wcache_server_down(struct winbindd_domain *domain)
{
	if (!wcache->tdb) return False;
	return (domain->sequence_number == DOM_SEQUENCE_NONE);
}


/*
  refresh the domain sequence number. If force is True
  then always refresh it, no matter how recently we fetched it
*/
static void refresh_sequence_number(struct winbindd_domain *domain, BOOL force)
{
	NTSTATUS status;
	unsigned time_diff;

	time_diff = time(NULL) - domain->last_seq_check;

	/* see if we have to refetch the domain sequence number */
	if (!force && (time_diff < lp_winbind_cache_time())) {
		return;
	}

	status = wcache->backend->sequence_number(domain, &domain->sequence_number);

	if (!NT_STATUS_IS_OK(status))
		DEBUG(10, ("refresh_sequence_number: backend returned 0x%08x\n", 
			   NT_STATUS_V(status)));
	
	/* Convert a NT_STATUS_UNSUCCESSFUL error to a
	   NT_STATUS_DOMAIN_CONTROLLER_NOT_FOUND.  The former is
	   returned when we can't make an initial connection to
	   the domain controller.  The latter is returned when we
	   can't fetch the sequence number on an already open
	   connection. */

	if (NT_STATUS_EQUAL(status, NT_STATUS_UNSUCCESSFUL))
		status = NT_STATUS_DOMAIN_CONTROLLER_NOT_FOUND;

	domain->last_status = status;

	if (!NT_STATUS_IS_OK(status))
		domain->sequence_number = DOM_SEQUENCE_NONE;

	domain->last_seq_check = time(NULL);

	DEBUG(10, ("refresh_sequence_number: seq number is now %d\n", 
		   domain->sequence_number));
}

/*
  decide if a cache entry has expired
*/
static BOOL centry_expired(struct winbindd_domain *domain, struct cache_entry *centry)
{
	/* if the server is OK and our cache entry came from when it was down then
	   the entry is invalid */
	if (domain->sequence_number != DOM_SEQUENCE_NONE && 
	    centry->sequence_number == DOM_SEQUENCE_NONE) {
		return True;
	}

	/* if the server is down or the cache entry is not older than the
	   current sequence number then it is OK */
	if (wcache_server_down(domain) || 
	    centry->sequence_number == domain->sequence_number) {
		return False;
	}

	/* it's expired */
	return True;
}

/*
  fetch an entry from the cache, with a varargs key. auto-fetch the sequence
  number and return status
*/
static struct cache_entry *wcache_fetch(struct winbind_cache *cache, 
					struct winbindd_domain *domain,
					const char *format, ...)
{
	va_list ap;
	char *kstr;
	TDB_DATA data;
	struct cache_entry *centry;
	TDB_DATA key;

	refresh_sequence_number(domain, False);

	va_start(ap, format);
	smb_xvasprintf(&kstr, format, ap);
	va_end(ap);
	
	key.dptr = kstr;
	key.dsize = strlen(kstr);
	data = tdb_fetch(wcache->tdb, key);
	free(kstr);
	if (!data.dptr) {
		/* a cache miss */
		return NULL;
	}

	centry = smb_xmalloc(sizeof(*centry));
	centry->data = (uchar *)data.dptr;
	centry->len = data.dsize;
	centry->ofs = 0;

	if (centry->len < 8) {
		/* huh? corrupt cache? */
		centry_free(centry);
		return NULL;
	}
	
	centry->status = NT_STATUS(centry_uint32(centry));
	centry->sequence_number = centry_uint32(centry);

	if (centry_expired(domain, centry)) {
		centry_free(centry);
		return NULL;
	}

	return centry;
}

/*
  make sure we have at least len bytes available in a centry 
*/
static void centry_expand(struct cache_entry *centry, uint32 len)
{
	uint8 *p;
	if (centry->len - centry->ofs >= len) return;
	centry->len *= 2;
	p = realloc(centry->data, centry->len);
	if (!p) {
		DEBUG(0,("out of memory: needed %d bytes in centry_expand\n", centry->len));
		smb_panic("out of memory in centry_expand");
	}
	centry->data = p;
}

/*
  push a uint32 into a centry 
*/
static void centry_put_uint32(struct cache_entry *centry, uint32 v)
{
	centry_expand(centry, 4);
	SIVAL(centry->data, centry->ofs, v);
	centry->ofs += 4;
}

/*
  push a uint8 into a centry 
*/
static void centry_put_uint8(struct cache_entry *centry, uint8 v)
{
	centry_expand(centry, 1);
	SCVAL(centry->data, centry->ofs, v);
	centry->ofs += 1;
}

/* 
   push a string into a centry 
 */
static void centry_put_string(struct cache_entry *centry, const char *s)
{
	int len;

	if (!s) {
		/* null strings are marked as len 0xFFFF */
		centry_put_uint8(centry, 0xFF);
		return;
	}

	len = strlen(s);
	/* can't handle more than 254 char strings. Truncating is probably best */
	if (len > 254) len = 254;
	centry_put_uint8(centry, len);
	centry_expand(centry, len);
	memcpy(centry->data + centry->ofs, s, len);
	centry->ofs += len;
}

/*
  start a centry for output. When finished, call centry_end()
*/
struct cache_entry *centry_start(struct winbindd_domain *domain, NTSTATUS status)
{
	struct cache_entry *centry;

	if (!wcache->tdb) return NULL;

	centry = smb_xmalloc(sizeof(*centry));

	centry->len = 8192; /* reasonable default */
	centry->data = smb_xmalloc(centry->len);
	centry->ofs = 0;
	centry->sequence_number = domain->sequence_number;
	centry_put_uint32(centry, NT_STATUS_V(status));
	centry_put_uint32(centry, centry->sequence_number);
	return centry;
}

/*
  finish a centry and write it to the tdb
*/
static void centry_end(struct cache_entry *centry, const char *format, ...)
{
	va_list ap;
	char *kstr;
	TDB_DATA key, data;

	va_start(ap, format);
	smb_xvasprintf(&kstr, format, ap);
	va_end(ap);

	key.dptr = kstr;
	key.dsize = strlen(kstr);
	data.dptr = (char *)centry->data;
	data.dsize = centry->ofs;

	tdb_store(wcache->tdb, key, data, TDB_REPLACE);
	free(kstr);
}

/* form a sid from the domain plus rid */
static DOM_SID *form_sid(struct winbindd_domain *domain, uint32 rid)
{
	static DOM_SID sid;
	sid_copy(&sid, &domain->sid);
	sid_append_rid(&sid, rid);
	return &sid;
}

static void wcache_save_name_to_sid(struct winbindd_domain *domain, NTSTATUS status, 
				    const char *name, DOM_SID *sid, enum SID_NAME_USE type)
{
	struct cache_entry *centry;
	uint32 len;
	fstring uname;

	centry = centry_start(domain, status);
	if (!centry) return;
	len = sid_size(sid);
	centry_expand(centry, len);
	centry_put_uint32(centry, type);
	sid_linearize((char *)centry->data + centry->ofs, len, sid);
	centry->ofs += len;
	fstrcpy(uname, name);
	strupper(uname);
	centry_end(centry, "NS/%s/%s", domain->name, uname);
	centry_free(centry);
}

static void wcache_save_sid_to_name(struct winbindd_domain *domain, NTSTATUS status, 
				    DOM_SID *sid, const char *name, enum SID_NAME_USE type, uint32 rid)
{
	struct cache_entry *centry;

	centry = centry_start(domain, status);
	if (!centry) return;
	if (NT_STATUS_IS_OK(status)) {
		centry_put_uint32(centry, type);
		centry_put_string(centry, name);
	}
	centry_end(centry, "SN/%s/%d", domain->name, rid);
	centry_free(centry);
}


static void wcache_save_user(struct winbindd_domain *domain, NTSTATUS status, WINBIND_USERINFO *info)
{
	struct cache_entry *centry;

	centry = centry_start(domain, status);
	if (!centry) return;
	centry_put_string(centry, info->acct_name);
	centry_put_string(centry, info->full_name);
	centry_put_uint32(centry, info->user_rid);
	centry_put_uint32(centry, info->group_rid);
	centry_end(centry, "U/%s/%d", domain->name, info->user_rid);
	centry_free(centry);
}


/* Query display info. This is the basic user list fn */
static NTSTATUS query_user_list(struct winbindd_domain *domain,
				TALLOC_CTX *mem_ctx,
				uint32 *num_entries, 
				WINBIND_USERINFO **info)
{
	struct winbind_cache *cache = get_cache(domain);
	struct cache_entry *centry = NULL;
	NTSTATUS status;
	int i;

	if (!cache->tdb) goto do_query;

	centry = wcache_fetch(cache, domain, "UL/%s", domain->name);
	if (!centry) goto do_query;

	*num_entries = centry_uint32(centry);
	
	if (*num_entries == 0) goto do_cached;

	(*info) = talloc(mem_ctx, sizeof(**info) * (*num_entries));
	if (! (*info)) smb_panic("query_user_list out of memory");
	for (i=0; i<(*num_entries); i++) {
		(*info)[i].acct_name = centry_string(centry, mem_ctx);
		(*info)[i].full_name = centry_string(centry, mem_ctx);
		(*info)[i].user_rid = centry_uint32(centry);
		(*info)[i].group_rid = centry_uint32(centry);
	}

do_cached:	

	/* If we are returning cached data and the domain controller
	   is down then we don't know whether the data is up to date
	   or not.  Return NT_STATUS_MORE_PROCESSING_REQUIRED to
	   indicate this. */

	if (wcache_server_down(domain)) {
		DEBUG(10, ("query_user_list: returning cached user list and server was down\n"));
		status = NT_STATUS_MORE_PROCESSING_REQUIRED;
	} else
		status = centry->status;

	centry_free(centry);
	return status;

do_query:
	*num_entries = 0;
	*info = NULL;

	/* Return status value returned by seq number check */

	if (!NT_STATUS_IS_OK(domain->last_status))
		return domain->last_status;

	status = cache->backend->query_user_list(domain, mem_ctx, num_entries, info);

	/* and save it */
	refresh_sequence_number(domain, True);
	centry = centry_start(domain, status);
	if (!centry) goto skip_save;
	centry_put_uint32(centry, *num_entries);
	for (i=0; i<(*num_entries); i++) {
		centry_put_string(centry, (*info)[i].acct_name);
		centry_put_string(centry, (*info)[i].full_name);
		centry_put_uint32(centry, (*info)[i].user_rid);
		centry_put_uint32(centry, (*info)[i].group_rid);
		if (cache->backend->consistent) {
			/* when the backend is consistent we can pre-prime some mappings */
			wcache_save_name_to_sid(domain, NT_STATUS_OK, 
						(*info)[i].acct_name, 
						form_sid(domain, (*info)[i].user_rid),
						SID_NAME_USER);
			wcache_save_sid_to_name(domain, NT_STATUS_OK, 
						form_sid(domain, (*info)[i].user_rid),
						(*info)[i].acct_name, 
						SID_NAME_USER, (*info)[i].user_rid);
			wcache_save_user(domain, NT_STATUS_OK, &(*info)[i]);
		}
	}	
	centry_end(centry, "UL/%s", domain->name);
	centry_free(centry);

skip_save:
	return status;
}

/* list all domain groups */
static NTSTATUS enum_dom_groups(struct winbindd_domain *domain,
				TALLOC_CTX *mem_ctx,
				uint32 *num_entries, 
				struct acct_info **info)
{
	struct winbind_cache *cache = get_cache(domain);
	struct cache_entry *centry = NULL;
	NTSTATUS status;
	int i;

	if (!cache->tdb) goto do_query;

	centry = wcache_fetch(cache, domain, "GL/%s", domain->name);
	if (!centry) goto do_query;

	*num_entries = centry_uint32(centry);
	
	if (*num_entries == 0) goto do_cached;

	(*info) = talloc(mem_ctx, sizeof(**info) * (*num_entries));
	if (! (*info)) smb_panic("enum_dom_groups out of memory");
	for (i=0; i<(*num_entries); i++) {
		fstrcpy((*info)[i].acct_name, centry_string(centry, mem_ctx));
		fstrcpy((*info)[i].acct_desc, centry_string(centry, mem_ctx));
		(*info)[i].rid = centry_uint32(centry);
	}

do_cached:	

	/* If we are returning cached data and the domain controller
	   is down then we don't know whether the data is up to date
	   or not.  Return NT_STATUS_MORE_PROCESSING_REQUIRED to
	   indicate this. */

	if (wcache_server_down(domain)) {
		DEBUG(10, ("query_user_list: returning cached user list and server was down\n"));
		status = NT_STATUS_MORE_PROCESSING_REQUIRED;
	} else
		status = centry->status;

	centry_free(centry);
	return status;

do_query:
	*num_entries = 0;
	*info = NULL;

	/* Return status value returned by seq number check */

	if (!NT_STATUS_IS_OK(domain->last_status))
		return domain->last_status;

	status = cache->backend->enum_dom_groups(domain, mem_ctx, num_entries, info);

	/* and save it */
	refresh_sequence_number(domain, True);
	centry = centry_start(domain, status);
	if (!centry) goto skip_save;
	centry_put_uint32(centry, *num_entries);
	for (i=0; i<(*num_entries); i++) {
		centry_put_string(centry, (*info)[i].acct_name);
		centry_put_string(centry, (*info)[i].acct_desc);
		centry_put_uint32(centry, (*info)[i].rid);
	}	
	centry_end(centry, "GL/%s", domain->name);
	centry_free(centry);

skip_save:
	return status;
}


/* convert a single name to a sid in a domain */
static NTSTATUS name_to_sid(struct winbindd_domain *domain,
			    const char *name,
			    DOM_SID *sid,
			    enum SID_NAME_USE *type)
{
	struct winbind_cache *cache = get_cache(domain);
	struct cache_entry *centry = NULL;
	NTSTATUS status;
	fstring uname;

	if (!cache->tdb) goto do_query;

	fstrcpy(uname, name);
	strupper(uname);
	centry = wcache_fetch(cache, domain, "NS/%s/%s", domain->name, uname);
	if (!centry) goto do_query;
	*type = centry_uint32(centry);
	sid_parse((char *)centry->data + centry->ofs, centry->len - centry->ofs, sid);

	status = centry->status;
	centry_free(centry);
	return status;

do_query:
	ZERO_STRUCTP(sid);

	/* Return status value returned by seq number check */

	if (!NT_STATUS_IS_OK(domain->last_status))
		return domain->last_status;

	status = cache->backend->name_to_sid(domain, name, sid, type);

	/* and save it */
	wcache_save_name_to_sid(domain, status, name, sid, *type);

	/* We can't save the sid to name mapping as we don't know the
	   correct case of the name without looking it up */

	return status;
}

/* convert a sid to a user or group name. The sid is guaranteed to be in the domain
   given */
static NTSTATUS sid_to_name(struct winbindd_domain *domain,
			    TALLOC_CTX *mem_ctx,
			    DOM_SID *sid,
			    char **name,
			    enum SID_NAME_USE *type)
{
	struct winbind_cache *cache = get_cache(domain);
	struct cache_entry *centry = NULL;
	NTSTATUS status;
	uint32 rid = 0;

	sid_peek_rid(sid, &rid);

	if (!cache->tdb) goto do_query;

	centry = wcache_fetch(cache, domain, "SN/%s/%d", domain->name, rid);
	if (!centry) goto do_query;
	if (NT_STATUS_IS_OK(centry->status)) {
		*type = centry_uint32(centry);
		*name = centry_string(centry, mem_ctx);
	}
	status = centry->status;
	centry_free(centry);
	return status;

do_query:
	*name = NULL;

	/* Return status value returned by seq number check */

	if (!NT_STATUS_IS_OK(domain->last_status))
		return domain->last_status;

	status = cache->backend->sid_to_name(domain, mem_ctx, sid, name, type);

	/* and save it */
	refresh_sequence_number(domain, True);
	wcache_save_sid_to_name(domain, status, sid, *name, *type, rid);
	wcache_save_name_to_sid(domain, status, *name, sid, *type);

	return status;
}


/* Lookup user information from a rid */
static NTSTATUS query_user(struct winbindd_domain *domain, 
			   TALLOC_CTX *mem_ctx, 
			   uint32 user_rid, 
			   WINBIND_USERINFO *info)
{
	struct winbind_cache *cache = get_cache(domain);
	struct cache_entry *centry = NULL;
	NTSTATUS status;

	if (!cache->tdb) goto do_query;

	centry = wcache_fetch(cache, domain, "U/%s/%d", domain->name, user_rid);
	if (!centry) goto do_query;

	info->acct_name = centry_string(centry, mem_ctx);
	info->full_name = centry_string(centry, mem_ctx);
	info->user_rid = centry_uint32(centry);
	info->group_rid = centry_uint32(centry);
	status = centry->status;
	centry_free(centry);
	return status;

do_query:
	ZERO_STRUCTP(info);

	/* Return status value returned by seq number check */

	if (!NT_STATUS_IS_OK(domain->last_status))
		return domain->last_status;

	status = cache->backend->query_user(domain, mem_ctx, user_rid, info);

	/* and save it */
	refresh_sequence_number(domain, True);
	wcache_save_user(domain, status, info);

	return status;
}


/* Lookup groups a user is a member of. */
static NTSTATUS lookup_usergroups(struct winbindd_domain *domain,
				  TALLOC_CTX *mem_ctx,
				  uint32 user_rid, 
				  uint32 *num_groups, uint32 **user_gids)
{
	struct winbind_cache *cache = get_cache(domain);
	struct cache_entry *centry = NULL;
	NTSTATUS status;
	int i;

	if (!cache->tdb) goto do_query;

	centry = wcache_fetch(cache, domain, "UG/%s/%d", domain->name, user_rid);
	if (!centry) goto do_query;

	*num_groups = centry_uint32(centry);
	
	if (*num_groups == 0) goto do_cached;

	(*user_gids) = talloc(mem_ctx, sizeof(**user_gids) * (*num_groups));
	if (! (*user_gids)) smb_panic("lookup_usergroups out of memory");
	for (i=0; i<(*num_groups); i++) {
		(*user_gids)[i] = centry_uint32(centry);
	}

do_cached:	
	status = centry->status;
	centry_free(centry);
	return status;

do_query:
	(*num_groups) = 0;
	(*user_gids) = NULL;

	/* Return status value returned by seq number check */

	if (!NT_STATUS_IS_OK(domain->last_status))
		return domain->last_status;

	status = cache->backend->lookup_usergroups(domain, mem_ctx, user_rid, num_groups, user_gids);

	/* and save it */
	refresh_sequence_number(domain, True);
	centry = centry_start(domain, status);
	if (!centry) goto skip_save;
	centry_put_uint32(centry, *num_groups);
	for (i=0; i<(*num_groups); i++) {
		centry_put_uint32(centry, (*user_gids)[i]);
	}	
	centry_end(centry, "UG/%s/%d", domain->name, user_rid);
	centry_free(centry);

skip_save:
	return status;
}


static NTSTATUS lookup_groupmem(struct winbindd_domain *domain,
				TALLOC_CTX *mem_ctx,
				uint32 group_rid, uint32 *num_names, 
				uint32 **rid_mem, char ***names, 
				uint32 **name_types)
{
	struct winbind_cache *cache = get_cache(domain);
	struct cache_entry *centry = NULL;
	NTSTATUS status;
	int i;

	if (!cache->tdb) goto do_query;

	centry = wcache_fetch(cache, domain, "GM/%s/%d", domain->name, group_rid);
	if (!centry) goto do_query;

	*num_names = centry_uint32(centry);
	
	if (*num_names == 0) goto do_cached;

	(*rid_mem) = talloc(mem_ctx, sizeof(**rid_mem) * (*num_names));
	(*names) = talloc(mem_ctx, sizeof(**names) * (*num_names));
	(*name_types) = talloc(mem_ctx, sizeof(**name_types) * (*num_names));

	if (! (*rid_mem) || ! (*names) || ! (*name_types)) {
		smb_panic("lookup_groupmem out of memory");
	}

	for (i=0; i<(*num_names); i++) {
		(*rid_mem)[i] = centry_uint32(centry);
		(*names)[i] = centry_string(centry, mem_ctx);
		(*name_types)[i] = centry_uint32(centry);
	}

do_cached:	
	status = centry->status;
	centry_free(centry);
	return status;

do_query:
	(*num_names) = 0;
	(*rid_mem) = NULL;
	(*names) = NULL;
	(*name_types) = NULL;
	
	/* Return status value returned by seq number check */

	if (!NT_STATUS_IS_OK(domain->last_status))
		return domain->last_status;

	status = cache->backend->lookup_groupmem(domain, mem_ctx, group_rid, num_names, 
						 rid_mem, names, name_types);

	/* and save it */
	refresh_sequence_number(domain, True);
	centry = centry_start(domain, status);
	if (!centry) goto skip_save;
	centry_put_uint32(centry, *num_names);
	for (i=0; i<(*num_names); i++) {
		centry_put_uint32(centry, (*rid_mem)[i]);
		centry_put_string(centry, (*names)[i]);
		centry_put_uint32(centry, (*name_types)[i]);
	}	
	centry_end(centry, "GM/%s/%d", domain->name, group_rid);
	centry_free(centry);

skip_save:
	return status;
}

/* find the sequence number for a domain */
static NTSTATUS sequence_number(struct winbindd_domain *domain, uint32 *seq)
{
	refresh_sequence_number(domain, False);

	*seq = domain->sequence_number;

	return NT_STATUS_OK;
}

/* enumerate trusted domains */
static NTSTATUS trusted_domains(struct winbindd_domain *domain,
				TALLOC_CTX *mem_ctx,
				uint32 *num_domains,
				char ***names,
				DOM_SID **dom_sids)
{
	struct winbind_cache *cache = get_cache(domain);

	/* we don't cache this call */
	return cache->backend->trusted_domains(domain, mem_ctx, num_domains, 
					       names, dom_sids);
}

/* find the domain sid */
static NTSTATUS domain_sid(struct winbindd_domain *domain, DOM_SID *sid)
{
	struct winbind_cache *cache = get_cache(domain);

	/* we don't cache this call */
	return cache->backend->domain_sid(domain, sid);
}

/* the ADS backend methods are exposed via this structure */
struct winbindd_methods cache_methods = {
	True,
	query_user_list,
	enum_dom_groups,
	name_to_sid,
	sid_to_name,
	query_user,
	lookup_usergroups,
	lookup_groupmem,
	sequence_number,
	trusted_domains,
	domain_sid
};
