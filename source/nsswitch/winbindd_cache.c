/* 
   Unix SMB/CIFS implementation.

   Winbind cache backend functions

   Copyright (C) Andrew Tridgell 2001
   Copyright (C) Gerald Carter   2003
   
   
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
#include "winbindd.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_WINBIND

struct winbind_cache {
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

	if (!wcache)
		return;
	if (wcache->tdb) {
		tdb_close(wcache->tdb);
		wcache->tdb = NULL;
	}
	if (opt_nocache)
		return;

	wcache->tdb = tdb_open_log(lock_path("winbindd_cache.tdb"), 5000, 
				   TDB_CLEAR_IF_FIRST, O_RDWR|O_CREAT, 0600);

	if (!wcache->tdb) {
		DEBUG(0,("Failed to open winbindd_cache.tdb!\n"));
	}
	DEBUG(10,("wcache_flush_cache success\n"));
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
	struct winbind_cache *ret = wcache;

	if (!domain->backend) {
		extern struct winbindd_methods msrpc_methods;
		switch (lp_security()) {
#ifdef HAVE_ADS
		case SEC_ADS: {
			extern struct winbindd_methods ads_methods;
			/* always obey the lp_security parameter for our domain */
			if (domain->primary) {
				domain->backend = &ads_methods;
				break;
			}

			/* only use ADS for native modes at the momment.
			   The problem is the correct detection of mixed 
			   mode domains from NT4 BDC's    --jerry */
			
			if ( domain->native_mode ) {
				DEBUG(5,("get_cache: Setting ADS methods for domain %s\n",
					domain->name));
				domain->backend = &ads_methods;
				break;
			}

			/* fall through */
		}	
#endif
		default:
			DEBUG(5,("get_cache: Setting MS-RPC methods for domain %s\n",
				domain->name));
			domain->backend = &msrpc_methods;
		}
	}

	if (ret)
		return ret;
	
	ret = smb_xmalloc(sizeof(*ret));
	ZERO_STRUCTP(ret);

	wcache = ret;
	wcache_flush_cache();

	return ret;
}

/*
  free a centry structure
*/
static void centry_free(struct cache_entry *centry)
{
	if (!centry)
		return;
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

/* pull a string from a cache entry, using the supplied
   talloc context 
*/
static DOM_SID *centry_sid(struct cache_entry *centry, TALLOC_CTX *mem_ctx)
{
	DOM_SID *sid;
	char *sid_string;

	sid = talloc(mem_ctx, sizeof(*sid));
	if (!sid)
		return NULL;
	
	sid_string = centry_string(centry, mem_ctx);
	if (!string_to_sid(sid, sid_string)) {
		return NULL;
	}
	return sid;
}

/* the server is considered down if it can't give us a sequence number */
static BOOL wcache_server_down(struct winbindd_domain *domain)
{
	BOOL ret;

	if (!wcache->tdb)
		return False;

	ret = (domain->sequence_number == DOM_SEQUENCE_NONE);

	if (ret)
		DEBUG(10,("wcache_server_down: server for Domain %s down\n", 
			domain->name ));
	return ret;
}

static NTSTATUS fetch_cache_seqnum( struct winbindd_domain *domain, time_t now )
{
	TDB_DATA data;
	fstring key;
	uint32 time_diff;
	
	if (!wcache->tdb) {
		DEBUG(10,("fetch_cache_seqnum: tdb == NULL\n"));
		return NT_STATUS_UNSUCCESSFUL;
	}
		
	fstr_sprintf( key, "SEQNUM/%s", domain->name );
	
	data = tdb_fetch_bystring( wcache->tdb, key );
	if ( !data.dptr || data.dsize!=8 ) {
		DEBUG(10,("fetch_cache_seqnum: invalid data size key [%s]\n", key ));
		return NT_STATUS_UNSUCCESSFUL;
	}
	
	domain->sequence_number = IVAL(data.dptr, 0);
	domain->last_seq_check  = IVAL(data.dptr, 4);
	
	/* have we expired? */
	
	time_diff = now - domain->last_seq_check;
	if ( time_diff > lp_winbind_cache_time() ) {
		DEBUG(10,("fetch_cache_seqnum: timeout [%s][%u @ %u]\n",
			domain->name, domain->sequence_number,
			(uint32)domain->last_seq_check));
		return NT_STATUS_UNSUCCESSFUL;
	}

	DEBUG(10,("fetch_cache_seqnum: success [%s][%u @ %u]\n", 
		domain->name, domain->sequence_number, 
		(uint32)domain->last_seq_check));

	return NT_STATUS_OK;
}

static NTSTATUS store_cache_seqnum( struct winbindd_domain *domain )
{
	TDB_DATA data, key;
	fstring key_str;
	char buf[8];
	
	if (!wcache->tdb) {
		DEBUG(10,("store_cache_seqnum: tdb == NULL\n"));
		return NT_STATUS_UNSUCCESSFUL;
	}
		
	fstr_sprintf( key_str, "SEQNUM/%s", domain->name );
	key.dptr = key_str;
	key.dsize = strlen(key_str)+1;
	
	SIVAL(buf, 0, domain->sequence_number);
	SIVAL(buf, 4, domain->last_seq_check);
	data.dptr = buf;
	data.dsize = 8;
	
	if ( tdb_store( wcache->tdb, key, data, TDB_REPLACE) == -1 ) {
		DEBUG(10,("store_cache_seqnum: tdb_store fail key [%s]\n", key_str ));
		return NT_STATUS_UNSUCCESSFUL;
	}

	DEBUG(10,("store_cache_seqnum: success [%s][%u @ %u]\n", 
		domain->name, domain->sequence_number, 
		(uint32)domain->last_seq_check));
	
	return NT_STATUS_OK;
}

/*
  refresh the domain sequence number. If force is True
  then always refresh it, no matter how recently we fetched it
*/

static void refresh_sequence_number(struct winbindd_domain *domain, BOOL force)
{
	NTSTATUS status;
	unsigned time_diff;
	time_t t = time(NULL);
	unsigned cache_time = lp_winbind_cache_time();

	get_cache( domain );

#if 0	/* JERRY -- disable as the default cache time is now 5 minutes */
	/* trying to reconnect is expensive, don't do it too often */
	if (domain->sequence_number == DOM_SEQUENCE_NONE) {
		cache_time *= 8;
	}
#endif

	time_diff = t - domain->last_seq_check;

	/* see if we have to refetch the domain sequence number */
	if (!force && (time_diff < cache_time)) {
		DEBUG(10, ("refresh_sequence_number: %s time ok\n", domain->name));
		goto done;
	}
	
	/* try to get the sequence number from the tdb cache first */
	/* this will update the timestamp as well */
	
	status = fetch_cache_seqnum( domain, t );
	if ( NT_STATUS_IS_OK(status) )
		goto done;	

	status = domain->backend->sequence_number(domain, &domain->sequence_number);

	if (!NT_STATUS_IS_OK(status)) {
		domain->sequence_number = DOM_SEQUENCE_NONE;
	}
	
	domain->last_status = status;
	domain->last_seq_check = time(NULL);
	
	/* save the new sequence number ni the cache */
	store_cache_seqnum( domain );

done:
	DEBUG(10, ("refresh_sequence_number: %s seq number is now %d\n", 
		   domain->name, domain->sequence_number));

	return;
}

/*
  decide if a cache entry has expired
*/
static BOOL centry_expired(struct winbindd_domain *domain, const char *keystr, struct cache_entry *centry)
{
	/* if the server is OK and our cache entry came from when it was down then
	   the entry is invalid */
	if (domain->sequence_number != DOM_SEQUENCE_NONE && 
	    centry->sequence_number == DOM_SEQUENCE_NONE) {
		DEBUG(10,("centry_expired: Key %s for domain %s invalid sequence.\n",
			keystr, domain->name ));
		return True;
	}

	/* if the server is down or the cache entry is not older than the
	   current sequence number then it is OK */
	if (wcache_server_down(domain) || 
	    centry->sequence_number == domain->sequence_number) {
		DEBUG(10,("centry_expired: Key %s for domain %s is good.\n",
			keystr, domain->name ));
		return False;
	}

	DEBUG(10,("centry_expired: Key %s for domain %s expired\n",
		keystr, domain->name ));

	/* it's expired */
	return True;
}

/*
  fetch an entry from the cache, with a varargs key. auto-fetch the sequence
  number and return status
*/
static struct cache_entry *wcache_fetch(struct winbind_cache *cache, 
					struct winbindd_domain *domain,
					const char *format, ...) PRINTF_ATTRIBUTE(3,4);
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
	if (!data.dptr) {
		/* a cache miss */
		free(kstr);
		return NULL;
	}

	centry = smb_xmalloc(sizeof(*centry));
	centry->data = (unsigned char *)data.dptr;
	centry->len = data.dsize;
	centry->ofs = 0;

	if (centry->len < 8) {
		/* huh? corrupt cache? */
		DEBUG(10,("wcache_fetch: Corrupt cache for key %s domain %s (len < 8) ?\n",
			kstr, domain->name ));
		centry_free(centry);
		free(kstr);
		return NULL;
	}
	
	centry->status = NT_STATUS(centry_uint32(centry));
	centry->sequence_number = centry_uint32(centry);

	if (centry_expired(domain, kstr, centry)) {
		extern BOOL opt_dual_daemon;

		DEBUG(10,("wcache_fetch: entry %s expired for domain %s\n",
			 kstr, domain->name ));

		if (opt_dual_daemon) {
			extern BOOL background_process;
			background_process = True;
			DEBUG(10,("wcache_fetch: background processing expired entry %s for domain %s\n",
				 kstr, domain->name ));
		} else {
			centry_free(centry);
			free(kstr);
			return NULL;
		}
	}

	DEBUG(10,("wcache_fetch: returning entry %s for domain %s\n",
		 kstr, domain->name ));

	free(kstr);
	return centry;
}

/*
  make sure we have at least len bytes available in a centry 
*/
static void centry_expand(struct cache_entry *centry, uint32 len)
{
	uint8 *p;
	if (centry->len - centry->ofs >= len)
		return;
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
	if (len > 254)
		len = 254;
	centry_put_uint8(centry, len);
	centry_expand(centry, len);
	memcpy(centry->data + centry->ofs, s, len);
	centry->ofs += len;
}

static void centry_put_sid(struct cache_entry *centry, const DOM_SID *sid) 
{
	fstring sid_string;
	centry_put_string(centry, sid_to_string(sid_string, sid));
}

/*
  start a centry for output. When finished, call centry_end()
*/
struct cache_entry *centry_start(struct winbindd_domain *domain, NTSTATUS status)
{
	struct cache_entry *centry;

	if (!wcache->tdb)
		return NULL;

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
static void centry_end(struct cache_entry *centry, const char *format, ...) PRINTF_ATTRIBUTE(2,3);
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

static void wcache_save_name_to_sid(struct winbindd_domain *domain, 
				    NTSTATUS status, const char *domain_name,
				    const char *name, const DOM_SID *sid, 
				    enum SID_NAME_USE type)
{
	struct cache_entry *centry;
	fstring uname;
	fstring sid_string;

	centry = centry_start(domain, status);
	if (!centry)
		return;
	centry_put_uint32(centry, type);
	centry_put_sid(centry, sid);
	fstrcpy(uname, name);
	strupper_m(uname);
	centry_end(centry, "NS/%s/%s", domain_name, uname);
	DEBUG(10,("wcache_save_name_to_sid: %s -> %s\n", uname, sid_string));
	centry_free(centry);
}

static void wcache_save_sid_to_name(struct winbindd_domain *domain, NTSTATUS status, 
				    const DOM_SID *sid, const char *domain_name, const char *name, enum SID_NAME_USE type)
{
	struct cache_entry *centry;
	fstring sid_string;

	centry = centry_start(domain, status);
	if (!centry)
		return;
	if (NT_STATUS_IS_OK(status)) {
		centry_put_uint32(centry, type);
		centry_put_string(centry, domain_name);
		centry_put_string(centry, name);
	}
	centry_end(centry, "SN/%s", sid_to_string(sid_string, sid));
	DEBUG(10,("wcache_save_sid_to_name: %s -> %s\n", sid_string, name));
	centry_free(centry);
}


static void wcache_save_user(struct winbindd_domain *domain, NTSTATUS status, WINBIND_USERINFO *info)
{
	struct cache_entry *centry;
	fstring sid_string;

	centry = centry_start(domain, status);
	if (!centry)
		return;
	centry_put_string(centry, info->acct_name);
	centry_put_string(centry, info->full_name);
	centry_put_sid(centry, info->user_sid);
	centry_put_sid(centry, info->group_sid);
	centry_end(centry, "U/%s", sid_to_string(sid_string, info->user_sid));
	DEBUG(10,("wcache_save_user: %s (acct_name %s)\n", sid_string, info->acct_name));
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
	unsigned int i, retry;

	if (!cache->tdb)
		goto do_query;

	centry = wcache_fetch(cache, domain, "UL/%s", domain->name);
	if (!centry)
		goto do_query;

	*num_entries = centry_uint32(centry);
	
	if (*num_entries == 0)
		goto do_cached;

	(*info) = talloc(mem_ctx, sizeof(**info) * (*num_entries));
	if (! (*info))
		smb_panic("query_user_list out of memory");
	for (i=0; i<(*num_entries); i++) {
		(*info)[i].acct_name = centry_string(centry, mem_ctx);
		(*info)[i].full_name = centry_string(centry, mem_ctx);
		(*info)[i].user_sid = centry_sid(centry, mem_ctx);
		(*info)[i].group_sid = centry_sid(centry, mem_ctx);
	}

do_cached:	
	status = centry->status;

	DEBUG(10,("query_user_list: [Cached] - cached list for domain %s status %s\n",
		domain->name, get_friendly_nt_error_msg(status) ));

	centry_free(centry);
	return status;

do_query:
	*num_entries = 0;
	*info = NULL;

	/* Return status value returned by seq number check */

	if (!NT_STATUS_IS_OK(domain->last_status))
		return domain->last_status;

	/* Put the query_user_list() in a retry loop.  There appears to be
	 * some bug either with Windows 2000 or Samba's handling of large
	 * rpc replies.  This manifests itself as sudden disconnection
	 * at a random point in the enumeration of a large (60k) user list.
	 * The retry loop simply tries the operation again. )-:  It's not
	 * pretty but an acceptable workaround until we work out what the
	 * real problem is. */

	retry = 0;
	do {

		DEBUG(10,("query_user_list: [Cached] - doing backend query for list for domain %s\n",
			domain->name ));

		status = domain->backend->query_user_list(domain, mem_ctx, num_entries, info);
		if (!NT_STATUS_IS_OK(status))
			DEBUG(3, ("query_user_list: returned 0x%08x, retrying\n", NT_STATUS_V(status)));
			if (NT_STATUS_V(status) == NT_STATUS_V(NT_STATUS_UNSUCCESSFUL)) {
				DEBUG(3, ("query_user_list: flushing connection cache\n"));
				winbindd_cm_flush();
			}

	} while (NT_STATUS_V(status) == NT_STATUS_V(NT_STATUS_UNSUCCESSFUL) && 
		 (retry++ < 5));

	/* and save it */
	refresh_sequence_number(domain, False);
	centry = centry_start(domain, status);
	if (!centry)
		goto skip_save;
	centry_put_uint32(centry, *num_entries);
	for (i=0; i<(*num_entries); i++) {
		centry_put_string(centry, (*info)[i].acct_name);
		centry_put_string(centry, (*info)[i].full_name);
		centry_put_sid(centry, (*info)[i].user_sid);
		centry_put_sid(centry, (*info)[i].group_sid);
		if (domain->backend->consistent) {
			/* when the backend is consistent we can pre-prime some mappings */
			wcache_save_name_to_sid(domain, NT_STATUS_OK, 
						(*info)[i].acct_name, 
						domain->name,
						(*info)[i].user_sid,
						SID_NAME_USER);
			wcache_save_sid_to_name(domain, NT_STATUS_OK, 
						(*info)[i].user_sid,
						domain->name,
						(*info)[i].acct_name, 
						SID_NAME_USER);
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
	unsigned int i;

	if (!cache->tdb)
		goto do_query;

	centry = wcache_fetch(cache, domain, "GL/%s/domain", domain->name);
	if (!centry)
		goto do_query;

	*num_entries = centry_uint32(centry);
	
	if (*num_entries == 0)
		goto do_cached;

	(*info) = talloc(mem_ctx, sizeof(**info) * (*num_entries));
	if (! (*info))
		smb_panic("enum_dom_groups out of memory");
	for (i=0; i<(*num_entries); i++) {
		fstrcpy((*info)[i].acct_name, centry_string(centry, mem_ctx));
		fstrcpy((*info)[i].acct_desc, centry_string(centry, mem_ctx));
		(*info)[i].rid = centry_uint32(centry);
	}

do_cached:	
	status = centry->status;

	DEBUG(10,("enum_dom_groups: [Cached] - cached list for domain %s status %s\n",
		domain->name, get_friendly_nt_error_msg(status) ));

	centry_free(centry);
	return status;

do_query:
	*num_entries = 0;
	*info = NULL;

	/* Return status value returned by seq number check */

	if (!NT_STATUS_IS_OK(domain->last_status))
		return domain->last_status;

	DEBUG(10,("enum_dom_groups: [Cached] - doing backend query for list for domain %s\n",
		domain->name ));

	status = domain->backend->enum_dom_groups(domain, mem_ctx, num_entries, info);

	/* and save it */
	refresh_sequence_number(domain, False);
	centry = centry_start(domain, status);
	if (!centry)
		goto skip_save;
	centry_put_uint32(centry, *num_entries);
	for (i=0; i<(*num_entries); i++) {
		centry_put_string(centry, (*info)[i].acct_name);
		centry_put_string(centry, (*info)[i].acct_desc);
		centry_put_uint32(centry, (*info)[i].rid);
	}	
	centry_end(centry, "GL/%s/domain", domain->name);
	centry_free(centry);

skip_save:
	return status;
}

/* list all domain groups */
static NTSTATUS enum_local_groups(struct winbindd_domain *domain,
				TALLOC_CTX *mem_ctx,
				uint32 *num_entries, 
				struct acct_info **info)
{
	struct winbind_cache *cache = get_cache(domain);
	struct cache_entry *centry = NULL;
	NTSTATUS status;
	unsigned int i;

	if (!cache->tdb)
		goto do_query;

	centry = wcache_fetch(cache, domain, "GL/%s/local", domain->name);
	if (!centry)
		goto do_query;

	*num_entries = centry_uint32(centry);
	
	if (*num_entries == 0)
		goto do_cached;

	(*info) = talloc(mem_ctx, sizeof(**info) * (*num_entries));
	if (! (*info))
		smb_panic("enum_dom_groups out of memory");
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
		DEBUG(10, ("enum_local_groups: returning cached user list and server was down\n"));
		status = NT_STATUS_MORE_PROCESSING_REQUIRED;
	} else
		status = centry->status;

	DEBUG(10,("enum_local_groups: [Cached] - cached list for domain %s status %s\n",
		domain->name, get_friendly_nt_error_msg(status) ));

	centry_free(centry);
	return status;

do_query:
	*num_entries = 0;
	*info = NULL;

	/* Return status value returned by seq number check */

	if (!NT_STATUS_IS_OK(domain->last_status))
		return domain->last_status;

	DEBUG(10,("enum_local_groups: [Cached] - doing backend query for list for domain %s\n",
		domain->name ));

	status = domain->backend->enum_local_groups(domain, mem_ctx, num_entries, info);

	/* and save it */
	refresh_sequence_number(domain, False);
	centry = centry_start(domain, status);
	if (!centry)
		goto skip_save;
	centry_put_uint32(centry, *num_entries);
	for (i=0; i<(*num_entries); i++) {
		centry_put_string(centry, (*info)[i].acct_name);
		centry_put_string(centry, (*info)[i].acct_desc);
		centry_put_uint32(centry, (*info)[i].rid);
	}
	centry_end(centry, "GL/%s/local", domain->name);
	centry_free(centry);

skip_save:
	return status;
}

/* convert a single name to a sid in a domain */
static NTSTATUS name_to_sid(struct winbindd_domain *domain,
			    TALLOC_CTX *mem_ctx,
			    const char *domain_name,
			    const char *name,
			    DOM_SID *sid,
			    enum SID_NAME_USE *type)
{
	struct winbind_cache *cache = get_cache(domain);
	struct cache_entry *centry = NULL;
	NTSTATUS status;
	fstring uname;
	DOM_SID *sid2;

	if (!cache->tdb)
		goto do_query;

	fstrcpy(uname, name);
	strupper_m(uname);
	centry = wcache_fetch(cache, domain, "NS/%s/%s", domain_name, uname);
	if (!centry)
		goto do_query;
	*type = (enum SID_NAME_USE)centry_uint32(centry);
	sid2 = centry_sid(centry, mem_ctx);
	if (!sid2) {
		ZERO_STRUCTP(sid);
	} else {
		sid_copy(sid, sid2);
	}

	status = centry->status;

	DEBUG(10,("name_to_sid: [Cached] - cached name for domain %s status %s\n",
		domain->name, get_friendly_nt_error_msg(status) ));

	centry_free(centry);
	return status;

do_query:
	ZERO_STRUCTP(sid);

	/* If the seq number check indicated that there is a problem
	 * with this DC, then return that status... except for
	 * access_denied.  This is special because the dc may be in
	 * "restrict anonymous = 1" mode, in which case it will deny
	 * most unauthenticated operations, but *will* allow the LSA
	 * name-to-sid that we try as a fallback. */

	if (!(NT_STATUS_IS_OK(domain->last_status)
	      || NT_STATUS_EQUAL(domain->last_status, NT_STATUS_ACCESS_DENIED)))
		return domain->last_status;

	DEBUG(10,("name_to_sid: [Cached] - doing backend query for name for domain %s\n",
		domain->name ));

	status = domain->backend->name_to_sid(domain, mem_ctx, domain_name, name, sid, type);

	/* and save it */
	wcache_save_name_to_sid(domain, status, domain_name, name, sid, *type);

	/* We can't save the sid to name mapping as we don't know the
	   correct case of the name without looking it up */

	return status;
}

/* convert a sid to a user or group name. The sid is guaranteed to be in the domain
   given */
static NTSTATUS sid_to_name(struct winbindd_domain *domain,
			    TALLOC_CTX *mem_ctx,
			    const DOM_SID *sid,
			    char **domain_name,
			    char **name,
			    enum SID_NAME_USE *type)
{
	struct winbind_cache *cache = get_cache(domain);
	struct cache_entry *centry = NULL;
	NTSTATUS status;
	fstring sid_string;

	if (!cache->tdb)
		goto do_query;

	centry = wcache_fetch(cache, domain, "SN/%s", sid_to_string(sid_string, sid));
	if (!centry)
		goto do_query;
	if (NT_STATUS_IS_OK(centry->status)) {
		*type = (enum SID_NAME_USE)centry_uint32(centry);
		*domain_name = centry_string(centry, mem_ctx);
		*name = centry_string(centry, mem_ctx);
	}
	status = centry->status;

	DEBUG(10,("sid_to_name: [Cached] - cached name for domain %s status %s\n",
		domain->name, get_friendly_nt_error_msg(status) ));

	centry_free(centry);
	return status;

do_query:
	*name = NULL;
	*domain_name = NULL;

	/* If the seq number check indicated that there is a problem
	 * with this DC, then return that status... except for
	 * access_denied.  This is special because the dc may be in
	 * "restrict anonymous = 1" mode, in which case it will deny
	 * most unauthenticated operations, but *will* allow the LSA
	 * sid-to-name that we try as a fallback. */

	if (!(NT_STATUS_IS_OK(domain->last_status)
	      || NT_STATUS_EQUAL(domain->last_status, NT_STATUS_ACCESS_DENIED)))
		return domain->last_status;

	DEBUG(10,("sid_to_name: [Cached] - doing backend query for name for domain %s\n",
		domain->name ));

	status = domain->backend->sid_to_name(domain, mem_ctx, sid, domain_name, name, type);

	/* and save it */
	refresh_sequence_number(domain, False);
	wcache_save_sid_to_name(domain, status, sid, *domain_name, *name, *type);
	wcache_save_name_to_sid(domain, status, *domain_name, *name, sid, *type);

	return status;
}


/* Lookup user information from a rid */
static NTSTATUS query_user(struct winbindd_domain *domain, 
			   TALLOC_CTX *mem_ctx, 
			   const DOM_SID *user_sid, 
			   WINBIND_USERINFO *info)
{
	struct winbind_cache *cache = get_cache(domain);
	struct cache_entry *centry = NULL;
	NTSTATUS status;

	if (!cache->tdb)
		goto do_query;

	centry = wcache_fetch(cache, domain, "U/%s", sid_string_static(user_sid));
	
	/* If we have an access denied cache entry and a cached info3 in the
           samlogon cache then do a query.  This will force the rpc back end
           to return the info3 data. */

	if (NT_STATUS_V(domain->last_status) == NT_STATUS_V(NT_STATUS_ACCESS_DENIED) &&
	    netsamlogon_cache_have(user_sid)) {
		DEBUG(10, ("query_user: cached access denied and have cached info3\n"));
		domain->last_status = NT_STATUS_OK;
		centry_free(centry);
		goto do_query;
	}
	
	if (!centry)
		goto do_query;

	info->acct_name = centry_string(centry, mem_ctx);
	info->full_name = centry_string(centry, mem_ctx);
	info->user_sid = centry_sid(centry, mem_ctx);
	info->group_sid = centry_sid(centry, mem_ctx);
	status = centry->status;

	DEBUG(10,("query_user: [Cached] - cached info for domain %s status %s\n",
		domain->name, get_friendly_nt_error_msg(status) ));

	centry_free(centry);
	return status;

do_query:
	ZERO_STRUCTP(info);

	/* Return status value returned by seq number check */

	if (!NT_STATUS_IS_OK(domain->last_status))
		return domain->last_status;
	
	DEBUG(10,("sid_to_name: [Cached] - doing backend query for info for domain %s\n",
		domain->name ));

	status = domain->backend->query_user(domain, mem_ctx, user_sid, info);

	/* and save it */
	refresh_sequence_number(domain, False);
	wcache_save_user(domain, status, info);

	return status;
}


/* Lookup groups a user is a member of. */
static NTSTATUS lookup_usergroups(struct winbindd_domain *domain,
				  TALLOC_CTX *mem_ctx,
				  const DOM_SID *user_sid, 
				  uint32 *num_groups, DOM_SID ***user_gids)
{
	struct winbind_cache *cache = get_cache(domain);
	struct cache_entry *centry = NULL;
	NTSTATUS status;
	unsigned int i;
	fstring sid_string;

	if (!cache->tdb)
		goto do_query;

	centry = wcache_fetch(cache, domain, "UG/%s", sid_to_string(sid_string, user_sid));
	
	/* If we have an access denied cache entry and a cached info3 in the
           samlogon cache then do a query.  This will force the rpc back end
           to return the info3 data. */

	if (NT_STATUS_V(domain->last_status) == NT_STATUS_V(NT_STATUS_ACCESS_DENIED) &&
	    netsamlogon_cache_have(user_sid)) {
		DEBUG(10, ("query_user: cached access denied and have cached info3\n"));
		domain->last_status = NT_STATUS_OK;
		centry_free(centry);
		goto do_query;
	}
	
	if (!centry)
		goto do_query;

	*num_groups = centry_uint32(centry);
	
	if (*num_groups == 0)
		goto do_cached;

	(*user_gids) = talloc(mem_ctx, sizeof(**user_gids) * (*num_groups));
	if (! (*user_gids))
		smb_panic("lookup_usergroups out of memory");
	for (i=0; i<(*num_groups); i++) {
		(*user_gids)[i] = centry_sid(centry, mem_ctx);
	}

do_cached:	
	status = centry->status;

	DEBUG(10,("lookup_usergroups: [Cached] - cached info for domain %s status %s\n",
		domain->name, get_friendly_nt_error_msg(status) ));

	centry_free(centry);
	return status;

do_query:
	(*num_groups) = 0;
	(*user_gids) = NULL;

	/* Return status value returned by seq number check */

	if (!NT_STATUS_IS_OK(domain->last_status))
		return domain->last_status;

	DEBUG(10,("lookup_usergroups: [Cached] - doing backend query for info for domain %s\n",
		domain->name ));

	status = domain->backend->lookup_usergroups(domain, mem_ctx, user_sid, num_groups, user_gids);

	/* and save it */
	refresh_sequence_number(domain, False);
	centry = centry_start(domain, status);
	if (!centry)
		goto skip_save;
	centry_put_uint32(centry, *num_groups);
	for (i=0; i<(*num_groups); i++) {
		centry_put_sid(centry, (*user_gids)[i]);
	}	
	centry_end(centry, "UG/%s", sid_to_string(sid_string, user_sid));
	centry_free(centry);

skip_save:
	return status;
}


static NTSTATUS lookup_groupmem(struct winbindd_domain *domain,
				TALLOC_CTX *mem_ctx,
				const DOM_SID *group_sid, uint32 *num_names, 
				DOM_SID ***sid_mem, char ***names, 
				uint32 **name_types)
{
	struct winbind_cache *cache = get_cache(domain);
	struct cache_entry *centry = NULL;
	NTSTATUS status;
	unsigned int i;
	fstring sid_string;

	if (!cache->tdb)
		goto do_query;

	centry = wcache_fetch(cache, domain, "GM/%s", sid_to_string(sid_string, group_sid));
	if (!centry)
		goto do_query;

	*num_names = centry_uint32(centry);
	
	if (*num_names == 0)
		goto do_cached;

	(*sid_mem) = talloc(mem_ctx, sizeof(**sid_mem) * (*num_names));
	(*names) = talloc(mem_ctx, sizeof(**names) * (*num_names));
	(*name_types) = talloc(mem_ctx, sizeof(**name_types) * (*num_names));

	if (! (*sid_mem) || ! (*names) || ! (*name_types)) {
		smb_panic("lookup_groupmem out of memory");
	}

	for (i=0; i<(*num_names); i++) {
		(*sid_mem)[i] = centry_sid(centry, mem_ctx);
		(*names)[i] = centry_string(centry, mem_ctx);
		(*name_types)[i] = centry_uint32(centry);
	}

do_cached:	
	status = centry->status;

	DEBUG(10,("lookup_groupmem: [Cached] - cached info for domain %s status %s\n",
		domain->name, get_friendly_nt_error_msg(status) ));

	centry_free(centry);
	return status;

do_query:
	(*num_names) = 0;
	(*sid_mem) = NULL;
	(*names) = NULL;
	(*name_types) = NULL;
	
	/* Return status value returned by seq number check */

	if (!NT_STATUS_IS_OK(domain->last_status))
		return domain->last_status;

	DEBUG(10,("lookup_groupmem: [Cached] - doing backend query for info for domain %s\n",
		domain->name ));

	status = domain->backend->lookup_groupmem(domain, mem_ctx, group_sid, num_names, 
						  sid_mem, names, name_types);

	/* and save it */
	refresh_sequence_number(domain, False);
	centry = centry_start(domain, status);
	if (!centry)
		goto skip_save;
	centry_put_uint32(centry, *num_names);
	for (i=0; i<(*num_names); i++) {
		centry_put_sid(centry, (*sid_mem)[i]);
		centry_put_string(centry, (*names)[i]);
		centry_put_uint32(centry, (*name_types)[i]);
	}	
	centry_end(centry, "GM/%s", sid_to_string(sid_string, group_sid));
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
				char ***alt_names,
				DOM_SID **dom_sids)
{
	get_cache(domain);

	DEBUG(10,("trusted_domains: [Cached] - doing backend query for info for domain %s\n",
		domain->name ));

	/* we don't cache this call */
	return domain->backend->trusted_domains(domain, mem_ctx, num_domains, 
					       names, alt_names, dom_sids);
}

/* find the domain sid */
static NTSTATUS domain_sid(struct winbindd_domain *domain, DOM_SID *sid)
{
	get_cache(domain);

	DEBUG(10,("domain_sid: [Cached] - doing backend query for info for domain %s\n",
		domain->name ));

	/* we don't cache this call */
	return domain->backend->domain_sid(domain, sid);
}

/* find the alternate names for the domain, if any */
static NTSTATUS alternate_name(struct winbindd_domain *domain)
{
	get_cache(domain);

	DEBUG(10,("alternate_name: [Cached] - doing backend query for info for domain %s\n",
		domain->name ));

	/* we don't cache this call */
	return domain->backend->alternate_name(domain);
}

/* Invalidate cached user and group lists coherently */

static int traverse_fn(TDB_CONTEXT *the_tdb, TDB_DATA kbuf, TDB_DATA dbuf, 
		       void *state)
{
	if (strncmp(kbuf.dptr, "UL/", 3) == 0 ||
	    strncmp(kbuf.dptr, "GL/", 3) == 0)
		tdb_delete(the_tdb, kbuf);

	return 0;
}

/* Invalidate the getpwnam and getgroups entries for a winbindd domain */

void wcache_invalidate_samlogon(struct winbindd_domain *domain, 
				NET_USER_INFO_3 *info3)
{
	struct winbind_cache *cache;
	
	if (!domain)
		return;

	cache = get_cache(domain);
	netsamlogon_clear_cached_user(cache->tdb, info3);
}

void wcache_invalidate_cache(void)
{
	struct winbindd_domain *domain;

	for (domain = domain_list(); domain; domain = domain->next) {
		struct winbind_cache *cache = get_cache(domain);

		DEBUG(10, ("wcache_invalidate_cache: invalidating cache "
			   "entries for %s\n", domain->name));
		if (cache)
			tdb_traverse(cache->tdb, traverse_fn, NULL);
	}
}

/* the ADS backend methods are exposed via this structure */
struct winbindd_methods cache_methods = {
	True,
	query_user_list,
	enum_dom_groups,
	enum_local_groups,
	name_to_sid,
	sid_to_name,
	query_user,
	lookup_usergroups,
	lookup_groupmem,
	sequence_number,
	trusted_domains,
	domain_sid,
	alternate_name
};
