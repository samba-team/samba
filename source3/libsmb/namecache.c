/*
   Unix SMB/CIFS implementation.

   NetBIOS name cache module on top of gencache mechanism.

   Copyright (C) Tim Potter         2002
   Copyright (C) Rafal Szczesniak   2002
   Copyright (C) Jeremy Allison     2007

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

#include "includes.h"
#include "lib/gencache.h"

#define IPSTR_LIST_SEP	","
#define IPSTR_LIST_CHAR	','

/**
 * Add ip string representation to ipstr list. Used also
 * as part of @function ipstr_list_make
 *
 * @param ipstr_list pointer to string containing ip list;
 *        MUST BE already allocated and IS reallocated if necessary
 * @param ipstr_size pointer to current size of ipstr_list (might be changed
 *        as a result of reallocation)
 * @param ip IP address which is to be added to list
 * @return pointer to string appended with new ip and possibly
 *         reallocated to new length
 **/

static char *ipstr_list_add(char **ipstr_list, const struct ip_service *service)
{
	char *new_ipstr = NULL;
	char addr_buf[INET6_ADDRSTRLEN];
	int ret;

	/* arguments checking */
	if (!ipstr_list || !service) {
		return NULL;
	}

	print_sockaddr(addr_buf,
			sizeof(addr_buf),
			&service->ss);

	/* attempt to convert ip to a string and append colon separator to it */
	if (*ipstr_list) {
		if (service->ss.ss_family == AF_INET) {
			/* IPv4 */
			ret = asprintf(&new_ipstr, "%s%s%s:%d",	*ipstr_list,
				       IPSTR_LIST_SEP, addr_buf,
				       service->port);
		} else {
			/* IPv6 */
			ret = asprintf(&new_ipstr, "%s%s[%s]:%d", *ipstr_list,
				       IPSTR_LIST_SEP, addr_buf,
				       service->port);
		}
		SAFE_FREE(*ipstr_list);
	} else {
		if (service->ss.ss_family == AF_INET) {
			/* IPv4 */
			ret = asprintf(&new_ipstr, "%s:%d", addr_buf,
				       service->port);
		} else {
			/* IPv6 */
			ret = asprintf(&new_ipstr, "[%s]:%d", addr_buf,
				       service->port);
		}
	}
	if (ret == -1) {
		return NULL;
	}
	*ipstr_list = new_ipstr;
	return *ipstr_list;
}

/**
 * Allocate and initialise an ipstr list using ip adresses
 * passed as arguments.
 *
 * @param ipstr_list pointer to string meant to be allocated and set
 * @param ip_list array of ip addresses to place in the list
 * @param ip_count number of addresses stored in ip_list
 * @return pointer to allocated ip string
 **/

static char *ipstr_list_make(char **ipstr_list,
			const struct ip_service *ip_list,
			int ip_count)
{
	int i;

	/* arguments checking */
	if (!ip_list || !ipstr_list) {
		return 0;
	}

	*ipstr_list = NULL;

	/* process ip addresses given as arguments */
	for (i = 0; i < ip_count; i++) {
		*ipstr_list = ipstr_list_add(ipstr_list, &ip_list[i]);
	}

	return (*ipstr_list);
}


/**
 * Parse given ip string list into array of ip addresses
 * (as ip_service structures)
 *    e.g. [IPv6]:port,192.168.1.100:389,192.168.1.78, ...
 *
 * @param ipstr ip string list to be parsed
 * @param ip_list pointer to array of ip addresses which is
 *        allocated by this function and must be freed by caller
 * @return number of successfully parsed addresses
 **/

static int ipstr_list_parse(const char *ipstr_list, struct ip_service **ip_list)
{
	TALLOC_CTX *frame;
	char *token_str = NULL;
	size_t i, count;

	if (!ipstr_list || !ip_list)
		return 0;

	count = count_chars(ipstr_list, IPSTR_LIST_CHAR) + 1;
	if ( (*ip_list = SMB_MALLOC_ARRAY(struct ip_service, count)) == NULL ) {
		DEBUG(0,("ipstr_list_parse: malloc failed for %lu entries\n",
					(unsigned long)count));
		return 0;
	}

	frame = talloc_stackframe();
	for ( i=0; next_token_talloc(frame, &ipstr_list, &token_str,
				IPSTR_LIST_SEP) && i<count; i++ ) {
		char *s = token_str;
		char *p = strrchr(token_str, ':');

		if (p) {
			*p = 0;
			(*ip_list)[i].port = atoi(p+1);
		}

		/* convert single token to ip address */
		if (token_str[0] == '[') {
			/* IPv6 address. */
			s++;
			p = strchr(token_str, ']');
			if (!p) {
				continue;
			}
			*p = '\0';
		}
		if (!interpret_string_addr(&(*ip_list)[i].ss,
					s,
					AI_NUMERICHOST)) {
			continue;
		}
	}
	TALLOC_FREE(frame);
	return count;
}

#define NBTKEY_FMT  "NBT/%s#%02X"

/**
 * Generates a key for netbios name lookups on basis of
 * netbios name and type.
 * The caller must free returned key string when finished.
 *
 * @param name netbios name string (case insensitive)
 * @param name_type netbios type of the name being looked up
 *
 * @return string consisted of uppercased name and appended
 *         type number
 */

static char *namecache_key(const char *name,
				int name_type)
{
	char *keystr = NULL;
	asprintf_strupper_m(&keystr, NBTKEY_FMT, name, name_type);

	return keystr;
}

/**
 * Store a name(s) in the name cache
 *
 * @param name netbios names array
 * @param name_type integer netbios name type
 * @param num_names number of names being stored
 * @param ip_list array of in_addr structures containing
 *        ip addresses being stored
 **/

bool namecache_store(const char *name,
			int name_type,
			int num_names,
			struct ip_service *ip_list)
{
	time_t expiry;
	char *key, *value_string;
	int i;
	bool ret;

	if (name_type > 255) {
		return False; /* Don't store non-real name types. */
	}

	if ( DEBUGLEVEL >= 5 ) {
		TALLOC_CTX *ctx = talloc_stackframe();
		char *addr = NULL;

		DEBUG(5, ("namecache_store: storing %d address%s for %s#%02x: ",
			num_names, num_names == 1 ? "": "es", name, name_type));

		for (i = 0; i < num_names; i++) {
			addr = print_canonical_sockaddr(ctx,
							&ip_list[i].ss);
			if (!addr) {
				continue;
			}
			DEBUGADD(5, ("%s%s", addr,
				(i == (num_names - 1) ? "" : ",")));

		}
		DEBUGADD(5, ("\n"));
		TALLOC_FREE(ctx);
	}

	key = namecache_key(name, name_type);
	if (!key) {
		return False;
	}

	expiry = time(NULL) + lp_name_cache_timeout();

	/*
	 * Generate string representation of ip addresses list
	 * First, store the number of ip addresses and then
	 * place each single ip
	 */
	if (!ipstr_list_make(&value_string, ip_list, num_names)) {
		SAFE_FREE(key);
		SAFE_FREE(value_string);
		return false;
	}

	/* set the entry */
	ret = gencache_set(key, value_string, expiry);
	SAFE_FREE(key);
	SAFE_FREE(value_string);
	return ret;
}

/**
 * Look up a name in the cache.
 *
 * @param name netbios name to look up for
 * @param name_type netbios name type of @param name
 * @param ip_list mallocated list of IP addresses if found in the cache,
 *        NULL otherwise
 * @param num_names number of entries found
 *
 * @return true upon successful fetch or
 *         false if name isn't found in the cache or has expired
 **/

bool namecache_fetch(const char *name,
			int name_type,
			struct ip_service **ip_list,
			int *num_names)
{
	char *key, *value;
	time_t timeout;

	/* exit now if null pointers were passed as they're required further */
	if (!ip_list || !num_names) {
		return False;
	}

	if (name_type > 255) {
		return False; /* Don't fetch non-real name types. */
	}

	*num_names = 0;

	/*
	 * Use gencache interface - lookup the key
	 */
	key = namecache_key(name, name_type);
	if (!key) {
		return False;
	}

	if (!gencache_get(key, talloc_tos(), &value, &timeout)) {
		DEBUG(5, ("no entry for %s#%02X found.\n", name, name_type));
		SAFE_FREE(key);
		return False;
	}

	DEBUG(5, ("name %s#%02X found.\n", name, name_type));

	/*
	 * Split up the stored value into the list of IP adresses
	 */
	*num_names = ipstr_list_parse(value, ip_list);

	SAFE_FREE(key);
	TALLOC_FREE(value);

	return *num_names > 0; /* true only if some ip has been fetched */
}

/**
 * Remove a namecache entry. Needed for site support.
 *
 **/

bool namecache_delete(const char *name, int name_type)
{
	bool ret;
	char *key;

	if (name_type > 255) {
		return False; /* Don't fetch non-real name types. */
	}

	key = namecache_key(name, name_type);
	if (!key) {
		return False;
	}
	ret = gencache_del(key);
	SAFE_FREE(key);
	return ret;
}

/**
 * Delete single namecache entry. Look at the
 * gencache_iterate definition.
 *
 **/

static void flush_netbios_name(const char *key,
			const char *value,
			time_t timeout,
			void *dptr)
{
	gencache_del(key);
	DEBUG(5, ("Deleting entry %s\n", key));
}

/**
 * Flush all names from the name cache.
 * It's done by gencache_iterate()
 *
 * @return true upon successful deletion or
 *         false in case of an error
 **/

void namecache_flush(void)
{
	/*
	 * iterate through each NBT cache's entry and flush it
	 * by flush_netbios_name function
	 */
	gencache_iterate(flush_netbios_name, NULL, "NBT/*");
	DEBUG(5, ("Namecache flushed\n"));
}

/* Construct a name status record key. */

static char *namecache_status_record_key(const char *name,
				int name_type1,
				int name_type2,
				const struct sockaddr_storage *keyip)
{
	char addr[INET6_ADDRSTRLEN];
	char *keystr = NULL;

	print_sockaddr(addr, sizeof(addr), keyip);
	asprintf_strupper_m(&keystr, "NBT/%s#%02X.%02X.%s", name,
			    name_type1, name_type2, addr);
	return keystr;
}

/* Store a name status record. */

bool namecache_status_store(const char *keyname, int keyname_type,
		int name_type, const struct sockaddr_storage *keyip,
		const char *srvname)
{
	char *key;
	time_t expiry;
	bool ret;

	key = namecache_status_record_key(keyname, keyname_type,
			name_type, keyip);
	if (!key)
		return False;

	expiry = time(NULL) + lp_name_cache_timeout();
	ret = gencache_set(key, srvname, expiry);

	if (ret) {
		DEBUG(5, ("namecache_status_store: entry %s -> %s\n",
					key, srvname ));
	} else {
		DEBUG(5, ("namecache_status_store: entry %s store failed.\n",
					key ));
	}

	SAFE_FREE(key);
	return ret;
}

/* Fetch a name status record. */

bool namecache_status_fetch(const char *keyname,
				int keyname_type,
				int name_type,
				const struct sockaddr_storage *keyip,
				char *srvname_out)
{
	char *key = NULL;
	char *value = NULL;
	time_t timeout;

	key = namecache_status_record_key(keyname, keyname_type,
			name_type, keyip);
	if (!key)
		return False;

	if (!gencache_get(key, talloc_tos(), &value, &timeout)) {
		DEBUG(5, ("namecache_status_fetch: no entry for %s found.\n",
					key));
		SAFE_FREE(key);
		return False;
	} else {
		DEBUG(5, ("namecache_status_fetch: key %s -> %s\n",
					key, value ));
	}

	strlcpy(srvname_out, value, 16);
	SAFE_FREE(key);
	TALLOC_FREE(value);
	return True;
}
