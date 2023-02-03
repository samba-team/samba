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
#include "libsmb/namequery.h"

#define IPSTR_LIST_SEP	","
#define IPSTR_LIST_CHAR	','

/**
 * Allocate and initialise an ipstr list using samba_sockaddr ip adresses
 * passed as arguments.
 *
 * @param ctx TALLOC_CTX to use
 * @param ip_list array of ip addresses to place in the list
 * @param ip_count number of addresses stored in ip_list
 * @return pointer to allocated ip string
 **/

static char *ipstr_list_make_sa(TALLOC_CTX *ctx,
			const struct samba_sockaddr *sa_list,
			size_t ip_count)
{
	char *ipstr_list = NULL;
	size_t i;

	/* arguments checking */
	if (sa_list == NULL) {
		return NULL;
	}

	/* process ip addresses given as arguments */
	for (i = 0; i < ip_count; i++) {
		char addr_buf[INET6_ADDRSTRLEN];
		char *new_str = NULL;

		print_sockaddr(addr_buf,
				sizeof(addr_buf),
				&sa_list[i].u.ss);

		if (sa_list[i].u.ss.ss_family == AF_INET) {
			/* IPv4 - port no longer used, store 0 */
			new_str = talloc_asprintf(ctx,
						"%s:%d",
						addr_buf,
						0);
		} else {
			/* IPv6 - port no longer used, store 0 */
			new_str = talloc_asprintf(ctx,
						"[%s]:%d",
						addr_buf,
						0);
		}
		if (new_str == NULL) {
			TALLOC_FREE(ipstr_list);
			return NULL;
		}

		if (ipstr_list == NULL) {
			/* First ip address. */
			ipstr_list = new_str;
		} else {
			/*
			 * Append the separator "," and then the new
			 * ip address to the existing list.
			 *
			 * The efficiency here is horrible, but
			 * ip_count should be small enough we can
			 * live with it.
			 */
			char *tmp = talloc_asprintf(ctx,
						"%s%s%s",
						ipstr_list,
						IPSTR_LIST_SEP,
						new_str);
			if (tmp == NULL) {
				TALLOC_FREE(new_str);
				TALLOC_FREE(ipstr_list);
				return NULL;
			}
			TALLOC_FREE(new_str);
			TALLOC_FREE(ipstr_list);
			ipstr_list = tmp;
		}
	}

	return ipstr_list;
}

/**
 * Parse given ip string list into array of ip addresses
 * (as ip_service structures)
 *    e.g. [IPv6]:port,192.168.1.100:389,192.168.1.78, ...
 *
 * @param ipstr ip string list to be parsed
 * @param ip_list pointer to array of ip addresses which is
 *        talloced by this function and must be freed by caller
 * @return number of successfully parsed addresses
 **/

static int ipstr_list_parse(TALLOC_CTX *ctx,
			const char *ipstr_list,
			struct samba_sockaddr **sa_list_out)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct samba_sockaddr *sa_list = NULL;
	char *token_str = NULL;
	size_t count;
	size_t array_size;

	*sa_list_out = NULL;

	array_size = count_chars(ipstr_list, IPSTR_LIST_CHAR) + 1;
	sa_list = talloc_zero_array(frame,
				struct samba_sockaddr,
				array_size);
	if (sa_list == NULL) {
		TALLOC_FREE(frame);
		return 0;
	}

	count = 0;
	while (next_token_talloc(frame,
				 &ipstr_list,
				 &token_str,
				 IPSTR_LIST_SEP)) {
		bool ok;
		char *s = token_str;
		char *p = strrchr(token_str, ':');
		struct sockaddr_storage ss;

		/* Ensure we don't overrun. */
		if (count >= array_size) {
			break;
		}

		if (p) {
			*p = 0;
			/* We now ignore the port. */
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
		ok = interpret_string_addr(&ss, s, AI_NUMERICHOST);
		if (!ok) {
			continue;
		}
		ok = sockaddr_storage_to_samba_sockaddr(&sa_list[count],
							&ss);
		if (!ok) {
			continue;
		}
		count++;
	}
	if (count > 0) {
		*sa_list_out = talloc_move(ctx, &sa_list);
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

static char *namecache_key(TALLOC_CTX *ctx,
			   const char *name,
			   int name_type)
{
	return talloc_asprintf_strupper_m(ctx,
					  NBTKEY_FMT,
					  name,
					  name_type);
}

/**
 * Store a name(s) in the name cache - samba_sockaddr version.
 *
 * @param name netbios names array
 * @param name_type integer netbios name type
 * @param num_names number of names being stored
 * @param ip_list array of in_addr structures containing
 *        ip addresses being stored
 **/

bool namecache_store(const char *name,
			int name_type,
			size_t num_names,
			struct samba_sockaddr *sa_list)
{
	time_t expiry;
	char *key = NULL;
	char *value_string = NULL;
	size_t i;
	bool ret = false;
	TALLOC_CTX *frame = talloc_stackframe();

	if (name_type > 255) {
		/* Don't store non-real name types. */
		goto out;
	}

	if ( DEBUGLEVEL >= 5 ) {
		char *addr = NULL;

		DBG_INFO("storing %zu address%s for %s#%02x: ",
			num_names, num_names == 1 ? "": "es", name, name_type);

		for (i = 0; i < num_names; i++) {
			addr = print_canonical_sockaddr(frame,
					&sa_list[i].u.ss);
			if (!addr) {
				continue;
			}
			DEBUGADD(5, ("%s%s", addr,
				(i == (num_names - 1) ? "" : ",")));

		}
		DEBUGADD(5, ("\n"));
	}

	key = namecache_key(frame, name, name_type);
	if (!key) {
		goto out;
	}

	expiry = time(NULL) + lp_name_cache_timeout();

	/*
	 * Generate string representation of ip addresses list
	 */
	value_string = ipstr_list_make_sa(frame, sa_list, num_names);
	if (value_string == NULL) {
		goto out;
	}

	/* set the entry */
	ret = gencache_set(key, value_string, expiry);

  out:

	TALLOC_FREE(key);
	TALLOC_FREE(value_string);
	TALLOC_FREE(frame);
	return ret;
}

/**
 * Look up a name in the cache.
 *
 * @param name netbios name to look up for
 * @param name_type netbios name type of @param name
 * @param ip_list talloced list of IP addresses if found in the cache,
 *        NULL otherwise
 * @param num_names number of entries found
 *
 * @return true upon successful fetch or
 *         false if name isn't found in the cache or has expired
 **/

bool namecache_fetch(TALLOC_CTX *ctx,
		const char *name,
		int name_type,
		struct samba_sockaddr **sa_list,
		size_t *num_names)
{
	char *key, *value;
	time_t timeout;

	if (name_type > 255) {
		return false; /* Don't fetch non-real name types. */
	}

	*num_names = 0;

	/*
	 * Use gencache interface - lookup the key
	 */
	key = namecache_key(talloc_tos(), name, name_type);
	if (!key) {
		return false;
	}

	if (!gencache_get(key, talloc_tos(), &value, &timeout)) {
		DBG_INFO("no entry for %s#%02X found.\n", name, name_type);
		TALLOC_FREE(key);
		return false;
	}

	DBG_INFO("name %s#%02X found.\n", name, name_type);

	/*
	 * Split up the stored value into the list of IP adresses
	 */
	*num_names = ipstr_list_parse(ctx, value, sa_list);

	TALLOC_FREE(key);
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
		return false; /* Don't fetch non-real name types. */
	}

	key = namecache_key(talloc_tos(), name, name_type);
	if (!key) {
		return false;
	}
	ret = gencache_del(key);
	TALLOC_FREE(key);
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
	DBG_INFO("Deleting entry %s\n", key);
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
	DBG_INFO("Namecache flushed\n");
}

/* Construct a name status record key. */

static char *namecache_status_record_key(TALLOC_CTX *ctx,
				const char *name,
				int name_type1,
				int name_type2,
				const struct sockaddr_storage *keyip)
{
	char addr[INET6_ADDRSTRLEN];

	print_sockaddr(addr, sizeof(addr), keyip);
	return talloc_asprintf_strupper_m(ctx,
					  "NBT/%s#%02X.%02X.%s",
					  name,
					  name_type1,
					  name_type2,
					  addr);
}

/* Store a name status record. */

bool namecache_status_store(const char *keyname, int keyname_type,
		int name_type, const struct sockaddr_storage *keyip,
		const char *srvname)
{
	char *key;
	time_t expiry;
	bool ret;

	key = namecache_status_record_key(talloc_tos(),
					  keyname,
					  keyname_type,
					  name_type,
					  keyip);
	if (!key)
		return false;

	expiry = time(NULL) + lp_name_cache_timeout();
	ret = gencache_set(key, srvname, expiry);

	if (ret) {
		DBG_INFO("entry %s -> %s\n", key, srvname);
	} else {
		DBG_INFO("entry %s store failed.\n", key);
	}

	TALLOC_FREE(key);
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

	key = namecache_status_record_key(talloc_tos(),
					  keyname,
					  keyname_type,
					  name_type,
					  keyip);
	if (!key)
		return false;

	if (!gencache_get(key, talloc_tos(), &value, &timeout)) {
		DBG_INFO("no entry for %s found.\n", key);
		TALLOC_FREE(key);
		return false;
	} else {
		DBG_INFO("key %s -> %s\n", key, value);
	}

	strlcpy(srvname_out, value, 16);
	TALLOC_FREE(key);
	TALLOC_FREE(value);
	return true;
}
