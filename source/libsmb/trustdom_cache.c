/* 
   Unix SMB/CIFS implementation.

   Trusted domain names cache on top of gencache.

   Copyright (C) Rafal Szczesniak	2002
   
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

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_ALL	/* there's no proper class yet */

#define TDOMKEY_FMT  "TDOM/%s"


/**
 * @file trustdom_cache.c
 *
 * Implementation of trusted domain names cache useful when
 * samba acts as domain member server. In such case, caching
 * domain names currently trusted gives a performance gain
 * because there's no need to query PDC each time we need
 * list of trusted domains
 **/

 
/**
 * Initialise trustdom name caching system. Call gencache
 * initialisation routine to perform necessary activities.
 *
 * @return true upon successful cache initialisation or
 *         false if cache init failed
 **/
 
BOOL trustdom_cache_enable(void)
{
	/* Init trustdom cache by calling gencache initialisation */
	if (!gencache_init()) {
		DEBUG(2, ("trustdomcache_enable: Couldn't initialise trustdom cache on top of gencache.\n"));
		return False;
	}

	return True;
}


/**
 * Shutdown trustdom name caching system. Calls gencache
 * shutdown function.
 *
 * @return true upon successful cache close or
 *         false if it failed
 **/
 
BOOL trustdom_cache_shutdown(void)
{
	/* Close trustdom cache by calling gencache shutdown */
	if (!gencache_shutdown()) {
		DEBUG(2, ("trustdomcache_shutdown: Couldn't shutdown trustdom cache on top of gencache.\n"));
		return False;
	}
	
	return True;
}


/**
 * Form up trustdom name key. It is based only
 * on domain name now.
 *
 * @param name trusted domain name
 * @return cache key for use in gencache mechanism
 **/

static char* trustdom_cache_key(const char* name)
{
	char* keystr;
	asprintf(&keystr, TDOMKEY_FMT, strupper_static(name));
	
	return keystr;
}


/**
 * Store trusted domain in gencache as the domain name (key)
 * and ip address of domain controller (value)
 *
 * @param name trusted domain name
 * @param alt_name alternative trusted domain name (used in ADS domains)
 * @param sid trusted domain's SID
 * @param timeout cache entry expiration time
 * @return true upon successful value storing or
 *         false if store attempt failed
 **/
 
BOOL trustdom_cache_store(char* name, char* alt_name, const DOM_SID *sid,
                          time_t timeout)
{
	char *key, *alt_key;
	fstring sid_string;

	/*
	 * we use gecache call to avoid annoying debug messages
	 * about initialised trustdom 
	 */
	if (!gencache_init()) return False;

	DEBUG(5, ("trustdom_store: storing SID %s of domain %s\n",
	          sid_string_static(sid), name));

	key = trustdom_cache_key(name);
	alt_key = alt_name ? trustdom_cache_key(alt_name) : NULL;

	/* Generate string representation domain SID */
	sid_to_string(sid_string, sid);

	/*
	 * try to put the names in the cache
	 */
	if (alt_key) {
		return (gencache_set(alt_key, sid_string, timeout)
		        && gencache_set(key, sid_string, timeout));
	}
		 
	return gencache_set(key, sid_string, timeout);
}


/**
 * Fetch trusted domain's dc from the gencache.
 * This routine can also be used to check whether given
 * domain is currently trusted one.
 *
 * @param name trusted domain name
 * @param sid trusted domain's SID to be returned
 * @return true if entry is found or
 *         false if has expired/doesn't exist
 **/
 
BOOL trustdom_cache_fetch(const char* name, DOM_SID* sid)
{
	char *key, *value;
	time_t timeout;

	/* init the cache */
	if (!gencache_init()) return False;
	
	/* exit now if null pointers were passed as they're required further */
	if (!sid) return False;

	/* prepare a key and get the value */
	key = trustdom_cache_key(name);
	
	if (!gencache_get(key, &value, &timeout)) {
		DEBUG(5, ("no entry for trusted domain %s found.\n", name));
		return False;
	} else {
		DEBUG(5, ("trusted domain %s found (%s)\n", name, value));
	}

	/* convert ip string representation into in_addr structure */
	if(! string_to_sid(sid, value)) {
		sid = NULL;
		return False;
	}
	
	return True;
}


/**
 * Delete single trustdom entry. Look at the
 * gencache_iterate definition.
 *
 **/

static void flush_trustdom_name(const char* key, const char *value, time_t timeout, void* dptr)
{
	gencache_del(key);
	DEBUG(5, ("Deleting entry %s\n", key));
}


/**
 * Flush all the trusted domains entries from the cache.
 **/

void trustdom_cache_flush(void)
{
	if (!gencache_init())
		return;

	/* 
	 * iterate through each TDOM cache's entry and flush it
	 * by flush_trustdom_name function
	 */
	gencache_iterate(flush_trustdom_name, NULL, trustdom_cache_key("*"));
	DEBUG(5, ("Trusted domains cache flushed\n"));
}

