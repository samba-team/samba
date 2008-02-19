#ifndef __LIB_GENCACHE_GENCACHE_H__
#define __LIB_GENCACHE_GENCACHE_H__

/**
 * Cache initialisation function. Opens cache tdb file or creates
 * it if does not exist.
 *
 * @return true on successful initialisation of the cache or
 *         false on failure
 **/
bool gencache_init(struct loadparm_context *lp_ctx);

/**
 * Cache shutdown function. Closes opened cache tdb file.
 *
 * @return true on successful closing the cache or
 *         false on failure during cache shutdown
 **/
bool gencache_shutdown(void);

/**
 * Set an entry in the cache file. If there's no such
 * one, then add it.
 *
 * @param keystr string that represents a key of this entry
 * @param value text representation value being cached
 * @param timeout time when the value is expired
 *
 * @retval true when entry is successfuly stored
 * @retval false on failure
 **/
bool gencache_set(const char *keystr, const char *value, time_t timeout);

/**
 * Set existing entry to the cache file.
 *
 * @param keystr string that represents a key of this entry
 * @param valstr text representation value being cached
 * @param timeout time when the value is expired
 *
 * @retval true when entry is successfuly set
 * @retval false on failure
 **/
bool gencache_set_only(const char *keystr, const char *valstr, time_t timeout);

/**
 * Delete one entry from the cache file.
 *
 * @param keystr string that represents a key of this entry
 *
 * @retval true upon successful deletion
 * @retval false in case of failure
 **/
bool gencache_del(const char *keystr);

/**
 * Get existing entry from the cache file.
 *
 * @param keystr string that represents a key of this entry
 * @param valstr buffer that is allocated and filled with the entry value
 *        buffer's disposing must be done outside
 * @param timeout pointer to a time_t that is filled with entry's
 *        timeout
 *
 * @retval true when entry is successfuly fetched
 * @retval false for failure
 **/
bool gencache_get(const char *keystr, char **valstr, time_t *timeout);

/**
 * Iterate through all entries which key matches to specified pattern
 *
 * @param fn pointer to the function that will be supplied with each single
 *        matching cache entry (key, value and timeout) as an arguments
 * @param data void pointer to an arbitrary data that is passed directly to the fn
 *        function on each call
 * @param keystr_pattern pattern the existing entries' keys are matched to
 *
 **/
void gencache_iterate(void (*fn)(const char* key, const char *value, time_t timeout, void* dptr),
                      void* data, const char* keystr_pattern);

/********************************************************************
 lock a key
********************************************************************/
int gencache_lock_entry( const char *key );

/********************************************************************
 unlock a key
********************************************************************/
void gencache_unlock_entry( const char *key );

#endif /* __LIB_GENCACHE_GENCACHE_H__ */

