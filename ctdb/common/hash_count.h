/*
   Using hash table for counting events

   Copyright (C) Amitay Isaacs  2017

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, see <http://www.gnu.org/licenses/>.
*/

#ifndef __CTDB_HASH_COUNT_H__
#define __CTDB_HASH_COUNT_H__

/**
 * @file hash_count.h
 *
 * @brief Count key-based events for specified interval
 *
 * This can be used to measure the rate of events based on any interval.
 * For example, number of occurrences per second.
 */

/**
 * @brief Handler callback function called when counter is incremented
 *
 * This function is called every time a counter is incremented for a key.
 * The counter argument is the number of times the increment function is
 * called during a count interval.
 *
 * This function should not modify key and data arguments.
 */
typedef void (*hash_count_update_handler_fn)(TDB_DATA key, uint64_t counter,
					     void *private_data);

/**
 * @brief Abstract structure representing hash based counting
 */
struct hash_count_context;

/**
 * @brief Initialize hash counting
 *
 * This return a new hash count context which is a talloc context.  Freeing
 * this context will free all the memory associated with hash count.
 *
 * @param[in] mem_ctx Talloc memory context
 * @param[in] count_interval The time interval for counting events
 * @param[in] handler Function called when counter is incremented
 * @param[in] private_data Private data to handler function
 * @param[out] result The new hash_count structure
 * @return 0 on success, errno on failure
 */
int hash_count_init(TALLOC_CTX *mem_ctx, struct timeval count_interval,
		    hash_count_update_handler_fn handler, void *private_data,
		    struct hash_count_context **result);

/**
 * @brief Increment a counter for a key
 *
 * First time this is called for a key, corresponding counter is set to 1
 * and the start time is noted.  For all subsequent calls made during the
 * count_interval (used in initializing the context) will increment
 * corresponding counter for the key.  After the count_interval has elapsed,
 * the counter will be reset to 1.
 *
 * @param[in] hcount The hash count context
 * @param[in] key The key for which counter is updated
 * @return 0 on success, errno on failure
 *
 * This will result in a callback function being called.
 */
int hash_count_increment(struct hash_count_context *hcount, TDB_DATA key);

/**
 * @brief Remove keys for which count interval has elapsed
 *
 * This function is used to clean the database of keys for which there are
 * no recent events.
 *
 * @param[in] hcount The hash count context
 * @param[out] delete_count The number of keys deleted
 */
void hash_count_expire(struct hash_count_context *hcount, int *delete_count);

#endif /* __CTDB_HASH_COUNT_H__ */
