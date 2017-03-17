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

#include "replace.h"
#include "system/filesys.h"
#include "system/time.h"

#include <tdb.h>

#include "lib/util/time.h"

#include "common/db_hash.h"
#include "common/hash_count.h"

struct hash_count_value {
	struct timeval update_time;
	uint64_t counter;
};

struct hash_count_context {
	struct db_hash_context *dh;
	struct timeval update_interval;
	hash_count_update_handler_fn handler;
	void *private_data;
};

/*
 * Initialise hash count map
 */
int hash_count_init(TALLOC_CTX *mem_ctx, struct timeval update_interval,
		    hash_count_update_handler_fn handler, void *private_data,
		    struct hash_count_context **result)
{
	struct hash_count_context *hcount;
	int ret;

	if (handler == NULL) {
		return EINVAL;
	}

	hcount = talloc_zero(mem_ctx, struct hash_count_context);
	if (hcount == NULL) {
		return ENOMEM;
	}

	ret = db_hash_init(hcount, "hash_count_db", 8192, DB_HASH_COMPLEX,
			    &hcount->dh);
	if (ret != 0) {
		talloc_free(hcount);
		return ret;
	}

	hcount->update_interval = update_interval;
	hcount->handler = handler;
	hcount->private_data = private_data;

	*result = hcount;
	return 0;
}

static int hash_count_fetch_parser(uint8_t *keybuf, size_t keylen,
				   uint8_t *databuf, size_t datalen,
				   void *private_data)
{
	struct hash_count_value *value =
		(struct hash_count_value *)private_data;

	if (datalen != sizeof(struct hash_count_value)) {
		return EIO;
	}

	*value = *(struct hash_count_value *)databuf;
	return 0;
}

static int hash_count_fetch(struct hash_count_context *hcount, TDB_DATA key,
			    struct hash_count_value *value)
{
	return db_hash_fetch(hcount->dh, key.dptr, key.dsize,
			     hash_count_fetch_parser, value);
}

static int hash_count_insert(struct hash_count_context *hcount, TDB_DATA key,
			     struct hash_count_value *value)
{
	return db_hash_insert(hcount->dh, key.dptr, key.dsize,
			      (uint8_t *)value,
			      sizeof(struct hash_count_value));
}

static int hash_count_update(struct hash_count_context *hcount, TDB_DATA key,
			     struct hash_count_value *value)
{
	return db_hash_add(hcount->dh, key.dptr, key.dsize,
			   (uint8_t *)value, sizeof(struct hash_count_value));
}

int hash_count_increment(struct hash_count_context *hcount, TDB_DATA key)
{
	struct hash_count_value value;
	struct timeval current_time = timeval_current();
	int ret;

	if (hcount == NULL) {
		return EINVAL;
	}

	ret = hash_count_fetch(hcount, key, &value);
	if (ret == 0) {
		struct timeval tmp_t;

		tmp_t = timeval_sum(&value.update_time,
				    &hcount->update_interval);
		if (timeval_compare(&current_time, &tmp_t) < 0) {
			value.counter += 1;
		} else {
			value.update_time = current_time;
			value.counter = 1;
		}

		hcount->handler(key, value.counter, hcount->private_data);
		ret = hash_count_update(hcount, key, &value);

	} else if (ret == ENOENT) {
		value.update_time = current_time;
		value.counter = 1;

		hcount->handler(key, value.counter, hcount->private_data);
		ret = hash_count_insert(hcount, key, &value);
	}

	return ret;
}

static struct timeval timeval_subtract(const struct timeval *tv1,
				       const struct timeval *tv2)
{
	struct timeval tv = *tv1;
	const unsigned int million = 1000000;

	if (tv.tv_sec > 1) {
		tv.tv_sec -= 1;
		tv.tv_usec += million;
	} else {
		return tv;
	}

	tv.tv_sec -= tv2->tv_sec;
	tv.tv_usec -= tv2->tv_usec;

	tv.tv_sec += tv.tv_usec / million;
	tv.tv_usec = tv.tv_usec % million;

	return tv;
}

struct hash_count_expire_state {
	struct db_hash_context *dh;
	struct timeval last_time;
	int count;
};

static int hash_count_expire_parser(uint8_t *keybuf, size_t keylen,
				    uint8_t *databuf, size_t datalen,
				    void *private_data)
{
	struct hash_count_expire_state *state =
		(struct hash_count_expire_state *)private_data;
	struct hash_count_value *value;
	int ret = 0;

	if (datalen != sizeof(struct hash_count_value)) {
		return EIO;
	}

	value = (struct hash_count_value *)databuf;
	if (timeval_compare(&value->update_time, &state->last_time) < 0) {
		ret = db_hash_delete(state->dh, keybuf, keylen);
		if (ret == 0) {
			state->count += 1;
		}
	}

	return ret;
}

void hash_count_expire(struct hash_count_context *hcount, int *delete_count)
{
	struct timeval current_time = timeval_current();
	struct hash_count_expire_state state;

	state.dh = hcount->dh;
	state.last_time = timeval_subtract(&current_time,
					   &hcount->update_interval);
	state.count = 0;

	(void) db_hash_traverse_update(hcount->dh, hash_count_expire_parser,
				       &state, NULL);

	if (delete_count != NULL) {
		*delete_count = state.count;
	}
}
