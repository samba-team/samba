/*
   hash_count tests

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

#include <assert.h>

#include "common/db_hash.c"
#include "common/hash_count.c"

#define KEY	"this_is_a_test_key"

static void test1_handler(TDB_DATA key, uint64_t counter, void *private_data)
{
	int *count = (int *)private_data;

	assert(key.dsize == strlen(KEY));
	assert(strcmp((char *)key.dptr, KEY) == 0);
	assert(counter > 0);

	(*count) += 1;
}

static void do_test1(void)
{
	struct hash_count_context *hc = NULL;
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct timeval interval = {1, 0};
	TDB_DATA key;
	int count = 0;
	int ret, i;

	key.dptr = (uint8_t *)discard_const(KEY);
	key.dsize = strlen(KEY);

	ret = hash_count_increment(hc, key);
	assert(ret == EINVAL);

	ret = hash_count_init(mem_ctx, interval, NULL, NULL, &hc);
	assert(ret == EINVAL);

	ret = hash_count_init(mem_ctx, interval, test1_handler, &count, &hc);
	assert(ret == 0);
	assert(hc != NULL);

	for (i=0; i<10; i++) {
		ret = hash_count_increment(hc, key);
		assert(ret == 0);
		assert(count == i+1);
	}

	talloc_free(hc);
	ret = talloc_get_size(mem_ctx);
	assert(ret == 0);

	talloc_free(mem_ctx);
}

static void test2_handler(TDB_DATA key, uint64_t counter, void *private_data)
{
	uint64_t *count = (uint64_t *)private_data;

	*count = counter;
}

static void do_test2(void)
{
	struct hash_count_context *hc;
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct timeval interval = {1, 0};
	TDB_DATA key;
	uint64_t count = 0;
	int ret;

	key.dptr = (uint8_t *)discard_const(KEY);
	key.dsize = strlen(KEY);

	ret = hash_count_init(mem_ctx, interval, test2_handler, &count, &hc);
	assert(ret == 0);

	ret = hash_count_increment(hc, key);
	assert(ret == 0);
	assert(count == 1);

	hash_count_expire(hc, &ret);
	assert(ret == 0);

	ret = hash_count_increment(hc, key);
	assert(ret == 0);
	assert(count == 2);

	sleep(2);

	ret = hash_count_increment(hc, key);
	assert(ret == 0);
	assert(count == 1);

	sleep(2);

	hash_count_expire(hc, &ret);
	assert(ret == 1);

	talloc_free(hc);
	ret = talloc_get_size(mem_ctx);
	assert(ret == 0);

	talloc_free(mem_ctx);
}

int main(void)
{
	do_test1();
	do_test2();

	return 0;
}
