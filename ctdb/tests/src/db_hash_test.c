/*
   db_hash tests

   Copyright (C) Amitay Isaacs  2015

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

static int record_parser(uint8_t *keybuf, size_t keylen,
			 uint8_t *databuf, size_t datalen,
			 void *private_data)
{
	int *count = (int *)private_data;

	(*count) += 1;
	return 0;
}

static void do_test(enum db_hash_type type)
{
	struct db_hash_context *dh = NULL;
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	uint8_t key[] = "This is a long key";
	uint8_t value[] = "This is a long value";
	int ret;
	int count = 0;

	ret = db_hash_insert(dh, key, sizeof(key), value, sizeof(value));
	assert(ret == EINVAL);

	ret = db_hash_add(dh, key, sizeof(key), value, sizeof(value));
	assert(ret == EINVAL);

	ret = db_hash_exists(dh, key, sizeof(key));
	assert(ret == EINVAL);

	ret = db_hash_delete(dh, key, sizeof(key));
	assert(ret == EINVAL);

	ret = db_hash_init(mem_ctx, "foobar", 1024, type, &dh);
	assert(ret == 0);

	ret = db_hash_insert(dh, key, sizeof(key), value, sizeof(value));
	assert(ret == 0);

	ret = db_hash_exists(dh, key, sizeof(key));
	assert(ret == 0);

	ret = db_hash_fetch(dh, key, sizeof(key), NULL, NULL);
	assert(ret == EINVAL);

	ret = db_hash_fetch(dh, key, sizeof(key), record_parser, &count);
	assert(ret == 0);
	assert(count == 1);

	ret = db_hash_insert(dh, key, sizeof(key), value, sizeof(value));
	assert(ret == EEXIST);

	ret = db_hash_delete(dh, key, sizeof(key));
	assert(ret == 0);

	ret = db_hash_exists(dh, key, sizeof(key));
	assert(ret == ENOENT);

	ret = db_hash_delete(dh, key, sizeof(key));
	assert(ret == ENOENT);

	ret = db_hash_add(dh, key, sizeof(key), key, sizeof(key));
	assert(ret == 0);

	ret = db_hash_add(dh, key, sizeof(key), value, sizeof(value));
	assert(ret == 0);

	talloc_free(dh);
	ret = talloc_get_size(mem_ctx);
	assert(ret == 0);

	talloc_free(mem_ctx);
}

static void do_traverse_test(enum db_hash_type type)
{
	struct db_hash_context *dh = NULL;
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	char key[16] = "keyXXXX";
	char value[] = "This is some test value";
	int count, ret, i;

	ret = db_hash_traverse(dh, NULL, NULL, &count);
	assert(ret == EINVAL);

	ret = db_hash_init(mem_ctx, "foobar", 1024, type, &dh);
	assert(ret == 0);

	for (i=0; i<2000; i++) {
		sprintf(key, "key%04d", i);
		ret = db_hash_insert(dh, (uint8_t *)key, sizeof(key),
				     (uint8_t *)value, sizeof(value));
		assert(ret == 0);
	}

	ret = db_hash_traverse(dh, NULL, NULL, &count);
	assert(ret == 0);
	assert(count == 2000);

	ret = db_hash_traverse(dh, record_parser, &count, NULL);
	assert(ret == 0);
	assert(count == 4000);

	talloc_free(dh);
	talloc_free(mem_ctx);
}

int main(void)
{
	do_test(DB_HASH_SIMPLE);
	do_test(DB_HASH_COMPLEX);
	do_traverse_test(DB_HASH_SIMPLE);
	do_traverse_test(DB_HASH_COMPLEX);
	return 0;
}
