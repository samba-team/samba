/*
   srvid tests

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
#include "common/srvid.c"

#define TEST_SRVID	0xBE11223344556677

static void test_handler(uint64_t srvid, TDB_DATA data, void *private_data)
{
	int *count = (int *)private_data;
	(*count)++;
}

int main(void)
{
	struct srvid_context *srv = NULL;
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	TALLOC_CTX *tmp_ctx = talloc_new(NULL);
	int ret;
	int count = 0;

	ret = srvid_register(srv, tmp_ctx, TEST_SRVID, test_handler, &count);
	assert(ret == EINVAL);

	ret = srvid_init(mem_ctx, &srv);
	assert(ret == 0);

	ret = srvid_deregister(srv, TEST_SRVID, &count);
	assert(ret == ENOENT);

	ret = srvid_register(srv, tmp_ctx, TEST_SRVID, test_handler, &count);
	assert(ret == 0);

	ret = srvid_exists(srv, TEST_SRVID, NULL);
	assert(ret == 0);

	ret = srvid_exists(srv, TEST_SRVID, &count);
	assert(ret == 0);

	ret = srvid_dispatch(srv, TEST_SRVID, 0, tdb_null);
	assert(ret == 0);
	assert(count == 1);

	ret = srvid_dispatch(srv, 0, TEST_SRVID, tdb_null);
	assert(ret == 0);
	assert(count == 2);

	ret = srvid_deregister(srv, TEST_SRVID, NULL);
	assert(ret == ENOENT);

	ret = srvid_deregister(srv, TEST_SRVID, &count);
	assert(ret == 0);

	ret = srvid_register(srv, tmp_ctx, TEST_SRVID, test_handler, &count);
	assert(ret == 0);

	talloc_free(tmp_ctx);
	ret = srvid_exists(srv, TEST_SRVID, NULL);
	assert(ret == ENOENT);

	ret = srvid_dispatch(srv, TEST_SRVID, 0, tdb_null);
	assert(ret == ENOENT);

	tmp_ctx = talloc_new(NULL);
	assert(tmp_ctx != NULL);

	ret = srvid_register(srv, tmp_ctx, TEST_SRVID, test_handler, NULL);
	assert(ret == 0);
	ret = srvid_exists(srv, TEST_SRVID, &count);
	assert(ret == ENOENT);

	ret = srvid_register(srv, tmp_ctx, TEST_SRVID, test_handler, &count);
	assert(ret == 0);
	ret = srvid_exists(srv, TEST_SRVID, &count);
	assert(ret == 0);

	talloc_free(srv);
	assert(talloc_get_size(mem_ctx) == 0);
	assert(talloc_get_size(tmp_ctx) == 0);

	talloc_free(mem_ctx);

	return 0;
}
