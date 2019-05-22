/*
   reqid tests

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

#include "common/reqid.c"


int main(void)
{
	struct reqid_context *reqid_ctx;
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	int i, ret;
	uint32_t reqid;
	int *data, *tmp;

	ret = reqid_init(mem_ctx, INT_MAX-200, &reqid_ctx);
	assert(ret == 0);

	data = talloc_zero(mem_ctx, int);
	assert(data != 0);

	for (i=0; i<1024*1024; i++) {
		reqid = reqid_new(reqid_ctx, data);
		assert(reqid != REQID_INVALID);
	}

	for (i=0; i<1024; i++) {
		tmp = reqid_find(reqid_ctx, i, int);
		assert(tmp == data);
	}

	for (i=0; i<1024; i++) {
		ret = reqid_remove(reqid_ctx, i);
		assert(ret == 0);
	}

	for (i=0; i<1024; i++) {
		tmp = reqid_find(reqid_ctx, i, int);
		assert(tmp == NULL);
	}

	for (i=0; i<1024; i++) {
		ret = reqid_remove(reqid_ctx, i);
		assert(ret == ENOENT);
	}

	talloc_free(reqid_ctx);
	assert(talloc_get_size(mem_ctx) == 0);

	ret = reqid_init(mem_ctx, INT_MAX-1, &reqid_ctx);
	assert(ret == 0);

	reqid = reqid_new(reqid_ctx, data);
	assert(reqid == INT_MAX);

	reqid = reqid_new(reqid_ctx, data);
	assert(reqid == 0);

	reqid_remove(reqid_ctx, 0);

	reqid = reqid_new(reqid_ctx, data);
	assert(reqid == 1);

	talloc_free(reqid_ctx);

	talloc_free(mem_ctx);

	return 0;
}
