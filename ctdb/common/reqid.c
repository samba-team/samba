/*
   ctdb request id handling code

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

#include <talloc.h>

#include "lib/util/idtree.h"
#include "reqid.h"

struct reqid_context {
	struct idr_context *idr;
	uint32_t lastid;
};

int reqid_init(TALLOC_CTX *mem_ctx, int start_id,
	       struct reqid_context **result)
{
	struct reqid_context *reqid_ctx;

	reqid_ctx = talloc_zero(mem_ctx, struct reqid_context);
	if (reqid_ctx == NULL) {
		return ENOMEM;
	}

	reqid_ctx->idr = idr_init(reqid_ctx);
	if (reqid_ctx->idr == NULL) {
		talloc_free(reqid_ctx);
		return ENOMEM;
	}

	if (start_id <= 0) {
		start_id = 1;
	}
	reqid_ctx->lastid = start_id;

	*result = reqid_ctx;
	return 0;
}

uint32_t reqid_new(struct reqid_context *reqid_ctx, void *private_data)
{
	int id;

	id = idr_get_new_above(reqid_ctx->idr, private_data,
			       reqid_ctx->lastid+1, INT_MAX);
	if (id < 0) {
		/* reqid wrapped */
		id = idr_get_new(reqid_ctx->idr, private_data, INT_MAX);
	}
	if (id == -1) {
		return REQID_INVALID;
	}

	reqid_ctx->lastid = id;
	return id;
}

void *_reqid_find(struct reqid_context *reqid_ctx, uint32_t reqid)
{
	return idr_find(reqid_ctx->idr, reqid);
}

int reqid_remove(struct reqid_context *reqid_ctx, uint32_t reqid)
{
	int ret;

	ret = idr_remove(reqid_ctx->idr, reqid);
	if (ret < 0) {
		return ENOENT;
	}
	return 0;
}
