/*
   Unix SMB/CIFS implementation.
   Main metadata server / Spotlight routines / noindex backend

   Copyright (C) Ralph Boehme 2019

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
#include "mdssvc.h"

static bool mdssvc_noindex_init(struct mdssvc_ctx *mdssvc_ctx)
{
	return true;
}

static bool mdssvc_noindex_shutdown(struct mdssvc_ctx *mdssvc_ctx)
{
	return true;
}

static bool mds_noindex_connect(struct mds_ctx *mds_ctx)
{
	return true;
}

static bool mds_noindex_search_start(struct sl_query *slq)
{
	slq->state = SLQ_STATE_DONE;
	return true;
}

static bool mds_noindex_search_cont(struct sl_query *slq)
{
	slq->state = SLQ_STATE_DONE;
	return true;
}

struct mdssvc_backend mdsscv_backend_noindex = {
	.init = mdssvc_noindex_init,
	.shutdown = mdssvc_noindex_shutdown,
	.connect = mds_noindex_connect,
	.search_start = mds_noindex_search_start,
	.search_cont = mds_noindex_search_cont,
};
