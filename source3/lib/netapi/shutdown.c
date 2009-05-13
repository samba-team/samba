/*
 *  Unix SMB/CIFS implementation.
 *  NetApi Shutdown Support
 *  Copyright (C) Guenther Deschner 2009
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include "includes.h"

#include "librpc/gen_ndr/libnetapi.h"
#include "lib/netapi/netapi.h"
#include "lib/netapi/netapi_private.h"
#include "lib/netapi/libnetapi.h"

/****************************************************************
****************************************************************/

WERROR NetShutdownInit_r(struct libnetapi_ctx *ctx,
			 struct NetShutdownInit *r)
{
	return WERR_NOT_SUPPORTED;
}

/****************************************************************
****************************************************************/

WERROR NetShutdownInit_l(struct libnetapi_ctx *ctx,
			 struct NetShutdownInit *r)
{
	LIBNETAPI_REDIRECT_TO_LOCALHOST(ctx, r, NetShutdownInit);
}

/****************************************************************
****************************************************************/

WERROR NetShutdownAbort_r(struct libnetapi_ctx *ctx,
			  struct NetShutdownAbort *r)
{
	return WERR_NOT_SUPPORTED;
}

/****************************************************************
****************************************************************/

WERROR NetShutdownAbort_l(struct libnetapi_ctx *ctx,
			  struct NetShutdownAbort *r)
{
	LIBNETAPI_REDIRECT_TO_LOCALHOST(ctx, r, NetShutdownAbort);
}
