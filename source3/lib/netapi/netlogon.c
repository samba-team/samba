/*
 *  Unix SMB/CIFS implementation.
 *  NetApi LogonControl Support
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

WERROR I_NetLogonControl_r(struct libnetapi_ctx *ctx,
			   struct I_NetLogonControl *r)
{
	return WERR_NOT_SUPPORTED;
}

/****************************************************************
****************************************************************/

WERROR I_NetLogonControl_l(struct libnetapi_ctx *ctx,
			   struct I_NetLogonControl *r)
{
	LIBNETAPI_REDIRECT_TO_LOCALHOST(ctx, r, I_NetLogonControl);
}

/****************************************************************
****************************************************************/

WERROR I_NetLogonControl2_r(struct libnetapi_ctx *ctx,
			    struct I_NetLogonControl2 *r)
{
	return WERR_NOT_SUPPORTED;
}

/****************************************************************
****************************************************************/

WERROR I_NetLogonControl2_l(struct libnetapi_ctx *ctx,
			    struct I_NetLogonControl2 *r)
{
	LIBNETAPI_REDIRECT_TO_LOCALHOST(ctx, r, I_NetLogonControl2);
}
