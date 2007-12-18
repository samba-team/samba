/*
 *  Unix SMB/CIFS implementation.
 *  NetApi Support
 *  Copyright (C) Guenther Deschner 2007
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

#ifndef __LIB_NETAPI_H__
#define __LIB_NETAPI_H__

#define NET_API_STATUS uint32_t

struct libnetapi_ctx {
	const char *debuglevel;
	char *username;
	char *workgroup;
	char *password;
};

NET_API_STATUS libnetapi_init(struct libnetapi_ctx **ctx);
NET_API_STATUS libnetapi_getctx(struct libnetapi_ctx **ctx);
NET_API_STATUS libnetapi_free(struct libnetapi_ctx *ctx);
NET_API_STATUS libnetapi_set_debuglevel(struct libnetapi_ctx *ctx, const char *debuglevel);
NET_API_STATUS libnetapi_get_debuglevel(struct libnetapi_ctx *ctx, const char **debuglevel);
NET_API_STATUS libnetapi_set_username(struct libnetapi_ctx *ctx, const char *username);
NET_API_STATUS libnetapi_set_password(struct libnetapi_ctx *ctx, const char *password);
NET_API_STATUS libnetapi_set_workgroup(struct libnetapi_ctx *ctx, const char *workgroup);

#include "joindomain.h"

#endif
