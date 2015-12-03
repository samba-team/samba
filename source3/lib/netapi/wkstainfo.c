/*
 *  Unix SMB/CIFS implementation.
 *  NetApi Workstation Support
 *  Copyright (C) Guenther Deschner 2007
 *  Copyright (C) Hans Leidekker 2013
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
#include "../librpc/gen_ndr/ndr_wkssvc_c.h"
#include "lib/smbconf/smbconf.h"
#include "lib/smbconf/smbconf_reg.h"

/****************************************************************
****************************************************************/

WERROR NetWkstaGetInfo_l(struct libnetapi_ctx *ctx,
                         struct NetWkstaGetInfo *r)
{
        LIBNETAPI_REDIRECT_TO_LOCALHOST(ctx, r, NetWkstaGetInfo);
}

/****************************************************************
****************************************************************/

static NTSTATUS map_wksta_info_to_WKSTA_INFO_buffer(TALLOC_CTX *mem_ctx,
                                                    uint32_t level,
                                                    union wkssvc_NetWkstaInfo *i,
                                                    uint8_t **buffer)
{
	struct WKSTA_INFO_100 i100;
	struct WKSTA_INFO_101 i101;
	struct WKSTA_INFO_102 i102;
	uint32_t num_info = 0;

	switch (level) {
	case 100:
		i100.wki100_platform_id		= i->info100->platform_id;
		i100.wki100_computername	= talloc_strdup(mem_ctx, i->info100->server_name);
		i100.wki100_langroup		= talloc_strdup(mem_ctx, i->info100->domain_name);
		i100.wki100_ver_major		= i->info100->version_major;
		i100.wki100_ver_minor		= i->info100->version_minor;

		ADD_TO_ARRAY(mem_ctx, struct WKSTA_INFO_100, i100,
			     (struct WKSTA_INFO_100 **)buffer,
			     &num_info);
		break;

	case 101:
		i101.wki101_platform_id		= i->info101->platform_id;
		i101.wki101_computername	= talloc_strdup(mem_ctx, i->info101->server_name);
		i101.wki101_langroup		= talloc_strdup(mem_ctx, i->info101->domain_name);
		i101.wki101_ver_major		= i->info101->version_major;
		i101.wki101_ver_minor		= i->info101->version_minor;
		i101.wki101_lanroot		= talloc_strdup(mem_ctx, i->info101->lan_root);

		ADD_TO_ARRAY(mem_ctx, struct WKSTA_INFO_101, i101,
			     (struct WKSTA_INFO_101 **)buffer,
			     &num_info);
		break;

	case 102:
		i102.wki102_platform_id		= i->info102->platform_id;
		i102.wki102_computername	= talloc_strdup(mem_ctx, i->info102->server_name);
		i102.wki102_langroup		= talloc_strdup(mem_ctx, i->info102->domain_name);
		i102.wki102_ver_major		= i->info102->version_major;
		i102.wki102_ver_minor		= i->info102->version_minor;
		i102.wki102_lanroot		= talloc_strdup(mem_ctx, i->info102->lan_root);
		i102.wki102_logged_on_users	= i->info102->logged_on_users;

		ADD_TO_ARRAY(mem_ctx, struct WKSTA_INFO_102, i102,
			     (struct WKSTA_INFO_102 **)buffer,
			     &num_info);
		break;

	default:
		return NT_STATUS_NOT_SUPPORTED;
	}

	return NT_STATUS_OK;
}

/****************************************************************
****************************************************************/

WERROR NetWkstaGetInfo_r(struct libnetapi_ctx *ctx,
			 struct NetWkstaGetInfo *r)
{
	NTSTATUS status;
	WERROR werr;
	union wkssvc_NetWkstaInfo info;
	struct dcerpc_binding_handle *b;

	if (!r->out.buffer) {
		return WERR_INVALID_PARAMETER;
	}

	switch (r->in.level) {
		case 100:
		case 101:
		case 102:
			break;
		default:
			return WERR_INVALID_LEVEL;
	}

	werr = libnetapi_get_binding_handle(ctx, r->in.server_name,
					    &ndr_table_wkssvc,
					    &b);
	if (!W_ERROR_IS_OK(werr)) {
		goto done;
	}

	status = dcerpc_wkssvc_NetWkstaGetInfo(b, talloc_tos(),
					       r->in.server_name,
					       r->in.level,
					       &info,
					       &werr);
	if (!NT_STATUS_IS_OK(status)) {
		werr = ntstatus_to_werror(status);
		goto done;
	}

	if (!W_ERROR_IS_OK(werr)) {
		goto done;
	}

	status = map_wksta_info_to_WKSTA_INFO_buffer(ctx, r->in.level, &info,
						     r->out.buffer);
	if (!NT_STATUS_IS_OK(status)) {
		werr = ntstatus_to_werror(status);
		goto done;
	}

 done:
	return werr;
}
