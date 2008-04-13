/*
 *  Unix SMB/CIFS implementation.
 *  NetApi Support
 *  Copyright (C) Guenther Deschner 2007-2008
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
#include "libnetapi.h"
#include "librpc/gen_ndr/ndr_libnetapi.h"

/****************************************************************
 NetJoinDomain
****************************************************************/

NET_API_STATUS NetJoinDomain(const char * server /* [in] [unique] */,
			     const char * domain /* [in] [ref] */,
			     const char * account_ou /* [in] [unique] */,
			     const char * account /* [in] [unique] */,
			     const char * password /* [in] [unique] */,
			     uint32_t join_flags /* [in] */)
{
	struct NetJoinDomain r;
	struct libnetapi_ctx *ctx = NULL;
	NET_API_STATUS status;
	WERROR werr;

	status = libnetapi_getctx(&ctx);
	if (status != 0) {
		return status;
	}

	/* In parameters */
	r.in.server = server;
	r.in.domain = domain;
	r.in.account_ou = account_ou;
	r.in.account = account;
	r.in.password = password;
	r.in.join_flags = join_flags;

	/* Out parameters */

	if (DEBUGLEVEL >= 10) {
		NDR_PRINT_IN_DEBUG(NetJoinDomain, &r);
	}

	if (LIBNETAPI_LOCAL_SERVER(server)) {
		werr = NetJoinDomain_l(ctx, &r);
	} else {
		werr = NetJoinDomain_r(ctx, &r);
	}

	r.out.result = W_ERROR_V(werr);

	if (DEBUGLEVEL >= 10) {
		NDR_PRINT_OUT_DEBUG(NetJoinDomain, &r);
	}

	return r.out.result;
}

/****************************************************************
 NetUnjoinDomain
****************************************************************/

NET_API_STATUS NetUnjoinDomain(const char * server_name /* [in] [unique] */,
			       const char * account /* [in] [unique] */,
			       const char * password /* [in] [unique] */,
			       uint32_t unjoin_flags /* [in] */)
{
	struct NetUnjoinDomain r;
	struct libnetapi_ctx *ctx = NULL;
	NET_API_STATUS status;
	WERROR werr;

	status = libnetapi_getctx(&ctx);
	if (status != 0) {
		return status;
	}

	/* In parameters */
	r.in.server_name = server_name;
	r.in.account = account;
	r.in.password = password;
	r.in.unjoin_flags = unjoin_flags;

	/* Out parameters */

	if (DEBUGLEVEL >= 10) {
		NDR_PRINT_IN_DEBUG(NetUnjoinDomain, &r);
	}

	if (LIBNETAPI_LOCAL_SERVER(server_name)) {
		werr = NetUnjoinDomain_l(ctx, &r);
	} else {
		werr = NetUnjoinDomain_r(ctx, &r);
	}

	r.out.result = W_ERROR_V(werr);

	if (DEBUGLEVEL >= 10) {
		NDR_PRINT_OUT_DEBUG(NetUnjoinDomain, &r);
	}

	return r.out.result;
}

/****************************************************************
 NetGetJoinInformation
****************************************************************/

NET_API_STATUS NetGetJoinInformation(const char * server_name /* [in] [unique] */,
				     const char * *name_buffer /* [out] [ref] */,
				     uint16_t *name_type /* [out] [ref] */)
{
	struct NetGetJoinInformation r;
	struct libnetapi_ctx *ctx = NULL;
	NET_API_STATUS status;
	WERROR werr;

	status = libnetapi_getctx(&ctx);
	if (status != 0) {
		return status;
	}

	/* In parameters */
	r.in.server_name = server_name;

	/* Out parameters */
	r.out.name_buffer = name_buffer;
	r.out.name_type = name_type;

	if (DEBUGLEVEL >= 10) {
		NDR_PRINT_IN_DEBUG(NetGetJoinInformation, &r);
	}

	if (LIBNETAPI_LOCAL_SERVER(server_name)) {
		werr = NetGetJoinInformation_l(ctx, &r);
	} else {
		werr = NetGetJoinInformation_r(ctx, &r);
	}

	r.out.result = W_ERROR_V(werr);

	if (DEBUGLEVEL >= 10) {
		NDR_PRINT_OUT_DEBUG(NetGetJoinInformation, &r);
	}

	return r.out.result;
}

/****************************************************************
 NetGetJoinableOUs
****************************************************************/

NET_API_STATUS NetGetJoinableOUs(const char * server_name /* [in] [unique] */,
				 const char * domain /* [in] [ref] */,
				 const char * account /* [in] [unique] */,
				 const char * password /* [in] [unique] */,
				 uint32_t *ou_count /* [out] [ref] */,
				 const char * **ous /* [out] [ref] */)
{
	struct NetGetJoinableOUs r;
	struct libnetapi_ctx *ctx = NULL;
	NET_API_STATUS status;
	WERROR werr;

	status = libnetapi_getctx(&ctx);
	if (status != 0) {
		return status;
	}

	/* In parameters */
	r.in.server_name = server_name;
	r.in.domain = domain;
	r.in.account = account;
	r.in.password = password;

	/* Out parameters */
	r.out.ou_count = ou_count;
	r.out.ous = ous;

	if (DEBUGLEVEL >= 10) {
		NDR_PRINT_IN_DEBUG(NetGetJoinableOUs, &r);
	}

	if (LIBNETAPI_LOCAL_SERVER(server_name)) {
		werr = NetGetJoinableOUs_l(ctx, &r);
	} else {
		werr = NetGetJoinableOUs_r(ctx, &r);
	}

	r.out.result = W_ERROR_V(werr);

	if (DEBUGLEVEL >= 10) {
		NDR_PRINT_OUT_DEBUG(NetGetJoinableOUs, &r);
	}

	return r.out.result;
}

/****************************************************************
 NetServerGetInfo
****************************************************************/

NET_API_STATUS NetServerGetInfo(const char * server_name /* [in] [unique] */,
				uint32_t level /* [in] */,
				uint8_t **buffer /* [out] [ref] */)
{
	struct NetServerGetInfo r;
	struct libnetapi_ctx *ctx = NULL;
	NET_API_STATUS status;
	WERROR werr;

	status = libnetapi_getctx(&ctx);
	if (status != 0) {
		return status;
	}

	/* In parameters */
	r.in.server_name = server_name;
	r.in.level = level;

	/* Out parameters */
	r.out.buffer = buffer;

	if (DEBUGLEVEL >= 10) {
		NDR_PRINT_IN_DEBUG(NetServerGetInfo, &r);
	}

	if (LIBNETAPI_LOCAL_SERVER(server_name)) {
		werr = NetServerGetInfo_l(ctx, &r);
	} else {
		werr = NetServerGetInfo_r(ctx, &r);
	}

	r.out.result = W_ERROR_V(werr);

	if (DEBUGLEVEL >= 10) {
		NDR_PRINT_OUT_DEBUG(NetServerGetInfo, &r);
	}

	return r.out.result;
}

/****************************************************************
 NetServerSetInfo
****************************************************************/

NET_API_STATUS NetServerSetInfo(const char * server_name /* [in] [unique] */,
				uint32_t level /* [in] */,
				uint8_t *buffer /* [in] [ref] */,
				uint32_t *parm_error /* [out] [ref] */)
{
	struct NetServerSetInfo r;
	struct libnetapi_ctx *ctx = NULL;
	NET_API_STATUS status;
	WERROR werr;

	status = libnetapi_getctx(&ctx);
	if (status != 0) {
		return status;
	}

	/* In parameters */
	r.in.server_name = server_name;
	r.in.level = level;
	r.in.buffer = buffer;

	/* Out parameters */
	r.out.parm_error = parm_error;

	if (DEBUGLEVEL >= 10) {
		NDR_PRINT_IN_DEBUG(NetServerSetInfo, &r);
	}

	if (LIBNETAPI_LOCAL_SERVER(server_name)) {
		werr = NetServerSetInfo_l(ctx, &r);
	} else {
		werr = NetServerSetInfo_r(ctx, &r);
	}

	r.out.result = W_ERROR_V(werr);

	if (DEBUGLEVEL >= 10) {
		NDR_PRINT_OUT_DEBUG(NetServerSetInfo, &r);
	}

	return r.out.result;
}

/****************************************************************
 NetGetDCName
****************************************************************/

NET_API_STATUS NetGetDCName(const char * server_name /* [in] [unique] */,
			    const char * domain_name /* [in] [unique] */,
			    uint8_t **buffer /* [out] [ref] */)
{
	struct NetGetDCName r;
	struct libnetapi_ctx *ctx = NULL;
	NET_API_STATUS status;
	WERROR werr;

	status = libnetapi_getctx(&ctx);
	if (status != 0) {
		return status;
	}

	/* In parameters */
	r.in.server_name = server_name;
	r.in.domain_name = domain_name;

	/* Out parameters */
	r.out.buffer = buffer;

	if (DEBUGLEVEL >= 10) {
		NDR_PRINT_IN_DEBUG(NetGetDCName, &r);
	}

	if (LIBNETAPI_LOCAL_SERVER(server_name)) {
		werr = NetGetDCName_l(ctx, &r);
	} else {
		werr = NetGetDCName_r(ctx, &r);
	}

	r.out.result = W_ERROR_V(werr);

	if (DEBUGLEVEL >= 10) {
		NDR_PRINT_OUT_DEBUG(NetGetDCName, &r);
	}

	return r.out.result;
}

/****************************************************************
 NetGetAnyDCName
****************************************************************/

NET_API_STATUS NetGetAnyDCName(const char * server_name /* [in] [unique] */,
			       const char * domain_name /* [in] [unique] */,
			       uint8_t **buffer /* [out] [ref] */)
{
	struct NetGetAnyDCName r;
	struct libnetapi_ctx *ctx = NULL;
	NET_API_STATUS status;
	WERROR werr;

	status = libnetapi_getctx(&ctx);
	if (status != 0) {
		return status;
	}

	/* In parameters */
	r.in.server_name = server_name;
	r.in.domain_name = domain_name;

	/* Out parameters */
	r.out.buffer = buffer;

	if (DEBUGLEVEL >= 10) {
		NDR_PRINT_IN_DEBUG(NetGetAnyDCName, &r);
	}

	if (LIBNETAPI_LOCAL_SERVER(server_name)) {
		werr = NetGetAnyDCName_l(ctx, &r);
	} else {
		werr = NetGetAnyDCName_r(ctx, &r);
	}

	r.out.result = W_ERROR_V(werr);

	if (DEBUGLEVEL >= 10) {
		NDR_PRINT_OUT_DEBUG(NetGetAnyDCName, &r);
	}

	return r.out.result;
}

/****************************************************************
 DsGetDcName
****************************************************************/

NET_API_STATUS DsGetDcName(const char * server_name /* [in] [unique] */,
			   const char * domain_name /* [in] [ref] */,
			   struct GUID *domain_guid /* [in] [unique] */,
			   const char * site_name /* [in] [unique] */,
			   uint32_t flags /* [in] */,
			   struct DOMAIN_CONTROLLER_INFO **dc_info /* [out] [ref] */)
{
	struct DsGetDcName r;
	struct libnetapi_ctx *ctx = NULL;
	NET_API_STATUS status;
	WERROR werr;

	status = libnetapi_getctx(&ctx);
	if (status != 0) {
		return status;
	}

	/* In parameters */
	r.in.server_name = server_name;
	r.in.domain_name = domain_name;
	r.in.domain_guid = domain_guid;
	r.in.site_name = site_name;
	r.in.flags = flags;

	/* Out parameters */
	r.out.dc_info = dc_info;

	if (DEBUGLEVEL >= 10) {
		NDR_PRINT_IN_DEBUG(DsGetDcName, &r);
	}

	if (LIBNETAPI_LOCAL_SERVER(server_name)) {
		werr = DsGetDcName_l(ctx, &r);
	} else {
		werr = DsGetDcName_r(ctx, &r);
	}

	r.out.result = W_ERROR_V(werr);

	if (DEBUGLEVEL >= 10) {
		NDR_PRINT_OUT_DEBUG(DsGetDcName, &r);
	}

	return r.out.result;
}

/****************************************************************
 NetUserAdd
****************************************************************/

NET_API_STATUS NetUserAdd(const char * server_name /* [in] [unique] */,
			  uint32_t level /* [in] */,
			  uint8_t *buffer /* [in] [ref] */,
			  uint32_t *parm_error /* [out] [ref] */)
{
	struct NetUserAdd r;
	struct libnetapi_ctx *ctx = NULL;
	NET_API_STATUS status;
	WERROR werr;

	status = libnetapi_getctx(&ctx);
	if (status != 0) {
		return status;
	}

	/* In parameters */
	r.in.server_name = server_name;
	r.in.level = level;
	r.in.buffer = buffer;

	/* Out parameters */
	r.out.parm_error = parm_error;

	if (DEBUGLEVEL >= 10) {
		NDR_PRINT_IN_DEBUG(NetUserAdd, &r);
	}

	if (LIBNETAPI_LOCAL_SERVER(server_name)) {
		werr = NetUserAdd_l(ctx, &r);
	} else {
		werr = NetUserAdd_r(ctx, &r);
	}

	r.out.result = W_ERROR_V(werr);

	if (DEBUGLEVEL >= 10) {
		NDR_PRINT_OUT_DEBUG(NetUserAdd, &r);
	}

	return r.out.result;
}

/****************************************************************
 NetUserDel
****************************************************************/

NET_API_STATUS NetUserDel(const char * server_name /* [in] [unique] */,
			  const char * user_name /* [in] [ref] */)
{
	struct NetUserDel r;
	struct libnetapi_ctx *ctx = NULL;
	NET_API_STATUS status;
	WERROR werr;

	status = libnetapi_getctx(&ctx);
	if (status != 0) {
		return status;
	}

	/* In parameters */
	r.in.server_name = server_name;
	r.in.user_name = user_name;

	/* Out parameters */

	if (DEBUGLEVEL >= 10) {
		NDR_PRINT_IN_DEBUG(NetUserDel, &r);
	}

	if (LIBNETAPI_LOCAL_SERVER(server_name)) {
		werr = NetUserDel_l(ctx, &r);
	} else {
		werr = NetUserDel_r(ctx, &r);
	}

	r.out.result = W_ERROR_V(werr);

	if (DEBUGLEVEL >= 10) {
		NDR_PRINT_OUT_DEBUG(NetUserDel, &r);
	}

	return r.out.result;
}

/****************************************************************
 NetUserEnum
****************************************************************/

NET_API_STATUS NetUserEnum(const char * server_name /* [in] [unique] */,
			   uint32_t level /* [in] */,
			   uint32_t filter /* [in] */,
			   uint8_t **buffer /* [out] [ref] */,
			   uint32_t prefmaxlen /* [in] */,
			   uint32_t *entries_read /* [out] [ref] */,
			   uint32_t *total_entries /* [out] [ref] */,
			   uint32_t *resume_handle /* [in,out] [ref] */)
{
	struct NetUserEnum r;
	struct libnetapi_ctx *ctx = NULL;
	NET_API_STATUS status;
	WERROR werr;

	status = libnetapi_getctx(&ctx);
	if (status != 0) {
		return status;
	}

	/* In parameters */
	r.in.server_name = server_name;
	r.in.level = level;
	r.in.filter = filter;
	r.in.prefmaxlen = prefmaxlen;
	r.in.resume_handle = resume_handle;

	/* Out parameters */
	r.out.buffer = buffer;
	r.out.entries_read = entries_read;
	r.out.total_entries = total_entries;
	r.out.resume_handle = resume_handle;

	if (DEBUGLEVEL >= 10) {
		NDR_PRINT_IN_DEBUG(NetUserEnum, &r);
	}

	if (LIBNETAPI_LOCAL_SERVER(server_name)) {
		werr = NetUserEnum_l(ctx, &r);
	} else {
		werr = NetUserEnum_r(ctx, &r);
	}

	r.out.result = W_ERROR_V(werr);

	if (DEBUGLEVEL >= 10) {
		NDR_PRINT_OUT_DEBUG(NetUserEnum, &r);
	}

	return r.out.result;
}

/****************************************************************
 NetQueryDisplayInformation
****************************************************************/

NET_API_STATUS NetQueryDisplayInformation(const char * server_name /* [in] [unique] */,
					  uint32_t level /* [in] */,
					  uint32_t idx /* [in] */,
					  uint32_t entries_requested /* [in] */,
					  uint32_t prefmaxlen /* [in] */,
					  uint32_t *entries_read /* [out] [ref] */,
					  void **buffer /* [out] [noprint,ref] */)
{
	struct NetQueryDisplayInformation r;
	struct libnetapi_ctx *ctx = NULL;
	NET_API_STATUS status;
	WERROR werr;

	status = libnetapi_getctx(&ctx);
	if (status != 0) {
		return status;
	}

	/* In parameters */
	r.in.server_name = server_name;
	r.in.level = level;
	r.in.idx = idx;
	r.in.entries_requested = entries_requested;
	r.in.prefmaxlen = prefmaxlen;

	/* Out parameters */
	r.out.entries_read = entries_read;
	r.out.buffer = buffer;

	if (DEBUGLEVEL >= 10) {
		NDR_PRINT_IN_DEBUG(NetQueryDisplayInformation, &r);
	}

	if (LIBNETAPI_LOCAL_SERVER(server_name)) {
		werr = NetQueryDisplayInformation_l(ctx, &r);
	} else {
		werr = NetQueryDisplayInformation_r(ctx, &r);
	}

	r.out.result = W_ERROR_V(werr);

	if (DEBUGLEVEL >= 10) {
		NDR_PRINT_OUT_DEBUG(NetQueryDisplayInformation, &r);
	}

	return r.out.result;
}

