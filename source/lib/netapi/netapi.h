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

#ifndef __LIB_NETAPI_H__
#define __LIB_NETAPI_H__

/****************************************************************
 NET_API_STATUS
****************************************************************/

typedef enum {
	NET_API_STATUS_SUCCESS = 0
} NET_API_STATUS;

/****************************************************************
****************************************************************/

struct libnetapi_ctx {
	char *debuglevel;
	char *error_string;
	char *username;
	char *workgroup;
	char *password;
	char *krb5_cc_env;
};

/****************************************************************
****************************************************************/

NET_API_STATUS libnetapi_init(struct libnetapi_ctx **ctx);
NET_API_STATUS libnetapi_getctx(struct libnetapi_ctx **ctx);
NET_API_STATUS libnetapi_free(struct libnetapi_ctx *ctx);
NET_API_STATUS libnetapi_set_debuglevel(struct libnetapi_ctx *ctx, const char *debuglevel);
NET_API_STATUS libnetapi_get_debuglevel(struct libnetapi_ctx *ctx, char **debuglevel);
NET_API_STATUS libnetapi_set_username(struct libnetapi_ctx *ctx, const char *username);
NET_API_STATUS libnetapi_set_password(struct libnetapi_ctx *ctx, const char *password);
NET_API_STATUS libnetapi_set_workgroup(struct libnetapi_ctx *ctx, const char *workgroup);
const char *libnetapi_errstr(NET_API_STATUS status);
NET_API_STATUS libnetapi_set_error_string(struct libnetapi_ctx *ctx, const char *format, ...);
const char *libnetapi_get_error_string(struct libnetapi_ctx *ctx, NET_API_STATUS status);


/****************************************************************
 NetApiBufferFree
****************************************************************/

NET_API_STATUS NetApiBufferFree(void *buffer);

/****************************************************************
 NetJoinDomain
****************************************************************/

NET_API_STATUS NetJoinDomain(const char * server /* [in] */,
			     const char * domain /* [in] [ref] */,
			     const char * account_ou /* [in] */,
			     const char * account /* [in] */,
			     const char * password /* [in] */,
			     uint32_t join_flags /* [in] */);

/****************************************************************
 NetUnjoinDomain
****************************************************************/

NET_API_STATUS NetUnjoinDomain(const char * server_name /* [in] */,
			       const char * account /* [in] */,
			       const char * password /* [in] */,
			       uint32_t unjoin_flags /* [in] */);

/****************************************************************
 NetGetJoinInformation
****************************************************************/

NET_API_STATUS NetGetJoinInformation(const char * server_name /* [in] */,
				     const char * *name_buffer /* [out] [ref] */,
				     uint16_t *name_type /* [out] [ref] */);

/****************************************************************
 NetGetJoinableOUs
****************************************************************/

NET_API_STATUS NetGetJoinableOUs(const char * server_name /* [in] */,
				 const char * domain /* [in] [ref] */,
				 const char * account /* [in] */,
				 const char * password /* [in] */,
				 uint32_t *ou_count /* [out] [ref] */,
				 const char * **ous /* [out] [ref] */);

/****************************************************************
 NetServerGetInfo
****************************************************************/

NET_API_STATUS NetServerGetInfo(const char * server_name /* [in] */,
				uint32_t level /* [in] */,
				uint8_t **buffer /* [out] [ref] */);

/****************************************************************
 NetServerSetInfo
****************************************************************/

NET_API_STATUS NetServerSetInfo(const char * server_name /* [in] */,
				uint32_t level /* [in] */,
				uint8_t *buffer /* [in] [ref] */,
				uint32_t *parm_error /* [out] [ref] */);

/****************************************************************
 NetGetDCName
****************************************************************/

NET_API_STATUS NetGetDCName(const char * server_name /* [in] */,
			    const char * domain_name /* [in] */,
			    uint8_t **buffer /* [out] [ref] */);

/****************************************************************
 NetGetAnyDCName
****************************************************************/

NET_API_STATUS NetGetAnyDCName(const char * server_name /* [in] */,
			       const char * domain_name /* [in] */,
			       uint8_t **buffer /* [out] [ref] */);

#endif
