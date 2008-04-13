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

#define ERROR_MORE_DATA	( 234L )

/****************************************************************
****************************************************************/

#ifndef _HEADER_misc

struct GUID {
	uint32_t time_low;
	uint16_t time_mid;
	uint16_t time_hi_and_version;
	uint8_t clock_seq[2];
	uint8_t node[6];
};

#endif /* _HEADER_misc */

#ifndef _HEADER_libnetapi

struct DOMAIN_CONTROLLER_INFO {
	const char * domain_controller_name;
	const char * domain_controller_address;
	uint32_t domain_controller_address_type;
	struct GUID domain_guid;
	const char * domain_name;
	const char * dns_forest_name;
	uint32_t flags;
	const char * dc_site_name;
	const char * client_site_name;
};

struct SERVER_INFO_1005 {
	const char * sv1005_comment;
};

struct USER_INFO_0 {
	const char * usri0_name;
};

struct USER_INFO_1 {
	const char * usri1_name;
	const char * usri1_password;
	uint32_t usri1_password_age;
	uint32_t usri1_priv;
	const char * usri1_home_dir;
	const char * usri1_comment;
	uint32_t usri1_flags;
	const char * usri1_script_path;
};

#endif /* _HEADER_libnetapi */

/****************************************************************
****************************************************************/

struct libnetapi_ctx {
	char *debuglevel;
	char *error_string;
	char *username;
	char *workgroup;
	char *password;
	char *krb5_cc_env;
	int use_kerberos;
};

/****************************************************************
****************************************************************/

NET_API_STATUS libnetapi_init(struct libnetapi_ctx **ctx);

/****************************************************************
****************************************************************/

NET_API_STATUS libnetapi_free(struct libnetapi_ctx *ctx);

/****************************************************************
****************************************************************/

NET_API_STATUS libnetapi_getctx(struct libnetapi_ctx **ctx);

/****************************************************************
****************************************************************/

NET_API_STATUS libnetapi_set_debuglevel(struct libnetapi_ctx *ctx,
					const char *debuglevel);

/****************************************************************
****************************************************************/

NET_API_STATUS libnetapi_set_username(struct libnetapi_ctx *ctx,
				      const char *username);

/****************************************************************
****************************************************************/

NET_API_STATUS libnetapi_set_password(struct libnetapi_ctx *ctx,
				      const char *password);

/****************************************************************
****************************************************************/

NET_API_STATUS libnetapi_set_workgroup(struct libnetapi_ctx *ctx,
				       const char *workgroup);

/****************************************************************
****************************************************************/

NET_API_STATUS libnetapi_set_use_kerberos(struct libnetapi_ctx *ctx);

/****************************************************************
****************************************************************/

const char *libnetapi_errstr(NET_API_STATUS status);

/****************************************************************
****************************************************************/

const char *libnetapi_get_error_string(struct libnetapi_ctx *ctx,
				       NET_API_STATUS status);


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


/****************************************************************
 DsGetDcName
****************************************************************/

NET_API_STATUS DsGetDcName(const char * server_name /* [in] [unique] */,
			   const char * domain_name /* [in] [ref] */,
			   struct GUID *domain_guid /* [in] [unique] */,
			   const char * site_name /* [in] [unique] */,
			   uint32_t flags /* [in] */,
			   struct DOMAIN_CONTROLLER_INFO **dc_info /* [out] [ref] */);

/****************************************************************
 NetUserAdd
****************************************************************/

NET_API_STATUS NetUserAdd(const char * server_name /* [in] */,
			  uint32_t level /* [in] */,
			  uint8_t *buffer /* [in] [ref] */,
			  uint32_t *parm_error /* [out] [ref] */);

/****************************************************************
 NetUserDel
****************************************************************/

NET_API_STATUS NetUserDel(const char * server_name /* [in] */,
			  const char * user_name /* [in] */);

/****************************************************************
 NetUserEnum
****************************************************************/

NET_API_STATUS NetUserEnum(const char * server_name /* [in] */,
			   uint32_t level /* [in] */,
			   uint32_t filter /* [in] */,
			   uint8_t **buffer /* [out] [ref] */,
			   uint32_t prefmaxlen /* [in] */,
			   uint32_t *entries_read /* [out] [ref] */,
			   uint32_t *total_entries /* [out] [ref] */,
			   uint32_t *resume_handle /* [in,out] [ref] */);

NET_API_STATUS NetQueryDisplayInformation(const char * server_name /* [in] [unique] */,
					  uint32_t level /* [in] */,
					  uint32_t idx /* [in] */,
					  uint32_t entries_requested /* [in] */,
					  uint32_t prefmaxlen /* [in] */,
					  uint32_t *entries_read /* [out] [ref] */,
					  void **buffer /* [out] [noprint,ref] */);

#endif
