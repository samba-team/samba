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

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

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

struct NET_DISPLAY_USER {
	const char * usri1_name;
	const char * usri1_comment;
	uint32_t usri1_flags;
	const char * usri1_full_name;
	uint32_t usri1_user_id;
	uint32_t usri1_next_index;
};

struct NET_DISPLAY_MACHINE {
	const char * usri2_name;
	const char * usri2_comment;
	uint32_t usri2_flags;
	uint32_t usri2_user_id;
	uint32_t usri2_next_index;
};

struct NET_DISPLAY_GROUP {
	const char * grpi3_name;
	const char * grpi3_comment;
	uint32_t grpi3_group_id;
	uint32_t grpi3_attributes;
	uint32_t grpi3_next_index;
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

/************************************************************//**
 *
 * NetJoinDomain
 *
 * @brief Join a computer to a domain or workgroup
 *
 * @param[in] server The server name to connect to
 * @param[in] domain The domain or workgroup to join
 * @param[in] account_ou The organizational Unit to create the computer account
 * in (AD only)
 * @param[in] account The domain account used for joining a domain
 * @param[in] password The domain account's password used for joining a domain
 * @param[in] join_flags Bitmask field to define specific join features
 * @return NET_API_STATUS
 *
 * example netdomjoin/netdomjoin.c
 ***************************************************************/

NET_API_STATUS NetJoinDomain(const char * server /* [in] */,
			     const char * domain /* [in] [ref] */,
			     const char * account_ou /* [in] */,
			     const char * account /* [in] */,
			     const char * password /* [in] */,
			     uint32_t join_flags /* [in] */);

/************************************************************//**
 *
 * NetUnjoinDomain
 *
 * @brief Unjoin a computer from a domain or workgroup
 *
 * @param[in] server_name The server name to connect to
 * @param[in] account The domain account used for unjoining a domain
 * @param[in] password The domain account's password used for unjoining a domain
 * @param[in] unjoin_flags Bitmask field to define specific unjoin features
 * @return NET_API_STATUS
 *
 ***************************************************************/

NET_API_STATUS NetUnjoinDomain(const char * server_name /* [in] */,
			       const char * account /* [in] */,
			       const char * password /* [in] */,
			       uint32_t unjoin_flags /* [in] */);

/************************************************************//**
 *
 * NetGetJoinInformation
 *
 * @brief Unjoin a computer from a domain or workgroup
 *
 * @param[in] server_name The server name to connect to
 * @param[out] name_buffer Returns the name of the workgroup or domain
 * @param[out] name_type  Returns the type of that name
 * @return NET_API_STATUS
 *
 * example netdomjoin-gui/netdomjoin-gui.c
 *
 ***************************************************************/

NET_API_STATUS NetGetJoinInformation(const char * server_name /* [in] */,
				     const char * *name_buffer /* [out] [ref] */,
				     uint16_t *name_type /* [out] [ref] */);

/************************************************************//**
 *
 * NetGetJoinableOUs
 *
 * @brief Query for the list of joinable organizational Units that can be used
 * for joining AD
 *
 * @param[in] server_name The server name to connect to
 * @param[in] domain The AD domain to query
 * @param[in] account The domain account used for the query
 * @param[in] password The domain account's password used for the query
 * @param[out] ou_count The number of ous returned
 * @param[out] ous Returned string array containing the ous
 * @return NET_API_STATUS
 *
 * example netdomjoin-gui/netdomjoin-gui.c
 *
 ***************************************************************/

NET_API_STATUS NetGetJoinableOUs(const char * server_name /* [in] */,
				 const char * domain /* [in] [ref] */,
				 const char * account /* [in] */,
				 const char * password /* [in] */,
				 uint32_t *ou_count /* [out] [ref] */,
				 const char * **ous /* [out] [ref] */);

/************************************************************//**
 *
 * NetServerGetInfo
 *
 * @brief Get Information on a server
 *
 * @param[in] server_name The server name to connect to
 * @param[in] level The level to define which information is requested
 * @param[out] buffer The returned buffer carrying the SERVER_INFO structure
 * @return NET_API_STATUS
 *
 ***************************************************************/

NET_API_STATUS NetServerGetInfo(const char * server_name /* [in] */,
				uint32_t level /* [in] */,
				uint8_t **buffer /* [out] [ref] */);

/************************************************************//**
 *
 * NetServerSetInfo
 *
 * @brief Get Information on a server
 *
 * @param[in] server_name The server name to connect to
 * @param[in] level The level to define which information is set
 * @param[in] buffer The buffer carrying the SERVER_INFO structure
 * @param[out] parm_error On failure returns the invalid SERVER_INFO member
 * @return NET_API_STATUS
 *
 ***************************************************************/

NET_API_STATUS NetServerSetInfo(const char * server_name /* [in] */,
				uint32_t level /* [in] */,
				uint8_t *buffer /* [in] [ref] */,
				uint32_t *parm_error /* [out] [ref] */);

/************************************************************//**
 *
 * NetGetDCName
 *
 * @brief Query for the PDC for a given domain
 *
 * @param[in] server_name The server name to connect to
 * @param[in] domain_name The name of the domain to lookup
 * @param[out] buffer The name of the domain to lookup
 * @return NET_API_STATUS
 *
 * example getdc/getdc.c
 ***************************************************************/

NET_API_STATUS NetGetDCName(const char * server_name /* [in] */,
			    const char * domain_name /* [in] */,
			    uint8_t **buffer /* [out] [ref] */);

/************************************************************//**
 *
 * NetGetAnyDCName
 *
 * @brief Query for any DC for a given domain
 *
 * @param[in] server_name The server name to connect to
 * @param[in] domain_name The name of the domain to lookup
 * @param[out] buffer The name of the domain to lookup
 * @return NET_API_STATUS
 *
 * example getdc/getdc.c
 ***************************************************************/

NET_API_STATUS NetGetAnyDCName(const char * server_name /* [in] */,
			       const char * domain_name /* [in] */,
			       uint8_t **buffer /* [out] [ref] */);


/************************************************************//**
 *
 * DsGetDcName
 *
 * @brief Lookup a DC for a given domain and return information structure
 *
 * @param[in] server_name The server name to connect to
 * @param[in] domain_name The name of the domain to lookup (cannot be NULL)
 * @param[in] domain_guid The GUID of the domain to lookup (optional)
 * @param[in] site_name The name of the site the DC should reside in
 * @param[in] flags A bitmask to request specific features supported by the DC
 * @param[out] dc_info Pointer to a DOMAIN_CONTROLLER_INFO structure
 * @return NET_API_STATUS
 *
 * example dsgetdc/dsgetdc.c
 ***************************************************************/

NET_API_STATUS DsGetDcName(const char * server_name /* [in] [unique] */,
			   const char * domain_name /* [in] [ref] */,
			   struct GUID *domain_guid /* [in] [unique] */,
			   const char * site_name /* [in] [unique] */,
			   uint32_t flags /* [in] */,
			   struct DOMAIN_CONTROLLER_INFO **dc_info /* [out] [ref] */);

/************************************************************//**
 *
 * NetUserAdd
 *
 * @brief Create a user on a given server
 *
 * @param[in] server_name The server name to connect to
 * @param[in] level The level of the USER_INFO structure passed in (Currently
 * only level 1 is supported)
 * @param[in] buffer The buffer carrying the USER_INFO structure
 * @param[out] parm_error In case of error returns the failing member of the
 * structure
 * @return NET_API_STATUS
 *
 * example user/user_add.c
 ***************************************************************/

NET_API_STATUS NetUserAdd(const char * server_name /* [in] */,
			  uint32_t level /* [in] */,
			  uint8_t *buffer /* [in] [ref] */,
			  uint32_t *parm_error /* [out] [ref] */);

/************************************************************//**
 *
 * NetUserDel
 *
 * @brief Delete a user on a given server
 *
 * @param[in] server_name The server name to connect to
 * @param[in] user_name The user account to delete
 * @return NET_API_STATUS
 *
 * example user/user_del.c
 ***************************************************************/

NET_API_STATUS NetUserDel(const char * server_name /* [in] */,
			  const char * user_name /* [in] */);

/************************************************************//**
 *
 * NetUserEnum
 *
 * @brief Enumerate accounts on a server
 *
 * @param[in] server_name The server name to connect to
 * @param[in] level The enumeration level used for the query (Currently only
 * level 0 is supported)
 * @param[in] filter The account flags filter used for the query
 * @param[out] buffer The returned enumeration buffer
 * @param[in] prefmaxlen The requested maximal buffer size
 * @param[out] entries_read The number of returned entries
 * @param[out] total_entries The number of total entries
 * @param[in,out] resume_handle A handle passed in and returned for resuming
 * operations
 * @return NET_API_STATUS
 *
 * example user/user_enum.c
 ***************************************************************/

NET_API_STATUS NetUserEnum(const char * server_name /* [in] */,
			   uint32_t level /* [in] */,
			   uint32_t filter /* [in] */,
			   uint8_t **buffer /* [out] [ref] */,
			   uint32_t prefmaxlen /* [in] */,
			   uint32_t *entries_read /* [out] [ref] */,
			   uint32_t *total_entries /* [out] [ref] */,
			   uint32_t *resume_handle /* [in,out] [ref] */);

/************************************************************//**
 *
 * NetQueryDisplayInformation
 *
 * @brief Enumerate accounts on a server
 *
 * @param[in] server_name The server name to connect to
 * @param[in] level The enumeration level used for the query
 * @param[in] idx The index to start the the display enumeration at
 * @param[in] entries_requested The number of entries requested
 * @param[in] prefmaxlen The requested maximal buffer size
 * @param[out] entries_read The number of returned entries
 * @param[out] buffer The returned display information buffer
 * @return NET_API_STATUS
 *
 * example user/user_dispinfo.c
 ***************************************************************/

NET_API_STATUS NetQueryDisplayInformation(const char * server_name /* [in] [unique] */,
					  uint32_t level /* [in] */,
					  uint32_t idx /* [in] */,
					  uint32_t entries_requested /* [in] */,
					  uint32_t prefmaxlen /* [in] */,
					  uint32_t *entries_read /* [out] [ref] */,
					  void **buffer /* [out] [noprint,ref] */);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LIB_NETAPI_H__ */
