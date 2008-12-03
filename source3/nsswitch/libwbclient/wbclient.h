/*
   Unix SMB/CIFS implementation.

   Winbind client API

   Copyright (C) Gerald (Jerry) Carter 2007

   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 3 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Library General Public License for more details.

   You should have received a copy of the GNU Lesser General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef _WBCLIENT_H
#define _WBCLIENT_H

#include <pwd.h>
#include <grp.h>

/* Define error types */

/**
 *  @brief Status codes returned from wbc functions
 **/

enum _wbcErrType {
	WBC_ERR_SUCCESS = 0,    /**< Successful completion **/
	WBC_ERR_NOT_IMPLEMENTED,/**< Function not implemented **/
	WBC_ERR_UNKNOWN_FAILURE,/**< General failure **/
	WBC_ERR_NO_MEMORY,      /**< Memory allocation error **/
	WBC_ERR_INVALID_SID,    /**< Invalid SID format **/
	WBC_ERR_INVALID_PARAM,  /**< An Invalid parameter was supplied **/
	WBC_ERR_WINBIND_NOT_AVAILABLE,   /**< Winbind daemon is not available **/
	WBC_ERR_DOMAIN_NOT_FOUND,        /**< Domain is not trusted or cannot be found **/
	WBC_ERR_INVALID_RESPONSE,        /**< Winbind returned an invalid response **/
	WBC_ERR_NSS_ERROR,            /**< NSS_STATUS error **/
	WBC_ERR_AUTH_ERROR,        /**< Authentication failed **/
	WBC_ERR_UNKNOWN_USER,      /**< User account cannot be found */
	WBC_ERR_UNKNOWN_GROUP,     /**< Group account cannot be found */
	WBC_ERR_PWD_CHANGE_FAILED  /**< Password Change has failed */
};

typedef enum _wbcErrType wbcErr;

#define WBC_ERROR_IS_OK(x) ((x) == WBC_ERR_SUCCESS)

const char *wbcErrorString(wbcErr error);

/**
 *  @brief Some useful details about the wbclient library
 *
 *  0.1: Initial version
 *  0.2: Added wbcRemoveUidMapping()
 *       Added wbcRemoveGidMapping()
 **/
#define WBCLIENT_MAJOR_VERSION 0
#define WBCLIENT_MINOR_VERSION 2
#define WBCLIENT_VENDOR_VERSION "Samba libwbclient"
struct wbcLibraryDetails {
	uint16_t major_version;
	uint16_t minor_version;
	const char *vendor_version;
};

/**
 *  @brief Some useful details about the running winbindd
 *
 **/
struct wbcInterfaceDetails {
	uint32_t interface_version;
	const char *winbind_version;
	char winbind_separator;
	const char *netbios_name;
	const char *netbios_domain;
	const char *dns_domain;
};

/*
 * Data types used by the Winbind Client API
 */

#ifndef WBC_MAXSUBAUTHS
#define WBC_MAXSUBAUTHS 15 /* max sub authorities in a SID */
#endif

/**
 *  @brief Windows Security Identifier
 *
 **/

struct wbcDomainSid {
	uint8_t   sid_rev_num;
	uint8_t   num_auths;
	uint8_t   id_auth[6];
	uint32_t  sub_auths[WBC_MAXSUBAUTHS];
};

/**
 * @brief Security Identifier type
 **/

enum wbcSidType {
	WBC_SID_NAME_USE_NONE=0,
	WBC_SID_NAME_USER=1,
	WBC_SID_NAME_DOM_GRP=2,
	WBC_SID_NAME_DOMAIN=3,
	WBC_SID_NAME_ALIAS=4,
	WBC_SID_NAME_WKN_GRP=5,
	WBC_SID_NAME_DELETED=6,
	WBC_SID_NAME_INVALID=7,
	WBC_SID_NAME_UNKNOWN=8,
	WBC_SID_NAME_COMPUTER=9
};

/**
 * @brief Security Identifier with attributes
 **/

struct wbcSidWithAttr {
	struct wbcDomainSid sid;
	uint32_t attributes;
};

/* wbcSidWithAttr->attributes */

#define WBC_SID_ATTR_GROUP_MANDATORY		0x00000001
#define WBC_SID_ATTR_GROUP_ENABLED_BY_DEFAULT	0x00000002
#define WBC_SID_ATTR_GROUP_ENABLED 		0x00000004
#define WBC_SID_ATTR_GROUP_OWNER 		0x00000008
#define WBC_SID_ATTR_GROUP_USEFOR_DENY_ONLY 	0x00000010
#define WBC_SID_ATTR_GROUP_RESOURCE 		0x20000000
#define WBC_SID_ATTR_GROUP_LOGON_ID 		0xC0000000

/**
 *  @brief Windows GUID
 *
 **/

struct wbcGuid {
	uint32_t time_low;
	uint16_t time_mid;
	uint16_t time_hi_and_version;
	uint8_t clock_seq[2];
	uint8_t node[6];
};

/**
 * @brief Domain Information
 **/

struct wbcDomainInfo {
	char *short_name;
	char *dns_name;
	struct wbcDomainSid sid;
	uint32_t domain_flags;
	uint32_t trust_flags;
	uint32_t trust_type;
};

/* wbcDomainInfo->domain_flags */

#define WBC_DOMINFO_DOMAIN_UNKNOWN    0x00000000
#define WBC_DOMINFO_DOMAIN_NATIVE     0x00000001
#define WBC_DOMINFO_DOMAIN_AD         0x00000002
#define WBC_DOMINFO_DOMAIN_PRIMARY    0x00000004
#define WBC_DOMINFO_DOMAIN_OFFLINE    0x00000008

/* wbcDomainInfo->trust_flags */

#define WBC_DOMINFO_TRUST_TRANSITIVE  0x00000001
#define WBC_DOMINFO_TRUST_INCOMING    0x00000002
#define WBC_DOMINFO_TRUST_OUTGOING    0x00000004

/* wbcDomainInfo->trust_type */

#define WBC_DOMINFO_TRUSTTYPE_NONE       0x00000000
#define WBC_DOMINFO_TRUSTTYPE_FOREST     0x00000001
#define WBC_DOMINFO_TRUSTTYPE_IN_FOREST  0x00000002
#define WBC_DOMINFO_TRUSTTYPE_EXTERNAL   0x00000003


/**
 * @brief Auth User Parameters
 **/

struct wbcAuthUserParams {
	const char *account_name;
	const char *domain_name;
	const char *workstation_name;

	uint32_t flags;

	uint32_t parameter_control;

	enum wbcAuthUserLevel {
		WBC_AUTH_USER_LEVEL_PLAIN = 1,
		WBC_AUTH_USER_LEVEL_HASH = 2,
		WBC_AUTH_USER_LEVEL_RESPONSE = 3
	} level;
	union {
		const char *plaintext;
		struct {
			uint8_t nt_hash[16];
			uint8_t lm_hash[16];
		} hash;
		struct {
			uint8_t challenge[8];
			uint32_t nt_length;
			uint8_t *nt_data;
			uint32_t lm_length;
			uint8_t *lm_data;
		} response;
	} password;
};

/**
 * @brief Generic Blob
 **/

struct wbcBlob {
	uint8_t *data;
	size_t length;
};

/**
 * @brief Named Blob
 **/

struct wbcNamedBlob {
	const char *name;
	uint32_t flags;
	struct wbcBlob blob;
};

/**
 * @brief Logon User Parameters
 **/

struct wbcLogonUserParams {
	const char *username;
	const char *password;
	size_t num_blobs;
	struct wbcNamedBlob *blobs;
};

/**
 * @brief ChangePassword Parameters
 **/

struct wbcChangePasswordParams {
	const char *account_name;
	const char *domain_name;

	uint32_t flags;

	enum wbcChangePasswordLevel {
		WBC_CHANGE_PASSWORD_LEVEL_PLAIN = 1,
		WBC_CHANGE_PASSWORD_LEVEL_RESPONSE = 2
	} level;

	union {
		const char *plaintext;
		struct {
			uint32_t old_nt_hash_enc_length;
			uint8_t *old_nt_hash_enc_data;
			uint32_t old_lm_hash_enc_length;
			uint8_t *old_lm_hash_enc_data;
		} response;
	} old_password;
	union {
		const char *plaintext;
		struct {
			uint32_t nt_length;
			uint8_t *nt_data;
			uint32_t lm_length;
			uint8_t *lm_data;
		} response;
	} new_password;
};

/* wbcAuthUserParams->parameter_control */

#define WBC_MSV1_0_CLEARTEXT_PASSWORD_ALLOWED		0x00000002
#define WBC_MSV1_0_UPDATE_LOGON_STATISTICS		0x00000004
#define WBC_MSV1_0_RETURN_USER_PARAMETERS		0x00000008
#define WBC_MSV1_0_ALLOW_SERVER_TRUST_ACCOUNT		0x00000020
#define WBC_MSV1_0_RETURN_PROFILE_PATH			0x00000200
#define WBC_MSV1_0_ALLOW_WORKSTATION_TRUST_ACCOUNT	0x00000800

/* wbcAuthUserParams->flags */

#define WBC_AUTH_PARAM_FLAGS_INTERACTIVE_LOGON		0x00000001

/**
 * @brief Auth User Information
 *
 * Some of the strings are maybe NULL
 **/

struct wbcAuthUserInfo {
	uint32_t user_flags;

	char *account_name;
	char *user_principal;
	char *full_name;
	char *domain_name;
	char *dns_domain_name;

	uint32_t acct_flags;
	uint8_t user_session_key[16];
	uint8_t lm_session_key[8];

	uint16_t logon_count;
	uint16_t bad_password_count;

	uint64_t logon_time;
	uint64_t logoff_time;
	uint64_t kickoff_time;
	uint64_t pass_last_set_time;
	uint64_t pass_can_change_time;
	uint64_t pass_must_change_time;

	char *logon_server;
	char *logon_script;
	char *profile_path;
	char *home_directory;
	char *home_drive;

	/*
	 * the 1st one is the account sid
	 * the 2nd one is the primary_group sid
	 * followed by the rest of the groups
	 */
	uint32_t num_sids;
	struct wbcSidWithAttr *sids;
};

/**
 * @brief Logon User Information
 *
 * Some of the strings are maybe NULL
 **/

struct wbcLogonUserInfo {
	struct wbcAuthUserInfo *info;
	size_t num_blobs;
	struct wbcNamedBlob *blobs;
};

/* wbcAuthUserInfo->user_flags */

#define WBC_AUTH_USER_INFO_GUEST			0x00000001
#define WBC_AUTH_USER_INFO_NOENCRYPTION			0x00000002
#define WBC_AUTH_USER_INFO_CACHED_ACCOUNT		0x00000004
#define WBC_AUTH_USER_INFO_USED_LM_PASSWORD		0x00000008
#define WBC_AUTH_USER_INFO_EXTRA_SIDS			0x00000020
#define WBC_AUTH_USER_INFO_SUBAUTH_SESSION_KEY		0x00000040
#define WBC_AUTH_USER_INFO_SERVER_TRUST_ACCOUNT		0x00000080
#define WBC_AUTH_USER_INFO_NTLMV2_ENABLED		0x00000100
#define WBC_AUTH_USER_INFO_RESOURCE_GROUPS		0x00000200
#define WBC_AUTH_USER_INFO_PROFILE_PATH_RETURNED	0x00000400
#define WBC_AUTH_USER_INFO_GRACE_LOGON			0x01000000

/* wbcAuthUserInfo->acct_flags */

#define WBC_ACB_DISABLED			0x00000001 /* 1 User account disabled */
#define WBC_ACB_HOMDIRREQ			0x00000002 /* 1 Home directory required */
#define WBC_ACB_PWNOTREQ			0x00000004 /* 1 User password not required */
#define WBC_ACB_TEMPDUP				0x00000008 /* 1 Temporary duplicate account */
#define WBC_ACB_NORMAL				0x00000010 /* 1 Normal user account */
#define WBC_ACB_MNS				0x00000020 /* 1 MNS logon user account */
#define WBC_ACB_DOMTRUST			0x00000040 /* 1 Interdomain trust account */
#define WBC_ACB_WSTRUST				0x00000080 /* 1 Workstation trust account */
#define WBC_ACB_SVRTRUST			0x00000100 /* 1 Server trust account */
#define WBC_ACB_PWNOEXP				0x00000200 /* 1 User password does not expire */
#define WBC_ACB_AUTOLOCK			0x00000400 /* 1 Account auto locked */
#define WBC_ACB_ENC_TXT_PWD_ALLOWED		0x00000800 /* 1 Encryped text password is allowed */
#define WBC_ACB_SMARTCARD_REQUIRED		0x00001000 /* 1 Smart Card required */
#define WBC_ACB_TRUSTED_FOR_DELEGATION		0x00002000 /* 1 Trusted for Delegation */
#define WBC_ACB_NOT_DELEGATED			0x00004000 /* 1 Not delegated */
#define WBC_ACB_USE_DES_KEY_ONLY		0x00008000 /* 1 Use DES key only */
#define WBC_ACB_DONT_REQUIRE_PREAUTH		0x00010000 /* 1 Preauth not required */
#define WBC_ACB_PW_EXPIRED			0x00020000 /* 1 Password Expired */
#define WBC_ACB_NO_AUTH_DATA_REQD		0x00080000   /* 1 = No authorization data required */

struct wbcAuthErrorInfo {
	uint32_t nt_status;
	char *nt_string;
	int32_t pam_error;
	char *display_string;
};

/**
 * @brief User Password Policy Information
 **/

/* wbcUserPasswordPolicyInfo->password_properties */

#define WBC_DOMAIN_PASSWORD_COMPLEX		0x00000001
#define WBC_DOMAIN_PASSWORD_NO_ANON_CHANGE	0x00000002
#define WBC_DOMAIN_PASSWORD_NO_CLEAR_CHANGE	0x00000004
#define WBC_DOMAIN_PASSWORD_LOCKOUT_ADMINS	0x00000008
#define WBC_DOMAIN_PASSWORD_STORE_CLEARTEXT	0x00000010
#define WBC_DOMAIN_REFUSE_PASSWORD_CHANGE	0x00000020

struct wbcUserPasswordPolicyInfo {
	uint32_t min_length_password;
	uint32_t password_history;
	uint32_t password_properties;
	uint64_t expire;
	uint64_t min_passwordage;
};

/**
 * @brief Change Password Reject Reason
 **/

enum wbcPasswordChangeRejectReason {
	WBC_PWD_CHANGE_REJECT_OTHER=0,
	WBC_PWD_CHANGE_REJECT_TOO_SHORT=1,
	WBC_PWD_CHANGE_REJECT_IN_HISTORY=2,
	WBC_PWD_CHANGE_REJECT_COMPLEXITY=5
};

/**
 * @brief Logoff User Parameters
 **/

struct wbcLogoffUserParams {
	const char *username;
	size_t num_blobs;
	struct wbcNamedBlob *blobs;
};

/** @brief Credential cache log-on parameters
 *
 */

struct wbcCredentialCacheParams {
        const char *account_name;
        const char *domain_name;
        enum wbcCredentialCacheLevel {
                WBC_CREDENTIAL_CACHE_LEVEL_NTLMSSP = 1
        } level;
        size_t num_blobs;
        struct wbcNamedBlob *blobs;
};


/** @brief Info returned by credential cache auth
 *
 */

struct wbcCredentialCacheInfo {
        size_t num_blobs;
        struct wbcNamedBlob *blobs;
};

/*
 * DomainControllerInfo struct
 */
struct wbcDomainControllerInfo {
	char *dc_name;
};

/*
 * DomainControllerInfoEx struct
 */
struct wbcDomainControllerInfoEx {
	const char *dc_unc;
	const char *dc_address;
	uint16_t dc_address_type;
	struct wbcGuid *domain_guid;
	const char *domain_name;
	const char *forest_name;
	uint32_t dc_flags;
	const char *dc_site_name;
	const char *client_site_name;
};

/*
 * Memory Management
 */

void wbcFreeMemory(void*);


/*
 * Utility functions for dealing with SIDs
 */

wbcErr wbcSidToString(const struct wbcDomainSid *sid,
		      char **sid_string);

wbcErr wbcStringToSid(const char *sid_string,
		      struct wbcDomainSid *sid);

/*
 * Utility functions for dealing with GUIDs
 */

wbcErr wbcGuidToString(const struct wbcGuid *guid,
		       char **guid_string);

wbcErr wbcStringToGuid(const char *guid_string,
		       struct wbcGuid *guid);

wbcErr wbcPing(void);

wbcErr wbcLibraryDetails(struct wbcLibraryDetails **details);

wbcErr wbcInterfaceDetails(struct wbcInterfaceDetails **details);

/*
 * Name/SID conversion
 */

wbcErr wbcLookupName(const char *dom_name,
		     const char *name,
		     struct wbcDomainSid *sid,
		     enum wbcSidType *name_type);

wbcErr wbcLookupSid(const struct wbcDomainSid *sid,
		    char **domain,
		    char **name,
		    enum wbcSidType *name_type);

wbcErr wbcLookupRids(struct wbcDomainSid *dom_sid,
		     int num_rids,
		     uint32_t *rids,
		     const char **domain_name,
		     const char ***names,
		     enum wbcSidType **types);

wbcErr wbcLookupUserSids(const struct wbcDomainSid *user_sid,
			 bool domain_groups_only,
			 uint32_t *num_sids,
			 struct wbcDomainSid **sids);

wbcErr wbcListUsers(const char *domain_name,
		    uint32_t *num_users,
		    const char ***users);

wbcErr wbcListGroups(const char *domain_name,
		     uint32_t *num_groups,
		     const char ***groups);

wbcErr wbcGetDisplayName(const struct wbcDomainSid *sid,
			 char **pdomain,
			 char **pfullname,
			 enum wbcSidType *pname_type);

/*
 * SID/uid/gid Mappings
 */

wbcErr wbcSidToUid(const struct wbcDomainSid *sid,
		   uid_t *puid);

wbcErr wbcQuerySidToUid(const struct wbcDomainSid *sid,
			uid_t *puid);

wbcErr wbcUidToSid(uid_t uid,
		   struct wbcDomainSid *sid);

wbcErr wbcQueryUidToSid(uid_t uid,
			struct wbcDomainSid *sid);

wbcErr wbcSidToGid(const struct wbcDomainSid *sid,
		   gid_t *pgid);

wbcErr wbcQuerySidToGid(const struct wbcDomainSid *sid,
			gid_t *pgid);

wbcErr wbcGidToSid(gid_t gid,
		   struct wbcDomainSid *sid);

wbcErr wbcQueryGidToSid(gid_t gid,
			struct wbcDomainSid *sid);

wbcErr wbcAllocateUid(uid_t *puid);

wbcErr wbcAllocateGid(gid_t *pgid);

wbcErr wbcSetUidMapping(uid_t uid, const struct wbcDomainSid *sid);

wbcErr wbcSetGidMapping(gid_t gid, const struct wbcDomainSid *sid);

wbcErr wbcRemoveUidMapping(uid_t uid, const struct wbcDomainSid *sid);

wbcErr wbcRemoveGidMapping(gid_t gid, const struct wbcDomainSid *sid);

wbcErr wbcSetUidHwm(uid_t uid_hwm);

wbcErr wbcSetGidHwm(gid_t gid_hwm);

/*
 * NSS Lookup User/Group details
 */

wbcErr wbcGetpwnam(const char *name, struct passwd **pwd);

wbcErr wbcGetpwuid(uid_t uid, struct passwd **pwd);

wbcErr wbcGetgrnam(const char *name, struct group **grp);

wbcErr wbcGetgrgid(gid_t gid, struct group **grp);

wbcErr wbcSetpwent(void);

wbcErr wbcEndpwent(void);

wbcErr wbcGetpwent(struct passwd **pwd);

wbcErr wbcSetgrent(void);

wbcErr wbcEndgrent(void);

wbcErr wbcGetgrent(struct group **grp);

wbcErr wbcGetgrlist(struct group **grp);

wbcErr wbcGetGroups(const char *account,
		    uint32_t *num_groups,
		    gid_t **_groups);


/*
 * Lookup Domain information
 */

wbcErr wbcDomainInfo(const char *domain,
		     struct wbcDomainInfo **info);

wbcErr wbcListTrusts(struct wbcDomainInfo **domains, 
		     size_t *num_domains);

/* Flags for wbcLookupDomainController */

#define WBC_LOOKUP_DC_FORCE_REDISCOVERY        0x00000001
#define WBC_LOOKUP_DC_DS_REQUIRED              0x00000010
#define WBC_LOOKUP_DC_DS_PREFERRED             0x00000020
#define WBC_LOOKUP_DC_GC_SERVER_REQUIRED       0x00000040
#define WBC_LOOKUP_DC_PDC_REQUIRED             0x00000080
#define WBC_LOOKUP_DC_BACKGROUND_ONLY          0x00000100
#define WBC_LOOKUP_DC_IP_REQUIRED              0x00000200
#define WBC_LOOKUP_DC_KDC_REQUIRED             0x00000400
#define WBC_LOOKUP_DC_TIMESERV_REQUIRED        0x00000800
#define WBC_LOOKUP_DC_WRITABLE_REQUIRED        0x00001000
#define WBC_LOOKUP_DC_GOOD_TIMESERV_PREFERRED  0x00002000
#define WBC_LOOKUP_DC_AVOID_SELF               0x00004000
#define WBC_LOOKUP_DC_ONLY_LDAP_NEEDED         0x00008000
#define WBC_LOOKUP_DC_IS_FLAT_NAME             0x00010000
#define WBC_LOOKUP_DC_IS_DNS_NAME              0x00020000
#define WBC_LOOKUP_DC_TRY_NEXTCLOSEST_SITE     0x00040000
#define WBC_LOOKUP_DC_DS_6_REQUIRED            0x00080000
#define WBC_LOOKUP_DC_RETURN_DNS_NAME          0x40000000
#define WBC_LOOKUP_DC_RETURN_FLAT_NAME         0x80000000

wbcErr wbcLookupDomainController(const char *domain,
				 uint32_t flags,
				 struct wbcDomainControllerInfo **dc_info);

wbcErr wbcLookupDomainControllerEx(const char *domain,
				   struct wbcGuid *guid,
				   const char *site,
				   uint32_t flags,
				   struct wbcDomainControllerInfoEx **dc_info);

/*
 * Athenticate functions
 */

wbcErr wbcAuthenticateUser(const char *username,
			   const char *password);

wbcErr wbcAuthenticateUserEx(const struct wbcAuthUserParams *params,
			     struct wbcAuthUserInfo **info,
			     struct wbcAuthErrorInfo **error);

wbcErr wbcLogonUser(const struct wbcLogonUserParams *params,
		    struct wbcLogonUserInfo **info,
		    struct wbcAuthErrorInfo **error,
		    struct wbcUserPasswordPolicyInfo **policy);

wbcErr wbcLogoffUser(const char *username,
		     uid_t uid,
		     const char *ccfilename);

wbcErr wbcLogoffUserEx(const struct wbcLogoffUserParams *params,
		       struct wbcAuthErrorInfo **error);

wbcErr wbcChangeUserPassword(const char *username,
			     const char *old_password,
			     const char *new_password);

wbcErr wbcChangeUserPasswordEx(const struct wbcChangePasswordParams *params,
			       struct wbcAuthErrorInfo **error,
			       enum wbcPasswordChangeRejectReason *reject_reason,
			       struct wbcUserPasswordPolicyInfo **policy);

wbcErr wbcCredentialCache(struct wbcCredentialCacheParams *params,
                          struct wbcCredentialCacheInfo **info,
                          struct wbcAuthErrorInfo **error);

/*
 * Resolve functions
 */
wbcErr wbcResolveWinsByName(const char *name, char **ip);
wbcErr wbcResolveWinsByIP(const char *ip, char **name);

/*
 * Trusted domain functions
 */
wbcErr wbcCheckTrustCredentials(const char *domain,
				struct wbcAuthErrorInfo **error);
/*
 * Helper functions
 */
wbcErr wbcAddNamedBlob(size_t *num_blobs,
		       struct wbcNamedBlob **blobs,
		       const char *name,
		       uint32_t flags,
		       uint8_t *data,
		       size_t length);

#endif      /* _WBCLIENT_H */
