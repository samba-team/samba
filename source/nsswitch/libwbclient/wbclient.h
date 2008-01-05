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
#include <nsswitch/libwbclient/wbc_err.h>

/*
 * Data types used by the Winbind Client API
 */

#ifndef MAXSUBAUTHS
#define MAXSUBAUTHS 15 /* max sub authorities in a SID */
#endif

/**
 *  @brief Windows Security Identifier
 *
 **/

struct wbcDomainSid {
	uint8_t   sid_rev_num;
	uint8_t   num_auths;
	uint8_t   id_auth[6];
	uint32_t  sub_auths[MAXSUBAUTHS];
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
 * @brief Domain Information
 **/

struct wbcDomainInfo {
	char *short_name;
	char *dns_name;
	struct wbcDomainSid sid;
	uint32_t flags;
};

/* wbcDomainInfo->flags */

#define WBC_DOMINFO_NATIVE            0x00000001
#define WBC_DOMINFO_AD                0x00000002
#define WBC_DOMINFO_PRIMARY           0x00000004

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

wbcErr wbcPing(void);

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

/*
 * SID/uid/gid Mappings
 */

wbcErr wbcSidToUid(const struct wbcDomainSid *sid,
		   uid_t *puid);

wbcErr wbcUidToSid(uid_t uid,
		   struct wbcDomainSid *sid);

wbcErr wbcSidToGid(const struct wbcDomainSid *sid,
		   gid_t *pgid);

wbcErr wbcGidToSid(gid_t gid,
		   struct wbcDomainSid *sid);

wbcErr wbcAllocateUid(uid_t *puid);

wbcErr wbcAllocateGid(uid_t *pgid);

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


/*
 * Lookup Domain information
 */

wbcErr wbcDomainInfo(const char *domain,
		     struct wbcDomainInfo **info);

wbcErr wbcDomainSequenceNumbers(void);

/*
 * Athenticate functions
 */

wbcErr wbcAuthenticateUser(const char *username,
			   const char *password);


#endif      /* _WBCLIENT_H */
