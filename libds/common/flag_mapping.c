/*
   Unix SMB/CIFS implementation.
   helper mapping functions for the UF and ACB flags

   Copyright (C) Stefan (metze) Metzmacher 2002
   Copyright (C) Andrew Tridgell 2004
   Copyright (C) Matthias Dieter Wallnöfer 2010

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "replace.h"
#include "lib/util/data_blob.h"
#include "lib/util/time.h"
#include "lib/util/debug.h"
#include "librpc/gen_ndr/samr.h"
#include "../libds/common/flags.h"
#include "flag_mapping.h"

/*
translated the ACB_CTRL Flags to UserFlags (userAccountControl)
*/
/* mapping between ADS userAccountControl and SAMR acct_flags */
static const struct {
	uint32_t uf;
	uint32_t acb;
} acct_flags_map[] = {
	{ UF_ACCOUNTDISABLE, ACB_DISABLED },
	{ UF_HOMEDIR_REQUIRED, ACB_HOMDIRREQ },
	{ UF_PASSWD_NOTREQD, ACB_PWNOTREQ },
	{ UF_TEMP_DUPLICATE_ACCOUNT, ACB_TEMPDUP },
	{ UF_NORMAL_ACCOUNT, ACB_NORMAL },
	{ UF_MNS_LOGON_ACCOUNT, ACB_MNS },
	{ UF_INTERDOMAIN_TRUST_ACCOUNT, ACB_DOMTRUST },
	{ UF_WORKSTATION_TRUST_ACCOUNT, ACB_WSTRUST },
	{ UF_SERVER_TRUST_ACCOUNT, ACB_SVRTRUST },
	{ UF_DONT_EXPIRE_PASSWD, ACB_PWNOEXP },
	{ UF_LOCKOUT, ACB_AUTOLOCK },
	{ UF_ENCRYPTED_TEXT_PASSWORD_ALLOWED, ACB_ENC_TXT_PWD_ALLOWED },
	{ UF_SMARTCARD_REQUIRED, ACB_SMARTCARD_REQUIRED },
	{ UF_TRUSTED_FOR_DELEGATION, ACB_TRUSTED_FOR_DELEGATION },
	{ UF_NOT_DELEGATED, ACB_NOT_DELEGATED },
	{ UF_USE_DES_KEY_ONLY, ACB_USE_DES_KEY_ONLY},
	{ UF_DONT_REQUIRE_PREAUTH, ACB_DONT_REQUIRE_PREAUTH },
	{ UF_PASSWORD_EXPIRED, ACB_PW_EXPIRED },
	{ UF_NO_AUTH_DATA_REQUIRED, ACB_NO_AUTH_DATA_REQD },
	{ UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION, ACB_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION },
	{ UF_PARTIAL_SECRETS_ACCOUNT, ACB_PARTIAL_SECRETS_ACCOUNT },
	{ UF_USE_AES_KEYS, ACB_USE_AES_KEYS }
};

uint32_t ds_acb2uf(uint32_t acb)
{
	unsigned int i;
	uint32_t ret = 0;
	for (i=0;i<ARRAY_SIZE(acct_flags_map);i++) {
		if (acct_flags_map[i].acb & acb) {
			ret |= acct_flags_map[i].uf;
		}
	}
	return ret;
}

/*
translated the UserFlags (userAccountControl) to ACB_CTRL Flags
*/
uint32_t ds_uf2acb(uint32_t uf)
{
	unsigned int i;
	uint32_t ret = 0;
	for (i=0;i<ARRAY_SIZE(acct_flags_map);i++) {
		if (acct_flags_map[i].uf & uf) {
			ret |= acct_flags_map[i].acb;
		}
	}
	return ret;
}

/*
get the accountType from the UserFlags
*/
uint32_t ds_uf2atype(uint32_t uf)
{
	uint32_t atype = 0x00000000;

	if (uf & UF_NORMAL_ACCOUNT)			atype = ATYPE_NORMAL_ACCOUNT;
	else if (uf & UF_TEMP_DUPLICATE_ACCOUNT)	atype = ATYPE_NORMAL_ACCOUNT;
	else if (uf & UF_SERVER_TRUST_ACCOUNT)		atype = ATYPE_WORKSTATION_TRUST;
	else if (uf & UF_WORKSTATION_TRUST_ACCOUNT)	atype = ATYPE_WORKSTATION_TRUST;
	else if (uf & UF_INTERDOMAIN_TRUST_ACCOUNT)	atype = ATYPE_INTERDOMAIN_TRUST;

	return atype;
}

/*
get the accountType from the groupType
*/
uint32_t ds_gtype2atype(uint32_t gtype)
{
	uint32_t atype = 0x00000000;

	switch(gtype) {
		case GTYPE_SECURITY_BUILTIN_LOCAL_GROUP:
			atype = ATYPE_SECURITY_LOCAL_GROUP;
			break;
		case GTYPE_SECURITY_GLOBAL_GROUP:
			atype = ATYPE_SECURITY_GLOBAL_GROUP;
			break;
		case GTYPE_SECURITY_DOMAIN_LOCAL_GROUP:
			atype = ATYPE_SECURITY_LOCAL_GROUP;
			break;
		case GTYPE_SECURITY_UNIVERSAL_GROUP:
			atype = ATYPE_SECURITY_UNIVERSAL_GROUP;
			break;

		case GTYPE_DISTRIBUTION_GLOBAL_GROUP:
			atype = ATYPE_DISTRIBUTION_GLOBAL_GROUP;
			break;
		case GTYPE_DISTRIBUTION_DOMAIN_LOCAL_GROUP:
			atype = ATYPE_DISTRIBUTION_LOCAL_GROUP;
			break;
		case GTYPE_DISTRIBUTION_UNIVERSAL_GROUP:
			atype = ATYPE_DISTRIBUTION_UNIVERSAL_GROUP;
			break;
	}

	return atype;
}

/* turn a sAMAccountType into a SID_NAME_USE */
enum lsa_SidType ds_atype_map(uint32_t atype)
{
	switch (atype & 0xF0000000) {
	case ATYPE_GLOBAL_GROUP:
		return SID_NAME_DOM_GRP;
	case ATYPE_SECURITY_LOCAL_GROUP:
		return SID_NAME_ALIAS;
	case ATYPE_ACCOUNT:
		return SID_NAME_USER;
	default:
		DEBUG(1,("hmm, need to map account type 0x%x\n", atype));
	}
	return SID_NAME_UNKNOWN;
}

/* get the default primary group RID for a given userAccountControl
 * (information according to MS-SAMR 3.1.1.8.1) */
uint32_t ds_uf2prim_group_rid(uint32_t uf)
{
	uint32_t prim_group_rid = DOMAIN_RID_USERS;

	if ((uf & UF_PARTIAL_SECRETS_ACCOUNT)
	 && (uf & UF_WORKSTATION_TRUST_ACCOUNT))    prim_group_rid = DOMAIN_RID_READONLY_DCS;
	else if (uf & UF_SERVER_TRUST_ACCOUNT)      prim_group_rid = DOMAIN_RID_DCS;
	else if (uf & UF_WORKSTATION_TRUST_ACCOUNT) prim_group_rid = DOMAIN_RID_DOMAIN_MEMBERS;

	return prim_group_rid;
}

const char *dsdb_user_account_control_flag_bit_to_string(uint32_t uf)
{
	switch (uf) {
	case UF_SCRIPT:
		return "UF_SCRIPT";
		break;
	case UF_ACCOUNTDISABLE:
		return "UF_ACCOUNTDISABLE";
		break;
	case UF_00000004:
		return "UF_00000004";
		break;
	case UF_HOMEDIR_REQUIRED:
		return "UF_HOMEDIR_REQUIRED";
		break;
	case UF_LOCKOUT:
		return "UF_LOCKOUT";
		break;
	case UF_PASSWD_NOTREQD:
		return "UF_PASSWD_NOTREQD";
		break;
	case UF_PASSWD_CANT_CHANGE:
		return "UF_PASSWD_CANT_CHANGE";
		break;
	case UF_ENCRYPTED_TEXT_PASSWORD_ALLOWED:
		return "UF_ENCRYPTED_TEXT_PASSWORD_ALLOWED";
		break;

	case UF_TEMP_DUPLICATE_ACCOUNT:
		return "UF_TEMP_DUPLICATE_ACCOUNT";
		break;
	case UF_NORMAL_ACCOUNT:
		return "UF_NORMAL_ACCOUNT";
		break;
	case UF_00000400:
		return "UF_00000400";
		break;
	case UF_INTERDOMAIN_TRUST_ACCOUNT:
		return "UF_INTERDOMAIN_TRUST_ACCOUNT";
		break;

	case UF_WORKSTATION_TRUST_ACCOUNT:
		return "UF_WORKSTATION_TRUST_ACCOUNT";
		break;
	case UF_SERVER_TRUST_ACCOUNT:
		return "UF_SERVER_TRUST_ACCOUNT";
		break;
	case UF_00004000:
		return "UF_00004000";
		break;
	case UF_00008000:
		return "UF_00008000";
		break;

	case UF_DONT_EXPIRE_PASSWD:
		return "UF_DONT_EXPIRE_PASSWD";
		break;
	case UF_MNS_LOGON_ACCOUNT:
		return "UF_MNS_LOGON_ACCOUNT";
		break;
	case UF_SMARTCARD_REQUIRED:
		return "UF_SMARTCARD_REQUIRED";
		break;
	case UF_TRUSTED_FOR_DELEGATION:
		return "UF_TRUSTED_FOR_DELEGATION";
		break;

	case UF_NOT_DELEGATED:
		return "UF_NOT_DELEGATED";
		break;
	case UF_USE_DES_KEY_ONLY:
		return "UF_USE_DES_KEY_ONLY";
		break;
	case UF_DONT_REQUIRE_PREAUTH:
		return "UF_DONT_REQUIRE_PREAUTH";
		break;
	case UF_PASSWORD_EXPIRED:
		return "UF_PASSWORD_EXPIRED";
		break;
	case UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION:
		return "UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION";
		break;
	case UF_NO_AUTH_DATA_REQUIRED:
		return "UF_NO_AUTH_DATA_REQUIRED";
		break;
	case UF_PARTIAL_SECRETS_ACCOUNT:
		return "UF_PARTIAL_SECRETS_ACCOUNT";
		break;
	case UF_USE_AES_KEYS:
		return "UF_USE_AES_KEYS";
		break;
	default:
		break;
	}
	return NULL;
}
