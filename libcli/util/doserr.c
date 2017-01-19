/* 
 *  Unix SMB/CIFS implementation.
 *  DOS error routines
 *  Copyright (C) Tim Potter 2002.
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

/* DOS error codes.  please read doserr.h */

#include "includes.h"

struct werror_code_struct {
        const char *dos_errstr;
        WERROR werror;
};

struct werror_str_struct {
        WERROR werror;
        const char *friendly_errstr;
};

#include "werror_gen.c"

static const struct werror_code_struct special_errs[] =
{
	{ "WERR_DNS_ERROR_NOT_ALLOWED_ON_ACTIVE_SKD", WERR_DNS_ERROR_NOT_ALLOWED_ON_ACTIVE_SKD },
        { "WERR_DNS_ERROR_INVALID_NSEC3_PARAMETERS", WERR_DNS_ERROR_INVALID_NSEC3_PARAMETERS },
        { "WERR_DNS_ERROR_DNSSEC_IS_DISABLED", WERR_DNS_ERROR_DNSSEC_IS_DISABLED },
        { "WERR_DNS_ERROR_NOT_ALLOWED_ON_UNSIGNED_ZONE", WERR_DNS_ERROR_NOT_ALLOWED_ON_UNSIGNED_ZONE },
        { "WERR_DNS_ERROR_KSP_DOES_NOT_SUPPORT_PROTECTION", WERR_DNS_ERROR_KSP_DOES_NOT_SUPPORT_PROTECTION },
        { "WERR_DNS_ERROR_BAD_KEYMASTER", WERR_DNS_ERROR_BAD_KEYMASTER },
        { "WERR_USER_APC", WERR_USER_APC },
        { "WERR_DNS_ERROR_UNEXPECTED_DATA_PROTECTION_ERROR", WERR_DNS_ERROR_UNEXPECTED_DATA_PROTECTION_ERROR },
        { "WERR_WAIT_2", WERR_WAIT_2 },
        { "WERR_WAIT_3", WERR_WAIT_3 },
        { "WERR_WAIT_1", WERR_WAIT_1 },
        { "WERR_DNS_ERROR_NSEC3_NAME_COLLISION", WERR_DNS_ERROR_NSEC3_NAME_COLLISION },
        { "WERR_DNS_ERROR_KSP_NOT_ACCESSIBLE", WERR_DNS_ERROR_KSP_NOT_ACCESSIBLE },
        { "WERR_DNS_ERROR_ROLLOVER_NOT_POKEABLE", WERR_DNS_ERROR_ROLLOVER_NOT_POKEABLE },
        { "WERR_DNS_ERROR_INVALID_KEY_SIZE", WERR_DNS_ERROR_INVALID_KEY_SIZE },
        { "WERR_DNS_ERROR_ROLLOVER_ALREADY_QUEUED", WERR_DNS_ERROR_ROLLOVER_ALREADY_QUEUED },
        { "WERR_DNS_ERROR_UNKNOWN_SIGNING_PARAMETER_VERSION", WERR_DNS_ERROR_UNKNOWN_SIGNING_PARAMETER_VERSION },
        { "WERR_DNS_ERROR_INVALID_INITIAL_ROLLOVER_OFFSET", WERR_DNS_ERROR_INVALID_INITIAL_ROLLOVER_OFFSET },
        { "WERR_DNS_ERROR_SIGNING_KEY_NOT_ACCESSIBLE", WERR_DNS_ERROR_SIGNING_KEY_NOT_ACCESSIBLE },
        { "WERR_DNS_REQUEST_PENDING", WERR_DNS_REQUEST_PENDING },
        { "WERR_LOG_HARD_ERROR", WERR_LOG_HARD_ERROR },
        { "WERR_DNS_ERROR_NOT_ALLOWED_ON_ZSK", WERR_DNS_ERROR_NOT_ALLOWED_ON_ZSK },
        { "WERR_OK", WERR_OK },
        { "WERR_DNS_ERROR_KEYMASTER_REQUIRED", WERR_DNS_ERROR_KEYMASTER_REQUIRED },
        { "WERR_STATUS_MORE_ENTRIES", WERR_STATUS_MORE_ENTRIES },
        { "WERR_DS_INVALID_ATTRIBUTE_SYNTAX", WERR_DS_INVALID_ATTRIBUTE_SYNTAX },
        { "WERR_ALERTED", WERR_ALERTED },
        { "WERR_DNS_ERROR_UNSUPPORTED_ALGORITHM", WERR_DNS_ERROR_UNSUPPORTED_ALGORITHM },
        { "WERR_DNS_ERROR_INVALID_NSEC3_ITERATION_COUNT", WERR_DNS_ERROR_INVALID_NSEC3_ITERATION_COUNT },
        { "WERR_DNS_ERROR_INVALID_XML", WERR_DNS_ERROR_INVALID_XML },
        { "WERR_DNS_ERROR_DELEGATION_REQUIRED", WERR_DNS_ERROR_DELEGATION_REQUIRED },
        { "WERR_ABANDONED_WAIT_63", WERR_ABANDONED_WAIT_63 },
        { "WERR_DNS_ERROR_UNEXPECTED_CNG_ERROR", WERR_DNS_ERROR_UNEXPECTED_CNG_ERROR },
        { "WERR_DNS_ERROR_DNAME_COLLISION", WERR_DNS_ERROR_DNAME_COLLISION },
        { "WERR_DNS_ERROR_INVALID_POLICY_TABLE", WERR_DNS_ERROR_INVALID_POLICY_TABLE },
        { "WERR_DNS_ERROR_NO_VALID_TRUST_ANCHORS", WERR_DNS_ERROR_NO_VALID_TRUST_ANCHORS },
        { "WERR_MULTIPLE_FAULT_VIOLATION", WERR_MULTIPLE_FAULT_VIOLATION },
        { "WERR_DNS_ERROR_INVALID_ROLLOVER_PERIOD", WERR_DNS_ERROR_INVALID_ROLLOVER_PERIOD },
        { "WERR_DNS_ERROR_INVALID_SIGNATURE_VALIDITY_PERIOD", WERR_DNS_ERROR_INVALID_SIGNATURE_VALIDITY_PERIOD },
        { "WERR_DNS_ERROR_NOT_ENOUGH_SIGNING_KEY_DESCRIPTORS", WERR_DNS_ERROR_NOT_ENOUGH_SIGNING_KEY_DESCRIPTORS },
        { "WERR_INVALID_PRIMARY_GROUP", WERR_INVALID_PRIMARY_GROUP },
        { "WERR_KERNEL_APC", WERR_KERNEL_APC },
        { "WERR_DNS_ERROR_NOT_ALLOWED_UNDER_DNAME", WERR_DNS_ERROR_NOT_ALLOWED_UNDER_DNAME },
        { "WERR_DNS_ERROR_TOO_MANY_SKDS", WERR_DNS_ERROR_TOO_MANY_SKDS },
        { "WERR_DNS_ERROR_NODE_IS_DNMAE", WERR_DNS_ERROR_NODE_IS_DNAME },
        { "WERR_DNS_ERROR_NODE_IS_DNAME", WERR_DNS_ERROR_NODE_IS_DNAME },
	{ "WERR_SERVICE_NOTIFICATION", WERR_SERVICE_NOTIFICATION },
        { "WERR_WAIT_63", WERR_WAIT_63 },
        { "WERR_DNS_ERROR_STANDBY_KEY_NOT_PRESENT", WERR_DNS_ERROR_STANDBY_KEY_NOT_PRESENT },
        { "WERR_DNS_ERROR_ALIAS_LOOP", WERR_DNS_ERROR_ALIAS_LOOP },
        { "WERR_DNS_ERROR_ROLLOVER_IN_PROGRESS", WERR_DNS_ERROR_ROLLOVER_IN_PROGRESS },
        { "WERR_DNS_ERROR_NOT_ALLOWED_ON_SIGNED_ZONE", WERR_DNS_ERROR_NOT_ALLOWED_ON_SIGNED_ZONE },
	{ 0, W_ERROR(0) }
};

/*****************************************************************************
 returns a windows error message.  not amazingly helpful, but better than a number.
 *****************************************************************************/
const char *win_errstr(WERROR werror)
{
        static char msg[40];
        int idx = 0;

	while (special_errs[idx].dos_errstr != NULL) {
		if (W_ERROR_V(special_errs[idx].werror) ==
		    W_ERROR_V(werror))
			return special_errs[idx].dos_errstr;
		idx++;
	}

	idx = 0;

	while (dos_errs[idx].dos_errstr != NULL) {
		if (W_ERROR_V(dos_errs[idx].werror) ==
                    W_ERROR_V(werror))
                        return dos_errs[idx].dos_errstr;
		idx++;
	}

	slprintf(msg, sizeof(msg), "DOS code 0x%08x", W_ERROR_V(werror));

        return msg;
}

/*****************************************************************************
 Get friendly error string for WERRORs
 *****************************************************************************/

const char *get_friendly_werror_msg(WERROR werror)
{
	int i = 0;

	for (i = 0; i < ARRAY_SIZE(dos_err_strs); i++) {
		if (W_ERROR_V(dos_err_strs[i].werror) ==
                    W_ERROR_V(werror)) {
			return dos_err_strs[i].friendly_errstr;
		}
	}

	return win_errstr(werror);
}
