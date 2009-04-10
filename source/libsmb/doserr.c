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

typedef const struct {
	const char *dos_errstr;
	WERROR werror;
} werror_code_struct;

typedef const struct {
	WERROR werror;
	const char *friendly_errstr;
} werror_str_struct;

werror_code_struct dos_errs[] =
{
	{ "WERR_OK", WERR_OK },
	{ "WERR_GENERAL_FAILURE", WERR_GENERAL_FAILURE },
	{ "WERR_BADFILE", WERR_BADFILE },
	{ "WERR_ACCESS_DENIED", WERR_ACCESS_DENIED },
	{ "WERR_BADFID", WERR_BADFID },
	{ "WERR_BADFUNC", WERR_BADFUNC },
	{ "WERR_INSUFFICIENT_BUFFER", WERR_INSUFFICIENT_BUFFER },
	{ "WERR_SEM_TIMEOUT", WERR_SEM_TIMEOUT },
	{ "WERR_NO_SUCH_SHARE", WERR_NO_SUCH_SHARE },
	{ "WERR_ALREADY_EXISTS", WERR_ALREADY_EXISTS },
	{ "WERR_INVALID_PARAM", WERR_INVALID_PARAM },
	{ "WERR_NOT_SUPPORTED", WERR_NOT_SUPPORTED },
	{ "WERR_BAD_PASSWORD", WERR_BAD_PASSWORD },
	{ "WERR_NOMEM", WERR_NOMEM },
	{ "WERR_INVALID_NAME", WERR_INVALID_NAME },
	{ "WERR_UNKNOWN_LEVEL", WERR_UNKNOWN_LEVEL },
	{ "WERR_OBJECT_PATH_INVALID", WERR_OBJECT_PATH_INVALID },
	{ "WERR_NO_MORE_ITEMS", WERR_NO_MORE_ITEMS },
	{ "WERR_MORE_DATA", WERR_MORE_DATA },
	{ "WERR_UNKNOWN_PRINTER_DRIVER", WERR_UNKNOWN_PRINTER_DRIVER },
	{ "WERR_INVALID_PRINTER_NAME", WERR_INVALID_PRINTER_NAME },
	{ "WERR_PRINTER_ALREADY_EXISTS", WERR_PRINTER_ALREADY_EXISTS },
	{ "WERR_INVALID_DATATYPE", WERR_INVALID_DATATYPE },
	{ "WERR_INVALID_ENVIRONMENT", WERR_INVALID_ENVIRONMENT },
	{ "WERR_INVALID_FORM_NAME", WERR_INVALID_FORM_NAME },
	{ "WERR_INVALID_FORM_SIZE", WERR_INVALID_FORM_SIZE },
	{ "WERR_BUF_TOO_SMALL", WERR_BUF_TOO_SMALL },
	{ "WERR_JOB_NOT_FOUND", WERR_JOB_NOT_FOUND },
	{ "WERR_DEST_NOT_FOUND", WERR_DEST_NOT_FOUND },
	{ "WERR_GROUP_NOT_FOUND", WERR_GROUP_NOT_FOUND },
	{ "WERR_USER_NOT_FOUND", WERR_USER_NOT_FOUND },
	{ "WERR_NOT_LOCAL_DOMAIN", WERR_NOT_LOCAL_DOMAIN },
	{ "WERR_USER_EXISTS", WERR_USER_EXISTS },
	{ "WERR_REVISION_MISMATCH", WERR_REVISION_MISMATCH },
	{ "WERR_NO_LOGON_SERVERS", WERR_NO_LOGON_SERVERS },
	{ "WERR_NO_SUCH_LOGON_SESSION", WERR_NO_SUCH_LOGON_SESSION },
	{ "WERR_USER_ALREADY_EXISTS", WERR_USER_ALREADY_EXISTS },
	{ "WERR_NO_SUCH_USER", WERR_NO_SUCH_USER },
	{ "WERR_GROUP_EXISTS", WERR_GROUP_EXISTS },
	{ "WERR_MEMBER_IN_GROUP", WERR_MEMBER_IN_GROUP },
	{ "WERR_USER_NOT_IN_GROUP", WERR_USER_NOT_IN_GROUP },
	{ "WERR_PRINTER_DRIVER_IN_USE", WERR_PRINTER_DRIVER_IN_USE },
	{ "WERR_STATUS_MORE_ENTRIES  ", WERR_STATUS_MORE_ENTRIES },
	{ "WERR_DFS_NO_SUCH_VOL", WERR_DFS_NO_SUCH_VOL },
	{ "WERR_DFS_NO_SUCH_SHARE", WERR_DFS_NO_SUCH_SHARE },
	{ "WERR_DFS_NO_SUCH_SERVER", WERR_DFS_NO_SUCH_SERVER },
	{ "WERR_DFS_INTERNAL_ERROR", WERR_DFS_INTERNAL_ERROR },
	{ "WERR_DFS_CANT_CREATE_JUNCT", WERR_DFS_CANT_CREATE_JUNCT },
	{ "WERR_INVALID_COMPUTER_NAME", WERR_INVALID_COMPUTER_NAME },
	{ "WERR_INVALID_DOMAINNAME", WERR_INVALID_DOMAINNAME },
	{ "WERR_MACHINE_LOCKED", WERR_MACHINE_LOCKED },
	{ "WERR_DC_NOT_FOUND", WERR_DC_NOT_FOUND },
	{ "WERR_SETUP_NOT_JOINED", WERR_SETUP_NOT_JOINED },
	{ "WERR_SETUP_ALREADY_JOINED", WERR_SETUP_ALREADY_JOINED },
	{ "WERR_SETUP_DOMAIN_CONTROLLER", WERR_SETUP_DOMAIN_CONTROLLER },
	{ "WERR_DEFAULT_JOIN_REQUIRED", WERR_DEFAULT_JOIN_REQUIRED },
	{ "WERR_DEVICE_NOT_AVAILABLE", WERR_DEVICE_NOT_AVAILABLE },
	{ "WERR_LOGON_FAILURE", WERR_LOGON_FAILURE },
	{ "WERR_WRONG_PASSWORD", WERR_WRONG_PASSWORD },
	{ "WERR_PASSWORD_RESTRICTION", WERR_PASSWORD_RESTRICTION },
	{ "WERR_NO_SUCH_DOMAIN", WERR_NO_SUCH_DOMAIN },
	{ "WERR_NONE_MAPPED", WERR_NONE_MAPPED },
	{ "WERR_INVALID_SECURITY_DESCRIPTOR", WERR_INVALID_SECURITY_DESCRIPTOR },
	{ "WERR_INVALID_DOMAIN_STATE", WERR_INVALID_DOMAIN_STATE },
	{ "WERR_INVALID_DOMAIN_ROLE", WERR_INVALID_DOMAIN_ROLE },
	{ "WERR_SPECIAL_ACCOUNT", WERR_SPECIAL_ACCOUNT },
	{ "WERR_ALIAS_EXISTS", WERR_ALIAS_EXISTS },
	{ "WERR_NO_SUCH_ALIAS", WERR_NO_SUCH_ALIAS },
	{ "WERR_MEMBER_IN_ALIAS", WERR_MEMBER_IN_ALIAS },
	{ "WERR_TIME_SKEW", WERR_TIME_SKEW },
	{ "WERR_INVALID_OWNER", WERR_INVALID_OWNER },
	{ "WERR_SERVER_UNAVAILABLE", WERR_SERVER_UNAVAILABLE },
	{ "WERR_IO_PENDING", WERR_IO_PENDING },
	{ "WERR_INVALID_SERVICE_CONTROL", WERR_INVALID_SERVICE_CONTROL },
	{ "WERR_SERVICE_ALREADY_RUNNING", WERR_SERVICE_ALREADY_RUNNING },
	{ "WERR_NET_NAME_NOT_FOUND", WERR_NET_NAME_NOT_FOUND },
	{ "WERR_REG_CORRUPT", WERR_REG_CORRUPT },
	{ "WERR_REG_IO_FAILURE", WERR_REG_IO_FAILURE },
	{ "WERR_REG_FILE_INVALID", WERR_REG_FILE_INVALID },
	{ "WERR_NO_SUCH_SERVICE", WERR_NO_SUCH_SERVICE },
	{ "WERR_SERVICE_DISABLED", WERR_SERVICE_DISABLED },
	{ "WERR_SERVICE_MARKED_FOR_DELETE", WERR_SERVICE_MARKED_FOR_DELETE },
	{ "WERR_SERVICE_EXISTS", WERR_SERVICE_EXISTS },
	{ "WERR_SERVICE_NEVER_STARTED", WERR_SERVICE_NEVER_STARTED },
	{ "WERR_DUPLICATE_SERVICE_NAME", WERR_DUPLICATE_SERVICE_NAME },
	{ "WERR_NOT_FOUND", WERR_NOT_FOUND },
	{ "WERR_CAN_NOT_COMPLETE", WERR_CAN_NOT_COMPLETE},
	{ "WERR_INVALID_FLAGS", WERR_INVALID_FLAGS},
	{ "WERR_PASSWORD_MUST_CHANGE", WERR_PASSWORD_MUST_CHANGE },
	{ "WERR_DOMAIN_CONTROLLER_NOT_FOUND", WERR_DOMAIN_CONTROLLER_NOT_FOUND },
	{ "WERR_ACCOUNT_LOCKED_OUT", WERR_ACCOUNT_LOCKED_OUT },
	{ "WERR_DS_DRA_BAD_DN", WERR_DS_DRA_BAD_DN },
	{ "WERR_DS_DRA_BAD_NC", WERR_DS_DRA_BAD_NC },
	{ NULL, W_ERROR(0) }
};

werror_str_struct dos_err_strs[] = {
	{ WERR_OK, "Success" },
	{ WERR_ACCESS_DENIED, "Access is denied" },
	{ WERR_INVALID_PARAM, "Invalid parameter" },
	{ WERR_NOT_SUPPORTED, "Not supported" },
	{ WERR_BAD_PASSWORD, "A bad password was supplied" },
	{ WERR_NOMEM, "Out of memory" },
	{ WERR_NO_LOGON_SERVERS, "No logon servers found" },
	{ WERR_NO_SUCH_LOGON_SESSION, "No such logon session" },
	{ WERR_DOMAIN_CONTROLLER_NOT_FOUND, "A domain controller could not be found" },
	{ WERR_DC_NOT_FOUND, "A domain controller could not be found" },
	{ WERR_SETUP_NOT_JOINED, "Join failed" },
	{ WERR_SETUP_ALREADY_JOINED, "Machine is already joined" },
	{ WERR_SETUP_DOMAIN_CONTROLLER, "Machine is a Domain Controller" },
	{ WERR_LOGON_FAILURE, "Invalid logon credentials" },
	{ WERR_USER_EXISTS, "User account already exists" },
	{ WERR_PASSWORD_MUST_CHANGE, "The password must be changed" },
	{ WERR_ACCOUNT_LOCKED_OUT, "Account locked out" },
	{ WERR_TIME_SKEW, "Time difference between client and server" },
	{ WERR_USER_ALREADY_EXISTS, "User already exists" },
	{ WERR_PASSWORD_RESTRICTION, "Password does not meet restrictions" },
	{ WERR_NONE_MAPPED, "Could not map names to SIDs" },
	{ WERR_NO_SUCH_USER, "No such User" },
	{ WERR_GROUP_EXISTS, "Group already exists" },
	{ WERR_DS_DRA_BAD_DN, "An invalid distinguished name was specified for this replication" },
	{ WERR_DS_DRA_BAD_NC, "An invalid naming context was specified for this replication operation" },
	{ WERR_WRONG_PASSWORD, "The current password is incorrect" }
};

/*****************************************************************************
 Returns a DOS error message.  not amazingly helpful, but better than a number.
 *****************************************************************************/

const char *dos_errstr(WERROR werror)
{
	char *result;
        int idx = 0;

	while (dos_errs[idx].dos_errstr != NULL) {
		if (W_ERROR_V(dos_errs[idx].werror) ==
                    W_ERROR_V(werror))
                        return dos_errs[idx].dos_errstr;
		idx++;
	}

	result = talloc_asprintf(talloc_tos(), "DOS code 0x%08x",
				 W_ERROR_V(werror));
	SMB_ASSERT(result != NULL);
        return result;
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

	return dos_errstr(werror);
}

/* compat function for samba4 */
const char *win_errstr(WERROR werror)
{
	return dos_errstr(werror);
}
