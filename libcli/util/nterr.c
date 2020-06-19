/*
 *  Unix SMB/CIFS implementation.
 *  RPC Pipe client / server routines
 *
 *  Copyright (C) Luke Kenneth Casson Leighton 1997-2001.
 *  Copyright (C) Andrew Bartlett
 *  Copyright (C) Andrew Tridgell
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

/* NT error codes.  please read nterr.h */

#include "includes.h"
#include "../libcli/ldap/ldap_errors.h"
#undef strcasecmp

#if !defined(N_)
#define N_(string) string
#endif

#define DOS_CODE(class, code) { #class ":" #code, NT_STATUS_DOS(class, code) }
#define LDAP_CODE(code) { #code, NT_STATUS_LDAP(code) }

typedef struct
{
	const char *nt_errstr;
	NTSTATUS nt_errcode;
} nt_err_code_struct;

#include "nterr_gen.c"

/* Errors which aren't in the generated code because they're not in the
 * same table as the other ones. */
static const nt_err_code_struct special_errs[] =
{
        { "NT_STATUS_OK", NT_STATUS_OK },
        { "STATUS_NO_MORE_FILES", STATUS_NO_MORE_FILES },
        { "STATUS_INVALID_EA_NAME", STATUS_INVALID_EA_NAME },
        { "STATUS_BUFFER_OVERFLOW", STATUS_BUFFER_OVERFLOW },
        { "STATUS_MORE_ENTRIES", STATUS_MORE_ENTRIES },
        { "STATUS_SOME_UNMAPPED", STATUS_SOME_UNMAPPED },
        { "NT_STATUS_ERROR_DS_OBJ_STRING_NAME_EXISTS", NT_STATUS_ERROR_DS_OBJ_STRING_NAME_EXISTS },
        { "NT_STATUS_ERROR_DS_INCOMPATIBLE_VERSION", NT_STATUS_ERROR_DS_INCOMPATIBLE_VERSION },
        { "NT_STATUS_SMB_NO_PREAUTH_INTEGRITY_HASH_OVERLAP", NT_STATUS_SMB_NO_PREAUTH_INTEGRITY_HASH_OVERLAP },
	{ "NT_STATUS_INACCESSIBLE_SYSTEM_SHORTCUT", NT_STATUS_INACCESSIBLE_SYSTEM_SHORTCUT },
	{ "NT_STATUS_ABIOS_NOT_PRESENT", NT_STATUS_ABIOS_NOT_PRESENT },
	{ "NT_STATUS_ABIOS_LID_NOT_EXIST", NT_STATUS_ABIOS_LID_NOT_EXIST },
	{ "NT_STATUS_ABIOS_LID_ALREADY_OWNED", NT_STATUS_ABIOS_LID_ALREADY_OWNED },
	{ "NT_STATUS_ABIOS_NOT_LID_OWNER", NT_STATUS_ABIOS_NOT_LID_OWNER },
	{ "NT_STATUS_ABIOS_INVALID_COMMAND", NT_STATUS_ABIOS_INVALID_COMMAND },
	{ "NT_STATUS_ABIOS_INVALID_LID", NT_STATUS_ABIOS_INVALID_LID },
	{ "NT_STATUS_ABIOS_SELECTOR_NOT_AVAILABLE", NT_STATUS_ABIOS_SELECTOR_NOT_AVAILABLE },
	{ "NT_STATUS_ABIOS_INVALID_SELECTOR", NT_STATUS_ABIOS_INVALID_SELECTOR },
	{ "NT_STATUS_HANDLE_NOT_WAITABLE", NT_STATUS_HANDLE_NOT_WAITABLE },
	{ "NT_STATUS_DEVICE_POWER_FAILURE", NT_STATUS_DEVICE_POWER_FAILURE },
	{ "NT_STATUS_VHD_SHARED", NT_STATUS_VHD_SHARED },
	{ "NT_STATUS_SMB_BAD_CLUSTER_DIALECT", NT_STATUS_SMB_BAD_CLUSTER_DIALECT },
	{ "NT_STATUS_NO_SUCH_JOB", NT_STATUS_NO_SUCH_JOB },

	DOS_CODE(ERRDOS, ERRsuccess),
	DOS_CODE(ERRDOS, ERRbadfunc),
	DOS_CODE(ERRDOS, ERRbadfile),
	DOS_CODE(ERRDOS, ERRbadpath),
	DOS_CODE(ERRDOS, ERRnofids),
	DOS_CODE(ERRDOS, ERRnoaccess),
	DOS_CODE(ERRDOS, ERRbadfid),
	DOS_CODE(ERRDOS, ERRbadmcb),
	DOS_CODE(ERRDOS, ERRnomem),
	DOS_CODE(ERRDOS, ERRbadmem),
	DOS_CODE(ERRDOS, ERRbadenv),
	DOS_CODE(ERRDOS, ERRbadaccess),
	DOS_CODE(ERRDOS, ERRbaddata),
	DOS_CODE(ERRDOS, ERRres),
	DOS_CODE(ERRDOS, ERRbaddrive),
	DOS_CODE(ERRDOS, ERRremcd),
	DOS_CODE(ERRDOS, ERRdiffdevice),
	DOS_CODE(ERRDOS, ERRnofiles),
	DOS_CODE(ERRDOS, ERRgeneral),
	DOS_CODE(ERRDOS, ERRbadshare),
	DOS_CODE(ERRDOS, ERRlock),
	DOS_CODE(ERRDOS, ERRunsup),
	DOS_CODE(ERRDOS, ERRnetnamedel),
	DOS_CODE(ERRDOS, ERRnosuchshare),
	DOS_CODE(ERRDOS, ERRfilexists),
	DOS_CODE(ERRDOS, ERRinvalidparam),
	DOS_CODE(ERRDOS, ERRcannotopen),
	DOS_CODE(ERRDOS, ERRinsufficientbuffer),
	DOS_CODE(ERRDOS, ERRinvalidname),
	DOS_CODE(ERRDOS, ERRunknownlevel),
	DOS_CODE(ERRDOS, ERRnotlocked),
	DOS_CODE(ERRDOS, ERRinvalidpath),
	DOS_CODE(ERRDOS, ERRcancelviolation),
	DOS_CODE(ERRDOS, ERRnoatomiclocks),
	DOS_CODE(ERRDOS, ERRrename),
	DOS_CODE(ERRDOS, ERRbadpipe),
	DOS_CODE(ERRDOS, ERRpipebusy),
	DOS_CODE(ERRDOS, ERRpipeclosing),
	DOS_CODE(ERRDOS, ERRnotconnected),
	DOS_CODE(ERRDOS, ERRmoredata),
	DOS_CODE(ERRDOS, ERRnomoreitems),
	DOS_CODE(ERRDOS, ERRbaddirectory),
	DOS_CODE(ERRDOS, ERReasnotsupported),
	DOS_CODE(ERRDOS, ERRlogonfailure),
	DOS_CODE(ERRDOS, ERRbuftoosmall),
	DOS_CODE(ERRDOS, ERRunknownipc),
	DOS_CODE(ERRDOS, ERRnosuchprintjob),
	DOS_CODE(ERRDOS, ERRinvgroup),
	DOS_CODE(ERRDOS, ERRnoipc),
	DOS_CODE(ERRDOS, ERRdriveralreadyinstalled),
	DOS_CODE(ERRDOS, ERRunknownprinterport),
	DOS_CODE(ERRDOS, ERRunknownprinterdriver),
	DOS_CODE(ERRDOS, ERRunknownprintprocessor),
	DOS_CODE(ERRDOS, ERRinvalidseparatorfile),
	DOS_CODE(ERRDOS, ERRinvalidjobpriority),
	DOS_CODE(ERRDOS, ERRinvalidprintername),
	DOS_CODE(ERRDOS, ERRprinteralreadyexists),
	DOS_CODE(ERRDOS, ERRinvalidprintercommand),
	DOS_CODE(ERRDOS, ERRinvaliddatatype),
	DOS_CODE(ERRDOS, ERRinvalidenvironment),
	DOS_CODE(ERRDOS, ERRunknownprintmonitor),
	DOS_CODE(ERRDOS, ERRprinterdriverinuse),
	DOS_CODE(ERRDOS, ERRspoolfilenotfound),
	DOS_CODE(ERRDOS, ERRnostartdoc),
	DOS_CODE(ERRDOS, ERRnoaddjob),
	DOS_CODE(ERRDOS, ERRprintprocessoralreadyinstalled),
	DOS_CODE(ERRDOS, ERRprintmonitoralreadyinstalled),
	DOS_CODE(ERRDOS, ERRinvalidprintmonitor),
	DOS_CODE(ERRDOS, ERRprintmonitorinuse),
	DOS_CODE(ERRDOS, ERRprinterhasjobsqueued),
	DOS_CODE(ERRDOS, ERReainconsistent),

	DOS_CODE(ERRSRV, ERRerror),
	DOS_CODE(ERRSRV, ERRbadpw),
	DOS_CODE(ERRSRV, ERRbadtype),
	DOS_CODE(ERRSRV, ERRaccess),
	DOS_CODE(ERRSRV, ERRinvnid),
	DOS_CODE(ERRSRV, ERRinvnetname),
	DOS_CODE(ERRSRV, ERRinvdevice),
	DOS_CODE(ERRSRV, ERRqfull),
	DOS_CODE(ERRSRV, ERRqtoobig),
	DOS_CODE(ERRSRV, ERRinvpfid),
	DOS_CODE(ERRSRV, ERRsmbcmd),
	DOS_CODE(ERRSRV, ERRsrverror),
	DOS_CODE(ERRSRV, ERRfilespecs),
	DOS_CODE(ERRSRV, ERRbadlink),
	DOS_CODE(ERRSRV, ERRbadpermits),
	DOS_CODE(ERRSRV, ERRbadpid),
	DOS_CODE(ERRSRV, ERRsetattrmode),
	DOS_CODE(ERRSRV, ERRpaused),
	DOS_CODE(ERRSRV, ERRmsgoff),
	DOS_CODE(ERRSRV, ERRnoroom),
	DOS_CODE(ERRSRV, ERRrmuns),
	DOS_CODE(ERRSRV, ERRtimeout),
	DOS_CODE(ERRSRV, ERRnoresource),
	DOS_CODE(ERRSRV, ERRtoomanyuids),
	DOS_CODE(ERRSRV, ERRbaduid),
	DOS_CODE(ERRSRV, ERRuseMPX),
	DOS_CODE(ERRSRV, ERRuseSTD),
	DOS_CODE(ERRSRV, ERRcontMPX),
	DOS_CODE(ERRSRV, ERRnosupport),
	DOS_CODE(ERRSRV, ERRunknownsmb),

	DOS_CODE(ERRHRD, ERRnowrite),
	DOS_CODE(ERRHRD, ERRbadunit),
	DOS_CODE(ERRHRD, ERRnotready),
	DOS_CODE(ERRHRD, ERRbadcmd),
	DOS_CODE(ERRHRD, ERRdata),
	DOS_CODE(ERRHRD, ERRbadreq),
	DOS_CODE(ERRHRD, ERRseek),
	DOS_CODE(ERRHRD, ERRbadmedia),
	DOS_CODE(ERRHRD, ERRbadsector),
	DOS_CODE(ERRHRD, ERRnopaper),
	DOS_CODE(ERRHRD, ERRwrite),
	DOS_CODE(ERRHRD, ERRread),
	DOS_CODE(ERRHRD, ERRgeneral),
	DOS_CODE(ERRHRD, ERRwrongdisk),
	DOS_CODE(ERRHRD, ERRFCBunavail),
	DOS_CODE(ERRHRD, ERRsharebufexc),
	DOS_CODE(ERRHRD, ERRdiskfull),

	LDAP_CODE(LDAP_SUCCESS),
	LDAP_CODE(LDAP_OPERATIONS_ERROR),
	LDAP_CODE(LDAP_PROTOCOL_ERROR),
	LDAP_CODE(LDAP_TIME_LIMIT_EXCEEDED),
	LDAP_CODE(LDAP_SIZE_LIMIT_EXCEEDED),
	LDAP_CODE(LDAP_COMPARE_FALSE),
	LDAP_CODE(LDAP_COMPARE_TRUE),
	LDAP_CODE(LDAP_AUTH_METHOD_NOT_SUPPORTED),
	LDAP_CODE(LDAP_STRONG_AUTH_REQUIRED),
	LDAP_CODE(LDAP_REFERRAL),
	LDAP_CODE(LDAP_ADMIN_LIMIT_EXCEEDED),
	LDAP_CODE(LDAP_UNAVAILABLE_CRITICAL_EXTENSION),
	LDAP_CODE(LDAP_CONFIDENTIALITY_REQUIRED),
	LDAP_CODE(LDAP_SASL_BIND_IN_PROGRESS),
	LDAP_CODE(LDAP_NO_SUCH_ATTRIBUTE),
	LDAP_CODE(LDAP_UNDEFINED_ATTRIBUTE_TYPE),
	LDAP_CODE(LDAP_INAPPROPRIATE_MATCHING),
	LDAP_CODE(LDAP_CONSTRAINT_VIOLATION),
	LDAP_CODE(LDAP_ATTRIBUTE_OR_VALUE_EXISTS),
	LDAP_CODE(LDAP_INVALID_ATTRIBUTE_SYNTAX),
	LDAP_CODE(LDAP_NO_SUCH_OBJECT),
	LDAP_CODE(LDAP_ALIAS_PROBLEM),
	LDAP_CODE(LDAP_INVALID_DN_SYNTAX),
	LDAP_CODE(LDAP_ALIAS_DEREFERENCING_PROBLEM),
	LDAP_CODE(LDAP_INAPPROPRIATE_AUTHENTICATION),
	LDAP_CODE(LDAP_INVALID_CREDENTIALS),
	LDAP_CODE(LDAP_INSUFFICIENT_ACCESS_RIGHTS),
	LDAP_CODE(LDAP_BUSY),
	LDAP_CODE(LDAP_UNAVAILABLE),
	LDAP_CODE(LDAP_UNWILLING_TO_PERFORM),
	LDAP_CODE(LDAP_LOOP_DETECT),
	LDAP_CODE(LDAP_NAMING_VIOLATION),
	LDAP_CODE(LDAP_OBJECT_CLASS_VIOLATION),
	LDAP_CODE(LDAP_NOT_ALLOWED_ON_NON_LEAF),
	LDAP_CODE(LDAP_NOT_ALLOWED_ON_RDN),
	LDAP_CODE(LDAP_ENTRY_ALREADY_EXISTS),
	LDAP_CODE(LDAP_OBJECT_CLASS_MODS_PROHIBITED),
	LDAP_CODE(LDAP_AFFECTS_MULTIPLE_DSAS),
	LDAP_CODE(LDAP_OTHER),

	{ NULL, NT_STATUS(0) }
};

/*****************************************************************************
 Returns an NT_STATUS constant as a string for inclusion in autogen C code.
 *****************************************************************************/

const char *get_nt_error_c_code(TALLOC_CTX *mem_ctx, NTSTATUS nt_code)
{
	char *result;
	int idx = 0;

	while (special_errs[idx].nt_errstr != NULL) {
		if (NT_STATUS_V(special_errs[idx].nt_errcode) ==
		    NT_STATUS_V(nt_code)) {
			result = talloc_strdup(mem_ctx, special_errs[idx].nt_errstr);
			return result;
		}
		idx++;
	}

	idx = 0;

	while (nt_errs[idx].nt_errstr != NULL) {
		if (NT_STATUS_V(nt_errs[idx].nt_errcode) ==
		    NT_STATUS_V(nt_code)) {
			result = talloc_strdup(mem_ctx, nt_errs[idx].nt_errstr);
			return result;
		}
		idx++;
	}

	result = talloc_asprintf(mem_ctx, "NT_STATUS(0x%08x)",
				 NT_STATUS_V(nt_code));
	return result;
}

/*****************************************************************************
 Returns the NT_STATUS constant matching the string supplied (as an NTSTATUS)
 *****************************************************************************/

NTSTATUS nt_status_string_to_code(const char *nt_status_str)
{
	int idx = 0;

	while (special_errs[idx].nt_errstr != NULL) {
		if (strcasecmp(special_errs[idx].nt_errstr, nt_status_str) == 0) {
			return special_errs[idx].nt_errcode;
		}
		idx++;
	}

	idx = 0;

	while (nt_errs[idx].nt_errstr != NULL) {
		if (strcasecmp(nt_errs[idx].nt_errstr, nt_status_str) == 0) {
			return nt_errs[idx].nt_errcode;
		}
		idx++;
	}

	return NT_STATUS_UNSUCCESSFUL;
}

/**
 * Squash an NT_STATUS in line with security requirements.
 * In an attempt to avoid giving the whole game away when users
 * are authenticating, NT replaces both NT_STATUS_NO_SUCH_USER and
 * NT_STATUS_WRONG_PASSWORD with NT_STATUS_LOGON_FAILURE in certain situations
 * (session setups in particular).
 *
 * @param nt_status NTSTATUS input for squashing.
 * @return the 'squashed' nt_status
 **/

NTSTATUS nt_status_squash(NTSTATUS nt_status)
{
	if NT_STATUS_IS_OK(nt_status) {
		return nt_status;
	} else if NT_STATUS_EQUAL(nt_status, NT_STATUS_NO_SUCH_USER) {
		/* Match WinXP and don't give the game away */
		return NT_STATUS_LOGON_FAILURE;

	} else if NT_STATUS_EQUAL(nt_status, NT_STATUS_WRONG_PASSWORD) {
		/* Match WinXP and don't give the game away */
		return NT_STATUS_LOGON_FAILURE;
	} else {
		return nt_status;
	}
}

/*****************************************************************************
 Returns an NT error message.  not amazingly helpful, but better than a number.
 *****************************************************************************/

const char *nt_errstr(NTSTATUS nt_code)
{
	static char msg[20];
	int idx = 0;

	while (special_errs[idx].nt_errstr != NULL) {
		if (NT_STATUS_V(special_errs[idx].nt_errcode) ==
		    NT_STATUS_V(nt_code)) {
			return special_errs[idx].nt_errstr;
		}
		idx++;
	}

	idx = 0;

	while (nt_errs[idx].nt_errstr != NULL) {
		if (NT_STATUS_V(nt_errs[idx].nt_errcode) ==
		    NT_STATUS_V(nt_code)) {
			return nt_errs[idx].nt_errstr;
		}
		idx++;
	}

	/*
	 * This should not really happen, we should have all error codes
	 * available. We have a problem that this might get wrongly
	 * overwritten by later calls in the same DEBUG statement.
	 */

	snprintf(msg, sizeof(msg), "NT code 0x%08x", NT_STATUS_V(nt_code));
	return msg;
}

/************************************************************************
 Print friendler version fo NT error code
 ***********************************************************************/

const char *get_friendly_nt_error_msg(NTSTATUS nt_code)
{
	int idx = 0;

	while (nt_err_desc[idx].nt_errstr != NULL) {
		if (NT_STATUS_V(nt_err_desc[idx].nt_errcode) == NT_STATUS_V(nt_code)) {
			return nt_err_desc[idx].nt_errstr;
		}
		idx++;
	}

	/* fall back to NT_STATUS_XXX string */

	return nt_errstr(nt_code);
}
