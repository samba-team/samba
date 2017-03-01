/*

   Authentication and authorization logging

   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2017

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

/*
 * Debug log levels for authentication logging (these both map to
 * LOG_NOTICE in syslog)
 */
#define AUTH_SUCCESS_LEVEL 4
#define AUTHZ_SUCCESS_LEVEL 5
#define AUTH_FAILURE_LEVEL 2

#include "includes.h"
#include "../lib/tsocket/tsocket.h"
#include "common_auth.h"
#include "lib/util/util_str_escape.h"
#include "libcli/security/dom_sid.h"

/*
 * Get a human readable timestamp.
 *
 * Returns the current time formatted as
 *  "Tue, 14 Mar 2017 08:38:42.209028 NZDT"
 *
 * The returned string is allocated by talloc in the supplied context.
 * It is the callers responsibility to free it.
 *
 */
static const char* get_timestamp( TALLOC_CTX *frame )
{
	char buffer[40];	/* formatted time less usec and timezone */
	char tz[10];		/* formatted time zone			 */
	struct tm* tm_info;	/* current local time			 */
	struct timeval tv;	/* current system time			 */
	int r;			/* response code from gettimeofday	 */
	const char * ts;	/* formatted time stamp			 */

	r = gettimeofday(&tv, NULL);
	if (r) {
		DBG_ERR("Unable to get time of day: (%d) %s\n",
			errno,
			strerror( errno));
		return NULL;
	}

	tm_info = localtime(&tv.tv_sec);
	if (tm_info == NULL) {
		DBG_ERR("Unable to determine local time\n");
		return NULL;
	}

	strftime(buffer, sizeof(buffer)-1, "%a, %d %b %Y %H:%M:%S", tm_info);
	strftime(tz, sizeof(tz)-1, "%Z", tm_info);
	ts = talloc_asprintf(frame, "%s.%06ld %s", buffer, tv.tv_usec, tz);
	if (ts == NULL) {
		DBG_ERR("Out of memory formatting time stamp\n");
	}
	return ts;
}

/*
 * Determine the type of the password supplied for the
 * authorisation attempt.
 *
 */
static const char* get_password_type(const struct auth_usersupplied_info *ui)
{

	const char *password_type = NULL;

	if (ui->password_state == AUTH_PASSWORD_RESPONSE &&
	    (ui->logon_parameters & MSV1_0_ALLOW_MSVCHAPV2) &&
	    ui->password.response.nt.length == 24) {
		password_type = "MSCHAPv2";
	} else if ((ui->logon_parameters & MSV1_0_CLEARTEXT_PASSWORD_SUPPLIED)
		   || (ui->password_state == AUTH_PASSWORD_PLAIN)) {
		password_type = "Plaintext";
	} else if (ui->password_state == AUTH_PASSWORD_HASH) {
		password_type = "Supplied-NT-Hash";
	} else if (ui->password_state == AUTH_PASSWORD_RESPONSE
		   && ui->password.response.nt.length > 24) {
		password_type = "NTLMv2";
	} else if (ui->password_state == AUTH_PASSWORD_RESPONSE
		   && ui->password.response.nt.length == 24) {
		password_type = "NTLMv1";
	} else if (ui->password_state == AUTH_PASSWORD_RESPONSE
		   && ui->password.response.lanman.length == 24) {
		password_type = "LANMan";
	} else if (ui->password_state == AUTH_PASSWORD_RESPONSE
		   && ui->password.response.nt.length == 0
		   && ui->password.response.lanman.length == 0) {
		password_type = "No-Password";
	}
	return password_type;
}

/*
 * Log details of an authentication attempt.
 * Successful and unsuccessful attempts are logged.
 *
 */
void log_authentication_event(const struct auth_usersupplied_info *ui,
			      NTSTATUS status,
			      const char *domain_name,
			      const char *account_name,
			      const char *unix_username,
			      struct dom_sid *sid)
{
	TALLOC_CTX *frame = NULL;

	const char *ts = NULL;		   /* formatted current time      */
	char *remote = NULL;		   /* formatted remote host       */
	char *local = NULL;		   /* formatted local host        */
	char *nl = NULL;		   /* NETLOGON details if present */
	char *trust_computer_name = NULL;
	char *trust_account_name = NULL;
	char *logon_line = NULL;
	const char *password_type = NULL;

	/* set the log level */
	int  level = NT_STATUS_IS_OK(status) ? AUTH_FAILURE_LEVEL : AUTH_SUCCESS_LEVEL;
	if (!CHECK_DEBUGLVLC( DBGC_AUTH_AUDIT, level)) {
		return;
	}

	frame = talloc_stackframe();

	password_type = get_password_type( ui);
	/* Get the current time */
        ts = get_timestamp(frame);

	/* Only log the NETLOGON details if they are present */
	if (ui->netlogon_trust_account.computer_name ||
	    ui->netlogon_trust_account.account_name) {
		trust_computer_name = log_escape(frame,
			ui->netlogon_trust_account.computer_name);
		trust_account_name  = log_escape(frame,
			ui->netlogon_trust_account.account_name);
		nl = talloc_asprintf(frame,
			" NETLOGON computer [%s] trust account [%s]",
			trust_computer_name, trust_account_name);
	}

	remote = tsocket_address_string(ui->remote_host, frame);
	local  = tsocket_address_string(ui->local_host, frame);

	if (NT_STATUS_IS_OK(status)) {
		char sid_buf[DOM_SID_STR_BUFLEN];

		dom_sid_string_buf(sid, sid_buf, sizeof(sid_buf));
		logon_line = talloc_asprintf(frame,
					     " became [%s]\\[%s] [%s].",
					     log_escape(frame, domain_name),
					     log_escape(frame, account_name),
					     sid_buf);
	} else {
		logon_line = talloc_asprintf(frame,
					     " mapped to [%s]\\[%s].",
					     log_escape(frame, ui->mapped.domain_name),
					     log_escape(frame, ui->mapped.account_name));
	}

	DEBUGC( DBGC_AUTH_AUDIT, level, (
		"Auth: [%s,%s] user [%s]\\[%s]"
		" at [%s] with [%s] status [%s]"
		" workstation [%s] remote host [%s]"
		"%s local host [%s]"
		" %s\n",
		ui->service_description,
		ui->auth_description,
		log_escape(frame, ui->client.domain_name),
		log_escape(frame, ui->client.account_name),
		ts,
		password_type,
		nt_errstr( status),
		log_escape(frame, ui->workstation_name),
		remote,
		logon_line,
		local,
		nl ? nl : ""
		));

	talloc_free(frame);
}


/*
 * Log details of a successful authorization to a service.
 *
 * Only successful authorizations are logged.  For clarity:
 * - NTLM bad passwords will be recorded by the above
 * - Kerberos decrypt failures need to be logged in gensec_gssapi et al
 *
 * The service may later refuse authorization due to an ACL.
 *
 */
void log_successful_authz_event(const struct tsocket_address *remote,
				const struct tsocket_address *local,
				const char *service_description,
				struct auth_session_info *session_info)
{
	TALLOC_CTX *frame = NULL;

	const char *ts = NULL;       /* formatted current time      */
	char *remote_str = NULL;     /* formatted remote host       */
	char *local_str = NULL;      /* formatted local host        */
	char sid_buf[DOM_SID_STR_BUFLEN];

	/* set the log level */
	if (!CHECK_DEBUGLVLC( DBGC_AUTH_AUDIT, AUTHZ_SUCCESS_LEVEL)) {
		return;
	}

	frame = talloc_stackframe();

	/* Get the current time */
        ts = get_timestamp(frame);

	remote_str = tsocket_address_string(remote, frame);
	local_str  = tsocket_address_string(local, frame);

	dom_sid_string_buf(&session_info->security_token->sids[0], sid_buf, sizeof(sid_buf));

	DEBUGC( DBGC_AUTH_AUDIT, AUTHZ_SUCCESS_LEVEL, (
		"Successful AuthZ: [%s] user [%s]\\[%s] [%s]"
		" at [%s]"
		" Remote host [%s]"
		" local host [%s]\n",
		service_description,
		log_escape(frame, session_info->info->domain_name),
		log_escape(frame, session_info->info->account_name),
		sid_buf,
		ts,
		remote_str,
		local_str));

	talloc_free(frame);
}
