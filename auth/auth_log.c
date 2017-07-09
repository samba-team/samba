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
#define AUTH_FAILURE_LEVEL 2
#define AUTH_SUCCESS_LEVEL 3
#define AUTHZ_SUCCESS_LEVEL 4

/* 5 is used for both authentication and authorization */
#define AUTH_ANONYMOUS_LEVEL 5
#define AUTHZ_ANONYMOUS_LEVEL 5

#define AUTHZ_JSON_TYPE "Authorization"
#define AUTH_JSON_TYPE  "Authentication"

/*
 * JSON message version numbers
 *
 * If adding a field increment the minor version
 * If removing or changing the format/meaning of a field
 * increment the major version.
 */
#define AUTH_MAJOR 1
#define AUTH_MINOR 0
#define AUTHZ_MAJOR 1
#define AUTHZ_MINOR 0

#include "includes.h"
#include "../lib/tsocket/tsocket.h"
#include "common_auth.h"
#include "lib/util/util_str_escape.h"
#include "libcli/security/dom_sid.h"
#include "libcli/security/security_token.h"
#include "librpc/gen_ndr/server_id.h"
#include "source4/lib/messaging/messaging.h"
#include "source4/lib/messaging/irpc.h"
#include "lib/util/server_id_db.h"
#include "lib/param/param.h"

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
static const char* get_timestamp(TALLOC_CTX *frame)
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
			strerror(errno));
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
static const char* get_password_type(const struct auth_usersupplied_info *ui);

#ifdef HAVE_JANSSON

#include <jansson.h>
#include "system/time.h"

/*
 * Context required by the JSON generation
 *  routines
 *
 */
struct json_context {
	json_t *root;
	bool error;
};

static NTSTATUS get_auth_event_server(struct imessaging_context *msg_ctx,
				      struct server_id *auth_event_server)
{
	NTSTATUS status;
	TALLOC_CTX *frame = talloc_stackframe();
	unsigned num_servers, i;
	struct server_id *servers;

	status = irpc_servers_byname(msg_ctx, frame,
				     AUTH_EVENT_NAME,
				     &num_servers, &servers);

	if (!NT_STATUS_IS_OK(status)) {
		DBG_NOTICE("Failed to find 'auth_event' registered on the "
			   "message bus to send JSON authentication events to: %s\n",
			   nt_errstr(status));
		TALLOC_FREE(frame);
		return status;
	}

	/*
	 * Select the first server that is listening, because
	 * we get connection refused as
	 * NT_STATUS_OBJECT_NAME_NOT_FOUND without waiting
	 */
	for (i = 0; i < num_servers; i++) {
		status = imessaging_send(msg_ctx, servers[i], MSG_PING,
					 &data_blob_null);
		if (NT_STATUS_IS_OK(status)) {
			*auth_event_server = servers[i];
			TALLOC_FREE(frame);
			return NT_STATUS_OK;
		}
	}
	DBG_NOTICE("Failed to find a running 'auth_event' server "
		   "registered on the message bus to send JSON "
		   "authentication events to\n");
	TALLOC_FREE(frame);
	return NT_STATUS_OBJECT_NAME_NOT_FOUND;
}

static void auth_message_send(struct imessaging_context *msg_ctx,
			      const char *json)
{
	struct server_id auth_event_server;
	NTSTATUS status;
	DATA_BLOB json_blob = data_blob_string_const(json);
	if (msg_ctx == NULL) {
		return;
	}

	/* Need to refetch the address each time as the destination server may
	 * have disconnected and reconnected in the interim, in which case
	 * messages may get lost, manifests in the auth_log tests
	 */
	status = get_auth_event_server(msg_ctx, &auth_event_server);
	if (!NT_STATUS_IS_OK(status)) {
		return;
	}

	status = imessaging_send(msg_ctx, auth_event_server, MSG_AUTH_LOG,
				 &json_blob);

	/* If the server crashed, try to find it again */
	if (NT_STATUS_EQUAL(status, NT_STATUS_OBJECT_NAME_NOT_FOUND)) {
		status = get_auth_event_server(msg_ctx, &auth_event_server);
		if (!NT_STATUS_IS_OK(status)) {
			return;
		}
		imessaging_send(msg_ctx, auth_event_server, MSG_AUTH_LOG,
				&json_blob);

	}
}

/*
 * Write the json object to the debug logs.
 *
 */
static void log_json(struct imessaging_context *msg_ctx,
		     struct json_context *context,
		     const char *type, int debug_class, int debug_level)
{
	char* json = NULL;

	if (context->error) {
		return;
	}

	json = json_dumps(context->root, 0);
	if (json == NULL) {
		DBG_ERR("Unable to convert JSON object to string\n");
		context->error = true;
		return;
	}

	DEBUGC(debug_class, debug_level, ("JSON %s: %s\n", type, json));
	auth_message_send(msg_ctx, json);

	if (json) {
		free(json);
	}

}

/*
 * Create a new json logging context.
 *
 * Free with a call to free_json_context
 *
 */
static struct json_context get_json_context(void) {

	struct json_context context;
	context.error = false;

	context.root = json_object();
	if (context.root == NULL) {
		context.error = true;
		DBG_ERR("Unable to create json_object\n");
	}
	return context;
}

/*
 * free a previously created json_context
 *
 */
static void free_json_context(struct json_context *context)
{
	if (context->root) {
		json_decref(context->root);
	}
}

/*
 * Output a JSON pair with name name and integer value value
 *
 */
static void add_int(struct json_context *context,
		    const char* name,
		    const int value)
{
	int rc = 0;

	if (context->error) {
		return;
	}

	rc = json_object_set_new(context->root, name, json_integer(value));
	if (rc) {
		DBG_ERR("Unable to set name [%s] value [%d]\n", name, value);
		context->error = true;
	}

}

/*
 * Output a JSON pair with name name and string value value
 *
 */
static void add_string(struct json_context *context,
		       const char* name,
		       const char* value)
{
	int rc = 0;

	if (context->error) {
		return;
	}

	if (value) {
		rc = json_object_set_new(context->root, name, json_string(value));
	} else {
		rc = json_object_set_new(context->root, name, json_null());
	}
	if (rc) {
		DBG_ERR("Unable to set name [%s] value [%s]\n", name, value);
		context->error = true;
	}
}


/*
 * Output a JSON pair with name name and object value
 *
 */
static void add_object(struct json_context *context,
		       const char* name,
		       struct json_context *value)
{
	int rc = 0;

	if (value->error) {
		context->error = true;
	}
	if (context->error) {
		return;
	}
	rc = json_object_set_new(context->root, name, value->root);
	if (rc) {
		DBG_ERR("Unable to add object [%s]\n", name);
		context->error = true;
	}
}

/*
 * Output a version object
 *
 * "version":{"major":1,"minor":0}
 *
 */
static void add_version(struct json_context *context, int major, int minor)
{
	struct json_context version = get_json_context();
	add_int(&version, "major", major);
	add_int(&version, "minor", minor);
	add_object(context, "version", &version);
}

/*
 * Output the current date and time as a timestamp in ISO 8601 format
 *
 * "timestamp":"2017-03-06T17:18:04.455081+1300"
 *
 */
static void add_timestamp(struct json_context *context)
{
	char buffer[40];	/* formatted time less usec and timezone */
	char timestamp[50];	/* the formatted ISO 8601 time stamp	 */
	char tz[10];		/* formatted time zone			 */
	struct tm* tm_info;	/* current local time			 */
	struct timeval tv;	/* current system time			 */
	int r;			/* response code from gettimeofday	 */

	if (context->error) {
		return;
	}

	r = gettimeofday(&tv, NULL);
	if (r) {
		DBG_ERR("Unable to get time of day: (%d) %s\n",
			errno,
			strerror(errno));
		context->error = true;
		return;
	}

	tm_info = localtime(&tv.tv_sec);
	if (tm_info == NULL) {
		DBG_ERR("Unable to determine local time\n");
		context->error = true;
		return;
	}

	strftime(buffer, sizeof(buffer)-1, "%Y-%m-%dT%T", tm_info);
	strftime(tz, sizeof(tz)-1, "%z", tm_info);
	snprintf(timestamp, sizeof(timestamp),"%s.%06ld%s",
		 buffer, tv.tv_usec, tz);
	add_string(context,"timestamp", timestamp);
}


/*
 * Output an address pair, with name name.
 *
 * "localAddress":"ipv6::::0"
 *
 */
static void add_address(struct json_context *context,
			const char *name,
			const struct tsocket_address *address)
{
	char *s = NULL;
	TALLOC_CTX *frame = talloc_stackframe();

	if (context->error) {
		return;
	}

	s = tsocket_address_string(address, frame);
	add_string(context, name, s);
	talloc_free(frame);

}

/*
 * Output a SID with name name
 *
 * "sid":"S-1-5-18"
 *
 */
static void add_sid(struct json_context *context,
		    const char *name,
		    const struct dom_sid *sid)
{
	char sid_buf[DOM_SID_STR_BUFLEN];

	if (context->error) {
		return;
	}

	dom_sid_string_buf(sid, sid_buf, sizeof(sid_buf));
	add_string(context, name, sid_buf);
}

/*
 * Write a machine parsable json formatted authentication log entry.
 *
 * IF removing or changing the format/meaning of a field please update the
 *    major version number AUTH_MAJOR
 *
 * IF adding a new field please update the minor version number AUTH_MINOR
 *
 *  To process the resulting log lines from the commend line use jq to
 *  parse the json.
 *
 *  grep "JSON Authentication" log file |
 *  sed 's;^[^{]*;;' |
 * jq -rc  '"\(.timestamp)\t\(.Authentication.status)\t
 *           \(.Authentication.clientDomain)\t
 *           \(.Authentication.clientAccount)
 *           \t\(.Authentication.workstation)
 *           \t\(.Authentication.remoteAddress)
 *           \t\(.Authentication.localAddress)"'
 */
static void log_authentication_event_json(
	                struct imessaging_context *msg_ctx,
			struct loadparm_context *lp_ctx,
			const struct auth_usersupplied_info *ui,
			NTSTATUS status,
			const char *domain_name,
			const char *account_name,
			const char *unix_username,
			struct dom_sid *sid,
			int debug_level)
{
	struct json_context context = get_json_context();
	struct json_context authentication;
	char negotiate_flags[11];

	add_timestamp(&context);
	add_string(&context, "type", AUTH_JSON_TYPE);

	authentication = get_json_context();
	add_version(&authentication, AUTH_MAJOR, AUTH_MINOR);
	add_string(&authentication, "status", nt_errstr(status));
	add_address(&authentication, "localAddress", ui->local_host);
	add_address(&authentication, "remoteAddress", ui->remote_host);
	add_string(&authentication,
		   "serviceDescription",
		   ui->service_description);
	add_string(&authentication, "authDescription", ui->auth_description);
	add_string(&authentication, "clientDomain", ui->client.domain_name);
	add_string(&authentication, "clientAccount", ui->client.account_name);
	add_string(&authentication, "workstation", ui->workstation_name);
	add_string(&authentication, "becameAccount", account_name);
	add_string(&authentication, "becameDomain", domain_name);
	add_sid(&authentication, "becameSid", sid);
	add_string(&authentication, "mappedAccount", ui->mapped.account_name);
	add_string(&authentication, "mappedDomain", ui->mapped.domain_name);
	add_string(&authentication,
		   "netlogonComputer",
		   ui->netlogon_trust_account.computer_name);
	add_string(&authentication,
		   "netlogonTrustAccount",
		   ui->netlogon_trust_account.account_name);
	snprintf(negotiate_flags,
		 sizeof( negotiate_flags),
		 "0x%08X",
		 ui->netlogon_trust_account.negotiate_flags);
	add_string(&authentication, "netlogonNegotiateFlags", negotiate_flags);
	add_int(&authentication,
		"netlogonSecureChannelType",
		ui->netlogon_trust_account.secure_channel_type);
	add_sid(&authentication,
		"netlogonTrustAccountSid",
		ui->netlogon_trust_account.sid);
	add_string(&authentication, "passwordType", get_password_type(ui));
	add_object(&context,AUTH_JSON_TYPE, &authentication);

	log_json(msg_ctx, &context, AUTH_JSON_TYPE, DBGC_AUTH_AUDIT, debug_level);
	free_json_context(&context);
}

/*
 * Log details of a successful authorization to a service,
 * in a machine parsable json format
 *
 * IF removing or changing the format/meaning of a field please update the
 *    major version number AUTHZ_MAJOR
 *
 * IF adding a new field please update the minor version number AUTHZ_MINOR
 *
 *  To process the resulting log lines from the commend line use jq to
 *  parse the json.
 *
 *  grep "JSON Authentication" log_file |\
 *  sed "s;^[^{]*;;" |\
 *  jq -rc '"\(.timestamp)\t
 *           \(.Authorization.domain)\t
 *           \(.Authorization.account)\t
 *           \(.Authorization.remoteAddress)"'
 *
 */
static void log_successful_authz_event_json(
				struct imessaging_context *msg_ctx,
				struct loadparm_context *lp_ctx,
				const struct tsocket_address *remote,
				const struct tsocket_address *local,
				const char *service_description,
				const char *auth_type,
				const char *transport_protection,
				struct auth_session_info *session_info,
				int debug_level)
{
	struct json_context context = get_json_context();
	struct json_context authorization;
	char account_flags[11];

	//start_object(&context, NULL);
	add_timestamp(&context);
	add_string(&context, "type", AUTHZ_JSON_TYPE);
	authorization = get_json_context();
	add_version(&authorization, AUTHZ_MAJOR, AUTHZ_MINOR);
	add_address(&authorization, "localAddress", local);
	add_address(&authorization, "remoteAddress", remote);
	add_string(&authorization, "serviceDescription", service_description);
	add_string(&authorization, "authType", auth_type);
	add_string(&authorization, "domain", session_info->info->domain_name);
	add_string(&authorization, "account", session_info->info->account_name);
	add_sid(&authorization, "sid", &session_info->security_token->sids[0]);
	add_string(&authorization,
		   "logonServer",
		   session_info->info->logon_server);
	add_string(&authorization, "transportProtection", transport_protection);

	snprintf(account_flags,
		 sizeof(account_flags),
		 "0x%08X",
		 session_info->info->acct_flags);
	add_string(&authorization, "accountFlags", account_flags);
	add_object(&context,AUTHZ_JSON_TYPE, &authorization);

	log_json(msg_ctx,
		 &context,
		 AUTHZ_JSON_TYPE,
		 DBGC_AUTH_AUDIT,
		 debug_level);
	free_json_context(&context);
}

#else

static void log_no_json(struct imessaging_context *msg_ctx,
                        struct loadparm_context *lp_ctx)
{
	if (msg_ctx && lp_ctx && lpcfg_auth_event_notification(lp_ctx)) {
		static bool auth_event_logged = false;
		if (auth_event_logged == false) {
			auth_event_logged = true;
			DBG_ERR("auth event notification = true but Samba was not compiled with jansson\n");
		}
	} else {
		static bool json_logged = false;
		if (json_logged == false) {
			json_logged = true;
			DBG_NOTICE("JSON auth logs not available unless compiled with jansson\n");
		}
	}

	return;
}

static void log_authentication_event_json(
	                struct imessaging_context *msg_ctx,
			struct loadparm_context *lp_ctx,
			const struct auth_usersupplied_info *ui,
			NTSTATUS status,
			const char *domain_name,
			const char *account_name,
			const char *unix_username,
			struct dom_sid *sid,
			int debug_level)
{
	log_no_json(msg_ctx, lp_ctx);
	return;
}

static void log_successful_authz_event_json(
				struct imessaging_context *msg_ctx,
				struct loadparm_context *lp_ctx,
				const struct tsocket_address *remote,
				const struct tsocket_address *local,
				const char *service_description,
				const char *auth_type,
				const char *transport_protection,
				struct auth_session_info *session_info,
				int debug_level)
{
	log_no_json(msg_ctx, lp_ctx);
	return;
}

#endif

/*
 * Determine the type of the password supplied for the
 * authorisation attempt.
 *
 */
static const char* get_password_type(const struct auth_usersupplied_info *ui)
{

	const char *password_type = NULL;

	if (ui->password_type != NULL) {
		password_type = ui->password_type;
	} else if (ui->auth_description != NULL &&
		   strncmp("ServerAuthenticate", ui->auth_description, 18) == 0)
	{
		if (ui->netlogon_trust_account.negotiate_flags
		    & NETLOGON_NEG_SUPPORTS_AES) {
			password_type = "HMAC-SHA256";
		} else if (ui->netlogon_trust_account.negotiate_flags
		           & NETLOGON_NEG_STRONG_KEYS) {
			password_type = "HMAC-MD5";
		} else {
			password_type = "DES";
		}
	} else if (ui->password_state == AUTH_PASSWORD_RESPONSE &&
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
 * Write a human readable authentication log entry.
 *
 */
static void log_authentication_event_human_readable(
			const struct auth_usersupplied_info *ui,
			NTSTATUS status,
			const char *domain_name,
			const char *account_name,
			const char *unix_username,
			struct dom_sid *sid,
			int debug_level)
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

	frame = talloc_stackframe();

	password_type = get_password_type(ui);
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
	local = tsocket_address_string(ui->local_host, frame);

	if (NT_STATUS_IS_OK(status)) {
		char sid_buf[DOM_SID_STR_BUFLEN];

		dom_sid_string_buf(sid, sid_buf, sizeof(sid_buf));
		logon_line = talloc_asprintf(frame,
					     " became [%s]\\[%s] [%s].",
					     log_escape(frame, domain_name),
					     log_escape(frame, account_name),
					     sid_buf);
	} else {
		logon_line = talloc_asprintf(
				frame,
				" mapped to [%s]\\[%s].",
				log_escape(frame, ui->mapped.domain_name),
				log_escape(frame, ui->mapped.account_name));
	}

	DEBUGC(DBGC_AUTH_AUDIT, debug_level,
	       ("Auth: [%s,%s] user [%s]\\[%s]"
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
		nt_errstr(status),
		log_escape(frame, ui->workstation_name),
		remote,
		logon_line,
		local,
		nl ? nl : ""
	       ));

	talloc_free(frame);
}

/*
 * Log details of an authentication attempt.
 * Successful and unsuccessful attempts are logged.
 *
 * NOTE: msg_ctx and lp_ctx is optional, but when supplied allows streaming the
 * authentication events over the message bus.
 */
void log_authentication_event(struct imessaging_context *msg_ctx,
			      struct loadparm_context *lp_ctx,
			      const struct auth_usersupplied_info *ui,
			      NTSTATUS status,
			      const char *domain_name,
			      const char *account_name,
			      const char *unix_username,
			      struct dom_sid *sid)
{
	/* set the log level */
	int debug_level = AUTH_FAILURE_LEVEL;

	if (NT_STATUS_IS_OK(status)) {
		debug_level = AUTH_SUCCESS_LEVEL;
		if (dom_sid_equal(sid, &global_sid_Anonymous)) {
			debug_level = AUTH_ANONYMOUS_LEVEL;
		}
	}

	if (CHECK_DEBUGLVLC(DBGC_AUTH_AUDIT, debug_level)) {
		log_authentication_event_human_readable(ui,
							status,
							domain_name,
							account_name,
							unix_username,
							sid,
							debug_level);
	}
	if (CHECK_DEBUGLVLC(DBGC_AUTH_AUDIT_JSON, debug_level) ||
	    (msg_ctx && lp_ctx && lpcfg_auth_event_notification(lp_ctx))) {
		log_authentication_event_json(msg_ctx, lp_ctx,
					      ui,
					      status,
					      domain_name,
					      account_name,
					      unix_username,
					      sid,
					      debug_level);
	}
}



/*
 * Log details of a successful authorization to a service,
 * in a human readable format.
 *
 */
static void log_successful_authz_event_human_readable(
				const struct tsocket_address *remote,
				const struct tsocket_address *local,
				const char *service_description,
				const char *auth_type,
				const char *transport_protection,
				struct auth_session_info *session_info,
				int debug_level)
{
	TALLOC_CTX *frame = NULL;

	const char *ts = NULL;       /* formatted current time      */
	char *remote_str = NULL;     /* formatted remote host       */
	char *local_str = NULL;      /* formatted local host        */
	char sid_buf[DOM_SID_STR_BUFLEN];

	frame = talloc_stackframe();

	/* Get the current time */
        ts = get_timestamp(frame);

	remote_str = tsocket_address_string(remote, frame);
	local_str = tsocket_address_string(local, frame);

	dom_sid_string_buf(&session_info->security_token->sids[0],
			   sid_buf,
			   sizeof(sid_buf));

	DEBUGC(DBGC_AUTH_AUDIT, debug_level,
	       ("Successful AuthZ: [%s,%s] user [%s]\\[%s] [%s]"
		" at [%s]"
		" Remote host [%s]"
		" local host [%s]\n",
		service_description,
		auth_type,
		log_escape(frame, session_info->info->domain_name),
		log_escape(frame, session_info->info->account_name),
		sid_buf,
		ts,
		remote_str,
		local_str));

	talloc_free(frame);
}

/*
 * Log details of a successful authorization to a service.
 *
 * Only successful authorizations are logged.  For clarity:
 * - NTLM bad passwords will be recorded by log_authentication_event
 * - Kerberos decrypt failures need to be logged in gensec_gssapi et al
 *
 * The service may later refuse authorization due to an ACL.
 *
 * NOTE: msg_ctx and lp_ctx is optional, but when supplied allows streaming the
 * authentication events over the message bus.
 */
void log_successful_authz_event(struct imessaging_context *msg_ctx,
				struct loadparm_context *lp_ctx,
				const struct tsocket_address *remote,
				const struct tsocket_address *local,
				const char *service_description,
				const char *auth_type,
				const char *transport_protection,
				struct auth_session_info *session_info)
{
	int debug_level = AUTHZ_SUCCESS_LEVEL;

	/* set the log level */
	if (security_token_is_anonymous(session_info->security_token)) {
		debug_level = AUTH_ANONYMOUS_LEVEL;
	}

	if (CHECK_DEBUGLVLC(DBGC_AUTH_AUDIT, debug_level)) {
		log_successful_authz_event_human_readable(remote,
							  local,
							  service_description,
							  auth_type,
							  transport_protection,
							  session_info,
							  debug_level);
	}
	if (CHECK_DEBUGLVLC(DBGC_AUTH_AUDIT_JSON, debug_level) ||
	    (msg_ctx && lp_ctx && lpcfg_auth_event_notification(lp_ctx))) {
		log_successful_authz_event_json(msg_ctx, lp_ctx,
						remote,
						local,
						service_description,
						auth_type,
						transport_protection,
						session_info,
						debug_level);
	}
}
