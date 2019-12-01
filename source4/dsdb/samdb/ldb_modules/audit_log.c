/*
   ldb database library

   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2018

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
 * Provide an audit log of changes made to the database and at a
 * higher level details of any password changes and resets.
 *
 */

#include "includes.h"
#include "ldb_module.h"
#include "lib/audit_logging/audit_logging.h"

#include "dsdb/samdb/samdb.h"
#include "dsdb/samdb/ldb_modules/util.h"
#include "dsdb/samdb/ldb_modules/audit_util_proto.h"
#include "libcli/security/dom_sid.h"
#include "auth/common_auth.h"
#include "param/param.h"
#include "librpc/gen_ndr/windows_event_ids.h"

#define OPERATION_JSON_TYPE "dsdbChange"
#define OPERATION_HR_TAG "DSDB Change"
#define OPERATION_MAJOR 1
#define OPERATION_MINOR 0
#define OPERATION_LOG_LVL 5

#define PASSWORD_JSON_TYPE "passwordChange"
#define PASSWORD_HR_TAG "Password Change"
#define PASSWORD_MAJOR 1
#define PASSWORD_MINOR 1
#define PASSWORD_LOG_LVL 5

#define TRANSACTION_JSON_TYPE "dsdbTransaction"
#define TRANSACTION_HR_TAG "DSDB Transaction"
#define TRANSACTION_MAJOR 1
#define TRANSACTION_MINOR 0
#define TRANSACTION_LOG_FAILURE_LVL 5
#define TRANSACTION_LOG_COMPLETION_LVL 10

#define REPLICATION_JSON_TYPE "replicatedUpdate"
#define REPLICATION_HR_TAG "Replicated Update"
#define REPLICATION_MAJOR 1
#define REPLICATION_MINOR 0
#define REPLICATION_LOG_LVL 5
/*
 * Attribute values are truncated in the logs if they are longer than
 * MAX_LENGTH
 */
#define MAX_LENGTH 1024

#define min(a, b) (((a)>(b))?(b):(a))

/*
 * Private data for the module, stored in the ldb_module private data
 */
struct audit_private {
	/*
	 * Should details of database operations be sent over the
	 * messaging bus.
	 */
	bool send_samdb_events;
	/*
	 * Should details of password changes and resets be sent over
	 * the messaging bus.
	 */
	bool send_password_events;
	/*
	 * The messaging context to send the messages over.  Will only
	 * be set if send_samdb_events or send_password_events are
	 * true.
	 */
	struct imessaging_context *msg_ctx;
	/*
	 * Unique transaction id for the current transaction
	 */
	struct GUID transaction_guid;
	/*
	 * Transaction start time, used to calculate the transaction
	 * duration.
	 */
	struct timeval transaction_start;
};

/*
 * @brief Has the password changed.
 *
 * Does the message contain a change to one of the password attributes? The
 * password attributes are defined in DSDB_PASSWORD_ATTRIBUTES
 *
 * @return true if the message contains a password attribute
 *
 */
static bool has_password_changed(const struct ldb_message *message)
{
	unsigned int i;
	if (message == NULL) {
		return false;
	}
	for (i=0;i<message->num_elements;i++) {
		if (dsdb_audit_is_password_attribute(
			message->elements[i].name)) {
			return true;
		}
	}
	return false;
}

/*
 * @brief get the password change windows event id
 *
 * Get the Windows Event Id for the action being performed on the user password.
 *
 * This routine assumes that the request contains password attributes and that the
 * password ACL checks have been performed by acl.c
 *
 * @param request the ldb_request to inspect
 * @param reply the ldb_reply, will contain the password controls
 *
 * @return The windows event code.
 */
static enum event_id_type get_password_windows_event_id(
	const struct ldb_request *request,
	const struct ldb_reply *reply)
{
	if(request->operation == LDB_ADD) {
		return EVT_ID_PASSWORD_RESET;
	} else {
		struct ldb_control *pav_ctrl = NULL;
		struct dsdb_control_password_acl_validation *pav = NULL;

		pav_ctrl = ldb_reply_get_control(
			discard_const(reply),
			DSDB_CONTROL_PASSWORD_ACL_VALIDATION_OID);
		if (pav_ctrl == NULL) {
			return EVT_ID_PASSWORD_RESET;
		}

		pav = talloc_get_type_abort(
			pav_ctrl->data,
			struct dsdb_control_password_acl_validation);

		if (pav->pwd_reset) {
			return EVT_ID_PASSWORD_RESET;
		} else {
			return EVT_ID_PASSWORD_CHANGE;
		}
	}
}
/*
 * @brief Is the request a password "Change" or a "Reset"
 *
 * Get a description of the action being performed on the user password.  This
 * routine assumes that the request contains password attributes and that the
 * password ACL checks have been performed by acl.c
 *
 * @param request the ldb_request to inspect
 * @param reply the ldb_reply, will contain the password controls
 *
 * @return "Change" if the password is being changed.
 *         "Reset"  if the password is being reset.
 */
static const char *get_password_action(
	const struct ldb_request *request,
	const struct ldb_reply *reply)
{
	if(request->operation == LDB_ADD) {
		return "Reset";
	} else {
		struct ldb_control *pav_ctrl = NULL;
		struct dsdb_control_password_acl_validation *pav = NULL;

		pav_ctrl = ldb_reply_get_control(
			discard_const(reply),
			DSDB_CONTROL_PASSWORD_ACL_VALIDATION_OID);
		if (pav_ctrl == NULL) {
			return "Reset";
		}

		pav = talloc_get_type_abort(
			pav_ctrl->data,
			struct dsdb_control_password_acl_validation);

		if (pav->pwd_reset) {
			return "Reset";
		} else {
			return "Change";
		}
	}
}

/*
 * @brief generate a JSON object detailing an ldb operation.
 *
 * Generate a JSON object detailing an ldb operation.
 *
 * @param module the ldb module
 * @param request the request
 * @param reply the result of the operation.
 *
 * @return the generated JSON object, should be freed with json_free.
 *
 *
 */
static struct json_object operation_json(
	struct ldb_module *module,
	const struct ldb_request *request,
	const struct ldb_reply *reply)
{
	struct ldb_context *ldb = NULL;
	const struct dom_sid *sid = NULL;
	bool as_system = false;
	struct json_object wrapper = json_empty_object;
	struct json_object audit = json_empty_object;
	const struct tsocket_address *remote = NULL;
	const char *dn = NULL;
	const char* operation = NULL;
	const struct GUID *unique_session_token = NULL;
	const struct ldb_message *message = NULL;
	struct audit_private *audit_private
		= talloc_get_type_abort(ldb_module_get_private(module),
					struct audit_private);
	int rc = 0;

	ldb = ldb_module_get_ctx(module);

	remote = dsdb_audit_get_remote_address(ldb);
	if (remote != NULL && dsdb_audit_is_system_session(module)) {
		as_system = true;
		sid = dsdb_audit_get_actual_sid(ldb);
		unique_session_token =
			dsdb_audit_get_actual_unique_session_token(ldb);
	} else {
		sid = dsdb_audit_get_user_sid(module);
		unique_session_token =
			dsdb_audit_get_unique_session_token(module);
	}
	dn = dsdb_audit_get_primary_dn(request);
	operation = dsdb_audit_get_operation_name(request);

	audit = json_new_object();
	if (json_is_invalid(&audit)) {
		goto failure;
	}
	rc = json_add_version(&audit, OPERATION_MAJOR, OPERATION_MINOR);
	if (rc != 0) {
		goto failure;
	}
	rc = json_add_int(&audit, "statusCode", reply->error);
	if (rc != 0) {
		goto failure;
	}
	rc = json_add_string(&audit, "status", ldb_strerror(reply->error));
	if (rc != 0) {
		goto failure;
	}
	rc = json_add_string(&audit, "operation", operation);
	if (rc != 0) {
		goto failure;
	}
	rc = json_add_address(&audit, "remoteAddress", remote);
	if (rc != 0) {
		goto failure;
	}
	rc = json_add_bool(&audit, "performedAsSystem", as_system);
	if (rc != 0) {
		goto failure;
	}
	rc = json_add_sid(&audit, "userSid", sid);
	if (rc != 0) {
		goto failure;
	}
	rc = json_add_string(&audit, "dn", dn);
	if (rc != 0) {
		goto failure;
	}
	rc = json_add_guid(
	    &audit, "transactionId", &audit_private->transaction_guid);
	if (rc != 0) {
		goto failure;
	}
	rc = json_add_guid(&audit, "sessionId", unique_session_token);
	if (rc != 0) {
		goto failure;
	}

	message = dsdb_audit_get_message(request);
	if (message != NULL) {
		struct json_object attributes =
			dsdb_audit_attributes_json(
				request->operation,
				message);
		if (json_is_invalid(&attributes)) {
			goto failure;
		}
		rc = json_add_object(&audit, "attributes", &attributes);
		if (rc != 0) {
			goto failure;
		}
	}

	wrapper = json_new_object();
	if (json_is_invalid(&wrapper)) {
		goto failure;
	}
	rc = json_add_timestamp(&wrapper);
	if (rc != 0) {
		goto failure;
	}
	rc = json_add_string(&wrapper, "type", OPERATION_JSON_TYPE);
	if (rc != 0) {
		goto failure;
	}
	rc = json_add_object(&wrapper, OPERATION_JSON_TYPE, &audit);
	if (rc != 0) {
		goto failure;
	}
	return wrapper;

failure:
	/*
	 * On a failure audit will not have been added to wrapper so it
	 * needs to free it to avoid a leak.
	 *
	 * wrapper is freed to invalidate it as it will have only been
	 * partially constructed and may be inconsistent.
	 *
	 * All the json manipulation routines handle a freed object correctly
	 */
	json_free(&audit);
	json_free(&wrapper);
	DBG_ERR("Unable to create ldb operation JSON audit message\n");
	return wrapper;
}

/*
 * @brief generate a JSON object detailing a replicated update.
 *
 * Generate a JSON object detailing a replicated update
 *
 * @param module the ldb module
 * @param request the request
 * @paran reply the result of the operation
 *
 * @return the generated JSON object, should be freed with json_free.
 *         NULL if there was an error generating the message.
 *
 */
static struct json_object replicated_update_json(
	struct ldb_module *module,
	const struct ldb_request *request,
	const struct ldb_reply *reply)
{
	struct json_object wrapper = json_empty_object;
	struct json_object audit = json_empty_object;
	struct audit_private *audit_private
		= talloc_get_type_abort(ldb_module_get_private(module),
					struct audit_private);
	struct dsdb_extended_replicated_objects *ro = talloc_get_type(
		request->op.extended.data,
		struct dsdb_extended_replicated_objects);
	const char *partition_dn = NULL;
	const char *error = NULL;
	int rc = 0;

	partition_dn = ldb_dn_get_linearized(ro->partition_dn);
	error = get_friendly_werror_msg(ro->error);

	audit = json_new_object();
	if (json_is_invalid(&audit)) {
		goto failure;
	}
	rc = json_add_version(&audit, REPLICATION_MAJOR, REPLICATION_MINOR);
	if (rc != 0) {
		goto failure;
	}
	rc = json_add_int(&audit, "statusCode", reply->error);
	if (rc != 0) {
		goto failure;
	}
	rc = json_add_string(&audit, "status", ldb_strerror(reply->error));
	if (rc != 0) {
		goto failure;
	}
	rc = json_add_guid(
	    &audit, "transactionId", &audit_private->transaction_guid);
	if (rc != 0) {
		goto failure;
	}
	rc = json_add_int(&audit, "objectCount", ro->num_objects);
	if (rc != 0) {
		goto failure;
	}
	rc = json_add_int(&audit, "linkCount", ro->linked_attributes_count);
	if (rc != 0) {
		goto failure;
	}
	rc = json_add_string(&audit, "partitionDN", partition_dn);
	if (rc != 0) {
		goto failure;
	}
	rc = json_add_string(&audit, "error", error);
	if (rc != 0) {
		goto failure;
	}
	rc = json_add_int(&audit, "errorCode", W_ERROR_V(ro->error));
	if (rc != 0) {
		goto failure;
	}
	rc = json_add_guid(
	    &audit, "sourceDsa", &ro->source_dsa->source_dsa_obj_guid);
	if (rc != 0) {
		goto failure;
	}
	rc = json_add_guid(
	    &audit, "invocationId", &ro->source_dsa->source_dsa_invocation_id);
	if (rc != 0) {
		goto failure;
	}

	wrapper = json_new_object();
	if (json_is_invalid(&wrapper)) {
		goto failure;
	}
	rc = json_add_timestamp(&wrapper);
	if (rc != 0) {
		goto failure;
	}
	rc = json_add_string(&wrapper, "type", REPLICATION_JSON_TYPE);
	if (rc != 0) {
		goto failure;
	}
	rc = json_add_object(&wrapper, REPLICATION_JSON_TYPE, &audit);
	if (rc != 0) {
		goto failure;
	}
	return wrapper;
failure:
	/*
	 * On a failure audit will not have been added to wrapper so it
	 * needs to be freed it to avoid a leak.
	 *
	 * wrapper is freed to invalidate it as it will have only been
	 * partially constructed and may be inconsistent.
	 *
	 * All the json manipulation routines handle a freed object correctly
	 */
	json_free(&audit);
	json_free(&wrapper);
	DBG_ERR("Unable to create replicated update JSON audit message\n");
	return wrapper;
}

/*
 * @brief generate a JSON object detailing a password change.
 *
 * Generate a JSON object detailing a password change.
 *
 * @param module the ldb module
 * @param request the request
 * @param reply the result/response
 * @param status the status code returned for the underlying ldb operation.
 *
 * @return the generated JSON object.
 *
 */
static struct json_object password_change_json(
	struct ldb_module *module,
	const struct ldb_request *request,
	const struct ldb_reply *reply)
{
	struct ldb_context *ldb = NULL;
	const struct dom_sid *sid = NULL;
	const char *dn = NULL;
	struct json_object wrapper = json_empty_object;
	struct json_object audit = json_empty_object;
	const struct tsocket_address *remote = NULL;
	const char* action = NULL;
	const struct GUID *unique_session_token = NULL;
	struct audit_private *audit_private
		= talloc_get_type_abort(ldb_module_get_private(module),
					struct audit_private);
	int rc = 0;
	enum event_id_type event_id;

	ldb = ldb_module_get_ctx(module);

	remote = dsdb_audit_get_remote_address(ldb);
	sid = dsdb_audit_get_user_sid(module);
	dn = dsdb_audit_get_primary_dn(request);
	action = get_password_action(request, reply);
	unique_session_token = dsdb_audit_get_unique_session_token(module);
	event_id = get_password_windows_event_id(request, reply);

	audit = json_new_object();
	if (json_is_invalid(&audit)) {
		goto failure;
	}
	rc = json_add_version(&audit, PASSWORD_MAJOR, PASSWORD_MINOR);
	if (rc != 0) {
		goto failure;
	}
	rc = json_add_int(&audit, "eventId", event_id);
	if (rc != 0) {
		goto failure;
	}
	rc = json_add_int(&audit, "statusCode", reply->error);
	if (rc != 0) {
		goto failure;
	}
	rc = json_add_string(&audit, "status", ldb_strerror(reply->error));
	if (rc != 0) {
		goto failure;
	}
	rc = json_add_address(&audit, "remoteAddress", remote);
	if (rc != 0) {
		goto failure;
	}
	rc = json_add_sid(&audit, "userSid", sid);
	if (rc != 0) {
		goto failure;
	}
	rc = json_add_string(&audit, "dn", dn);
	if (rc != 0) {
		goto failure;
	}
	rc = json_add_string(&audit, "action", action);
	if (rc != 0) {
		goto failure;
	}
	rc = json_add_guid(
	    &audit, "transactionId", &audit_private->transaction_guid);
	if (rc != 0) {
		goto failure;
	}
	rc = json_add_guid(&audit, "sessionId", unique_session_token);
	if (rc != 0) {
		goto failure;
	}

	wrapper = json_new_object();
	if (json_is_invalid(&wrapper)) {
		goto failure;
	}
	rc = json_add_timestamp(&wrapper);
	if (rc != 0) {
		goto failure;
	}
	rc = json_add_string(&wrapper, "type", PASSWORD_JSON_TYPE);
	if (rc != 0) {
		goto failure;
	}
	rc = json_add_object(&wrapper, PASSWORD_JSON_TYPE, &audit);
	if (rc != 0) {
		goto failure;
	}

	return wrapper;
failure:
	/*
	 * On a failure audit will not have been added to wrapper so it
	 * needs to free it to avoid a leak.
	 *
	 * wrapper is freed to invalidate it as it will have only been
	 * partially constructed and may be inconsistent.
	 *
	 * All the json manipulation routines handle a freed object correctly
	 */
	json_free(&wrapper);
	json_free(&audit);
	DBG_ERR("Unable to create password change JSON audit message\n");
	return wrapper;
}


/*
 * @brief create a JSON object containing details of a transaction event.
 *
 * Create a JSON object detailing a transaction transaction life cycle events,
 * i.e. begin, commit, roll back
 *
 * @param action a one word description of the event/action
 * @param transaction_id the GUID identifying the current transaction.
 * @param status the status code returned by the operation
 * @param duration the duration of the operation.
 *
 * @return a JSON object detailing the event
 */
static struct json_object transaction_json(
	const char *action,
	struct GUID *transaction_id,
	const int64_t duration)
{
	struct json_object wrapper = json_empty_object;
	struct json_object audit = json_empty_object;
	int rc = 0;

	audit = json_new_object();
	if (json_is_invalid(&audit)) {
		goto failure;
	}

	rc = json_add_version(&audit, TRANSACTION_MAJOR, TRANSACTION_MINOR);
	if (rc != 0) {
		goto failure;
	}
	rc = json_add_string(&audit, "action", action);
	if (rc != 0) {
		goto failure;
	}
	rc = json_add_guid(&audit, "transactionId", transaction_id);
	if (rc != 0) {
		goto failure;
	}
	rc = json_add_int(&audit, "duration", duration);
	if (rc != 0) {
		goto failure;
	}

	wrapper = json_new_object();
	if (json_is_invalid(&wrapper)) {
		goto failure;
	}
	rc = json_add_timestamp(&wrapper);
	if (rc != 0) {
		goto failure;
	}
	rc = json_add_string(&wrapper, "type", TRANSACTION_JSON_TYPE);
	if (rc != 0) {
		goto failure;
	}
	rc = json_add_object(&wrapper, TRANSACTION_JSON_TYPE, &audit);
	if (rc != 0) {
		goto failure;
	}

	return wrapper;
failure:
	/*
	 * On a failure audit will not have been added to wrapper so it
	 * needs to free it to avoid a leak.
	 *
	 * wrapper is freed to invalidate it as it will have only been
	 * partially constructed and may be inconsistent.
	 *
	 * All the json manipulation routines handle a freed object correctly
	 */
	json_free(&wrapper);
	json_free(&audit);
	DBG_ERR("Unable to create transaction JSON audit message\n");
	return wrapper;
}


/*
 * @brief generate a JSON object detailing a commit failure.
 *
 * Generate a JSON object containing details of a commit failure.
 *
 * @param action the commit action, "commit" or "prepare"
 * @param status the status code returned by commit
 * @param reason any extra failure information/reason available
 * @param transaction_id the GUID identifying the current transaction.
 */
static struct json_object commit_failure_json(
	const char *action,
	const int64_t duration,
	int status,
	const char *reason,
	struct GUID *transaction_id)
{
	struct json_object wrapper = json_empty_object;
	struct json_object audit = json_empty_object;
	int rc = 0;

	audit = json_new_object();
	if (json_is_invalid(&audit)) {
		goto failure;
	}
	rc = json_add_version(&audit, TRANSACTION_MAJOR, TRANSACTION_MINOR);
	if (rc != 0) {
		goto failure;
	}
	rc = json_add_string(&audit, "action", action);
	if (rc != 0) {
		goto failure;
	}
	rc = json_add_guid(&audit, "transactionId", transaction_id);
	if (rc != 0) {
		goto failure;
	}
	rc = json_add_int(&audit, "duration", duration);
	if (rc != 0) {
		goto failure;
	}
	rc = json_add_int(&audit, "statusCode", status);
	if (rc != 0) {
		goto failure;
	}
	rc = json_add_string(&audit, "status", ldb_strerror(status));
	if (rc != 0) {
		goto failure;
	}
	rc = json_add_string(&audit, "reason", reason);
	if (rc != 0) {
		goto failure;
	}

	wrapper = json_new_object();
	if (json_is_invalid(&wrapper)) {
		goto failure;
	}
	rc = json_add_timestamp(&wrapper);
	if (rc != 0) {
		goto failure;
	}
	rc = json_add_string(&wrapper, "type", TRANSACTION_JSON_TYPE);
	if (rc != 0) {
		goto failure;
	}
	rc = json_add_object(&wrapper, TRANSACTION_JSON_TYPE, &audit);
	if (rc != 0) {
		goto failure;
	}

	return wrapper;
failure:
	/*
	 * On a failure audit will not have been added to wrapper so it
	 * needs to free it to avoid a leak.
	 *
	 * wrapper is freed to invalidate it as it will have only been
	 * partially constructed and may be inconsistent.
	 *
	 * All the json manipulation routines handle a freed object correctly
	 */
	json_free(&audit);
	json_free(&wrapper);
	DBG_ERR("Unable to create commit failure JSON audit message\n");
	return wrapper;
}

/*
 * @brief Print a human readable log line for a password change event.
 *
 * Generate a human readable log line detailing a password change.
 *
 * @param mem_ctx The talloc context that will own the generated log line.
 * @param module the ldb module
 * @param request the request
 * @param reply the result/response
 * @param status the status code returned for the underlying ldb operation.
 *
 * @return the generated log line.
 */
static char *password_change_human_readable(
	TALLOC_CTX *mem_ctx,
	struct ldb_module *module,
	const struct ldb_request *request,
	const struct ldb_reply *reply)
{
	struct ldb_context *ldb = NULL;
	const char *remote_host = NULL;
	const struct dom_sid *sid = NULL;
	struct dom_sid_buf user_sid;
	const char *timestamp = NULL;
	char *log_entry = NULL;
	const char *action = NULL;
	const char *dn = NULL;

	TALLOC_CTX *ctx = talloc_new(NULL);

	ldb = ldb_module_get_ctx(module);

	remote_host = dsdb_audit_get_remote_host(ldb, ctx);
	sid = dsdb_audit_get_user_sid(module);
	timestamp = audit_get_timestamp(ctx);
	action = get_password_action(request, reply);
	dn = dsdb_audit_get_primary_dn(request);

	log_entry = talloc_asprintf(
		mem_ctx,
		"[%s] at [%s] status [%s] "
		"remote host [%s] SID [%s] DN [%s]",
		action,
		timestamp,
		ldb_strerror(reply->error),
		remote_host,
		dom_sid_str_buf(sid, &user_sid),
		dn);
	TALLOC_FREE(ctx);
	return log_entry;
}
/*
 * @brief Generate a human readable string, detailing attributes in a message
 *
 * For modify operations each attribute is prefixed with the action.
 * Normal values are enclosed in []
 * Base64 values are enclosed in {}
 * Truncated values are indicated by three trailing dots "..."
 *
 * @param ldb The ldb_context
 * @param buffer The attributes will be appended to the buffer.
 *               assumed to have been allocated via talloc.
 * @param operation The operation type
 * @param message the message to process
 *
 */
static char *log_attributes(
	struct ldb_context *ldb,
	char *buffer,
	enum ldb_request_type operation,
	const struct ldb_message *message)
{
	size_t i, j;
	for (i=0;i<message->num_elements;i++) {
		if (i > 0) {
			buffer = talloc_asprintf_append_buffer(buffer, " ");
		}

		if (message->elements[i].name == NULL) {
			ldb_debug(
				ldb,
				LDB_DEBUG_ERROR,
				"Error: Invalid element name (NULL) at "
				"position %zu", i);
			return NULL;
		}

		if (operation == LDB_MODIFY) {
			const char *action =NULL;
			action = dsdb_audit_get_modification_action(
				message->elements[i].flags);
			buffer = talloc_asprintf_append_buffer(
				buffer,
				"%s: %s ",
				action,
				message->elements[i].name);
		} else {
			buffer = talloc_asprintf_append_buffer(
				buffer,
				"%s ",
				message->elements[i].name);
		}

		if (dsdb_audit_redact_attribute(message->elements[i].name)) {
			/*
			 * Do not log the value of any secret or password
			 * attributes
			 */
			buffer = talloc_asprintf_append_buffer(
				buffer,
				"[REDACTED SECRET ATTRIBUTE]");
			continue;
		}

		for (j=0;j<message->elements[i].num_values;j++) {
			struct ldb_val v;
			bool use_b64_encode = false;
			size_t length;
			if (j > 0) {
				buffer = talloc_asprintf_append_buffer(
					buffer,
					" ");
			}

			v = message->elements[i].values[j];
			length = min(MAX_LENGTH, v.length);
			use_b64_encode = ldb_should_b64_encode(ldb, &v);
			if (use_b64_encode) {
				const char *encoded = ldb_base64_encode(
					buffer,
					(char *)v.data,
					length);
				buffer = talloc_asprintf_append_buffer(
					buffer,
				        "{%s%s}",
					encoded,
					(v.length > MAX_LENGTH ? "..." : ""));
			} else {
				buffer = talloc_asprintf_append_buffer(
					buffer,
					"[%*.*s%s]",
					(int)length,
					(int)length,
					(char *)v.data,
					(v.length > MAX_LENGTH ? "..." : ""));
			}
		}
	}
	return buffer;
}

/*
 * @brief generate a human readable log entry detailing an ldb operation.
 *
 * Generate a human readable log entry detailing an ldb operation.
 *
 * @param mem_ctx The talloc context owning the returned string.
 * @param module the ldb module
 * @param request the request
 * @param reply the result of the operation
 *
 * @return the log entry.
 *
 */
static char *operation_human_readable(
	TALLOC_CTX *mem_ctx,
	struct ldb_module *module,
	const struct ldb_request *request,
	const struct ldb_reply *reply)
{
	struct ldb_context *ldb = NULL;
	const char *remote_host = NULL;
	const struct tsocket_address *remote = NULL;
	const struct dom_sid *sid = NULL;
	struct dom_sid_buf user_sid;
	const char *timestamp = NULL;
	const char *op_name = NULL;
	char *log_entry = NULL;
	const char *dn = NULL;
	const char *new_dn = NULL;
	const struct ldb_message *message = NULL;

	TALLOC_CTX *ctx = talloc_new(NULL);

	ldb = ldb_module_get_ctx(module);

	remote_host = dsdb_audit_get_remote_host(ldb, ctx);
	remote = dsdb_audit_get_remote_address(ldb);
	if (remote != NULL && dsdb_audit_is_system_session(module)) {
		sid = dsdb_audit_get_actual_sid(ldb);
	} else {
		sid = dsdb_audit_get_user_sid(module);
	}
	timestamp = audit_get_timestamp(ctx);
	op_name = dsdb_audit_get_operation_name(request);
	dn = dsdb_audit_get_primary_dn(request);
	new_dn = dsdb_audit_get_secondary_dn(request);

	message = dsdb_audit_get_message(request);

	log_entry = talloc_asprintf(
		mem_ctx,
		"[%s] at [%s] status [%s] "
		"remote host [%s] SID [%s] DN [%s]",
		op_name,
		timestamp,
		ldb_strerror(reply->error),
		remote_host,
		dom_sid_str_buf(sid, &user_sid),
		dn);
	if (new_dn != NULL) {
		log_entry = talloc_asprintf_append_buffer(
			log_entry,
			" New DN [%s]",
			new_dn);
	}
	if (message != NULL) {
		log_entry = talloc_asprintf_append_buffer(log_entry,
							  " attributes [");
		log_entry = log_attributes(ldb,
					   log_entry,
					   request->operation,
					   message);
		log_entry = talloc_asprintf_append_buffer(log_entry, "]");
	}
	TALLOC_FREE(ctx);
	return log_entry;
}

/*
 * @brief generate a human readable log entry detailing a replicated update
 *        operation.
 *
 * Generate a human readable log entry detailing a replicated update operation
 *
 * @param mem_ctx The talloc context owning the returned string.
 * @param module the ldb module
 * @param request the request
 * @param reply the result of the operation.
 *
 * @return the log entry.
 *
 */
static char *replicated_update_human_readable(
	TALLOC_CTX *mem_ctx,
	struct ldb_module *module,
	const struct ldb_request *request,
	const struct ldb_reply *reply)
{
	struct dsdb_extended_replicated_objects *ro = talloc_get_type(
		request->op.extended.data,
		struct dsdb_extended_replicated_objects);
	const char *partition_dn = NULL;
	const char *error = NULL;
	char *log_entry = NULL;
	char *timestamp = NULL;
	struct GUID_txt_buf object_buf;
	const char *object = NULL;
	struct GUID_txt_buf invocation_buf;
	const char *invocation = NULL;


	TALLOC_CTX *ctx = talloc_new(NULL);

	timestamp = audit_get_timestamp(ctx);
	error = get_friendly_werror_msg(ro->error);
	partition_dn = ldb_dn_get_linearized(ro->partition_dn);
	object = GUID_buf_string(
		&ro->source_dsa->source_dsa_obj_guid,
		&object_buf);
	invocation = GUID_buf_string(
		&ro->source_dsa->source_dsa_invocation_id,
		&invocation_buf);


	log_entry = talloc_asprintf(
		mem_ctx,
		"at [%s] status [%s] error [%s] partition [%s] objects [%d] "
		"links [%d] object [%s] invocation [%s]",
		timestamp,
		ldb_strerror(reply->error),
		error,
		partition_dn,
		ro->num_objects,
		ro->linked_attributes_count,
		object,
		invocation);

	TALLOC_FREE(ctx);
	return log_entry;
}
/*
 * @brief create a human readable log entry detailing a transaction event.
 *
 * Create a human readable log entry detailing a transaction event.
 * i.e. begin, commit, roll back
 *
 * @param mem_ctx The talloc context owning the returned string.
 * @param action a one word description of the event/action
 * @param duration the duration of the transaction.
 *
 * @return the log entry
 */
static char *transaction_human_readable(
	TALLOC_CTX *mem_ctx,
	const char* action,
	const int64_t duration)
{
	const char *timestamp = NULL;
	char *log_entry = NULL;

	TALLOC_CTX *ctx = talloc_new(NULL);

	timestamp = audit_get_timestamp(ctx);

	log_entry = talloc_asprintf(
		mem_ctx,
		"[%s] at [%s] duration [%"PRIi64"]",
		action,
		timestamp,
		duration);

	TALLOC_FREE(ctx);
	return log_entry;
}

/*
 * @brief generate a human readable log entry detailing a commit failure.
 *
 * Generate generate a human readable log entry detailing a commit failure.
 *
 * @param mem_ctx The talloc context owning the returned string.
 * @param action the commit action, "prepare" or "commit"
 * @param status the status code returned by commit
 * @param reason any extra failure information/reason available
 *
 * @return the log entry
 */
static char *commit_failure_human_readable(
	TALLOC_CTX *mem_ctx,
	const char *action,
	const int64_t duration,
	int status,
	const char *reason)
{
	const char *timestamp = NULL;
	char *log_entry = NULL;

	TALLOC_CTX *ctx = talloc_new(NULL);

	timestamp = audit_get_timestamp(ctx);

	log_entry = talloc_asprintf(
		mem_ctx,
		"[%s] at [%s] duration [%"PRIi64"] status [%d] reason [%s]",
		action,
		timestamp,
		duration,
		status,
		reason);

	TALLOC_FREE(ctx);
	return log_entry;
}

/*
 * @brief log details of a standard ldb operation.
 *
 * Log the details of an ldb operation in JSON and or human readable format
 * and send over the message bus.
 *
 * @param module the ldb_module
 * @param request the operation request.
 * @param reply the operation result.
 * @param the status code returned for the operation.
 *
 */
static void log_standard_operation(
	struct ldb_module *module,
	const struct ldb_request *request,
	const struct ldb_reply *reply)
{

	const struct ldb_message *message = dsdb_audit_get_message(request);
	bool password_changed = has_password_changed(message);
	struct audit_private *audit_private =
		talloc_get_type_abort(ldb_module_get_private(module),
				      struct audit_private);

	TALLOC_CTX *ctx = talloc_new(NULL);

	if (CHECK_DEBUGLVLC(DBGC_DSDB_AUDIT, OPERATION_LOG_LVL)) {
		char *entry = NULL;
		entry = operation_human_readable(
			ctx,
			module,
			request,
			reply);
		audit_log_human_text(
			OPERATION_HR_TAG,
			entry,
			DBGC_DSDB_AUDIT,
			OPERATION_LOG_LVL);
		TALLOC_FREE(entry);
	}
	if (CHECK_DEBUGLVLC(DBGC_DSDB_PWD_AUDIT, PASSWORD_LOG_LVL)) {
		if (password_changed) {
			char *entry = NULL;
			entry = password_change_human_readable(
				ctx,
				module,
				request,
				reply);
			audit_log_human_text(
				PASSWORD_HR_TAG,
				entry,
				DBGC_DSDB_PWD_AUDIT,
				PASSWORD_LOG_LVL);
			TALLOC_FREE(entry);
		}
	}
	if (CHECK_DEBUGLVLC(DBGC_DSDB_AUDIT_JSON, OPERATION_LOG_LVL) ||
		(audit_private->msg_ctx
		 && audit_private->send_samdb_events)) {
		struct json_object json;
		json = operation_json(module, request, reply);
		audit_log_json(
			&json,
			DBGC_DSDB_AUDIT_JSON,
			OPERATION_LOG_LVL);
		if (audit_private->msg_ctx
		    && audit_private->send_samdb_events) {
			audit_message_send(
				audit_private->msg_ctx,
				DSDB_EVENT_NAME,
				MSG_DSDB_LOG,
				&json);
		}
		json_free(&json);
	}
	if (CHECK_DEBUGLVLC(DBGC_DSDB_PWD_AUDIT_JSON, PASSWORD_LOG_LVL) ||
		(audit_private->msg_ctx
		 && audit_private->send_password_events)) {
		if (password_changed) {
			struct json_object json;
			json = password_change_json(module, request, reply);
			audit_log_json(
				&json,
				DBGC_DSDB_PWD_AUDIT_JSON,
				PASSWORD_LOG_LVL);
			if (audit_private->send_password_events) {
				audit_message_send(
					audit_private->msg_ctx,
					DSDB_PWD_EVENT_NAME,
					MSG_DSDB_PWD_LOG,
					&json);
			}
			json_free(&json);
		}
	}
	TALLOC_FREE(ctx);
}

/*
 * @brief log details of a replicated update.
 *
 * Log the details of a replicated update in JSON and or human readable
 * format and send over the message bus.
 *
 * @param module the ldb_module
 * @param request the operation request
 * @param reply the result of the operation.
 *
 */
static void log_replicated_operation(
	struct ldb_module *module,
	const struct ldb_request *request,
	const struct ldb_reply *reply)
{

	struct audit_private *audit_private =
		talloc_get_type_abort(ldb_module_get_private(module),
				struct audit_private);

	TALLOC_CTX *ctx = talloc_new(NULL);

	if (CHECK_DEBUGLVLC(DBGC_DSDB_AUDIT, REPLICATION_LOG_LVL)) {
		char *entry = NULL;
		entry = replicated_update_human_readable(
			ctx,
			module,
			request,
			reply);
		audit_log_human_text(
			REPLICATION_HR_TAG,
			entry,
			DBGC_DSDB_AUDIT,
			REPLICATION_LOG_LVL);
		TALLOC_FREE(entry);
	}
	if (CHECK_DEBUGLVLC(DBGC_DSDB_AUDIT_JSON, REPLICATION_LOG_LVL) ||
		(audit_private->msg_ctx && audit_private->send_samdb_events)) {
		struct json_object json;
		json = replicated_update_json(module, request, reply);
		audit_log_json(
			&json,
			DBGC_DSDB_AUDIT_JSON,
			REPLICATION_LOG_LVL);
		if (audit_private->send_samdb_events) {
			audit_message_send(
				audit_private->msg_ctx,
				DSDB_EVENT_NAME,
				MSG_DSDB_LOG,
				&json);
		}
		json_free(&json);
	}
	TALLOC_FREE(ctx);
}

/*
 * @brief log details of an ldb operation.
 *
 * Log the details of an ldb operation in JSON and or human readable format
 * and send over the message bus.
 *
 * @param module the ldb_module
 * @param request the operation request
 * @part reply the result of the operation
 *
 */
static void log_operation(
	struct ldb_module *module,
	const struct ldb_request *request,
	const struct ldb_reply *reply)
{

	if (request->operation == LDB_EXTENDED) {
		if (strcmp(
			request->op.extended.oid,
			DSDB_EXTENDED_REPLICATED_OBJECTS_OID) != 0) {

			log_replicated_operation(module, request, reply);
		}
	} else {
		log_standard_operation(module, request, reply);
	}
}

/*
 * @brief log details of a transaction event.
 *
 * Log the details of a transaction event in JSON and or human readable format
 * and send over the message bus.
 *
 * @param module the ldb_module
 * @param action the transaction event i.e. begin, commit, roll back.
 * @param log_level the logging level
 *
 */
static void log_transaction(
	struct ldb_module *module,
	const char *action,
	int log_level)
{

	struct audit_private *audit_private =
		talloc_get_type_abort(ldb_module_get_private(module),
				      struct audit_private);
	const struct timeval now = timeval_current();
	const int64_t duration = usec_time_diff(&now, &audit_private->transaction_start);

	TALLOC_CTX *ctx = talloc_new(NULL);

	if (CHECK_DEBUGLVLC(DBGC_DSDB_TXN_AUDIT, log_level)) {
		char* entry = NULL;
		entry = transaction_human_readable(ctx, action, duration);
		audit_log_human_text(
			TRANSACTION_HR_TAG,
			entry,
			DBGC_DSDB_TXN_AUDIT,
			log_level);
		TALLOC_FREE(entry);
	}
	if (CHECK_DEBUGLVLC(DBGC_DSDB_TXN_AUDIT_JSON, log_level) ||
		(audit_private->msg_ctx && audit_private->send_samdb_events)) {
		struct json_object json;
		json = transaction_json(
			action,
			&audit_private->transaction_guid,
			duration);
		audit_log_json(
			&json,
			DBGC_DSDB_TXN_AUDIT_JSON,
			log_level);
		if (audit_private->send_samdb_events) {
			audit_message_send(
				audit_private->msg_ctx,
				DSDB_EVENT_NAME,
				MSG_DSDB_LOG,
				&json);
		}
		json_free(&json);
	}
	TALLOC_FREE(ctx);
}

/*
 * @brief log details of a commit failure.
 *
 * Log the details of a commit failure in JSON and or human readable
 * format and send over the message bus.
 *
 * @param module the ldb_module
 * @param action the commit action "prepare" or "commit"
 * @param status the ldb status code returned by prepare commit.
 *
 */
static void log_commit_failure(
	struct ldb_module *module,
	const char *action,
	int status)
{

	struct audit_private *audit_private =
		talloc_get_type_abort(ldb_module_get_private(module),
				      struct audit_private);
	const char* reason = dsdb_audit_get_ldb_error_string(module, status);
	const int log_level = TRANSACTION_LOG_FAILURE_LVL;
	const struct timeval now = timeval_current();
	const int64_t duration = usec_time_diff(&now,
						&audit_private->transaction_start);

	TALLOC_CTX *ctx = talloc_new(NULL);

	if (CHECK_DEBUGLVLC(DBGC_DSDB_TXN_AUDIT, log_level)) {

		char* entry = NULL;
		entry = commit_failure_human_readable(
			ctx,
			action,
			duration,
			status,
			reason);
		audit_log_human_text(
			TRANSACTION_HR_TAG,
			entry,
			DBGC_DSDB_TXN_AUDIT,
			TRANSACTION_LOG_FAILURE_LVL);
		TALLOC_FREE(entry);
	}
	if (CHECK_DEBUGLVLC(DBGC_DSDB_TXN_AUDIT_JSON, log_level) ||
		(audit_private->msg_ctx
		 && audit_private->send_samdb_events)) {
		struct json_object json;
		json = commit_failure_json(
			action,
			duration,
			status,
			reason,
			&audit_private->transaction_guid);
		audit_log_json(
			&json,
			DBGC_DSDB_TXN_AUDIT_JSON,
			log_level);
		if (audit_private->send_samdb_events) {
			audit_message_send(audit_private->msg_ctx,
					   DSDB_EVENT_NAME,
					   MSG_DSDB_LOG,
					   &json);
		}
		json_free(&json);
	}
	TALLOC_FREE(ctx);
}

/*
 * Context needed by audit_callback
 */
struct audit_callback_context {
	struct ldb_request *request;
	struct ldb_module *module;
};

/*
 * @brief call back function for the ldb_operations.
 *
 * As the LDB operations are async, and we wish to examine the results of
 * the operations, a callback needs to be registered to process the results
 * of the LDB operations.
 *
 * @param req the ldb request
 * @param res the result of the operation
 *
 * @return the LDB_STATUS
 */
static int audit_callback(struct ldb_request *req, struct ldb_reply *ares)
{
	struct audit_callback_context *ac = NULL;

	ac = talloc_get_type(
		req->context,
		struct audit_callback_context);

	if (!ares) {
		return ldb_module_done(
			ac->request,
			NULL,
			NULL,
			LDB_ERR_OPERATIONS_ERROR);
	}

	/* pass on to the callback */
	switch (ares->type) {
	case LDB_REPLY_ENTRY:
		return ldb_module_send_entry(
			ac->request,
			ares->message,
			ares->controls);

	case LDB_REPLY_REFERRAL:
		return ldb_module_send_referral(
			ac->request,
			ares->referral);

	case LDB_REPLY_DONE:
		/*
		 * Log the operation once DONE
		 */
		log_operation(ac->module, ac->request, ares);
		return ldb_module_done(
			ac->request,
			ares->controls,
			ares->response,
			ares->error);

	default:
		/* Can't happen */
		return LDB_ERR_OPERATIONS_ERROR;
	}
}

/*
 * @brief Add the current transaction identifier to the request.
 *
 * Add the current transaction identifier in the module private data,
 * to the request as a control.
 *
 * @param module
 * @param req the request.
 *
 * @return an LDB_STATUS code, LDB_SUCCESS if successful.
 */
static int add_transaction_id(
	struct ldb_module *module,
	struct ldb_request *req)
{
	struct audit_private *audit_private =
		talloc_get_type_abort(ldb_module_get_private(module),
				      struct audit_private);
	struct dsdb_control_transaction_identifier *transaction_id;
	int ret;

	transaction_id = talloc_zero(
		req,
		struct dsdb_control_transaction_identifier);
	if (transaction_id == NULL) {
		struct ldb_context *ldb = ldb_module_get_ctx(module);
		return ldb_oom(ldb);
	}
	transaction_id->transaction_guid = audit_private->transaction_guid;
	ret = ldb_request_add_control(req,
				      DSDB_CONTROL_TRANSACTION_IDENTIFIER_OID,
				      false,
				      transaction_id);
	return ret;

}

/*
 * @brief log details of an add operation.
 *
 * Log the details of an add operation.
 *
 * @param module the ldb_module
 * @param req the ldb_request
 *
 * @return ldb status code
 */
static int log_add(
	struct ldb_module *module,
	struct ldb_request *req)
{
	struct audit_callback_context *context = NULL;
	struct ldb_request *new_req = NULL;
	struct ldb_context *ldb = NULL;
	int ret;

	ldb = ldb_module_get_ctx(module);
	context = talloc_zero(req, struct audit_callback_context);

	if (context == NULL) {
		return ldb_oom(ldb);
	}
	context->request = req;
	context->module  = module;
	/*
	 * We want to log the return code status, so we need to register
	 * a callback function to get the actual result.
	 * We need to take a new copy so that we don't alter the callers copy
	 */
	ret = ldb_build_add_req(
		&new_req,
		ldb,
		req,
		req->op.add.message,
		req->controls,
		context,
		audit_callback,
		req);
	if (ret != LDB_SUCCESS) {
		return ret;
	}
	ret = add_transaction_id(module, new_req);
	if (ret != LDB_SUCCESS) {
		return ret;
	}
	return ldb_next_request(module, new_req);
}

/*
 * @brief log details of an delete operation.
 *
 * Log the details of an delete operation.
 *
 * @param module the ldb_module
 * @param req the ldb_request
 *
 * @return ldb status code
 */
static int log_delete(
	struct ldb_module *module,
	struct ldb_request *req)
{
	struct audit_callback_context *context = NULL;
	struct ldb_request *new_req = NULL;
	struct ldb_context *ldb = NULL;
	int ret;

	ldb = ldb_module_get_ctx(module);
	context = talloc_zero(req, struct audit_callback_context);

	if (context == NULL) {
		return ldb_oom(ldb);
	}
	context->request = req;
	context->module  = module;
	/*
	 * We want to log the return code status, so we need to register
	 * a callback function to get the actual result.
	 * We need to take a new copy so that we don't alter the callers copy
	 */
	ret = ldb_build_del_req(&new_req,
				ldb,
				req,
				req->op.del.dn,
				req->controls,
				context,
				audit_callback,
				req);
	if (ret != LDB_SUCCESS) {
		return ret;
	}
	ret = add_transaction_id(module, new_req);
	if (ret != LDB_SUCCESS) {
		return ret;
	}
	return ldb_next_request(module, new_req);
}

/*
 * @brief log details of a modify operation.
 *
 * Log the details of a modify operation.
 *
 * @param module the ldb_module
 * @param req the ldb_request
 *
 * @return ldb status code
 */
static int log_modify(
	struct ldb_module *module,
	struct ldb_request *req)
{
	struct audit_callback_context *context = NULL;
	struct ldb_request *new_req = NULL;
	struct ldb_context *ldb = NULL;
	int ret;

	ldb = ldb_module_get_ctx(module);
	context = talloc_zero(req, struct audit_callback_context);

	if (context == NULL) {
		return ldb_oom(ldb);
	}
	context->request = req;
	context->module  = module;
	/*
	 * We want to log the return code status, so we need to register
	 * a callback function to get the actual result.
	 * We need to take a new copy so that we don't alter the callers copy
	 */
	ret = ldb_build_mod_req(
		& new_req,
		ldb,
		req,
		req->op.mod.message,
		req->controls,
		context,
		audit_callback,
		req);
	if (ret != LDB_SUCCESS) {
		return ret;
	}
	ret = add_transaction_id(module, new_req);
	if (ret != LDB_SUCCESS) {
		return ret;
	}
	return ldb_next_request(module, new_req);
}

/*
 * @brief process a transaction start.
 *
 * process a transaction start, as we don't currently log transaction starts
 * just generate the new transaction_id.
 *
 * @param module the ldb_module
 * @param req the ldb_request
 *
 * @return ldb status code
 */
static int log_start_transaction(struct ldb_module *module)
{
	struct audit_private *audit_private =
		talloc_get_type_abort(ldb_module_get_private(module),
				      struct audit_private);

	/*
	 * We do not log transaction begins
	 * however we do generate a new transaction_id and record the start
	 * time so that we can log the transaction duration.
	 *
	 */
	audit_private->transaction_guid = GUID_random();
	audit_private->transaction_start = timeval_current();
	return ldb_next_start_trans(module);
}

/*
 * @brief log details of a prepare commit.
 *
 * Log the details of a prepare commit, currently only details of
 * failures are logged.
 *
 * @param module the ldb_module
 * @param req the ldb_request
 *
 * @return ldb status code
 */
static int log_prepare_commit(struct ldb_module *module)
{

	int ret = ldb_next_prepare_commit(module);
	if (ret != LDB_SUCCESS) {
		/*
		 * We currently only log prepare commit failures
		 */
		log_commit_failure(module, "prepare", ret);
	}
	return ret;
}

/*
 * @brief process a transaction end aka commit.
 *
 * process a transaction end, as we don't currently log transaction ends
 * just clear transaction_id.
 *
 * @param module the ldb_module
 * @param req the ldb_request
 *
 * @return ldb status code
 */
static int log_end_transaction(struct ldb_module *module)
{
	struct audit_private *audit_private =
		talloc_get_type_abort(ldb_module_get_private(module),
				      struct audit_private);
	int ret = 0;


	ret = ldb_next_end_trans(module);
	if (ret == LDB_SUCCESS) {
		log_transaction(
			module,
			"commit",
			TRANSACTION_LOG_COMPLETION_LVL);
	} else {
		log_commit_failure(module, "commit", ret);
	}
	/*
	 * Clear the transaction id inserted by log_start_transaction
	 */
	audit_private->transaction_guid = GUID_zero();
	return ret;
}

/*
 * @brief log details of a transaction delete aka roll back.
 *
 * Log details of a transaction roll back.
 *
 * @param module the ldb_module
 * @param req the ldb_request
 *
 * @return ldb status code
 */
static int log_del_transaction(struct ldb_module *module)
{
	struct audit_private *audit_private =
		talloc_get_type_abort(ldb_module_get_private(module),
				      struct audit_private);

	log_transaction(module, "rollback", TRANSACTION_LOG_FAILURE_LVL);
	audit_private->transaction_guid = GUID_zero();
	return ldb_next_del_trans(module);
}

/*
 * @brief log details of an extended operation.
 *
 * Log the details of an extended operation.
 *
 * @param module the ldb_module
 * @param req the ldb_request
 *
 * @return ldb status code
 */
static int log_extended(
	struct ldb_module *module,
	struct ldb_request *req)
{
	struct audit_callback_context *context = NULL;
	struct ldb_request *new_req = NULL;
	struct ldb_context *ldb = NULL;
	int ret;

	/*
	 * Currently we only log replication extended operations
	 */
	if (strcmp(
		req->op.extended.oid,
		DSDB_EXTENDED_REPLICATED_OBJECTS_OID) != 0) {

		return ldb_next_request(module, req);
	}
	ldb = ldb_module_get_ctx(module);
	context = talloc_zero(req, struct audit_callback_context);

	if (context == NULL) {
		return ldb_oom(ldb);
	}
	context->request = req;
	context->module  = module;
	/*
	 * We want to log the return code status, so we need to register
	 * a callback function to get the actual result.
	 * We need to take a new copy so that we don't alter the callers copy
	 */
	ret = ldb_build_extended_req(
		&new_req,
		ldb,
		req,
		req->op.extended.oid,
		req->op.extended.data,
		req->controls,
		context,
		audit_callback,
		req);
	if (ret != LDB_SUCCESS) {
		return ret;
	}
	ret = add_transaction_id(module, new_req);
	if (ret != LDB_SUCCESS) {
		return ret;
	}
	return ldb_next_request(module, new_req);
}

/*
 * @brief module initialisation
 */
static int log_init(struct ldb_module *module)
{

	struct ldb_context *ldb = ldb_module_get_ctx(module);
	struct audit_private *audit_private = NULL;
	struct loadparm_context *lp_ctx
		= talloc_get_type_abort(ldb_get_opaque(ldb, "loadparm"),
					struct loadparm_context);
	struct tevent_context *ev = ldb_get_event_context(ldb);
	bool sdb_events = false;
	bool pwd_events = false;

	audit_private = talloc_zero(module, struct audit_private);
	if (audit_private == NULL) {
		return ldb_module_oom(module);
	}

	if (lp_ctx != NULL) {
		sdb_events = lpcfg_dsdb_event_notification(lp_ctx);
		pwd_events = lpcfg_dsdb_password_event_notification(lp_ctx);
	}
	if (sdb_events || pwd_events) {
		audit_private->send_samdb_events = sdb_events;
		audit_private->send_password_events = pwd_events;
		audit_private->msg_ctx
			= imessaging_client_init(audit_private,
						 lp_ctx,
						 ev);
	}

	ldb_module_set_private(module, audit_private);
	return ldb_next_init(module);
}

static const struct ldb_module_ops ldb_audit_log_module_ops = {
	.name              = "audit_log",
	.init_context	   = log_init,
	.add		   = log_add,
	.modify		   = log_modify,
	.del		   = log_delete,
	.start_transaction = log_start_transaction,
	.prepare_commit    = log_prepare_commit,
	.end_transaction   = log_end_transaction,
	.del_transaction   = log_del_transaction,
	.extended	   = log_extended,
};

int ldb_audit_log_module_init(const char *version)
{
	LDB_MODULE_CHECK_VERSION(version);
	return ldb_register_module(&ldb_audit_log_module_ops);
}
