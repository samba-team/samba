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
 * Provide an audit log of changes made to group memberships
 *
 */

#include "includes.h"
#include "ldb_module.h"
#include "lib/audit_logging/audit_logging.h"
#include "librpc/gen_ndr/windows_event_ids.h"

#include "dsdb/samdb/samdb.h"
#include "dsdb/samdb/ldb_modules/util.h"
#include "dsdb/samdb/ldb_modules/audit_util_proto.h"
#include "libcli/security/dom_sid.h"
#include "auth/common_auth.h"
#include "param/param.h"

#define AUDIT_JSON_TYPE "groupChange"
#define AUDIT_HR_TAG "Group Change"
#define AUDIT_MAJOR 1
#define AUDIT_MINOR 1
#define GROUP_LOG_LVL 5

static const char *const group_attrs[] = {"member", "groupType", NULL};
static const char *const group_type_attr[] = {"groupType", NULL};
static const char * const primary_group_attr[] = {
	"primaryGroupID",
	"objectSID",
	NULL};

struct audit_context {
	bool send_events;
	struct imessaging_context *msg_ctx;
};

struct audit_callback_context {
	struct ldb_request *request;
	struct ldb_module *module;
	struct ldb_message_element *members;
	uint32_t primary_group;
	void (*log_changes)(
		struct audit_callback_context *acc,
		const int status);
};

/*
 * @brief get the transaction id.
 *
 * Get the id of the transaction that the current request is contained in.
 *
 * @param req the request.
 *
 * @return the transaction id GUID, or NULL if it is not there.
 */
static struct GUID *get_transaction_id(
	const struct ldb_request *request)
{
	struct ldb_control *control;
	struct dsdb_control_transaction_identifier *transaction_id;

	control = ldb_request_get_control(
		discard_const(request),
		DSDB_CONTROL_TRANSACTION_IDENTIFIER_OID);
	if (control == NULL) {
		return NULL;
	}
	transaction_id = talloc_get_type(
		control->data,
		struct dsdb_control_transaction_identifier);
	if (transaction_id == NULL) {
		return NULL;
	}
	return &transaction_id->transaction_guid;
}

/*
 * @brief generate a JSON log entry for a group change.
 *
 * Generate a JSON object containing details of a users group change.
 *
 * @param module the ldb module
 * @param request the ldb_request
 * @param action the change action being performed
 * @param user the user name
 * @param group the group name
 * @param status the ldb status code for the ldb operation.
 *
 * @return A json object containing the details.
 * 	   NULL if an error was detected
 */
static struct json_object audit_group_json(const struct ldb_module *module,
					   const struct ldb_request *request,
					   const char *action,
					   const char *user,
					   const char *group,
					   const enum event_id_type event_id,
					   const int status)
{
	struct ldb_context *ldb = NULL;
	const struct dom_sid *sid = NULL;
	struct json_object wrapper = json_empty_object;
	struct json_object audit = json_empty_object;
	const struct tsocket_address *remote = NULL;
	const struct GUID *unique_session_token = NULL;
	struct GUID *transaction_id = NULL;
	int rc = 0;

	ldb = ldb_module_get_ctx(discard_const(module));

	remote = dsdb_audit_get_remote_address(ldb);
	sid = dsdb_audit_get_user_sid(module);
	unique_session_token = dsdb_audit_get_unique_session_token(module);
	transaction_id = get_transaction_id(request);

	audit = json_new_object();
	if (json_is_invalid(&audit)) {
		goto failure;
	}
	rc = json_add_version(&audit, AUDIT_MAJOR, AUDIT_MINOR);
	if (rc != 0) {
		goto failure;
	}
	if (event_id != EVT_ID_NONE) {
		rc = json_add_int(&audit, "eventId", event_id);
		if (rc != 0) {
			goto failure;
		}
	}
	rc = json_add_int(&audit, "statusCode", status);
	if (rc != 0) {
		goto failure;
	}
	rc = json_add_string(&audit, "status", ldb_strerror(status));
	if (rc != 0) {
		goto failure;
	}
	rc = json_add_string(&audit, "action", action);
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
	rc = json_add_string(&audit, "group", group);
	if (rc != 0) {
		goto failure;
	}
	rc = json_add_guid(&audit, "transactionId", transaction_id);
	if (rc != 0) {
		goto failure;
	}
	rc = json_add_guid(&audit, "sessionId", unique_session_token);
	if (rc != 0) {
		goto failure;
	}
	rc = json_add_string(&audit, "user", user);
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
	rc = json_add_string(&wrapper, "type", AUDIT_JSON_TYPE);
	if (rc != 0) {
		goto failure;
	}
	rc = json_add_object(&wrapper, AUDIT_JSON_TYPE, &audit);
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
	DBG_ERR("Failed to create group change JSON log message\n");
	return wrapper;
}

/*
 * @brief generate a human readable log entry for a group change.
 *
 * Generate a human readable log entry containing details of a users group
 * change.
 *
 * @param ctx the talloc context owning the returned log entry
 * @param module the ldb module
 * @param request the ldb_request
 * @param action the change action being performed
 * @param user the user name
 * @param group the group name
 * @param status the ldb status code for the ldb operation.
 *
 * @return A human readable log line.
 */
static char *audit_group_human_readable(
	TALLOC_CTX *mem_ctx,
	const struct ldb_module *module,
	const struct ldb_request *request,
	const char *action,
	const char *user,
	const char *group,
	const int status)
{
	struct ldb_context *ldb = NULL;
	const char *remote_host = NULL;
	const struct dom_sid *sid = NULL;
	const char *user_sid = NULL;
	const char *timestamp = NULL;
	char *log_entry = NULL;

	TALLOC_CTX *ctx = talloc_new(NULL);

	ldb = ldb_module_get_ctx(discard_const(module));

	remote_host = dsdb_audit_get_remote_host(ldb, ctx);
	sid = dsdb_audit_get_user_sid(module);
	user_sid = dom_sid_string(ctx, sid);
	timestamp = audit_get_timestamp(ctx);

	log_entry = talloc_asprintf(
		mem_ctx,
		"[%s] at [%s] status [%s] "
		"Remote host [%s] SID [%s] Group [%s] User [%s]",
		action,
		timestamp,
		ldb_strerror(status),
		remote_host,
		user_sid,
		group,
		user);
	TALLOC_FREE(ctx);
	return log_entry;
}

/*
 * @brief generate an array of parsed_dns, deferring the actual parsing.
 *
 * Get an array of 'struct parsed_dns' without the parsing.
 * The parsed_dns are parsed only when needed to avoid the expense of parsing.
 *
 * This procedure assumes that the dn's are sorted in GUID order and contains
 * no duplicates.  This should be valid as the module sits below repl_meta_data
 * which ensures this.
 *
 * @param mem_ctx The memory context that will own the generated array
 * @param el The message element used to generate the array.
 *
 * @return an array of struct parsed_dns, or NULL in the event of an error
 */
static struct parsed_dn *get_parsed_dns(
	TALLOC_CTX *mem_ctx,
	struct ldb_message_element *el)
{
	int ret;
	struct parsed_dn *pdn = NULL;

	if (el == NULL || el->num_values == 0) {
		return NULL;
	}

	ret = get_parsed_dns_trusted(mem_ctx, el, &pdn);
	if (ret == LDB_ERR_OPERATIONS_ERROR) {
		DBG_ERR("Out of memory\n");
		return NULL;
	}
	return pdn;

}

enum dn_compare_result {
	LESS_THAN,
	BINARY_EQUAL,
	EQUAL,
	GREATER_THAN
};
/*
 * @brief compare parsed_dn, using GUID ordering
 *
 * Compare two parsed_dn structures, using GUID ordering.
 * To avoid the overhead of parsing the DN's this function does a binary
 * compare first. The DN's tre only parsed if they are not equal at a binary
 * level.
 *
 * @param ctx talloc context that will own the parsed dsdb_dn
 * @param ldb ldb_context
 * @param dn1 The first dn
 * @param dn2 The second dn
 *
 * @return BINARY_EQUAL values are equal at a binary level
 *         EQUAL        DN's are equal but the meta data is different
 *         LESS_THAN    dn1's GUID is less than dn2's GUID
 *         GREATER_THAN dn1's GUID is greater than  dn2's GUID
 *
 */
static enum dn_compare_result dn_compare(
	TALLOC_CTX *mem_ctx,
	struct ldb_context *ldb,
	struct parsed_dn *dn1,
	struct parsed_dn *dn2) {

	int res = 0;

	/*
	 * Do a binary compare first to avoid unnecessary parsing
	 */
	if (data_blob_cmp(dn1->v, dn2->v) == 0) {
		/*
		 * Values are equal at a binary level so no need
		 * for further processing
		 */
		return BINARY_EQUAL;
	}
	/*
	 * Values not equal at the binary level, so lets
	 * do a GUID ordering compare. To do this we will need to ensure
	 * that the dn's have been parsed.
	 */
	if (dn1->dsdb_dn == NULL) {
		really_parse_trusted_dn(
			mem_ctx,
			ldb,
			dn1,
			LDB_SYNTAX_DN);
	}
	if (dn2->dsdb_dn == NULL) {
		really_parse_trusted_dn(
			mem_ctx,
			ldb,
			dn2,
			LDB_SYNTAX_DN);
	}

	res = ndr_guid_compare(&dn1->guid, &dn2->guid);
	if (res < 0) {
		return LESS_THAN;
	} else if (res == 0) {
		return EQUAL;
	} else {
		return GREATER_THAN;
	}
}

/*
 * @brief Get the DN of a users primary group as a printable string.
 *
 * Get the DN of a users primary group as a printable string.
 *
 * @param mem_ctx Talloc context the the returned string will be allocated on.
 * @param module The ldb module
 * @param account_sid The SID for the uses account.
 * @param primary_group_rid The RID for the users primary group.
 *
 * @return a formatted DN, or null if there is an error.
 */
static const char *get_primary_group_dn(
	TALLOC_CTX *mem_ctx,
	struct ldb_module *module,
	struct dom_sid *account_sid,
	uint32_t primary_group_rid)
{
	NTSTATUS status;

	struct ldb_context *ldb = NULL;
	struct dom_sid *domain_sid = NULL;
	struct dom_sid *primary_group_sid = NULL;
	char *sid = NULL;
	struct ldb_dn *dn = NULL;
	struct ldb_message *msg = NULL;
	int rc;

	ldb = ldb_module_get_ctx(module);

	status = dom_sid_split_rid(mem_ctx, account_sid, &domain_sid, NULL);
	if (!NT_STATUS_IS_OK(status)) {
		return NULL;
	}

	primary_group_sid = dom_sid_add_rid(
		mem_ctx,
		domain_sid,
		primary_group_rid);
	if (!primary_group_sid) {
		return NULL;
	}

	sid = dom_sid_string(mem_ctx, primary_group_sid);
	if (sid == NULL) {
		return NULL;
	}

	dn = ldb_dn_new_fmt(mem_ctx, ldb, "<SID=%s>", sid);
	if(dn == NULL) {
		return sid;
	}
	rc = dsdb_search_one(
		ldb,
		mem_ctx,
		&msg,
		dn,
		LDB_SCOPE_BASE,
		NULL,
		0,
		NULL);
	if (rc != LDB_SUCCESS) {
		return NULL;
	}

	return ldb_dn_get_linearized(msg->dn);
}

/*
 * @brief Log details of a change to a users primary group.
 *
 * Log details of a change to a users primary group.
 * There is no windows event id associated with a Primary Group change.
 * However for a new user we generate an added to group event.
 *
 * @param module The ldb module.
 * @param request The request being logged.
 * @param action Description of the action being performed.
 * @param group The linearized for of the group DN
 * @param status the LDB status code for the processing of the request.
 *
 */
static void log_primary_group_change(
	struct ldb_module *module,
	const struct ldb_request *request,
	const char *action,
	const char *group,
	const int  status)
{
	const char *user = NULL;

	struct audit_context *ac =
		talloc_get_type(
			ldb_module_get_private(module),
			struct audit_context);

	TALLOC_CTX *ctx = talloc_new(NULL);

	user = dsdb_audit_get_primary_dn(request);
	if (CHECK_DEBUGLVLC(DBGC_DSDB_GROUP_AUDIT, GROUP_LOG_LVL)) {
		char *message = NULL;
		message = audit_group_human_readable(
			ctx,
			module,
			request,
			action,
			user,
			group,
			status);
		audit_log_human_text(
			AUDIT_HR_TAG,
			message,
			DBGC_DSDB_GROUP_AUDIT,
			GROUP_LOG_LVL);
		TALLOC_FREE(message);
	}

	if (CHECK_DEBUGLVLC(DBGC_DSDB_GROUP_AUDIT_JSON, GROUP_LOG_LVL) ||
		(ac->msg_ctx && ac->send_events)) {

		struct json_object json;
		json = audit_group_json(
		    module, request, action, user, group, EVT_ID_NONE, status);
		audit_log_json(
			&json,
			DBGC_DSDB_GROUP_AUDIT_JSON,
			GROUP_LOG_LVL);
		if (ac->send_events) {
			audit_message_send(
				ac->msg_ctx,
				DSDB_GROUP_EVENT_NAME,
				MSG_GROUP_LOG,
				&json);
		}
		json_free(&json);
		if (request->operation == LDB_ADD) {
			/*
			 * Have just added a user, generate a groupChange
			 * message indicating the user has been added to thier
			 * new PrimaryGroup.
			 */
		}
	}
	TALLOC_FREE(ctx);
}

/*
 * @brief Log details of a single change to a users group membership.
 *
 * Log details of a change to a users group membership, except for changes
 * to their primary group which is handled by log_primary_group_change.
 *
 * @param module The ldb module.
 * @param request The request being logged.
 * @param action Description of the action being performed.
 * @param user The linearized form of the users DN
 * @param status the LDB status code for the processing of the request.
 *
 */
static void log_membership_change(struct ldb_module *module,
				  const struct ldb_request *request,
				  const char *action,
				  const char *user,
				  const enum event_id_type event_id,
				  const int status)
{
	const char *group = NULL;
	struct audit_context *ac =
		talloc_get_type(
			ldb_module_get_private(module),
			struct audit_context);

	TALLOC_CTX *ctx = talloc_new(NULL);
	group = dsdb_audit_get_primary_dn(request);
	if (CHECK_DEBUGLVLC(DBGC_DSDB_GROUP_AUDIT, GROUP_LOG_LVL)) {
		char *message = NULL;
		message = audit_group_human_readable(
			ctx,
			module,
			request,
			action,
			user,
			group,
			status);
		audit_log_human_text(
			AUDIT_HR_TAG,
			message,
			DBGC_DSDB_GROUP_AUDIT,
			GROUP_LOG_LVL);
		TALLOC_FREE(message);
	}

	if (CHECK_DEBUGLVLC(DBGC_DSDB_GROUP_AUDIT_JSON, GROUP_LOG_LVL) ||
		(ac->msg_ctx && ac->send_events)) {
		struct json_object json;
		json = audit_group_json(
		    module, request, action, user, group, event_id, status);
		audit_log_json(
			&json,
			DBGC_DSDB_GROUP_AUDIT_JSON,
			GROUP_LOG_LVL);
		if (ac->send_events) {
			audit_message_send(
				ac->msg_ctx,
				DSDB_GROUP_EVENT_NAME,
				MSG_GROUP_LOG,
				&json);
		}
		json_free(&json);
	}
	TALLOC_FREE(ctx);
}

/*
 * @brief Get the windows event type id for removing a user from a group type.
 *
 * @param group_type the type of the current group, see libds/common/flags.h
 *
 * @return the Windows Event Id
 *
 */
static enum event_id_type get_remove_member_event(uint32_t group_type)
{

	switch (group_type) {
	case GTYPE_SECURITY_BUILTIN_LOCAL_GROUP:
		return EVT_ID_USER_REMOVED_FROM_LOCAL_SEC_GROUP;
	case GTYPE_SECURITY_GLOBAL_GROUP:
		return EVT_ID_USER_REMOVED_FROM_GLOBAL_SEC_GROUP;
	case GTYPE_SECURITY_DOMAIN_LOCAL_GROUP:
		return EVT_ID_USER_REMOVED_FROM_LOCAL_SEC_GROUP;
	case GTYPE_SECURITY_UNIVERSAL_GROUP:
		return EVT_ID_USER_REMOVED_FROM_UNIVERSAL_SEC_GROUP;
	case GTYPE_DISTRIBUTION_GLOBAL_GROUP:
		return EVT_ID_USER_REMOVED_FROM_GLOBAL_GROUP;
	case GTYPE_DISTRIBUTION_DOMAIN_LOCAL_GROUP:
		return EVT_ID_USER_REMOVED_FROM_LOCAL_GROUP;
	case GTYPE_DISTRIBUTION_UNIVERSAL_GROUP:
		return EVT_ID_USER_REMOVED_FROM_UNIVERSAL_GROUP;
	default:
		return EVT_ID_NONE;
	}
}

/*
 * @brief Get the windows event type id for adding a user to a group type.
 *
 * @param group_type the type of the current group, see libds/common/flags.h
 *
 * @return the Windows Event Id
 *
 */
static enum event_id_type get_add_member_event(uint32_t group_type)
{

	switch (group_type) {
	case GTYPE_SECURITY_BUILTIN_LOCAL_GROUP:
		return EVT_ID_USER_ADDED_TO_LOCAL_SEC_GROUP;
	case GTYPE_SECURITY_GLOBAL_GROUP:
		return EVT_ID_USER_ADDED_TO_GLOBAL_SEC_GROUP;
	case GTYPE_SECURITY_DOMAIN_LOCAL_GROUP:
		return EVT_ID_USER_ADDED_TO_LOCAL_SEC_GROUP;
	case GTYPE_SECURITY_UNIVERSAL_GROUP:
		return EVT_ID_USER_ADDED_TO_UNIVERSAL_SEC_GROUP;
	case GTYPE_DISTRIBUTION_GLOBAL_GROUP:
		return EVT_ID_USER_ADDED_TO_GLOBAL_GROUP;
	case GTYPE_DISTRIBUTION_DOMAIN_LOCAL_GROUP:
		return EVT_ID_USER_ADDED_TO_LOCAL_GROUP;
	case GTYPE_DISTRIBUTION_UNIVERSAL_GROUP:
		return EVT_ID_USER_ADDED_TO_UNIVERSAL_GROUP;
	default:
		return EVT_ID_NONE;
	}
}

/*
 * @brief Log all the changes to a users group membership.
 *
 * Log details of a change to a users group memberships, except for changes
 * to their primary group which is handled by log_primary_group_change.
 *
 * @param module The ldb module.
 * @param request The request being logged.
 * @param action Description of the action being performed.
 * @param user The linearized form of the users DN
 * @param status the LDB status code for the processing of the request.
 *
 */
static void log_membership_changes(struct ldb_module *module,
				   const struct ldb_request *request,
				   struct ldb_message_element *el,
				   struct ldb_message_element *old_el,
				   uint32_t group_type,
				   int status)
{
	unsigned int i, old_i, new_i;
	unsigned int old_num_values;
	unsigned int max_num_values;
	unsigned int new_num_values;
	struct parsed_dn *old_val = NULL;
	struct parsed_dn *new_val = NULL;
	struct parsed_dn *new_values = NULL;
	struct parsed_dn *old_values = NULL;
	struct ldb_context *ldb = NULL;

	TALLOC_CTX *ctx = talloc_new(NULL);

	old_num_values = old_el ? old_el->num_values : 0;
	new_num_values = el ? el->num_values : 0;
	max_num_values = old_num_values + new_num_values;

	if (max_num_values == 0) {
		/*
		 * There is nothing to do!
		 */
		TALLOC_FREE(ctx);
		return;
	}

	old_values = get_parsed_dns(ctx, old_el);
	new_values = get_parsed_dns(ctx, el);
	ldb = ldb_module_get_ctx(module);

	old_i = 0;
	new_i = 0;
	for (i = 0; i < max_num_values; i++) {
		enum dn_compare_result cmp;
		if (old_i < old_num_values && new_i < new_num_values) {
			/*
			 * Both list have values, so compare the values
			 */
			old_val = &old_values[old_i];
			new_val = &new_values[new_i];
			cmp = dn_compare(ctx, ldb, old_val, new_val);
		} else if (old_i < old_num_values) {
			/*
			 * the new list is empty, read the old list
			 */
			old_val = &old_values[old_i];
			new_val = NULL;
			cmp = LESS_THAN;
		} else if (new_i < new_num_values) {
			/*
			 * the old list is empty, read new list
			 */
			old_val = NULL;
			new_val = &new_values[new_i];
			cmp = GREATER_THAN;
		} else {
			break;
		}

		if (cmp == LESS_THAN) {
			/*
			 * Have an entry in the original record that is not in
			 * the new record. So it's been deleted
			 */
			const char *user = NULL;
			enum event_id_type event_id;
			if (old_val->dsdb_dn == NULL) {
				really_parse_trusted_dn(
					ctx,
					ldb,
					old_val,
					LDB_SYNTAX_DN);
			}
			user = ldb_dn_get_linearized(old_val->dsdb_dn->dn);
			event_id = get_remove_member_event(group_type);
			log_membership_change(
			    module, request, "Removed", user, event_id, status);
			old_i++;
		} else if (cmp == BINARY_EQUAL) {
			/*
			 * DN's unchanged at binary level so nothing to do.
			 */
			old_i++;
			new_i++;
		} else if (cmp == EQUAL) {
			/*
			 * DN is unchanged now need to check the flags to
			 * determine if a record has been deleted or undeleted
			 */
			uint32_t old_flags;
			uint32_t new_flags;
			if (old_val->dsdb_dn == NULL) {
				really_parse_trusted_dn(
					ctx,
					ldb,
					old_val,
					LDB_SYNTAX_DN);
			}
			if (new_val->dsdb_dn == NULL) {
				really_parse_trusted_dn(
					ctx,
					ldb,
					new_val,
					LDB_SYNTAX_DN);
			}

			dsdb_get_extended_dn_uint32(
				old_val->dsdb_dn->dn,
				&old_flags,
				"RMD_FLAGS");
			dsdb_get_extended_dn_uint32(
				new_val->dsdb_dn->dn,
				&new_flags,
				"RMD_FLAGS");
			if (new_flags == old_flags) {
				/*
				 * No changes to the Repl meta data so can
				 * no need to log the change
				 */
				old_i++;
				new_i++;
				continue;
			}
			if (new_flags & DSDB_RMD_FLAG_DELETED) {
				/*
				 * DN has been deleted.
				 */
				const char *user = NULL;
				enum event_id_type event_id;
				user = ldb_dn_get_linearized(
					old_val->dsdb_dn->dn);
				event_id = get_remove_member_event(group_type);
				log_membership_change(module,
						      request,
						      "Removed",
						      user,
						      event_id,
						      status);
			} else {
				/*
				 * DN has been re-added
				 */
				const char *user = NULL;
				enum event_id_type event_id;
				user = ldb_dn_get_linearized(
					new_val->dsdb_dn->dn);
				event_id = get_add_member_event(group_type);
				log_membership_change(module,
						      request,
						      "Added",
						      user,
						      event_id,
						      status);
			}
			old_i++;
			new_i++;
		} else {
			/*
			 * Member in the updated record that's not in the
			 * original, so it must have been added.
			 */
			const char *user = NULL;
			enum event_id_type event_id;
			if ( new_val->dsdb_dn == NULL) {
				really_parse_trusted_dn(
					ctx,
					ldb,
					new_val,
					LDB_SYNTAX_DN);
			}
			user = ldb_dn_get_linearized(new_val->dsdb_dn->dn);
			event_id = get_add_member_event(group_type);
			log_membership_change(
			    module, request, "Added", user, event_id, status);
			new_i++;
		}
	}

	TALLOC_FREE(ctx);
}

/*
 * @brief log a group change message for a newly added user.
 *
 * When a user is added we need to generate a GroupChange Add message to
 * log that the user has been added to their PrimaryGroup
 */
static void log_new_user_added_to_primary_group(
    TALLOC_CTX *ctx,
    struct audit_callback_context *acc,
    const char *group,
    const int status)
{
	uint32_t group_type;
	enum event_id_type event_id = EVT_ID_NONE;
	struct ldb_result *res = NULL;
	struct ldb_dn *group_dn = NULL;
	struct ldb_context *ldb = NULL;
	int ret;

	ldb = ldb_module_get_ctx(acc->module);
	group_dn = ldb_dn_new(ctx, ldb, group);
	ret = dsdb_module_search_dn(acc->module,
				    ctx,
				    &res,
				    group_dn,
				    group_type_attr,
				    DSDB_FLAG_NEXT_MODULE |
					DSDB_SEARCH_REVEAL_INTERNALS |
					DSDB_SEARCH_SHOW_DN_IN_STORAGE_FORMAT,
				    NULL);
	if (ret == LDB_SUCCESS) {
		const char *user = NULL;
		group_type =
		    ldb_msg_find_attr_as_uint(res->msgs[0], "groupType", 0);
		event_id = get_add_member_event(group_type);
		user = dsdb_audit_get_primary_dn(acc->request);
		log_membership_change(
		    acc->module, acc->request, "Added", user, event_id, status);
	}
}

/*
 * @brief Log the details of a primary group change.
 *
 * Retrieve the users primary groupo after the operation has completed
 * and call log_primary_group_change to log the actual changes.
 *
 * @param acc details of the primary group before the operation.
 * @param status The status code returned by the operation.
 *
 * @return an LDB status code.
 */
static void log_user_primary_group_change(
	struct audit_callback_context *acc,
	const int status)
{
	TALLOC_CTX *ctx = talloc_new(NULL);
	uint32_t new_rid;
	struct dom_sid *account_sid = NULL;
	int ret;
	const struct ldb_message *msg = dsdb_audit_get_message(acc->request);

	if (status == LDB_SUCCESS && msg != NULL) {
		struct ldb_result *res = NULL;
		ret = dsdb_module_search_dn(
			acc->module,
			ctx,
			&res,
			msg->dn,
			primary_group_attr,
			DSDB_FLAG_NEXT_MODULE |
			DSDB_SEARCH_REVEAL_INTERNALS |
			DSDB_SEARCH_SHOW_DN_IN_STORAGE_FORMAT,
			NULL);
		if (ret == LDB_SUCCESS) {
			new_rid = ldb_msg_find_attr_as_uint(
				msg,
				"primaryGroupID",
				~0);
			account_sid = samdb_result_dom_sid(
				ctx,
				res->msgs[0],
				"objectSid");
		}
	}
	/*
	 * If we don't have a new value then the user has been deleted
	 * which we currently do not log.
	 * Otherwise only log if the primary group has actually changed.
	 */
	if (account_sid != NULL &&
	    new_rid != ~0 &&
	    acc->primary_group != new_rid) {
		const char* group = get_primary_group_dn(
			ctx,
			acc->module,
			account_sid,
			new_rid);
		log_primary_group_change(
			acc->module,
			acc->request,
			"PrimaryGroup",
			group,
			status);
		/*
		 * Are we adding a new user with the primaryGroupID
		 * set. If so and we're generating JSON audit logs, will need to
		 * generate an "Add" message with the appropriate windows
		 * event id.
		 */
		if (acc->request->operation == LDB_ADD) {
			log_new_user_added_to_primary_group(
			    ctx, acc, group, status);
		}
	}
	TALLOC_FREE(ctx);
}

/*
 * @brief log the changes to users group membership.
 *
 * Retrieve the users group memberships after the operation has completed
 * and call log_membership_changes to log the actual changes.
 *
 * @param acc details of the group memberships before the operation.
 * @param status The status code returned by the operation.
 *
 */
static void log_group_membership_changes(
	struct audit_callback_context *acc,
	const int status)
{
	TALLOC_CTX *ctx = talloc_new(NULL);
	struct ldb_message_element *new_val = NULL;
	int ret;
	uint32_t group_type = 0;
	const struct ldb_message *msg = dsdb_audit_get_message(acc->request);
	if (status == LDB_SUCCESS && msg != NULL) {
		struct ldb_result *res = NULL;
		ret = dsdb_module_search_dn(
			acc->module,
			ctx,
			&res,
			msg->dn,
			group_attrs,
			DSDB_FLAG_NEXT_MODULE |
			DSDB_SEARCH_REVEAL_INTERNALS |
			DSDB_SEARCH_SHOW_DN_IN_STORAGE_FORMAT,
			NULL);
		if (ret == LDB_SUCCESS) {
			new_val = ldb_msg_find_element(res->msgs[0], "member");
			group_type = ldb_msg_find_attr_as_uint(
			    res->msgs[0], "groupType", 0);
			log_membership_changes(acc->module,
					       acc->request,
					       new_val,
					       acc->members,
					       group_type,
					       status);
			TALLOC_FREE(ctx);
			return;
		}
	}
	/*
	 * If we get here either
	 *   one of the lower level modules failed and the group record did
	 *   not get updated
	 * or
	 *   the updated group record could not be read.
	 *
	 * In both cases it does not make sense to log individual membership
	 * changes so we log a group membership change "Failure" message.
	 *
	 */
	log_membership_change(acc->module,
	                      acc->request,
			      "Failure",
			      "",
			      EVT_ID_NONE,
			      status);
	TALLOC_FREE(ctx);
}

/*
 * @brief call back function to log changes to the group memberships.
 *
 * Call back function to log changes to the uses broup memberships.
 *
 * @param req the ldb request.
 * @param ares the ldb result
 *
 * @return am LDB status code.
 */
static int group_audit_callback(
	struct ldb_request *req,
	struct ldb_reply *ares)
{
	struct audit_callback_context *ac = NULL;

	ac = talloc_get_type(
		req->context,
		struct audit_callback_context);

	if (!ares) {
		return ldb_module_done(
				ac->request, NULL, NULL,
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
		 * Log on DONE now we have a result code
		 */
		ac->log_changes(ac, ares->error);
		return ldb_module_done(
			ac->request,
			ares->controls,
			ares->response,
			ares->error);
		break;

	default:
		/* Can't happen */
		return LDB_ERR_OPERATIONS_ERROR;
	}
}

/*
 * @brief Does this request change the primary group.
 *
 * Does the request change the primary group, i.e. does it contain the
 * primaryGroupID attribute.
 *
 * @param req the request to examine.
 *
 * @return True if the request modifies the primary group.
 */
static bool has_primary_group_id(struct ldb_request *req)
{
	struct ldb_message_element *el = NULL;
	const struct ldb_message *msg = NULL;

	msg = dsdb_audit_get_message(req);
	el = ldb_msg_find_element(msg, "primaryGroupID");

	return (el != NULL);
}

/*
 * @brief Does this request change group membership.
 *
 * Does the request change the ses group memberships, i.e. does it contain the
 * member attribute.
 *
 * @param req the request to examine.
 *
 * @return True if the request modifies the users group memberships.
 */
static bool has_group_membership_changes(struct ldb_request *req)
{
	struct ldb_message_element *el = NULL;
	const struct ldb_message *msg = NULL;

	msg = dsdb_audit_get_message(req);
	el = ldb_msg_find_element(msg, "member");

	return (el != NULL);
}



/*
 * @brief Install the callback function to log an add request.
 *
 * Install the callback function to log an add request changing the users
 * group memberships. As we want to log the returned status code, we need to
 * register a callback function that will be called once the operation has
 * completed.
 *
 * This function reads the current user record so that we can log the before
 * and after state.
 *
 * @param module The ldb module.
 * @param req The modify request.
 *
 * @return and LDB status code.
 */
static int set_group_membership_add_callback(
	struct ldb_module *module,
	struct ldb_request *req)
{
	struct audit_callback_context *context = NULL;
	struct ldb_request *new_req = NULL;
	struct ldb_context *ldb = NULL;
	int ret;
	/*
	 * Adding group memberships so will need to log the changes.
	 */
	ldb = ldb_module_get_ctx(module);
	context = talloc_zero(req, struct audit_callback_context);

	if (context == NULL) {
		return ldb_oom(ldb);
	}
	context->request = req;
	context->module = module;
	context->log_changes = log_group_membership_changes;
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
		group_audit_callback,
		req);
	if (ret != LDB_SUCCESS) {
		return ret;
	}
	return ldb_next_request(module, new_req);
}


/*
 * @brief Install the callback function to log a modify request.
 *
 * Install the callback function to log a modify request changing the primary
 * group . As we want to log the returned status code, we need to register a
 * callback function that will be called once the operation has completed.
 *
 * This function reads the current user record so that we can log the before
 * and after state.
 *
 * @param module The ldb module.
 * @param req The modify request.
 *
 * @return and LDB status code.
 */
static int set_primary_group_modify_callback(
	struct ldb_module *module,
	struct ldb_request *req)
{
	struct audit_callback_context *context = NULL;
	struct ldb_request *new_req = NULL;
	struct ldb_context *ldb = NULL;
	const struct ldb_message *msg = NULL;
	struct ldb_result *res = NULL;
	int ret;

	TALLOC_CTX *ctx = talloc_new(NULL);

	ldb = ldb_module_get_ctx(module);

	context = talloc_zero(req, struct audit_callback_context);
	if (context == NULL) {
		ret = ldb_oom(ldb);
		goto exit;
	}
	context->request = req;
	context->module = module;
	context->log_changes = log_user_primary_group_change;

	msg = dsdb_audit_get_message(req);
	ret = dsdb_module_search_dn(
		module,
		ctx,
		&res,
		msg->dn,
		primary_group_attr,
		DSDB_FLAG_NEXT_MODULE |
		DSDB_SEARCH_REVEAL_INTERNALS |
		DSDB_SEARCH_SHOW_DN_IN_STORAGE_FORMAT,
		NULL);
	if (ret == LDB_SUCCESS) {
		uint32_t pg;
		pg = ldb_msg_find_attr_as_uint(
			res->msgs[0],
			"primaryGroupID",
			~0);
		context->primary_group = pg;
	}
	/*
	 * We want to log the return code status, so we need to register
	 * a callback function to get the actual result.
	 * We need to take a new copy so that we don't alter the callers copy
	 */
	ret = ldb_build_mod_req(
		&new_req,
		ldb,
		req,
		req->op.add.message,
		req->controls,
		context,
		group_audit_callback,
		req);
	if (ret != LDB_SUCCESS) {
		goto exit;
	}
	ret = ldb_next_request(module, new_req);
exit:
	TALLOC_FREE(ctx);
	return ret;
}

/*
 * @brief Install the callback function to log an add request.
 *
 * Install the callback function to log an add request changing the primary
 * group . As we want to log the returned status code, we need to register a
 * callback function that will be called once the operation has completed.
 *
 * This function reads the current user record so that we can log the before
 * and after state.
 *
 * @param module The ldb module.
 * @param req The modify request.
 *
 * @return and LDB status code.
 */
static int set_primary_group_add_callback(
	struct ldb_module *module,
	struct ldb_request *req)
{
	struct audit_callback_context *context = NULL;
	struct ldb_request *new_req = NULL;
	struct ldb_context *ldb = NULL;
	int ret;
	/*
	 * Adding a user with a primary group.
	 */
	ldb = ldb_module_get_ctx(module);
	context = talloc_zero(req, struct audit_callback_context);

	if (context == NULL) {
		return ldb_oom(ldb);
	}
	context->request = req;
	context->module = module;
	context->log_changes = log_user_primary_group_change;
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
		group_audit_callback,
		req);
	if (ret != LDB_SUCCESS) {
		return ret;
	}
	return ldb_next_request(module, new_req);
}

/*
 * @brief Module handler for add operations.
 *
 * Inspect the current add request, and if needed log any group membership
 * changes.
 *
 * @param module The ldb module.
 * @param req The modify request.
 *
 * @return and LDB status code.
 */
static int group_add(
	struct ldb_module *module,
	struct ldb_request *req)
{

	struct audit_context *ac =
		talloc_get_type(
			ldb_module_get_private(module),
			struct audit_context);
	/*
	 * Currently we don't log replicated group changes
	 */
	if (ldb_request_get_control(req, DSDB_CONTROL_REPLICATED_UPDATE_OID)) {
		return ldb_next_request(module, req);
	}

	if (CHECK_DEBUGLVLC(DBGC_DSDB_GROUP_AUDIT, GROUP_LOG_LVL) ||
		CHECK_DEBUGLVLC(DBGC_DSDB_GROUP_AUDIT_JSON, GROUP_LOG_LVL) ||
		(ac->msg_ctx && ac->send_events)) {
		/*
		 * Avoid the overheads of logging unless it has been
		 * enabled
		 */
		if (has_group_membership_changes(req)) {
			return set_group_membership_add_callback(module, req);
		}
		if (has_primary_group_id(req)) {
			return set_primary_group_add_callback(module, req);
		}
	}
	return ldb_next_request(module, req);
}

/*
 * @brief Module handler for delete operations.
 *
 * Currently there is no logging for delete operations.
 *
 * @param module The ldb module.
 * @param req The modify request.
 *
 * @return and LDB status code.
 */
static int group_delete(
	struct ldb_module *module,
	struct ldb_request *req)
{
	return ldb_next_request(module, req);
}

/*
 * @brief Install the callback function to log a modify request.
 *
 * Install the callback function to log a modify request. As we want to log the
 * returned status code, we need to register a callback function that will be
 * called once the operation has completed.
 *
 * This function reads the current user record so that we can log the before
 * and after state.
 *
 * @param module The ldb module.
 * @param req The modify request.
 *
 * @return and LDB status code.
 */
static int set_group_modify_callback(
	struct ldb_module *module,
	struct ldb_request *req)
{
	struct audit_callback_context *context = NULL;
	struct ldb_request *new_req = NULL;
	struct ldb_context *ldb = NULL;
	struct ldb_result *res = NULL;
	int ret;

	ldb = ldb_module_get_ctx(module);
	context = talloc_zero(req, struct audit_callback_context);

	if (context == NULL) {
		return ldb_oom(ldb);
	}
	context->request = req;
	context->module  = module;
	context->log_changes = log_group_membership_changes;

	/*
	 * About to change the group memberships need to read
	 * the current state from the database.
	 */
	ret = dsdb_module_search_dn(
		module,
		context,
		&res,
		req->op.add.message->dn,
		group_attrs,
		DSDB_FLAG_NEXT_MODULE |
		DSDB_SEARCH_REVEAL_INTERNALS |
		DSDB_SEARCH_SHOW_DN_IN_STORAGE_FORMAT,
		NULL);
	if (ret == LDB_SUCCESS) {
		context->members = ldb_msg_find_element(res->msgs[0], "member");
	}

	ret = ldb_build_mod_req(
		&new_req,
		ldb,
		req,
		req->op.mod.message,
		req->controls,
		context,
		group_audit_callback,
		req);
	if (ret != LDB_SUCCESS) {
		return ret;
	}
	return ldb_next_request(module, new_req);
}

/*
 * @brief Module handler for modify operations.
 *
 * Inspect the current modify request, and if needed log any group membership
 * changes.
 *
 * @param module The ldb module.
 * @param req The modify request.
 *
 * @return and LDB status code.
 */
static int group_modify(
	struct ldb_module *module,
	struct ldb_request *req)
{

	struct audit_context *ac =
		talloc_get_type(
			ldb_module_get_private(module),
			struct audit_context);
	/*
	 * Currently we don't log replicated group changes
	 */
	if (ldb_request_get_control(req, DSDB_CONTROL_REPLICATED_UPDATE_OID)) {
		return ldb_next_request(module, req);
	}

	if (CHECK_DEBUGLVLC(DBGC_DSDB_GROUP_AUDIT, GROUP_LOG_LVL) ||
	    CHECK_DEBUGLVLC(DBGC_DSDB_GROUP_AUDIT_JSON, GROUP_LOG_LVL) ||
		(ac->msg_ctx && ac->send_events)) {
		/*
		 * Avoid the overheads of logging unless it has been
		 * enabled
		 */
		if (has_group_membership_changes(req)) {
			return set_group_modify_callback(module, req);
		}
		if (has_primary_group_id(req)) {
			return set_primary_group_modify_callback(module, req);
		}
	}
	return ldb_next_request(module, req);
}

/*
 * @brief ldb module initialisation
 *
 * Initialise the module, loading the private data etc.
 *
 * @param module The ldb module to initialise.
 *
 * @return An LDB status code.
 */
static int group_init(struct ldb_module *module)
{

	struct ldb_context *ldb = ldb_module_get_ctx(module);
	struct audit_context *context = NULL;
	struct loadparm_context *lp_ctx
		= talloc_get_type_abort(
			ldb_get_opaque(ldb, "loadparm"),
			struct loadparm_context);
	struct tevent_context *ev = ldb_get_event_context(ldb);

	context = talloc_zero(module, struct audit_context);
	if (context == NULL) {
		return ldb_module_oom(module);
	}

	if (lp_ctx && lpcfg_dsdb_group_change_notification(lp_ctx)) {
		context->send_events = true;
		context->msg_ctx = imessaging_client_init(context,
							  lp_ctx,
							  ev);
	}

	ldb_module_set_private(module, context);
	return ldb_next_init(module);
}

static const struct ldb_module_ops ldb_group_audit_log_module_ops = {
	.name              = "group_audit_log",
	.add		   = group_add,
	.modify		   = group_modify,
	.del		   = group_delete,
	.init_context	   = group_init,
};

int ldb_group_audit_log_module_init(const char *version)
{
	LDB_MODULE_CHECK_VERSION(version);
	return ldb_register_module(&ldb_group_audit_log_module_ops);
}
