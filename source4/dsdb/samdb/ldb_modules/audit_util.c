/*
   ldb database module utility library

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
 * Common utility functions for SamDb audit logging.
 *
 */

#include "includes.h"
#include "ldb_module.h"
#include "lib/audit_logging/audit_logging.h"

#include "dsdb/samdb/samdb.h"
#include "dsdb/samdb/ldb_modules/util.h"
#include "libcli/security/dom_sid.h"
#include "libcli/security/security_token.h"
#include "auth/common_auth.h"
#include "param/param.h"
#include "dsdb/samdb/ldb_modules/util.h"
#include "dsdb/samdb/ldb_modules/audit_util_proto.h"

#define MAX_LENGTH 1024

#define min(a, b) (((a)>(b))?(b):(a))

/*
 * List of attributes considered secret or confidential the values of these
 * attributes should not be displayed in log messages.
 */
static const char * const secret_attributes[] = {
	DSDB_SECRET_ATTRIBUTES,
	NULL};
/*
 * List of attributes that contain a password, used to detect password changes
 */
static const char * const password_attributes[] = {
	DSDB_PASSWORD_ATTRIBUTES,
	NULL};

/*
 * @brief Should the value of the specified value be redacted.
 *
 * The values of secret or password attributes should not be displayed.
 *
 * @param name The attributes name.
 *
 * @return True if the attribute should be redacted
 */
bool dsdb_audit_redact_attribute(const char * name)
{

	if (ldb_attr_in_list(secret_attributes, name)) {
		return true;
	}

	if (ldb_attr_in_list(password_attributes, name)) {
		return true;
	}

	return false;
}

/*
 * @brief is the attribute a password attribute?
 *
 * Is the attribute a password attribute.
 *
 * @return True if the attribute is a "Password" attribute.
 */
bool dsdb_audit_is_password_attribute(const char * name)
{

	bool is_password = ldb_attr_in_list(password_attributes, name);
	return is_password;
}

/*
 * @brief Get the remote address from the ldb context.
 *
 * The remote address is stored in the ldb opaque value "remoteAddress"
 * it is the responsibility of the higher level code to ensure that this
 * value is set.
 *
 * @param ldb the ldb_context.
 *
 * @return the remote address if known, otherwise NULL.
 */
const struct tsocket_address *dsdb_audit_get_remote_address(
	struct ldb_context *ldb)
{
	void *opaque_remote_address = NULL;
	struct tsocket_address *remote_address;

	opaque_remote_address = ldb_get_opaque(ldb,
					       "remoteAddress");
	if (opaque_remote_address == NULL) {
		return NULL;
	}

	remote_address = talloc_get_type(opaque_remote_address,
					 struct tsocket_address);
	return remote_address;
}

/*
 * @brief Get the actual user SID from ldb context.
 *
 * The actual user SID is stored in the ldb opaque value "networkSessionInfo"
 * it is the responsibility of the higher level code to ensure that this
 * value is set.
 *
 * @param ldb the ldb_context.
 *
 * @return the users actual sid.
 */
const struct dom_sid *dsdb_audit_get_actual_sid(struct ldb_context *ldb)
{
	void *opaque_session = NULL;
	struct auth_session_info *session = NULL;
	struct security_token *user_token = NULL;

	opaque_session = ldb_get_opaque(ldb, DSDB_NETWORK_SESSION_INFO);
	if (opaque_session == NULL) {
		return NULL;
	}

	session = talloc_get_type(opaque_session, struct auth_session_info);
	if (session == NULL) {
		return NULL;
	}

	user_token = session->security_token;
	if (user_token == NULL) {
		return NULL;
	}
	return &user_token->sids[0];
}
/*
 * @brief get the ldb error string.
 *
 * Get the ldb error string if set, otherwise get the generic error code
 * for the status code.
 *
 * @param ldb the ldb_context.
 * @param status the ldb_status code.
 *
 * @return a string describing the error.
 */
const char *dsdb_audit_get_ldb_error_string(
	struct ldb_module *module,
	int status)
{
	struct ldb_context *ldb = ldb_module_get_ctx(module);
	const char *err_string = ldb_errstring(ldb);

	if (err_string == NULL) {
		return ldb_strerror(status);
	}
	return err_string;
}

/*
 * @brief get the SID of the user performing the operation.
 *
 * Get the SID of the user performing the operation.
 *
 * @param module the ldb_module.
 *
 * @return the SID of the currently logged on user.
 */
const struct dom_sid *dsdb_audit_get_user_sid(const struct ldb_module *module)
{
	struct security_token *user_token = NULL;

	/*
	 * acl_user_token does not alter module so it's safe
	 * to discard the const.
	 */
	user_token = acl_user_token(discard_const(module));
	if (user_token == NULL) {
		return NULL;
	}
	return &user_token->sids[0];

}

/*
 * @brief is operation being performed using the system session.
 *
 * Is the operation being performed using the system session.
 *
 * @param module the ldb_module.
 *
 * @return true if the operation is being performed using the system session.
 */
bool dsdb_audit_is_system_session(const struct ldb_module *module)
{
	struct security_token *user_token = NULL;

	/*
	 * acl_user_token does not alter module and security_token_is_system
	 * does not alter the security token so it's safe to discard the const.
	 */
	user_token = acl_user_token(discard_const(module));
	if (user_token == NULL) {
		return false;
	}
	return security_token_is_system(user_token);;

}

/*
 * @brief get the session identifier GUID
 *
 * Get the GUID that uniquely identifies the current authenticated session.
 *
 * @param module the ldb_module.
 *
 * @return the unique session GUID
 */
const struct GUID *dsdb_audit_get_unique_session_token(
	const struct ldb_module *module)
{
	struct ldb_context *ldb = ldb_module_get_ctx(discard_const(module));
	struct auth_session_info *session_info
		= (struct auth_session_info *)ldb_get_opaque(
			ldb,
			DSDB_SESSION_INFO);
	if(!session_info) {
		return NULL;
	}
	return &session_info->unique_session_token;
}

/*
 * @brief get the actual user session identifier
 *
 * Get the GUID that uniquely identifies the current authenticated session.
 * This is the session of the connected user, as it may differ from the
 * session the operation is being performed as, i.e. for operations performed
 * under the system session.
 *
 * @param context the ldb_context.
 *
 * @return the unique session GUID
 */
const struct GUID *dsdb_audit_get_actual_unique_session_token(
	struct ldb_context *ldb)
{
	struct auth_session_info *session_info
		= (struct auth_session_info *)ldb_get_opaque(
			ldb,
			DSDB_NETWORK_SESSION_INFO);
	if(!session_info) {
		return NULL;
	}
	return &session_info->unique_session_token;
}

/*
 * @brief Get a printable string value for the remote host address.
 *
 * Get a printable string representation of the remote host, for display in the
 * the audit logs.
 *
 * @param ldb the ldb context.
 * @param mem_ctx the talloc memory context that will own the returned string.
 *
 * @return A string representation of the remote host address or "Unknown"
 *
 */
char *dsdb_audit_get_remote_host(struct ldb_context *ldb, TALLOC_CTX *mem_ctx)
{
	const struct tsocket_address *remote_address;
	char* remote_host = NULL;

	remote_address = dsdb_audit_get_remote_address(ldb);
	if (remote_address == NULL) {
		remote_host = talloc_asprintf(mem_ctx, "Unknown");
		return remote_host;
	}

	remote_host = tsocket_address_string(remote_address, mem_ctx);
	return remote_host;
}

/*
 * @brief get a printable representation of the primary DN.
 *
 * Get a printable representation of the primary DN. The primary DN is the
 * DN of the object being added, deleted, modified or renamed.
 *
 * @param the ldb_request.
 *
 * @return a printable and linearized DN
 */
const char* dsdb_audit_get_primary_dn(const struct ldb_request *request)
{
	struct ldb_dn *dn = NULL;
	switch (request->operation) {
	case LDB_ADD:
		if (request->op.add.message != NULL) {
			dn = request->op.add.message->dn;
		}
		break;
	case LDB_MODIFY:
		if (request->op.mod.message != NULL) {
			dn = request->op.mod.message->dn;
		}
		break;
	case LDB_DELETE:
		dn = request->op.del.dn;
		break;
	case LDB_RENAME:
		dn = request->op.rename.olddn;
		break;
	default:
		dn = NULL;
		break;
	}
	if (dn == NULL) {
		return NULL;
	}
	return ldb_dn_get_linearized(dn);
}

/*
 * @brief Get the ldb_message from a request.
 *
 * Get the ldb_message for the request, returns NULL is there is no
 * associated ldb_message
 *
 * @param The request
 *
 * @return the message associated with this request, or NULL
 */
const struct ldb_message *dsdb_audit_get_message(
	const struct ldb_request *request)
{
	switch (request->operation) {
	case LDB_ADD:
		return request->op.add.message;
	case LDB_MODIFY:
		return request->op.mod.message;
	default:
		return NULL;
	}
}

/*
 * @brief get the secondary dn, i.e. the target dn for a rename.
 *
 * Get the secondary dn, i.e. the target for a rename. This is only applicable
 * got a rename operation, for the non rename operations this function returns
 * NULL.
 *
 * @param request the ldb_request.
 *
 * @return the secondary dn in a printable and linearized form.
 */
const char *dsdb_audit_get_secondary_dn(const struct ldb_request *request)
{
	switch (request->operation) {
	case LDB_RENAME:
		return ldb_dn_get_linearized(request->op.rename.newdn);
	default:
		return NULL;
	}
}

/*
 * @brief Map the request operation to a description.
 *
 * Get a description of the operation for logging
 *
 * @param request the ldb_request
 *
 * @return a string describing the operation, or "Unknown" if the operation
 *         is not known.
 */
const char *dsdb_audit_get_operation_name(const struct ldb_request *request)
{
	switch (request->operation) {
	case LDB_SEARCH:
		return "Search";
	case LDB_ADD:
		return "Add";
	case LDB_MODIFY:
		return "Modify";
	case LDB_DELETE:
		return "Delete";
	case LDB_RENAME:
		return "Rename";
	case LDB_EXTENDED:
		return "Extended";
	case LDB_REQ_REGISTER_CONTROL:
		return "Register Control";
	case LDB_REQ_REGISTER_PARTITION:
		return "Register Partition";
	default:
		return "Unknown";
	}
}

/*
 * @brief get a description of a modify action for logging.
 *
 * Get a brief description of the modification action suitable for logging.
 *
 * @param flags the ldb_attributes flags.
 *
 * @return a brief description, or "unknown".
 */
const char *dsdb_audit_get_modification_action(unsigned int flags)
{
	switch (LDB_FLAG_MOD_TYPE(flags)) {
	case LDB_FLAG_MOD_ADD:
		return "add";
	case LDB_FLAG_MOD_DELETE:
		return "delete";
	case LDB_FLAG_MOD_REPLACE:
		return "replace";
	default:
		return "unknown";
	}
}

/*
 * @brief Add an ldb_value to a json object array
 *
 * Convert the current ldb_value to a JSON object and append it to array.
 * {
 *	"value":"xxxxxxxx",
 *	"base64":true
 *	"truncated":true
 * }
 *
 * value     is the JSON string representation of the ldb_val,
 *           will be null if the value is zero length. The value will be
 *           truncated if it is more than MAX_LENGTH bytes long. It will also
 *           be base64 encoded if it contains any non printable characters.
 *
 * base64    Indicates that the value is base64 encoded, will be absent if the
 *           value is not encoded.
 *
 * truncated Indicates that the length of the value exceeded MAX_LENGTH and was
 *           truncated.  Note that vales are truncated and then base64 encoded.
 *           so an encoded value can be longer than MAX_LENGTH.
 *
 * @param array the JSON array to append the value to.
 * @param lv the ldb_val to convert and append to the array.
 *
 */
static int dsdb_audit_add_ldb_value(struct json_object *array,
				    const struct ldb_val lv)
{
	bool base64;
	int len;
	struct json_object value = json_empty_object;
	int rc = 0;

	json_assert_is_array(array);
	if (json_is_invalid(array)) {
		return -1;
	}

	if (lv.length == 0 || lv.data == NULL) {
		rc = json_add_object(array, NULL, NULL);
		if (rc != 0) {
			goto failure;
		}
		return 0;
	}

	base64 = ldb_should_b64_encode(NULL, &lv);
	len = min(lv.length, MAX_LENGTH);
	value = json_new_object();
	if (json_is_invalid(&value)) {
		goto failure;
	}

	if (lv.length > MAX_LENGTH) {
		rc = json_add_bool(&value, "truncated", true);
		if (rc != 0) {
			goto failure;
		}
	}
	if (base64) {
		TALLOC_CTX *ctx = talloc_new(NULL);
		char *encoded = ldb_base64_encode(
			ctx,
			(char*) lv.data,
			len);

		if (ctx == NULL) {
			goto failure;
		}

		rc = json_add_bool(&value, "base64", true);
		if (rc != 0) {
			TALLOC_FREE(ctx);
			goto failure;
		}
		rc = json_add_string(&value, "value", encoded);
		if (rc != 0) {
			TALLOC_FREE(ctx);
			goto failure;
		}
		TALLOC_FREE(ctx);
	} else {
		rc = json_add_stringn(&value, "value", (char *)lv.data, len);
		if (rc != 0) {
			goto failure;
		}
	}
	/*
	 * As array is a JSON array the element name is NULL
	 */
	rc = json_add_object(array, NULL, &value);
	if (rc != 0) {
		goto failure;
	}
	return 0;
failure:
	/*
	 * In the event of a failure value will not have been added to array
	 * so it needs to be freed to prevent a leak.
	 */
	json_free(&value);
	DBG_ERR("unable to add ldb value to JSON audit message");
	return -1;
}

/*
 * @brief Build a JSON object containing the attributes in an ldb_message.
 *
 * Build a JSON object containing all the attributes in an ldb_message.
 * The attributes are keyed by attribute name, the values of "secret attributes"
 * are supressed.
 *
 * {
 * 	"password":{
 * 		"redacted":true,
 * 		"action":"delete"
 * 	},
 * 	"name":{
 * 		"values": [
 * 			{
 *				"value":"xxxxxxxx",
 *				"base64":true
 *				"truncated":true
 *			},
 * 		],
 * 		"action":"add",
 * 	}
 * }
 *
 * values is an array of json objects generated by add_ldb_value.
 * redacted indicates that the attribute is secret.
 * action is only set for modification operations.
 *
 * @param operation the ldb operation being performed
 * @param message the ldb_message to process.
 *
 * @return A populated json object.
 *
 */
struct json_object dsdb_audit_attributes_json(
	enum ldb_request_type operation,
	const struct ldb_message* message)
{

	unsigned int i, j;
	struct json_object attributes = json_new_object();

	if (json_is_invalid(&attributes)) {
		goto failure;
	}
	for (i=0;i<message->num_elements;i++) {
		struct json_object actions = json_empty_object;
		struct json_object attribute = json_empty_object;
		struct json_object action = json_empty_object;
		const char *name = message->elements[i].name;
		int rc = 0;

		action = json_new_object();
		if (json_is_invalid(&action)) {
			goto failure;
		}

		/*
		 * If this is a modify operation tag the attribute with
		 * the modification action.
		 */
		if (operation == LDB_MODIFY) {
			const char *act = NULL;
			const int flags =  message->elements[i].flags;
			act = dsdb_audit_get_modification_action(flags);
			rc = json_add_string(&action, "action", act);
			if (rc != 0) {
				json_free(&action);
				goto failure;
			}
		}
		if (operation == LDB_ADD) {
			rc = json_add_string(&action, "action", "add");
			if (rc != 0) {
				json_free(&action);
				goto failure;
			}
		}

		/*
		 * If the attribute is a secret attribute, tag it as redacted
		 * and don't include the values
		 */
		if (dsdb_audit_redact_attribute(name)) {
			rc = json_add_bool(&action, "redacted", true);
			if (rc != 0) {
				json_free(&action);
				goto failure;
			}
		} else {
			struct json_object values;
			/*
			 * Add the values for the action
			 */
			values = json_new_array();
			if (json_is_invalid(&values)) {
				json_free(&action);
				goto failure;
			}

			for (j=0;j<message->elements[i].num_values;j++) {
				rc = dsdb_audit_add_ldb_value(
				    &values, message->elements[i].values[j]);
				if (rc != 0) {
					json_free(&values);
					json_free(&action);
					goto failure;
				}
			}
			rc = json_add_object(&action, "values", &values);
			if (rc != 0) {
				json_free(&values);
				json_free(&action);
				goto failure;
			}
		}
		attribute = json_get_object(&attributes, name);
		if (json_is_invalid(&attribute)) {
			json_free(&action);
			goto failure;
		}
		actions = json_get_array(&attribute, "actions");
		if (json_is_invalid(&actions)) {
			json_free(&action);
			goto failure;
		}
		rc = json_add_object(&actions, NULL, &action);
		if (rc != 0) {
			json_free(&action);
			goto failure;
		}
		rc = json_add_object(&attribute, "actions", &actions);
		if (rc != 0) {
			json_free(&actions);
			goto failure;
		}
		rc = json_add_object(&attributes, name, &attribute);
		if (rc != 0) {
			json_free(&attribute);
			goto failure;
		}
	}
	return attributes;
failure:
	json_free(&attributes);
	DBG_ERR("Unable to create ldb attributes JSON audit message\n");
	return attributes;
}
