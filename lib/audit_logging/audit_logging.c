/*
   common routines for audit logging

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
 * Error handling:
 *
 * The json_object structure contains a boolean 'error'.  This is set whenever
 * an error is detected. All the library functions check this flag and return
 * immediately if it is set.
 *
 *	if (object->error) {
 *		return;
 *	}
 *
 * This allows the operations to be sequenced naturally with out the clutter
 * of error status checks.
 *
 *	audit = json_new_object();
 *	json_add_version(&audit, OPERATION_MAJOR, OPERATION_MINOR);
 *	json_add_int(&audit, "statusCode", ret);
 *	json_add_string(&audit, "status", ldb_strerror(ret));
 *	json_add_string(&audit, "operation", operation);
 *	json_add_address(&audit, "remoteAddress", remote);
 *	json_add_sid(&audit, "userSid", sid);
 *	json_add_string(&audit, "dn", dn);
 *	json_add_guid(&audit, "transactionId", &ac->transaction_guid);
 *	json_add_guid(&audit, "sessionId", unique_session_token);
 *
 * The assumptions are that errors will be rare, and that the audit logging
 * code should not cause failures. So errors are logged but processing
 * continues on a best effort basis.
 */

#include "includes.h"

#include "librpc/ndr/libndr.h"
#include "lib/tsocket/tsocket.h"
#include "libcli/security/dom_sid.h"
#include "lib/messaging/messaging.h"
#include "auth/common_auth.h"
#include "audit_logging.h"

/*
 * @brief Get a human readable timestamp.
 *
 * Returns the current time formatted as
 *  "Tue, 14 Mar 2017 08:38:42.209028 NZDT"
 *
 * The returned string is allocated by talloc in the supplied context.
 * It is the callers responsibility to free it.
 *
 * @param mem_ctx talloc memory context that owns the returned string.
 *
 * @return a human readable time stamp.
 *
 */
char* audit_get_timestamp(TALLOC_CTX *frame)
{
	char buffer[40];	/* formatted time less usec and timezone */
	char tz[10];		/* formatted time zone			 */
	struct tm* tm_info;	/* current local time			 */
	struct timeval tv;	/* current system time			 */
	int r;			/* response code from gettimeofday	 */
	char * ts;		/* formatted time stamp			 */

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
 * @brief write an audit message to the audit logs.
 *
 * Write a human readable text audit message to the samba logs.
 *
 * @param prefix Text to be printed at the start of the log line
 * @param message The content of the log line.
 * @param debub_class The debug class to log the message with.
 * @param debug_level The debug level to log the message with.
 */
void audit_log_human_text(const char* prefix,
			  const char* message,
			  int debug_class,
			  int debug_level)
{
	DEBUGC(debug_class, debug_level, ("%s %s\n", prefix, message));
}

#ifdef HAVE_JANSSON
/*
 * @brief write a json object to the samba audit logs.
 *
 * Write the json object to the audit logs as a formatted string
 *
 * @param prefix Text to be printed at the start of the log line
 * @param message The content of the log line.
 * @param debub_class The debug class to log the message with.
 * @param debug_level The debug level to log the message with.
 */
void audit_log_json(const char* prefix,
		    struct json_object* message,
		    int debug_class,
		    int debug_level)
{
	TALLOC_CTX *ctx = talloc_new(NULL);
	char *s = json_to_string(ctx, message);
	DEBUGC(debug_class, debug_level, ("JSON %s: %s\n", prefix, s));
	TALLOC_FREE(ctx);
}

/*
 * @brief get a connection to the messaging event server.
 *
 * Get a connection to the messaging event server registered by server_name.
 *
 * @param msg_ctx a valid imessaging_context.
 * @param server_name name of messaging event server to connect to.
 * @param server_id The event server details to populate
 *
 * @return NTSTATUS
 */
static NTSTATUS get_event_server(
	struct imessaging_context *msg_ctx,
	const char *server_name,
	struct server_id *event_server)
{
	NTSTATUS status;
	TALLOC_CTX *frame = talloc_stackframe();
	unsigned num_servers, i;
	struct server_id *servers;

	status = irpc_servers_byname(
		msg_ctx,
		frame,
		server_name,
		&num_servers,
		&servers);

	if (!NT_STATUS_IS_OK(status)) {
		DBG_NOTICE(
			"Failed to find '%s' registered on the message bus to "
			"send JSON audit events to: %s\n",
			server_name,
			nt_errstr(status));
		TALLOC_FREE(frame);
		return status;
	}

	/*
	 * Select the first server that is listening, because we get
	 * connection refused as NT_STATUS_OBJECT_NAME_NOT_FOUND
	 * without waiting
	 */
	for (i = 0; i < num_servers; i++) {
		status = imessaging_send(
			msg_ctx,
			servers[i],
			MSG_PING,
			&data_blob_null);
		if (NT_STATUS_IS_OK(status)) {
			*event_server = servers[i];
			TALLOC_FREE(frame);
			return NT_STATUS_OK;
		}
	}
	DBG_NOTICE(
		"Failed to find '%s' registered on the message bus to "
		"send JSON audit events to: %s\n",
		server_name,
		nt_errstr(status));
	TALLOC_FREE(frame);
	return NT_STATUS_OBJECT_NAME_NOT_FOUND;
}

/*
 * @brief send an audit message to a messaging event server.
 *
 * Send the message to a registered and listening event server.
 * Note: Any errors are logged, and the message is not sent.  This is to ensure
 *       that a poorly behaved event server does not impact Samba.
 *
 *       As it is possible to lose messages, especially during server
 *       shut down, currently this function is primarily intended for use
 *       in integration tests.
 *
 * @param msg_ctx an imessaging_context, can be NULL in which case no message
 *                will be sent.
 * @param server_name the naname of the event server to send the message to.
 * @param messag_type A message type defined in librpc/idl/messaging.idl
 * @param message The message to send.
 *
 */
void audit_message_send(
	struct imessaging_context *msg_ctx,
	const char *server_name,
	uint32_t message_type,
	struct json_object *message)
{
	struct server_id event_server = {};
	NTSTATUS status;

	const char *message_string = NULL;
	DATA_BLOB message_blob = data_blob_null;
	TALLOC_CTX *ctx = talloc_new(NULL);

	if (msg_ctx == NULL) {
		DBG_DEBUG("No messaging context\n");
		TALLOC_FREE(ctx);
		return;
	}

	/* Need to refetch the address each time as the destination server may
	 * have disconnected and reconnected in the interim, in which case
	 * messages may get lost
	 */
	status = get_event_server(msg_ctx, server_name, &event_server);
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(ctx);
		return;
	}

	message_string = json_to_string(ctx, message);
	message_blob = data_blob_string_const(message_string);
	status = imessaging_send(
		msg_ctx,
		event_server,
		message_type,
		&message_blob);

	/*
	 * If the server crashed, try to find it again
	 */
	if (NT_STATUS_EQUAL(status, NT_STATUS_OBJECT_NAME_NOT_FOUND)) {
		status = get_event_server(msg_ctx, server_name, &event_server);
		if (!NT_STATUS_IS_OK(status)) {
			TALLOC_FREE(ctx);
			return;
		}
		imessaging_send(
			msg_ctx,
			event_server,
			message_type,
			&message_blob);
	}
	TALLOC_FREE(ctx);
}

/*
 * @brief Create a new struct json_object, wrapping a JSON Object.
 *
 * Create a new json object, the json_object wraps the underlying json
 * implementations JSON Object representation.
 *
 * Free with a call to json_free_object, note that the jansson inplementation
 * allocates memory with malloc and not talloc.
 *
 * @return a struct json_object, error will be set to true if the object
 *         could not be created.
 *
 */
struct json_object json_new_object(void) {

	struct json_object object;
	object.error = false;

	object.root = json_object();
	if (object.root == NULL) {
		object.error = true;
		DBG_ERR("Unable to create json_object\n");
	}
	return object;
}

/*
 * @brief Create a new struct json_object wrapping a JSON Array.
 *
 * Create a new json object, the json_object wraps the underlying json
 * implementations JSON Array representation.
 *
 * Free with a call to json_free_object, note that the jansson inplementation
 * allocates memory with malloc and not talloc.
 *
 * @return a struct json_object, error will be set to true if the array
 *         could not be created.
 *
 */
struct json_object json_new_array(void) {

	struct json_object array;
	array.error = false;

	array.root = json_array();
	if (array.root == NULL) {
		array.error = true;
		DBG_ERR("Unable to create json_array\n");
	}
	return array;
}


/*
 * @brief free and invalidate a previously created JSON object.
 *
 * Release any resources owned by a json_object, and then mark the structure
 * as invalid.  It is safe to call this multiple times on an object.
 *
 */
void json_free(struct json_object *object)
{
	if (object->root != NULL) {
		json_decref(object->root);
	}
	object->root = NULL;
	object->error = true;
}

/*
 * @brief is the current JSON object invalid?
 *
 * Check the state of the object to determine if it is invalid.
 *
 * @return is the object valid?
 *
 */
bool json_is_invalid(struct json_object *object)
{
	return object->error;
}

/*
 * @brief Add an integer value to a JSON object.
 *
 * Add an integer value named 'name' to the json object.
 * In the event of an error object will be invalidated.
 *
 * @param object the JSON object to be updated.
 * @param name the name of the value.
 * @param value the value.
 *
 */
void json_add_int(struct json_object *object,
		  const char* name,
		  const int value)
{
	int rc = 0;

	if (object->error) {
		return;
	}

	rc = json_object_set_new(object->root, name, json_integer(value));
	if (rc) {
		DBG_ERR("Unable to set name [%s] value [%d]\n", name, value);
		object->error = true;
	}
}

/*
 * @brief Add a boolean value to a JSON object.
 *
 * Add a boolean value named 'name' to the json object.
 * In the event of an error object will be invalidated.
 *
 * @param object the JSON object to be updated.
 * @param name the name.
 * @param value the value.
 *
 */
void json_add_bool(struct json_object *object,
		   const char* name,
		   const bool value)
{
	int rc = 0;

	if (object->error) {
		return;
	}

	rc = json_object_set_new(object->root, name, json_boolean(value));
	if (rc) {
		DBG_ERR("Unable to set name [%s] value [%d]\n", name, value);
		object->error = true;
	}

}

/*
 * @brief Add a string value to a JSON object.
 *
 * Add a string value named 'name' to the json object.
 * In the event of an error object will be invalidated.
 *
 * @param object the JSON object to be updated.
 * @param name the name.
 * @param value the value.
 *
 */
void json_add_string(struct json_object *object,
		     const char* name,
		     const char* value)
{
	int rc = 0;

	if (object->error) {
		return;
	}

	if (value) {
		rc = json_object_set_new(
			object->root,
			name,
			json_string(value));
	} else {
		rc = json_object_set_new(object->root, name, json_null());
	}
	if (rc) {
		DBG_ERR("Unable to set name [%s] value [%s]\n", name, value);
		object->error = true;
	}
}

/*
 * @brief Assert that the current JSON object is an array.
 *
 * Check that the current object is a JSON array, and if not
 * invalidate the object. We also log an error message as this indicates
 * bug in the calling code.
 *
 * @param object the JSON object to be validated.
 */
void json_assert_is_array(struct json_object *array) {

	if (array->error) {
		return;
	}

	if (json_is_array(array->root) == false) {
		DBG_ERR("JSON object is not an array\n");
		array->error = true;
		return;
	}
}

/*
 * @brief Add a JSON object to a JSON object.
 *
 * Add a JSON object named 'name' to the json object.
 * In the event of an error object will be invalidated.
 *
 * @param object the JSON object to be updated.
 * @param name the name.
 * @param value the value.
 *
 */
void json_add_object(struct json_object *object,
		     const char* name,
		     struct json_object *value)
{
	int rc = 0;
	json_t *jv = NULL;

	if (object->error) {
		return;
	}

	if (value != NULL && value->error) {
		object->error = true;
		return;
	}

	jv = value == NULL ? json_null() : value->root;

	if (json_is_array(object->root)) {
		rc = json_array_append_new(object->root, jv);
	} else if (json_is_object(object->root)) {
		rc = json_object_set_new(object->root, name,  jv);
	} else {
		DBG_ERR("Invalid JSON object type\n");
		object->error = true;
	}
	if (rc) {
		DBG_ERR("Unable to add object [%s]\n", name);
		object->error = true;
	}
}

/*
 * @brief Add a string to a JSON object, truncating if necessary.
 *
 *
 * Add a string value named 'name' to the json object, the string will be
 * truncated if it is more than len characters long. If len is 0 the value
 * is encoded as a JSON null.
 *
 * In the event of an error object will be invalidated.
 *
 * @param object the JSON object to be updated.
 * @param name the name.
 * @param value the value.
 * @param len the maximum number of characters to be copied.
 *
 */
void json_add_stringn(struct json_object *object,
		      const char *name,
		      const char *value,
		      const size_t len)
{

	int rc = 0;
	if (object->error) {
		return;
	}

	if (value != NULL && len > 0) {
		char buffer[len+1];
		strncpy(buffer, value, len);
		buffer[len] = '\0';
		rc = json_object_set_new(object->root,
					 name,
					 json_string(buffer));
	} else {
		rc = json_object_set_new(object->root, name, json_null());
	}
	if (rc) {
		DBG_ERR("Unable to set name [%s] value [%s]\n", name, value);
		object->error = true;
	}
}

/*
 * @brief Add a version object to a JSON object
 *
 * Add a version object to the JSON object
 * 	"version":{"major":1, "minor":0}
 *
 * The version tag is intended to aid the processing of the JSON messages
 * The major version number should change when an attribute is:
 *  - renamed
 *  - removed
 *  - its meaning changes
 *  - its contents change format
 * The minor version should change whenever a new attribute is added and for
 * minor bug fixes to an attributes content.
 *
 * In the event of an error object will be invalidated.
 *
 * @param object the JSON object to be updated.
 * @param major the major version number
 * @param minor the minor version number
 */
void json_add_version(struct json_object *object, int major, int minor)
{
	struct json_object version = json_new_object();
	json_add_int(&version, "major", major);
	json_add_int(&version, "minor", minor);
	json_add_object(object, "version", &version);
}

/*
 * @brief add an ISO 8601 timestamp to the object.
 *
 * Add the current date and time as a timestamp in ISO 8601 format
 * to a JSON object
 *
 * "timestamp":"2017-03-06T17:18:04.455081+1300"
 *
 * In the event of an error object will be invalidated.
 *
 * @param object the JSON object to be updated.
 */
void json_add_timestamp(struct json_object *object)
{
	char buffer[40];	/* formatted time less usec and timezone */
	char timestamp[65];	/* the formatted ISO 8601 time stamp	 */
	char tz[10];		/* formatted time zone			 */
	struct tm* tm_info;	/* current local time			 */
	struct timeval tv;	/* current system time			 */
	int r;			/* response code from gettimeofday	 */

	if (object->error) {
		return;
	}

	r = gettimeofday(&tv, NULL);
	if (r) {
		DBG_ERR("Unable to get time of day: (%d) %s\n",
			errno,
			strerror(errno));
		object->error = true;
		return;
	}

	tm_info = localtime(&tv.tv_sec);
	if (tm_info == NULL) {
		DBG_ERR("Unable to determine local time\n");
		object->error = true;
		return;
	}

	strftime(buffer, sizeof(buffer)-1, "%Y-%m-%dT%T", tm_info);
	strftime(tz, sizeof(tz)-1, "%z", tm_info);
	snprintf(
		timestamp,
		sizeof(timestamp),
		"%s.%06ld%s",
		buffer,
		tv.tv_usec,
		tz);
	json_add_string(object, "timestamp", timestamp);
}


/*
 *@brief Add a tsocket_address to a JSON object
 *
 * Add the string representation of a Samba tsocket_address to the object.
 *
 * "localAddress":"ipv6::::0"
 *
 * In the event of an error object will be invalidated.
 *
 * @param object the JSON object to be updated.
 * @param name the name.
 * @param address the tsocket_address.
 *
 */
void json_add_address(struct json_object *object,
		      const char *name,
		      const struct tsocket_address *address)
{

	if (object->error) {
		return;
	}
	if (address == NULL) {
		int rc = json_object_set_new(object->root, name, json_null());
		if (rc) {
			DBG_ERR("Unable to set address [%s] to null\n", name);
			object->error = true;
		}
	} else {
		TALLOC_CTX *ctx = talloc_new(NULL);
		char *s = NULL;

		s = tsocket_address_string(address, ctx);
		json_add_string(object, name, s);
		TALLOC_FREE(ctx);
	}
}

/*
 * @brief Add a formatted string representation of a sid to a json object.
 *
 * Add the string representation of a Samba sid to the object.
 *
 * "sid":"S-1-5-18"
 *
 * In the event of an error object will be invalidated.
 *
 * @param object the JSON object to be updated.
 * @param name the name.
 * @param sid the sid
 *
 */
void json_add_sid(struct json_object *object,
		  const char *name,
		  const struct dom_sid *sid)
{

	if (object->error) {
		return;
	}
	if (sid == NULL) {
		int rc = json_object_set_new(object->root, name, json_null());
		if (rc) {
			DBG_ERR("Unable to set SID [%s] to null\n", name);
			object->error = true;
		}
	} else {
		char sid_buf[DOM_SID_STR_BUFLEN];

		dom_sid_string_buf(sid, sid_buf, sizeof(sid_buf));
		json_add_string(object, name, sid_buf);
	}
}

/*
 * @brief Add a formatted string representation of a guid to a json object.
 *
 * Add the string representation of a Samba GUID to the object.
 *
 * "guid":"1fb9f2ee-2a4d-4bf8-af8b-cb9d4529a9ab"
 *
 * In the event of an error object will be invalidated.
 *
 * @param object the JSON object to be updated.
 * @param name the name.
 * @param guid the guid.
 *
 *
 */
void json_add_guid(struct json_object *object,
		   const char *name,
		   const struct GUID *guid)
{


	if (object->error) {
		return;
	}
	if (guid == NULL) {
		int rc = json_object_set_new(object->root, name, json_null());
		if (rc) {
			DBG_ERR("Unable to set GUID [%s] to null\n", name);
			object->error = true;
		}
	} else {
		char *guid_str;
		struct GUID_txt_buf guid_buff;

		guid_str = GUID_buf_string(guid, &guid_buff);
		json_add_string(object, name, guid_str);
	}
}


/*
 * @brief Convert a JSON object into a string
 *
 * Convert the jsom object into a string suitable for printing on a log line,
 * i.e. with no embedded line breaks.
 *
 * If the object is invalid it returns NULL.
 *
 * @param mem_ctx the talloc memory context owning the returned string
 * @param object the json object.
 *
 * @return A string representation of the object or NULL if the object
 *         is invalid.
 */
char *json_to_string(TALLOC_CTX *mem_ctx,
		     struct json_object *object)
{
	char *json = NULL;
	char *json_string = NULL;

	if (object->error) {
		return NULL;
	}

	/*
	 * json_dumps uses malloc, so need to call free(json) to release
	 * the memory
	 */
	json = json_dumps(object->root, 0);
	if (json == NULL) {
		DBG_ERR("Unable to convert JSON object to string\n");
		return NULL;
	}

	json_string = talloc_strdup(mem_ctx, json);
	if (json_string == NULL) {
		free(json);
		DBG_ERR("Unable to copy JSON object string to talloc string\n");
		return NULL;
	}
	free(json);

	return json_string;
}

/*
 * @brief get a json array named "name" from the json object.
 *
 * Get the array attribute named name, creating it if it does not exist.
 *
 * @param object the json object.
 * @param name the name of the array attribute
 *
 * @return The array object, will be created if it did not exist.
 */
struct json_object json_get_array(struct json_object *object,
				  const char* name)
{

	struct json_object array = json_new_array();
	json_t *a = NULL;

	if (object->error) {
		array.error = true;
		return array;
	}

	a = json_object_get(object->root, name);
	if (a == NULL) {
		return array;
	}
	json_array_extend(array.root, a);

	return array;
}

/*
 * @brief get a json object named "name" from the json object.
 *
 * Get the object attribute named name, creating it if it does not exist.
 *
 * @param object the json object.
 * @param name the name of the object attribute
 *
 * @return The object, will be created if it did not exist.
 */
struct json_object json_get_object(struct json_object *object,
				   const char* name)
{

	struct json_object o = json_new_object();
	json_t *v = NULL;

	if (object->error) {
		o.error = true;
		return o;
	}

	v = json_object_get(object->root, name);
	if (v == NULL) {
		return o;
	}
	json_object_update(o.root, v);

	return o;
}
#endif
