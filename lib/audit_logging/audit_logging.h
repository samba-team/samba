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

#include <talloc.h>
#include "lib/messaging/irpc.h"
#include "lib/tsocket/tsocket.h"

char* audit_get_timestamp(
	TALLOC_CTX *frame);

void audit_message_send(
	struct imessaging_context *msg_ctx,
	const char *server_name,
	uint32_t message_type,
	const char *message);
#ifdef HAVE_JANSSON
#include <jansson.h>
/*
 * Wrapper for jannson JSON object
 *
 */
struct json_object {
	json_t *root;
	bool error;
};

struct json_object json_new_object(void);
struct json_object json_new_array(void);
void json_free(struct json_object *object);
void json_assert_is_array(struct json_object *array);
bool json_is_invalid(struct json_object *object);

void json_add_int(
	struct json_object *object,
	const char* name,
	const int value);
void json_add_bool(
	struct json_object *object,
	const char* name,
	const bool value);
void json_add_string(
	struct json_object *object,
	const char* name,
	const char* value);
void json_add_object(
	struct json_object *object,
	const char* name,
	struct json_object *value);
void json_add_stringn(
	struct json_object *object,
	const char *name,
	const char *value,
	const size_t len);
void json_add_version(
	struct json_object *object,
	int major,
	int minor);
void json_add_timestamp(struct json_object *object);
void json_add_address(
	struct json_object *object,
	const char *name,
	const struct tsocket_address *address);
void json_add_sid(
	struct json_object *object,
	const char *name,
	const struct dom_sid *sid);
void json_add_guid(
	struct json_object *object,
	const char *name,
	const struct GUID *guid);

char *json_to_string(TALLOC_CTX *mem_ctx, struct json_object *object);
#endif
