/*
   CTDB event daemon protocol

   Copyright (C) Amitay Isaacs  2018

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, see <http://www.gnu.org/licenses/>.
*/

#include "replace.h"

#include <talloc.h>

#include "protocol/protocol_basic.h"

#include "event_protocol.h"
#include "event_protocol_api.h"

static size_t ctdb_event_script_action_len(enum ctdb_event_script_action in)
{
	uint32_t u32 = in;

	return ctdb_uint32_len(&u32);
}

static void ctdb_event_script_action_push(enum ctdb_event_script_action in,
					  uint8_t *buf,
					  size_t *npush)
{
	uint32_t u32 = in;

	ctdb_uint32_push(&u32, buf, npush);
}

static int ctdb_event_script_action_pull(uint8_t *buf,
					 size_t buflen,
					 enum ctdb_event_script_action *out,
					 size_t *npull)
{
	enum ctdb_event_script_action value;
	uint32_t u32;
	size_t np;
	int ret;

	ret = ctdb_uint32_pull(buf, buflen, &u32, &np);
	if (ret != 0) {
		return ret;
	}

	switch (u32) {
	case 0:
		value = CTDB_EVENT_SCRIPT_DISABLE;
		break;

	case 1:
		value = CTDB_EVENT_SCRIPT_ENABLE;
		break;

	default:
		return EINVAL;
	}

	*out = value;
	*npull = np;

	return 0;
}

static size_t ctdb_event_command_len(enum ctdb_event_command in)
{
	uint32_t u32 = in;

	return ctdb_uint32_len(&u32);
}

static void ctdb_event_command_push(enum ctdb_event_command in,
				    uint8_t *buf,
				    size_t *npush)
{
	uint32_t u32 = in;

	ctdb_uint32_push(&u32, buf, npush);
}

static int ctdb_event_command_pull(uint8_t *buf,
				   size_t buflen,
				   enum ctdb_event_command *out,
				   size_t *npull)
{
	enum ctdb_event_command value;
	uint32_t u32;
	size_t np;
	int ret;

	ret = ctdb_uint32_pull(buf, buflen, &u32, &np);
	if (ret != 0) {
		return ret;
	}

	switch (u32) {
	case 1:
		value = CTDB_EVENT_CMD_RUN;
		break;

	case 2:
		value = CTDB_EVENT_CMD_STATUS;
		break;

	case 3:
		value = CTDB_EVENT_CMD_SCRIPT;
		break;

	default:
		return EINVAL;
	}

	*out = value;
	*npull = np;

	return 0;
}

static size_t ctdb_event_script_len(struct ctdb_event_script *in)
{
	return ctdb_stringn_len(&in->name) +
		ctdb_timeval_len(&in->begin) +
		ctdb_timeval_len(&in->end) +
		ctdb_int32_len(&in->result) +
		ctdb_stringn_len(&in->output);
}

static void ctdb_event_script_push(struct ctdb_event_script *in,
				   uint8_t *buf,
				   size_t *npush)
{
	size_t offset = 0, np;

	ctdb_stringn_push(&in->name, buf+offset, &np);
	offset += np;

	ctdb_timeval_push(&in->begin, buf+offset, &np);
	offset += np;

	ctdb_timeval_push(&in->end, buf+offset, &np);
	offset += np;

	ctdb_int32_push(&in->result, buf+offset, &np);
	offset += np;

	ctdb_stringn_push(&in->output, buf+offset, &np);
	offset += np;

	*npush = offset;
}

static int ctdb_event_script_pull_elems(uint8_t *buf,
					size_t buflen,
					TALLOC_CTX *mem_ctx,
					struct ctdb_event_script *value,
					size_t *npull)
{
	size_t offset = 0, np;
	int ret;

	ret = ctdb_stringn_pull(buf+offset,
				buflen-offset,
				mem_ctx,
				&value->name,
				&np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	ret = ctdb_timeval_pull(buf+offset,
				buflen-offset,
				&value->begin,
				&np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	ret = ctdb_timeval_pull(buf+offset,
				buflen-offset,
				&value->end,
				&np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	ret = ctdb_int32_pull(buf+offset,
			      buflen-offset,
			      &value->result,
			      &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	ret = ctdb_stringn_pull(buf+offset,
				buflen-offset,
				mem_ctx,
				&value->output,
				&np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	*npull = offset;

	return 0;
}

#ifdef EVENT_PROTOCOL_TEST
static int ctdb_event_script_pull(uint8_t *buf,
				  size_t buflen,
				  TALLOC_CTX *mem_ctx,
				  struct ctdb_event_script **out,
				  size_t *npull)
{
	struct ctdb_event_script *value;
	int ret;

	value = talloc(mem_ctx, struct ctdb_event_script);
	if (value == NULL) {
		return ENOMEM;
	}

	ret = ctdb_event_script_pull_elems(buf, buflen, value, value, npull);
	if (ret != 0) {
		talloc_free(value);
		return ret;
	}

	*out = value;

	return 0;
}
#endif

static size_t ctdb_event_script_list_len(struct ctdb_event_script_list *in)
{
	size_t len;
	int i;

	len = ctdb_int32_len(&in->num_scripts);

	for (i=0; i<in->num_scripts; i++) {
		len += ctdb_event_script_len(&in->script[i]);
	}

	return len;
}

static void ctdb_event_script_list_push(struct ctdb_event_script_list *in,
					uint8_t *buf,
					size_t *npush)
{
	size_t offset = 0, np;
	int i;

	ctdb_int32_push(&in->num_scripts, buf+offset, &np);
	offset += np;

	for (i=0; i<in->num_scripts; i++) {
		ctdb_event_script_push(&in->script[i], buf+offset, &np);
		offset += np;
	}

	*npush = offset;
}

static int ctdb_event_script_list_pull(uint8_t *buf,
				       size_t buflen,
				       TALLOC_CTX *mem_ctx,
				       struct ctdb_event_script_list **out,
				       size_t *npull)
{
	struct ctdb_event_script_list *value = NULL;
	size_t offset = 0, np;
	int num_scripts;
	int ret, i;

	ret = ctdb_int32_pull(buf+offset, buflen-offset, &num_scripts, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	if (num_scripts < 0) {
		return EINVAL;
	}

	value = talloc_zero(mem_ctx, struct ctdb_event_script_list);
	if (value == NULL) {
		return ENOMEM;
	}

	value->num_scripts = num_scripts;
	if (num_scripts == 0) {
		goto done;
	}

	value->script = talloc_array(value, struct ctdb_event_script,
				     num_scripts);
	if (value->script == NULL) {
		ret = ENOMEM;
		goto fail;
	}

	for (i=0; i<num_scripts; i++) {
		ret = ctdb_event_script_pull_elems(buf+offset,
						   buflen-offset,
						   value,
						   &value->script[i],
						   &np);
		if (ret != 0) {
			goto fail;
		}
		offset += np;
	}

done:
	*out = value;
	*npull = offset;

	return 0;

fail:
	talloc_free(value);
	return ret;
}

static size_t ctdb_event_request_run_len(struct ctdb_event_request_run *in)
{
	return ctdb_stringn_len(&in->component) +
		ctdb_stringn_len(&in->event) +
		ctdb_stringn_len(&in->args) +
		ctdb_uint32_len(&in->timeout) +
		ctdb_uint32_len(&in->flags);
}

static void ctdb_event_request_run_push(struct ctdb_event_request_run *in,
					uint8_t *buf,
					size_t *npush)
{
	size_t offset = 0, np;

	ctdb_stringn_push(&in->component, buf+offset, &np);
	offset += np;

	ctdb_stringn_push(&in->event, buf+offset, &np);
	offset += np;

	ctdb_stringn_push(&in->args, buf+offset, &np);
	offset += np;

	ctdb_uint32_push(&in->timeout, buf+offset, &np);
	offset += np;

	ctdb_uint32_push(&in->flags, buf+offset, &np);
	offset += np;

	*npush = offset;
}

static int ctdb_event_request_run_pull(uint8_t *buf,
				       size_t buflen,
				       TALLOC_CTX *mem_ctx,
				       struct ctdb_event_request_run **out,
				       size_t *npull)
{
	struct ctdb_event_request_run *value;
	size_t offset = 0, np;
	int ret;

	value = talloc(mem_ctx, struct ctdb_event_request_run);
	if (value == NULL) {
		return ENOMEM;
	}

	ret = ctdb_stringn_pull(buf+offset,
				buflen-offset,
				value,
				&value->component,
				&np);
	if (ret != 0) {
		goto fail;
	}
	offset += np;

	ret = ctdb_stringn_pull(buf+offset,
				buflen-offset,
				value,
				&value->event,
				&np);
	if (ret != 0) {
		goto fail;
	}
	offset += np;

	ret = ctdb_stringn_pull(buf+offset,
				buflen-offset,
				value,
				&value->args,
				&np);
	if (ret != 0) {
		goto fail;
	}
	offset += np;

	ret = ctdb_uint32_pull(buf+offset,
			       buflen-offset,
			       &value->timeout,
			       &np);
	if (ret != 0) {
		goto fail;
	}
	offset += np;

	ret = ctdb_uint32_pull(buf+offset,
			       buflen-offset,
			       &value->flags,
			       &np);
	if (ret != 0) {
		goto fail;
	}
	offset += np;

	*out = value;
	*npull = offset;

	return 0;

fail:
	talloc_free(value);
	return ret;
}

static size_t ctdb_event_request_status_len(
				struct ctdb_event_request_status *in)
{
	return ctdb_stringn_len(&in->component) +
		ctdb_stringn_len(&in->event);
}

static void ctdb_event_request_status_push(
				struct ctdb_event_request_status *in,
				uint8_t *buf,
				size_t *npush)
{
	size_t offset = 0, np;

	ctdb_stringn_push(&in->component, buf+offset, &np);
	offset += np;

	ctdb_stringn_push(&in->event, buf+offset, &np);
	offset += np;

	*npush = offset;
}

static int ctdb_event_request_status_pull(
				uint8_t *buf,
				size_t buflen,
				TALLOC_CTX *mem_ctx,
				struct ctdb_event_request_status **out,
				size_t *npull)
{
	struct ctdb_event_request_status *value;
	size_t offset = 0, np;
	int ret;

	value = talloc(mem_ctx, struct ctdb_event_request_status);
	if (value == NULL) {
		return ENOMEM;
	}

	ret = ctdb_stringn_pull(buf+offset,
				buflen-offset,
				value,
				&value->component,
				&np);
	if (ret != 0) {
		goto fail;
	}
	offset += np;

	ret = ctdb_stringn_pull(buf+offset,
				buflen-offset,
				value,
				&value->event,
				&np);
	if (ret != 0) {
		goto fail;
	}
	offset += np;

	*out = value;
	*npull = offset;

	return 0;

fail:
	talloc_free(value);
	return ret;
}

static size_t ctdb_event_request_script_len(
				struct ctdb_event_request_script *in)
{
	return ctdb_stringn_len(&in->component) +
		ctdb_stringn_len(&in->script) +
		ctdb_event_script_action_len(in->action);
}

static void ctdb_event_request_script_push(
				struct ctdb_event_request_script *in,
				uint8_t *buf,
				size_t *npush)
{
	size_t offset = 0, np;

	ctdb_stringn_push(&in->component, buf+offset, &np);
	offset += np;

	ctdb_stringn_push(&in->script, buf+offset, &np);
	offset += np;

	ctdb_event_script_action_push(in->action, buf+offset, &np);
	offset += np;

	*npush = offset;
}

static int ctdb_event_request_script_pull(
				uint8_t *buf,
				size_t buflen,
				TALLOC_CTX *mem_ctx,
				struct ctdb_event_request_script **out,
				size_t *npull)
{
	struct ctdb_event_request_script *value;
	size_t offset = 0, np;
	int ret;

	value = talloc(mem_ctx, struct ctdb_event_request_script);
	if (value == NULL) {
		return ENOMEM;
	}

	ret = ctdb_stringn_pull(buf+offset,
				buflen-offset,
				value,
				&value->component,
				&np);
	if (ret != 0) {
		goto fail;
	}
	offset += np;

	ret = ctdb_stringn_pull(buf+offset,
				buflen-offset,
				value,
				&value->script,
				&np);
	if (ret != 0) {
		goto fail;
	}
	offset += np;

	ret = ctdb_event_script_action_pull(buf+offset,
					    buflen-offset,
					    &value->action,
					    &np);
	if (ret != 0) {
		goto fail;
	}
	offset += np;

	*out = value;
	*npull = offset;

	return 0;

fail:
	talloc_free(value);
	return ret;
}

static size_t ctdb_event_reply_status_len(
				struct ctdb_event_reply_status *in)
{
	return ctdb_int32_len(&in->summary) +
		ctdb_event_script_list_len(in->script_list);
}

static void ctdb_event_reply_status_push(
				struct ctdb_event_reply_status *in,
				uint8_t *buf,
				size_t *npush)
{
	size_t offset = 0, np;

	ctdb_int32_push(&in->summary, buf+offset, &np);
	offset += np;

	ctdb_event_script_list_push(in->script_list, buf+offset, &np);
	offset += np;

	*npush = offset;
}

static int ctdb_event_reply_status_pull(
				uint8_t *buf,
				size_t buflen,
				TALLOC_CTX *mem_ctx,
				struct ctdb_event_reply_status **out,
				size_t *npull)
{
	struct ctdb_event_reply_status *value;
	size_t offset = 0, np;
	int ret;

	value = talloc(mem_ctx, struct ctdb_event_reply_status);
	if (value == NULL) {
		return ENOMEM;
	}

	ret = ctdb_int32_pull(buf+offset, buflen-offset, &value->summary, &np);
	if (ret != 0) {
		goto fail;
	}
	offset += np;

	ret = ctdb_event_script_list_pull(buf+offset,
					  buflen-offset,
					  value,
					  &value->script_list,
					  &np);
	if (ret != 0) {
		goto fail;
	}
	offset += np;

	*out = value;
	*npull = offset;

	return 0;

fail:
	talloc_free(value);
	return ret;
}

static size_t ctdb_event_header_len(struct ctdb_event_header *in)
{
	return ctdb_uint32_len(&in->length) +
		ctdb_uint32_len(&in->version) +
		ctdb_uint32_len(&in->reqid);
}

static void ctdb_event_header_push(struct ctdb_event_header *in,
				   uint8_t *buf,
				   size_t *npush)
{
	size_t offset = 0, np;

	ctdb_uint32_push(&in->length, buf+offset, &np);
	offset += np;

	ctdb_uint32_push(&in->version, buf+offset, &np);
	offset += np;

	ctdb_uint32_push(&in->reqid, buf+offset, &np);
	offset += np;

	*npush = offset;
}

static int ctdb_event_header_pull(uint8_t *buf,
				  size_t buflen,
				  struct ctdb_event_header *value,
				  size_t *npull)
{
	size_t offset = 0, np;
	int ret;

	ret = ctdb_uint32_pull(buf+offset,
			       buflen-offset,
			       &value->length,
			       &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	ret = ctdb_uint32_pull(buf+offset,
			       buflen-offset,
			       &value->version,
			       &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	ret = ctdb_uint32_pull(buf+offset,
			       buflen-offset,
			       &value->reqid,
			       &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	*npull = offset;

	return 0;
}

int ctdb_event_header_extract(uint8_t *buf,
			      size_t buflen,
			      struct ctdb_event_header *value)
{
	size_t np;

	return ctdb_event_header_pull(buf, buflen, value, &np);
}

static size_t ctdb_event_request_data_len(struct ctdb_event_request *in)
{
	size_t len;

	len = ctdb_event_command_len(in->cmd);

	switch (in->cmd) {
	case CTDB_EVENT_CMD_RUN:
		len += ctdb_event_request_run_len(in->data.run);
		break;

	case CTDB_EVENT_CMD_STATUS:
		len += ctdb_event_request_status_len(in->data.status);
		break;

	case CTDB_EVENT_CMD_SCRIPT:
		len += ctdb_event_request_script_len(in->data.script);
		break;

	default:
		break;
	}

	return len;
}

static void ctdb_event_request_data_push(struct ctdb_event_request *in,
					 uint8_t *buf,
					 size_t *npush)
{
	size_t offset = 0, np;

	ctdb_event_command_push(in->cmd, buf+offset, &np);
	offset += np;

	switch (in->cmd) {
	case CTDB_EVENT_CMD_RUN:
		ctdb_event_request_run_push(in->data.run, buf+offset, &np);
		break;

	case CTDB_EVENT_CMD_STATUS:
		ctdb_event_request_status_push(in->data.status,
					       buf+offset,
					       &np);
		break;

	case CTDB_EVENT_CMD_SCRIPT:
		ctdb_event_request_script_push(in->data.script,
					       buf+offset,
					       &np);
		break;
	default:
		np = 0;
		break;
	}
	offset += np;

	*npush = offset;
}

static int ctdb_event_request_data_pull(uint8_t *buf,
					size_t buflen,
					TALLOC_CTX *mem_ctx,
					struct ctdb_event_request **out,
					size_t *npull)
{
	struct ctdb_event_request *value;
	size_t offset = 0, np;
	int ret;

	value = talloc(mem_ctx, struct ctdb_event_request);
	if (value == NULL) {
		return ENOMEM;
	}

	ret = ctdb_event_command_pull(buf+offset,
				      buflen-offset,
				      &value->cmd,
				      &np);
	if (ret != 0) {
		goto fail;
	}
	offset += np;

	switch (value->cmd) {
	case CTDB_EVENT_CMD_RUN:
		ret = ctdb_event_request_run_pull(buf+offset,
						  buflen-offset,
						  value,
						  &value->data.run,
						  &np);
		break;

	case CTDB_EVENT_CMD_STATUS:
		ret = ctdb_event_request_status_pull(buf+offset,
						     buflen-offset,
						     value,
						     &value->data.status,
						     &np);
		break;

	case CTDB_EVENT_CMD_SCRIPT:
		ret = ctdb_event_request_script_pull(buf+offset,
						     buflen-offset,
						     value,
						     &value->data.script,
						     &np);
		break;

	default:
		np = 0;
		break;
	}

	if (ret != 0) {
		goto fail;
	}
	offset += np;

	*out = value;
	*npull = offset;

	return 0;

fail:
	talloc_free(value);
	return ret;
}

static size_t ctdb_event_reply_data_len(struct ctdb_event_reply *in)
{
	size_t len;

	len = ctdb_event_command_len(in->cmd) +
		ctdb_int32_len(&in->result);

	if (in->result != 0) {
		goto done;
	}

	switch (in->cmd) {
	case CTDB_EVENT_CMD_STATUS:
		len += ctdb_event_reply_status_len(in->data.status);
		break;

	default:
		break;
	}

done:
	return len;
}

static void ctdb_event_reply_data_push(struct ctdb_event_reply *in,
				       uint8_t *buf,
				       size_t *npush)
{
	size_t offset = 0, np;

	ctdb_event_command_push(in->cmd, buf+offset, &np);
	offset += np;

	ctdb_int32_push(&in->result, buf+offset, &np);
	offset += np;

	if (in->result != 0) {
		goto done;
	}

	switch (in->cmd) {
	case CTDB_EVENT_CMD_STATUS:
		ctdb_event_reply_status_push(in->data.status, buf+offset, &np);
		break;

	default:
		np = 0;
		break;
	}
	offset += np;

done:
	*npush = offset;
}

static int ctdb_event_reply_data_pull(uint8_t *buf,
				      size_t buflen,
				      TALLOC_CTX *mem_ctx,
				      struct ctdb_event_reply **out,
				      size_t *npull)
{
	struct ctdb_event_reply *value;
	size_t offset = 0, np;
	int ret;

	value = talloc(mem_ctx, struct ctdb_event_reply);
	if (value == NULL) {
		return ENOMEM;
	}

	ret = ctdb_event_command_pull(buf+offset,
				      buflen-offset,
				      &value->cmd,
				      &np);
	if (ret != 0) {
		goto fail;
	}
	offset += np;

	ret = ctdb_int32_pull(buf+offset, buflen-offset, &value->result, &np);
	if (ret != 0) {
		goto fail;
	}
	offset += np;

	if (value->result != 0) {
		goto done;
	}

	switch (value->cmd) {
	case CTDB_EVENT_CMD_STATUS:
		ret = ctdb_event_reply_status_pull(buf+offset,
						   buflen-offset,
						   value,
						   &value->data.status,
						   &np);
		break;

	default:
		np = 0;
		break;
	}

	if (ret != 0) {
		goto fail;
	}
	offset += np;

done:
	*out = value;
	*npull = offset;

	return 0;

fail:
	talloc_free(value);
	return ret;
}

size_t ctdb_event_request_len(struct ctdb_event_header *h,
			      struct ctdb_event_request *in)
{
	return ctdb_event_header_len(h) +
		ctdb_event_request_data_len(in);
}

int ctdb_event_request_push(struct ctdb_event_header *h,
			    struct ctdb_event_request *in,
			    uint8_t *buf,
			    size_t *buflen)
{
	size_t len, offset = 0, np;

	len = ctdb_event_request_len(h, in);
	if (*buflen < len) {
		*buflen = len;
		return EMSGSIZE;
	}

	h->length = *buflen;

	ctdb_event_header_push(h, buf+offset, &np);
	offset += np;

	ctdb_event_request_data_push(in, buf+offset, &np);
	offset += np;

	if (offset > *buflen) {
		return EMSGSIZE;
	}

	return 0;
}

int ctdb_event_request_pull(uint8_t *buf,
			    size_t buflen,
			    struct ctdb_event_header *h,
			    TALLOC_CTX *mem_ctx,
			    struct ctdb_event_request **out)
{
	size_t offset = 0, np;
	int ret;

	ret = ctdb_event_header_pull(buf+offset, buflen-offset, h, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	ret = ctdb_event_request_data_pull(buf+offset,
					   buflen-offset,
					   mem_ctx,
					   out,
					   &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	if (offset > buflen) {
		return EMSGSIZE;
	}

	return 0;
}

size_t ctdb_event_reply_len(struct ctdb_event_header *h,
			    struct ctdb_event_reply *in)
{
	return ctdb_event_header_len(h) +
		ctdb_event_reply_data_len(in);
}

int ctdb_event_reply_push(struct ctdb_event_header *h,
			  struct ctdb_event_reply *in,
			  uint8_t *buf,
			  size_t *buflen)
{
	size_t len, offset = 0, np;

	len = ctdb_event_reply_len(h, in);
	if (*buflen < len) {
		*buflen = len;
		return EMSGSIZE;
	}

	h->length = *buflen;

	ctdb_event_header_push(h, buf+offset, &np);
	offset += np;

	ctdb_event_reply_data_push(in, buf+offset, &np);
	offset += np;

	if (offset > *buflen) {
		return EMSGSIZE;
	}

	return 0;
}

int ctdb_event_reply_pull(uint8_t *buf,
			  size_t buflen,
			  struct ctdb_event_header *h,
			  TALLOC_CTX *mem_ctx,
			  struct ctdb_event_reply **out)
{
	size_t offset = 0, np;
	int ret;

	ret = ctdb_event_header_pull(buf+offset, buflen-offset, h, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	ret = ctdb_event_reply_data_pull(buf+offset,
					 buflen-offset,
					 mem_ctx,
					 out,
					 &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	if (offset > buflen) {
		return EMSGSIZE;
	}

	return 0;
}
