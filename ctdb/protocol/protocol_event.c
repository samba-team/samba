/*
   CTDB eventd protocol marshalling

   Copyright (C) Amitay Isaacs  2016

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
#include "system/network.h"

#include <talloc.h>

#include "protocol.h"
#include "protocol_private.h"
#include "protocol_api.h"

static size_t ctdb_event_len(enum ctdb_event in)
{
	uint32_t u32 = in;

	return ctdb_uint32_len(&u32);
}

static void ctdb_event_push(enum ctdb_event in, uint8_t *buf, size_t *npush)
{
	size_t np;
	uint32_t u32 = in;

	ctdb_uint32_push(&u32, buf, &np);

	*npush = np;
}

static int ctdb_event_pull(uint8_t *buf, size_t buflen,
			   TALLOC_CTX *mem_ctx, enum ctdb_event *out,
			   size_t *npull)
{
	uint32_t uint32_value;
	enum ctdb_event value;
	size_t np;
	int ret;

	ret = ctdb_uint32_pull(buf, buflen, &uint32_value, &np);
	if (ret != 0) {
		return ret;
	}

	switch (uint32_value) {
	case 0:
		value = CTDB_EVENT_INIT;
		break;

	case 1:
		value = CTDB_EVENT_SETUP;
		break;

	case 2:
		value = CTDB_EVENT_STARTUP;
		break;

	case 3:
		value = CTDB_EVENT_START_RECOVERY;
		break;

	case 4:
		value = CTDB_EVENT_RECOVERED;
		break;

	case 5:
		value = CTDB_EVENT_TAKE_IP;
		break;

	case 6:
		value = CTDB_EVENT_RELEASE_IP;
		break;

	case 7:
		value = CTDB_EVENT_STOPPED;
		break;

	case 8:
		value = CTDB_EVENT_MONITOR;
		break;

	case 9:
		value = CTDB_EVENT_STATUS;
		break;

	case 10:
		value = CTDB_EVENT_SHUTDOWN;
		break;

	case 11:
		value = CTDB_EVENT_RELOAD;
		break;

	case 12:
		value = CTDB_EVENT_UPDATE_IP;
		break;

	case 13:
		value = CTDB_EVENT_IPREALLOCATED;
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

static void ctdb_event_command_push(enum ctdb_event_command in, uint8_t *buf,
				    size_t *npush)
{
	size_t np;
	uint32_t u32 = in;

	ctdb_uint32_push(&u32, buf, &np);

	*npush = np;
}

static int ctdb_event_command_pull(uint8_t *buf, size_t buflen,
				   TALLOC_CTX *mem_ctx,
				   enum ctdb_event_command *out,
				   size_t *npull)
{
	uint32_t uint32_value;
	enum ctdb_event_command value;
	size_t np;
	int ret;

	ret = ctdb_uint32_pull(buf, buflen, &uint32_value, &np);
	if (ret != 0) {
		return ret;
	}

	switch (uint32_value) {
	case 1:
		value = CTDB_EVENT_COMMAND_RUN;
		break;

	case 2:
		value = CTDB_EVENT_COMMAND_STATUS;
		break;

	case 3:
		value = CTDB_EVENT_COMMAND_SCRIPT_LIST;
		break;

	case 4:
		value = CTDB_EVENT_COMMAND_SCRIPT_ENABLE;
		break;

	case 5:
		value = CTDB_EVENT_COMMAND_SCRIPT_DISABLE;
		break;

	default:
		return EINVAL;
	}

	*out = value;
	*npull = np;
	return 0;
}

static size_t ctdb_event_status_state_len(enum ctdb_event_status_state in)
{
	uint32_t u32 = in;

	return ctdb_uint32_len(&u32);
}

static void ctdb_event_status_state_push(enum ctdb_event_status_state in,
					 uint8_t *buf, size_t *npush)
{
	size_t np;
	uint32_t u32 = in;

	ctdb_uint32_push(&u32, buf, &np);

	*npush = np;
}

static int ctdb_event_status_state_pull(uint8_t *buf, size_t buflen,
					TALLOC_CTX *mem_ctx,
					enum ctdb_event_status_state *out,
					size_t *npull)
{
	uint32_t uint32_value;
	enum ctdb_event_status_state value;
	size_t np;
	int ret;

	ret = ctdb_uint32_pull(buf, buflen, &uint32_value, &np);
	if (ret != 0) {
		return ret;
	}

	switch (uint32_value) {
	case 1:
		value = CTDB_EVENT_LAST_RUN;
		break;

	case 2:
		value = CTDB_EVENT_LAST_PASS;
		break;

	case 3:
		value = CTDB_EVENT_LAST_FAIL;
		break;

	default:
		return EINVAL;
	}

	*out = value;
	*npull = np;
	return 0;
}

static size_t ctdb_event_request_run_len(struct ctdb_event_request_run *in)
{
	return ctdb_event_len(in->event) +
	       ctdb_uint32_len(&in->timeout) +
	       ctdb_stringn_len(&in->arg_str);
}

static void ctdb_event_request_run_push(struct ctdb_event_request_run *in,
					uint8_t *buf, size_t *npush)
{
	size_t offset = 0, np;

	ctdb_event_push(in->event, buf, &np);
	offset += np;

	ctdb_uint32_push(&in->timeout, buf+offset, &np);
	offset += np;

	ctdb_stringn_push(&in->arg_str, buf+offset, &np);
	offset += np;

	*npush = offset;
}

static int ctdb_event_request_run_pull(uint8_t *buf, size_t buflen,
				       TALLOC_CTX *mem_ctx,
				       struct ctdb_event_request_run **out,
				       size_t *npull)
{
	struct ctdb_event_request_run *rdata;
	size_t offset = 0, np;
	int ret;

	rdata = talloc(mem_ctx, struct ctdb_event_request_run);
	if (rdata == NULL) {
		return ENOMEM;
	}

	ret = ctdb_event_pull(buf, buflen, rdata, &rdata->event, &np);
	if (ret != 0) {
		goto fail;
	}
	offset += np;

	ret = ctdb_uint32_pull(buf+offset, buflen-offset, &rdata->timeout,
			       &np);
	if (ret != 0) {
		goto fail;
	}
	offset += np;

	ret = ctdb_stringn_pull(buf+offset, buflen-offset,
				rdata, &rdata->arg_str, &np);
	if (ret != 0) {
		goto fail;
	}
	offset += np;

	*out = rdata;
	*npull = offset;
	return 0;

fail:
	talloc_free(rdata);
	return ret;
}

static size_t ctdb_event_request_status_len(
				struct ctdb_event_request_status *in)
{
	return ctdb_event_len(in->event) +
	       ctdb_event_status_state_len(in->state);
}

static void ctdb_event_request_status_push(
				struct ctdb_event_request_status *in,
				uint8_t *buf, size_t *npush)
{
	size_t offset = 0, np;

	ctdb_event_push(in->event, buf, &np);
	offset += np;

	ctdb_event_status_state_push(in->state, buf+offset, &np);
	offset += np;

	*npush = offset;
}

static int ctdb_event_request_status_pull(
				uint8_t *buf, size_t buflen,
				TALLOC_CTX *mem_ctx,
				struct ctdb_event_request_status **out,
				size_t *npull)
{
	struct ctdb_event_request_status *rdata;
	size_t offset = 0, np;
	int ret;

	rdata = talloc(mem_ctx, struct ctdb_event_request_status);
	if (rdata == NULL) {
		return ENOMEM;
	}

	ret = ctdb_event_pull(buf, buflen, rdata, &rdata->event, &np);
	if (ret != 0) {
		talloc_free(rdata);
		return ret;
	}
	offset += np;

	ret = ctdb_event_status_state_pull(buf+offset, buflen-offset,
					   rdata, &rdata->state, &np);
	if (ret != 0) {
		talloc_free(rdata);
		return ret;
	}
	offset += np;

	*out = rdata;
	*npull = offset;
	return 0;
}

static size_t ctdb_event_request_script_enable_len(
				struct ctdb_event_request_script_enable *in)
{
	return ctdb_stringn_len(&in->script_name);
}

static void ctdb_event_request_script_enable_push(
				struct ctdb_event_request_script_enable *in,
				uint8_t *buf, size_t *npush)
{
	size_t np;

	ctdb_stringn_push(&in->script_name, buf, &np);

	*npush = np;
}

static int ctdb_event_request_script_enable_pull(
				uint8_t *buf, size_t buflen,
				TALLOC_CTX *mem_ctx,
				struct ctdb_event_request_script_enable **out,
				size_t *npull)
{
	struct ctdb_event_request_script_enable *rdata;
	size_t np;
	int ret;

	rdata = talloc(mem_ctx, struct ctdb_event_request_script_enable);
	if (rdata == NULL) {
		return ENOMEM;
	}

	ret = ctdb_stringn_pull(buf, buflen, rdata, &rdata->script_name, &np);
	if (ret != 0) {
		talloc_free(rdata);
		return ret;
	}

	*out = rdata;
	*npull = np;
	return 0;
}

static size_t ctdb_event_request_script_disable_len(
				struct ctdb_event_request_script_disable *in)
{
	return ctdb_stringn_len(&in->script_name);
}

static void ctdb_event_request_script_disable_push(
				struct ctdb_event_request_script_disable *in,
				uint8_t *buf, size_t *npush)
{
	size_t np;

	ctdb_stringn_push(&in->script_name, buf, &np);

	*npush = np;
}

static int ctdb_event_request_script_disable_pull(
				uint8_t *buf, size_t buflen,
				TALLOC_CTX *mem_ctx,
				struct ctdb_event_request_script_disable **out,
				size_t *npull)
{
	struct ctdb_event_request_script_disable *rdata;
	size_t np;
	int ret;

	rdata = talloc(mem_ctx, struct ctdb_event_request_script_disable);
	if (rdata == NULL) {
		return ENOMEM;
	}

	ret = ctdb_stringn_pull(buf, buflen, rdata, &rdata->script_name, &np);
	if (ret != 0) {
		talloc_free(rdata);
		return ret;
	}

	*out = rdata;
	*npull = np;
	return 0;
}

static size_t ctdb_event_request_data_len(struct ctdb_event_request_data *in)
{
	size_t len = 0;

	len += ctdb_event_command_len(in->command);

	switch(in->command) {
	case CTDB_EVENT_COMMAND_RUN:
		len += ctdb_event_request_run_len(in->data.run);
		break;

	case CTDB_EVENT_COMMAND_STATUS:
		len += ctdb_event_request_status_len(in->data.status);
		break;

	case CTDB_EVENT_COMMAND_SCRIPT_LIST:
		break;

	case CTDB_EVENT_COMMAND_SCRIPT_ENABLE:
		len += ctdb_event_request_script_enable_len(
						in->data.script_enable);
		break;

	case CTDB_EVENT_COMMAND_SCRIPT_DISABLE:
		len += ctdb_event_request_script_disable_len(
						in->data.script_disable);
		break;
	}

	return len;
}

static void ctdb_event_request_data_push(struct ctdb_event_request_data *in,
					 uint8_t *buf, size_t *npush)
{
	size_t offset = 0, np;

	ctdb_event_command_push(in->command, buf, &np);
	offset += np;

	np = 0;
	switch (in->command) {
	case CTDB_EVENT_COMMAND_RUN:
		ctdb_event_request_run_push(in->data.run, buf+offset, &np);
		break;

	case CTDB_EVENT_COMMAND_STATUS:
		ctdb_event_request_status_push(in->data.status, buf+offset,
					       &np);
		break;

	case CTDB_EVENT_COMMAND_SCRIPT_LIST:
		break;

	case CTDB_EVENT_COMMAND_SCRIPT_ENABLE:
		ctdb_event_request_script_enable_push(
						in->data.script_enable,
						buf+offset, &np);
		break;

	case CTDB_EVENT_COMMAND_SCRIPT_DISABLE:
		ctdb_event_request_script_disable_push(
						in->data.script_disable,
						buf+offset, &np);
		break;
	}
	offset += np;

	*npush = offset;
}

static int ctdb_event_request_data_pull(uint8_t *buf, size_t buflen,
					TALLOC_CTX *mem_ctx,
					struct ctdb_event_request_data *out,
					size_t *npull)
{
	size_t offset = 0, np;
	int ret;

	ret = ctdb_event_command_pull(buf, buflen, mem_ctx, &out->command,
				      &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	np = 0;
	switch (out->command) {
	case CTDB_EVENT_COMMAND_RUN:
		ret = ctdb_event_request_run_pull(buf+offset, buflen-offset,
						  mem_ctx, &out->data.run,
						  &np);
		break;

	case CTDB_EVENT_COMMAND_STATUS:
		ret = ctdb_event_request_status_pull(
						buf+offset, buflen-offset,
						mem_ctx, &out->data.status,
						&np);
		break;

	case CTDB_EVENT_COMMAND_SCRIPT_LIST:
		ret = 0;
		break;

	case CTDB_EVENT_COMMAND_SCRIPT_ENABLE:
		ret = ctdb_event_request_script_enable_pull(
						buf+offset, buflen-offset,
						mem_ctx,
						&out->data.script_enable,
						&np);
		break;

	case CTDB_EVENT_COMMAND_SCRIPT_DISABLE:
		ret = ctdb_event_request_script_disable_pull(
						buf+offset, buflen-offset,
						mem_ctx,
						&out->data.script_disable,
						&np);
		break;
	}

	if (ret != 0) {
		return ret;
	}

	offset += np;

	*npull = offset;
	return 0;
}

static size_t ctdb_event_reply_status_len(struct ctdb_event_reply_status *in)
{
	return ctdb_int32_len(&in->status) +
	       ctdb_script_list_len(in->script_list);
}

static void ctdb_event_reply_status_push(struct ctdb_event_reply_status *in,
					 uint8_t *buf, size_t *npush)
{
	size_t offset = 0, np;

	ctdb_int32_push(&in->status, buf, &np);
	offset += np;

	ctdb_script_list_push(in->script_list, buf+offset, &np);
	offset += np;

	*npush = offset;
}

static int ctdb_event_reply_status_pull(uint8_t *buf, size_t buflen,
					TALLOC_CTX *mem_ctx,
					struct ctdb_event_reply_status **out,
					size_t *npull)
{
	struct ctdb_event_reply_status *rdata;
	size_t offset = 0, np;
	int ret;

	rdata = talloc(mem_ctx, struct ctdb_event_reply_status);
	if (rdata == NULL) {
		return ENOMEM;
	}

	ret = ctdb_int32_pull(buf, buflen, &rdata->status, &np);
	if (ret != 0) {
		talloc_free(rdata);
		return ret;
	}
	offset += np;

	ret = ctdb_script_list_pull(buf+offset, buflen-offset,
				    rdata, &rdata->script_list, &np);
	if (ret != 0) {
		talloc_free(rdata);
		return ret;
	}
	offset += np;

	*out = rdata;
	*npull = offset;
	return 0;
}

static size_t ctdb_event_reply_script_list_len(
				struct ctdb_event_reply_script_list *in)
{
	return ctdb_script_list_len(in->script_list);
}

static void ctdb_event_reply_script_list_push(
				struct ctdb_event_reply_script_list *in,
				uint8_t *buf, size_t *npush)
{
	size_t np;

	ctdb_script_list_push(in->script_list, buf, &np);

	*npush = np;
}

static int ctdb_event_reply_script_list_pull(
				uint8_t *buf, size_t buflen,
				TALLOC_CTX *mem_ctx,
				struct ctdb_event_reply_script_list **out,
				size_t *npull)
{
	struct ctdb_event_reply_script_list *rdata;
	size_t np;
	int ret;

	rdata = talloc(mem_ctx, struct ctdb_event_reply_script_list);
	if (rdata == NULL) {
		return ENOMEM;
	}

	ret = ctdb_script_list_pull(buf, buflen, rdata, &rdata->script_list,
				    &np);
	if (ret != 0) {
		talloc_free(rdata);
		return ret;
	}

	*out = rdata;
	*npull = np;
	return 0;
}

static size_t ctdb_event_reply_data_len(struct ctdb_event_reply_data *in)
{
	size_t len = 0;

	len += ctdb_event_command_len(in->command);
	len += ctdb_int32_len(&in->result);

	switch (in->command) {
	case CTDB_EVENT_COMMAND_RUN:
		break;

	case CTDB_EVENT_COMMAND_STATUS:
		len += ctdb_event_reply_status_len(in->data.status);
		break;

	case CTDB_EVENT_COMMAND_SCRIPT_LIST:
		len += ctdb_event_reply_script_list_len(in->data.script_list);
		break;

	case CTDB_EVENT_COMMAND_SCRIPT_ENABLE:
		break;

	case CTDB_EVENT_COMMAND_SCRIPT_DISABLE:
		break;
	}

	return len;
}

static void ctdb_event_reply_data_push(struct ctdb_event_reply_data *in,
				       uint8_t *buf, size_t *npush)
{
	size_t offset = 0, np;

	ctdb_event_command_push(in->command, buf, &np);
	offset += np;

	ctdb_int32_push(&in->result, buf+offset, &np);
	offset += np;

	np = 0;
	switch (in->command) {
	case CTDB_EVENT_COMMAND_RUN:
		break;

	case CTDB_EVENT_COMMAND_STATUS:
		ctdb_event_reply_status_push(in->data.status, buf+offset, &np);
		break;

	case CTDB_EVENT_COMMAND_SCRIPT_LIST:
		ctdb_event_reply_script_list_push(in->data.script_list,
						  buf+offset, &np);
		break;

	case CTDB_EVENT_COMMAND_SCRIPT_ENABLE:
		break;

	case CTDB_EVENT_COMMAND_SCRIPT_DISABLE:
		break;
	}
	offset += np;

	*npush = offset;
}

static int ctdb_event_reply_data_pull(uint8_t *buf, size_t buflen,
				      TALLOC_CTX *mem_ctx,
				      struct ctdb_event_reply_data *out,
				      size_t *npull)
{
	size_t offset = 0, np;
	int ret;

	ret = ctdb_event_command_pull(buf, buflen, mem_ctx, &out->command,
				      &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	ret = ctdb_int32_pull(buf+offset, buflen-offset, &out->result, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	np = 0;
	switch (out->command) {
	case CTDB_EVENT_COMMAND_RUN:
		break;

	case CTDB_EVENT_COMMAND_STATUS:
		ret = ctdb_event_reply_status_pull(
					buf+offset, buflen-offset,
					mem_ctx, &out->data.status, &np);
		break;

	case CTDB_EVENT_COMMAND_SCRIPT_LIST:
		ret = ctdb_event_reply_script_list_pull(
					buf+offset, buflen-offset,
					mem_ctx, &out->data.script_list, &np);
		break;

	case CTDB_EVENT_COMMAND_SCRIPT_ENABLE:
		break;

	case CTDB_EVENT_COMMAND_SCRIPT_DISABLE:
		break;
	}

	if (ret != 0) {
		return ret;
	}

	offset += np;

	*npull = offset;
	return 0;
}

size_t ctdb_event_request_len(struct ctdb_event_request *in)
{
	return sock_packet_header_len(&in->header) +
	       ctdb_event_request_data_len(&in->rdata);
}

int ctdb_event_request_push(struct ctdb_event_request *in,
			    uint8_t *buf, size_t *buflen)
{
	size_t len, offset = 0, np;

	len = ctdb_event_request_len(in);
	if (*buflen < len) {
		*buflen = len;
		return EMSGSIZE;
	}

	in->header.length = *buflen;

	sock_packet_header_push(&in->header, buf, &np);
	offset += np;

	ctdb_event_request_data_push(&in->rdata, buf+offset, &np);
	offset += np;

	if (offset > *buflen) {
		return EMSGSIZE;
	}

	return 0;
}

int ctdb_event_request_pull(uint8_t *buf, size_t buflen,
			    TALLOC_CTX *mem_ctx,
			    struct ctdb_event_request *out)
{
	size_t offset = 0, np;
	int ret;

	ret = sock_packet_header_pull(buf, buflen, &out->header, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	ret = ctdb_event_request_data_pull(buf+offset, buflen-offset,
					   mem_ctx, &out->rdata, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	if (offset > buflen) {
		return EMSGSIZE;
	}

	return 0;
}

size_t ctdb_event_reply_len(struct ctdb_event_reply *in)
{
	return sock_packet_header_len(&in->header) +
	       ctdb_event_reply_data_len(&in->rdata);
}

int ctdb_event_reply_push(struct ctdb_event_reply *in,
			  uint8_t *buf, size_t *buflen)
{
	size_t len, offset = 0, np;

	len = ctdb_event_reply_len(in);
	if (*buflen < len) {
		*buflen = len;
		return EMSGSIZE;
	}

	in->header.length = *buflen;

	sock_packet_header_push(&in->header, buf, &np);
	offset += np;

	ctdb_event_reply_data_push(&in->rdata, buf+offset, &np);
	offset += np;

	if (offset > *buflen) {
		return EMSGSIZE;
	}

	return 0;
}

int ctdb_event_reply_pull(uint8_t *buf, size_t buflen,
			  TALLOC_CTX *mem_ctx,
			  struct ctdb_event_reply *out)
{
	size_t offset = 0, np;
	int ret;

	ret = sock_packet_header_pull(buf, buflen, &out->header, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	ret = ctdb_event_reply_data_pull(buf+offset, buflen-offset,
					 mem_ctx, &out->rdata, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	if (offset > buflen) {
		return EMSGSIZE;
	}

	return 0;
}
