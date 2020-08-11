/*
   Unix SMB/CIFS implementation.
   Infrastructure for async ldap client requests
   Copyright (C) Volker Lendecke 2009

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

#include "replace.h"
#include "tldap.h"
#include "system/network.h"
#include "system/locale.h"
#include "lib/util/talloc_stack.h"
#include "lib/util/samba_util.h"
#include "lib/util_tsock.h"
#include "../lib/util/asn1.h"
#include "../lib/tsocket/tsocket.h"
#include "../lib/util/tevent_unix.h"

static TLDAPRC tldap_simple_recv(struct tevent_req *req);
static bool tldap_msg_set_pending(struct tevent_req *req);

#define TEVENT_TLDAP_RC_MAGIC (0x87bcd26e)

bool tevent_req_ldap_error(struct tevent_req *req, TLDAPRC rc)
{
	uint64_t err;

	if (TLDAP_RC_IS_SUCCESS(rc)) {
		return false;
	}

	err = TEVENT_TLDAP_RC_MAGIC;
	err <<= 32;
	err |= TLDAP_RC_V(rc);

	return tevent_req_error(req, err);
}

bool tevent_req_is_ldap_error(struct tevent_req *req, TLDAPRC *perr)
{
	enum tevent_req_state state;
	uint64_t err;

	if (!tevent_req_is_error(req, &state, &err)) {
		return false;
	}
	switch (state) {
	case TEVENT_REQ_TIMED_OUT:
		*perr = TLDAP_TIMEOUT;
		break;
	case TEVENT_REQ_NO_MEMORY:
		*perr = TLDAP_NO_MEMORY;
		break;
	case TEVENT_REQ_USER_ERROR:
		if ((err >> 32) != TEVENT_TLDAP_RC_MAGIC) {
			abort();
		}
		*perr = TLDAP_RC(err & 0xffffffff);
		break;
	default:
		*perr = TLDAP_OPERATIONS_ERROR;
		break;
	}
	return true;
}

struct tldap_ctx_attribute {
	char *name;
	void *ptr;
};

struct tldap_context {
	int ld_version;
	struct tstream_context *conn;
	int msgid;
	struct tevent_queue *outgoing;
	struct tevent_req **pending;
	struct tevent_req *read_req;

	/* For the sync wrappers we need something like get_last_error... */
	struct tldap_message *last_msg;

	/* debug */
	void (*log_fn)(void *context, enum tldap_debug_level level,
		       const char *fmt, va_list ap);
	void *log_private;

	struct tldap_ctx_attribute *ctx_attrs;
};

struct tldap_message {
	struct asn1_data *data;
	uint8_t *inbuf;
	int type;
	int id;

	/* RESULT_ENTRY */
	char *dn;
	struct tldap_attribute *attribs;

	/* Error data sent by the server */
	TLDAPRC lderr;
	char *res_matcheddn;
	char *res_diagnosticmessage;
	char *res_referral;
	DATA_BLOB res_serverSaslCreds;
	struct tldap_control *res_sctrls;

	/* Controls sent by the server */
	struct tldap_control *ctrls;
};

void tldap_set_debug(struct tldap_context *ld,
		     void (*log_fn)(void *log_private,
				    enum tldap_debug_level level,
				    const char *fmt,
				    va_list ap) PRINTF_ATTRIBUTE(3,0),
		     void *log_private)
{
	ld->log_fn = log_fn;
	ld->log_private = log_private;
}

static void tldap_debug(
	struct tldap_context *ld,
	enum tldap_debug_level level,
	const char *fmt, ...) PRINTF_ATTRIBUTE(3,4);

static void tldap_debug(struct tldap_context *ld,
			 enum tldap_debug_level level,
			 const char *fmt, ...)
{
	va_list ap;
	if (!ld) {
		return;
	}
	if (ld->log_fn == NULL) {
		return;
	}
	va_start(ap, fmt);
	ld->log_fn(ld->log_private, level, fmt, ap);
	va_end(ap);
}

static int tldap_next_msgid(struct tldap_context *ld)
{
	int result;

	result = ld->msgid++;
	if (ld->msgid == 2147483647) {
		ld->msgid = 1;
	}
	return result;
}

struct tldap_context *tldap_context_create(TALLOC_CTX *mem_ctx, int fd)
{
	struct tldap_context *ctx;
	int ret;

	ctx = talloc_zero(mem_ctx, struct tldap_context);
	if (ctx == NULL) {
		return NULL;
	}
	ret = tstream_bsd_existing_socket(ctx, fd, &ctx->conn);
	if (ret == -1) {
		TALLOC_FREE(ctx);
		return NULL;
	}
	ctx->msgid = 1;
	ctx->ld_version = 3;
	ctx->outgoing = tevent_queue_create(ctx, "tldap_outgoing");
	if (ctx->outgoing == NULL) {
		TALLOC_FREE(ctx);
		return NULL;
	}
	return ctx;
}

bool tldap_connection_ok(struct tldap_context *ld)
{
	int ret;

	if (ld == NULL) {
		return false;
	}

	if (ld->conn == NULL) {
		return false;
	}

	ret = tstream_pending_bytes(ld->conn);
	if (ret == -1) {
		return false;
	}

	return true;
}

static size_t tldap_pending_reqs(struct tldap_context *ld)
{
	return talloc_array_length(ld->pending);
}

struct tstream_context *tldap_get_tstream(struct tldap_context *ld)
{
	return ld->conn;
}

void tldap_set_tstream(struct tldap_context *ld,
		       struct tstream_context *stream)
{
	ld->conn = stream;
}

static struct tldap_ctx_attribute *tldap_context_findattr(
	struct tldap_context *ld, const char *name)
{
	size_t i, num_attrs;

	num_attrs = talloc_array_length(ld->ctx_attrs);

	for (i=0; i<num_attrs; i++) {
		if (strcmp(ld->ctx_attrs[i].name, name) == 0) {
			return &ld->ctx_attrs[i];
		}
	}
	return NULL;
}

bool tldap_context_setattr(struct tldap_context *ld,
			   const char *name, const void *_pptr)
{
	struct tldap_ctx_attribute *tmp, *attr;
	char *tmpname;
	int num_attrs;
	void **pptr = (void **)discard_const_p(void,_pptr);

	attr = tldap_context_findattr(ld, name);
	if (attr != NULL) {
		/*
		 * We don't actually delete attrs, we don't expect tons of
		 * attributes being shuffled around.
		 */
		TALLOC_FREE(attr->ptr);
		if (*pptr != NULL) {
			attr->ptr = talloc_move(ld->ctx_attrs, pptr);
			*pptr = NULL;
		}
		return true;
	}

	tmpname = talloc_strdup(ld, name);
	if (tmpname == NULL) {
		return false;
	}

	num_attrs = talloc_array_length(ld->ctx_attrs);

	tmp = talloc_realloc(ld, ld->ctx_attrs, struct tldap_ctx_attribute,
			     num_attrs+1);
	if (tmp == NULL) {
		TALLOC_FREE(tmpname);
		return false;
	}
	tmp[num_attrs].name = talloc_move(tmp, &tmpname);
	if (*pptr != NULL) {
		tmp[num_attrs].ptr = talloc_move(tmp, pptr);
	} else {
		tmp[num_attrs].ptr = NULL;
	}
	*pptr = NULL;
	ld->ctx_attrs = tmp;
	return true;
}

void *tldap_context_getattr(struct tldap_context *ld, const char *name)
{
	struct tldap_ctx_attribute *attr = tldap_context_findattr(ld, name);

	if (attr == NULL) {
		return NULL;
	}
	return attr->ptr;
}

struct read_ldap_state {
	uint8_t *buf;
	bool done;
};

static ssize_t read_ldap_more(uint8_t *buf, size_t buflen, void *private_data);
static void read_ldap_done(struct tevent_req *subreq);

static struct tevent_req *read_ldap_send(TALLOC_CTX *mem_ctx,
					 struct tevent_context *ev,
					 struct tstream_context *conn)
{
	struct tevent_req *req, *subreq;
	struct read_ldap_state *state;

	req = tevent_req_create(mem_ctx, &state, struct read_ldap_state);
	if (req == NULL) {
		return NULL;
	}
	state->done = false;

	subreq = tstream_read_packet_send(state, ev, conn, 2, read_ldap_more,
					  state);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, read_ldap_done, req);
	return req;
}

static ssize_t read_ldap_more(uint8_t *buf, size_t buflen, void *private_data)
{
	struct read_ldap_state *state = talloc_get_type_abort(
		private_data, struct read_ldap_state);
	size_t len;
	int i, lensize;

	if (state->done) {
		/* We've been here, we're done */
		return 0;
	}

	/*
	 * From ldap.h: LDAP_TAG_MESSAGE is 0x30
	 */
	if (buf[0] != 0x30) {
		return -1;
	}

	len = buf[1];
	if ((len & 0x80) == 0) {
		state->done = true;
		return len;
	}

	lensize = (len & 0x7f);
	len = 0;

	if (buflen == 2) {
		/* Please get us the full length */
		return lensize;
	}
	if (buflen > 2 + lensize) {
		state->done = true;
		return 0;
	}
	if (buflen != 2 + lensize) {
		return -1;
	}

	for (i=0; i<lensize; i++) {
		len = (len << 8) | buf[2+i];
	}
	return len;
}

static void read_ldap_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct read_ldap_state *state = tevent_req_data(
		req, struct read_ldap_state);
	ssize_t nread;
	int err;

	nread = tstream_read_packet_recv(subreq, state, &state->buf, &err);
	TALLOC_FREE(subreq);
	if (nread == -1) {
		tevent_req_error(req, err);
		return;
	}
	tevent_req_done(req);
}

static ssize_t read_ldap_recv(struct tevent_req *req, TALLOC_CTX *mem_ctx,
			      uint8_t **pbuf, int *perrno)
{
	struct read_ldap_state *state = tevent_req_data(
		req, struct read_ldap_state);

	if (tevent_req_is_unix_error(req, perrno)) {
		return -1;
	}
	*pbuf = talloc_move(mem_ctx, &state->buf);
	return talloc_get_size(*pbuf);
}

struct tldap_msg_state {
	struct tldap_context *ld;
	struct tevent_context *ev;
	int id;
	struct iovec iov;

	struct asn1_data *data;
	uint8_t *inbuf;
};

static bool tldap_push_controls(struct asn1_data *data,
				struct tldap_control *sctrls,
				int num_sctrls)
{
	int i;

	if ((sctrls == NULL) || (num_sctrls == 0)) {
		return true;
	}

	if (!asn1_push_tag(data, ASN1_CONTEXT(0))) return false;

	for (i=0; i<num_sctrls; i++) {
		struct tldap_control *c = &sctrls[i];
		if (!asn1_push_tag(data, ASN1_SEQUENCE(0))) return false;
		if (!asn1_write_OctetString(data, c->oid, strlen(c->oid))) return false;
		if (c->critical) {
			if (!asn1_write_BOOLEAN(data, true)) return false;
		}
		if (c->value.data != NULL) {
			if (!asn1_write_OctetString(data, c->value.data,
					       c->value.length)) return false;
		}
		if (!asn1_pop_tag(data)) return false; /* ASN1_SEQUENCE(0) */
	}

	return asn1_pop_tag(data); /* ASN1_CONTEXT(0) */
}

#define tldap_context_disconnect(ld, status) \
	_tldap_context_disconnect(ld, status, __location__)

static void _tldap_context_disconnect(struct tldap_context *ld,
				      TLDAPRC status,
				      const char *location)
{
	if (ld->conn == NULL) {
		/*
		 * We don't need to tldap_debug() on
		 * a potential 2nd run.
		 *
		 * The rest of the function would just
		 * be a noop for the 2nd run anyway.
		 */
		return;
	}

	tldap_debug(ld, TLDAP_DEBUG_WARNING,
		    "tldap_context_disconnect: %s at %s\n",
		    tldap_rc2string(status),
		    location);
	tevent_queue_stop(ld->outgoing);
	TALLOC_FREE(ld->read_req);
	TALLOC_FREE(ld->conn);

	while (talloc_array_length(ld->pending) > 0) {
		struct tevent_req *req = NULL;
		struct tldap_msg_state *state = NULL;

		req = ld->pending[0];
		state = tevent_req_data(req, struct tldap_msg_state);
		tevent_req_defer_callback(req, state->ev);
		tevent_req_ldap_error(req, status);
	}
}

static void tldap_msg_sent(struct tevent_req *subreq);
static void tldap_msg_received(struct tevent_req *subreq);

static struct tevent_req *tldap_msg_send(TALLOC_CTX *mem_ctx,
					 struct tevent_context *ev,
					 struct tldap_context *ld,
					 int id, struct asn1_data *data,
					 struct tldap_control *sctrls,
					 int num_sctrls)
{
	struct tevent_req *req, *subreq;
	struct tldap_msg_state *state;
	DATA_BLOB blob;
	bool ok;

	tldap_debug(ld, TLDAP_DEBUG_TRACE, "tldap_msg_send: sending msg %d\n",
		    id);

	req = tevent_req_create(mem_ctx, &state, struct tldap_msg_state);
	if (req == NULL) {
		return NULL;
	}
	state->ld = ld;
	state->ev = ev;
	state->id = id;

	ok = tldap_connection_ok(ld);
	if (!ok) {
		tevent_req_ldap_error(req, TLDAP_SERVER_DOWN);
		return tevent_req_post(req, ev);
	}

	if (!tldap_push_controls(data, sctrls, num_sctrls)) {
		tevent_req_ldap_error(req, TLDAP_ENCODING_ERROR);
		return tevent_req_post(req, ev);
	}


	if (!asn1_pop_tag(data)) {
		tevent_req_ldap_error(req, TLDAP_ENCODING_ERROR);
		return tevent_req_post(req, ev);
	}

	if (!asn1_blob(data, &blob)) {
		tevent_req_ldap_error(req, TLDAP_ENCODING_ERROR);
		return tevent_req_post(req, ev);
	}

	if (!tldap_msg_set_pending(req)) {
		tevent_req_oom(req);
		return tevent_req_post(req, ev);;
	}

	state->iov.iov_base = (void *)blob.data;
	state->iov.iov_len = blob.length;

	subreq = tstream_writev_queue_send(state, ev, ld->conn, ld->outgoing,
					   &state->iov, 1);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, tldap_msg_sent, req);
	return req;
}

static void tldap_msg_unset_pending(struct tevent_req *req)
{
	struct tldap_msg_state *state = tevent_req_data(
		req, struct tldap_msg_state);
	struct tldap_context *ld = state->ld;
	int num_pending = tldap_pending_reqs(ld);
	int i;

	tevent_req_set_cleanup_fn(req, NULL);

	for (i=0; i<num_pending; i++) {
		if (req == ld->pending[i]) {
			break;
		}
	}
	if (i == num_pending) {
		/*
		 * Something's seriously broken. Just returning here is the
		 * right thing nevertheless, the point of this routine is to
		 * remove ourselves from cli->pending.
		 */
		return;
	}

	if (num_pending == 1) {
		TALLOC_FREE(ld->pending);
		return;
	}

	/*
	 * Remove ourselves from the cli->pending array
	 */
	if (num_pending > 1) {
		ld->pending[i] = ld->pending[num_pending-1];
	}

	/*
	 * No NULL check here, we're shrinking by sizeof(void *), and
	 * talloc_realloc just adjusts the size for this.
	 */
	ld->pending = talloc_realloc(NULL, ld->pending, struct tevent_req *,
				     num_pending - 1);
}

static void tldap_msg_cleanup(struct tevent_req *req,
			      enum tevent_req_state req_state)
{
	tldap_msg_unset_pending(req);
}

static bool tldap_msg_set_pending(struct tevent_req *req)
{
	struct tldap_msg_state *state = tevent_req_data(
		req, struct tldap_msg_state);
	struct tldap_context *ld;
	struct tevent_req **pending;
	int num_pending;

	ld = state->ld;
	num_pending = tldap_pending_reqs(ld);

	pending = talloc_realloc(ld, ld->pending, struct tevent_req *,
				 num_pending+1);
	if (pending == NULL) {
		return false;
	}
	pending[num_pending] = req;
	ld->pending = pending;
	tevent_req_set_cleanup_fn(req, tldap_msg_cleanup);

	if (ld->read_req != NULL) {
		return true;
	}

	/*
	 * We're the first one, add the read_ldap request that waits for the
	 * answer from the server
	 */
	ld->read_req = read_ldap_send(ld->pending, state->ev, ld->conn);
	if (ld->read_req == NULL) {
		tldap_msg_unset_pending(req);
		return false;
	}
	tevent_req_set_callback(ld->read_req, tldap_msg_received, ld);
	return true;
}

static void tldap_msg_sent(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct tldap_msg_state *state = tevent_req_data(
		req, struct tldap_msg_state);
	ssize_t nwritten;
	int err;

	nwritten = tstream_writev_queue_recv(subreq, &err);
	TALLOC_FREE(subreq);
	if (nwritten == -1) {
		tldap_context_disconnect(state->ld, TLDAP_SERVER_DOWN);
		return;
	}
}

static int tldap_msg_msgid(struct tevent_req *req)
{
	struct tldap_msg_state *state = tevent_req_data(
		req, struct tldap_msg_state);

	return state->id;
}

static void tldap_msg_received(struct tevent_req *subreq)
{
	struct tldap_context *ld = tevent_req_callback_data(
		subreq, struct tldap_context);
	struct tevent_req *req;
	struct tldap_msg_state *state;
	struct asn1_data *data;
	uint8_t *inbuf;
	ssize_t received;
	size_t num_pending;
	int i, err;
	TLDAPRC status = TLDAP_PROTOCOL_ERROR;
	int id;
	uint8_t type;
	bool ok;

	received = read_ldap_recv(subreq, talloc_tos(), &inbuf, &err);
	TALLOC_FREE(subreq);
	ld->read_req = NULL;
	if (received == -1) {
		status = TLDAP_SERVER_DOWN;
		goto fail;
	}

	data = asn1_init(talloc_tos(), ASN1_MAX_TREE_DEPTH);
	if (data == NULL) {
		/*
		 * We have to disconnect all, we can't tell which of
		 * the requests this reply is for.
		 */
		status = TLDAP_NO_MEMORY;
		goto fail;
	}
	asn1_load_nocopy(data, inbuf, received);

	ok = true;
	ok &= asn1_start_tag(data, ASN1_SEQUENCE(0));
	ok &= asn1_read_Integer(data, &id);
	ok &= asn1_peek_uint8(data, &type);

	if (!ok) {
		status = TLDAP_PROTOCOL_ERROR;
		goto fail;
	}

	tldap_debug(ld, TLDAP_DEBUG_TRACE, "tldap_msg_received: got msg %d "
		    "type %d\n", id, (int)type);

	if (id == 0) {
		tldap_debug(
			ld,
			TLDAP_DEBUG_WARNING,
			"tldap_msg_received: got msgid 0 of "
			"type %"PRIu8", disconnecting\n",
			type);
		tldap_context_disconnect(ld, TLDAP_SERVER_DOWN);
		return;
	}

	num_pending = talloc_array_length(ld->pending);

	for (i=0; i<num_pending; i++) {
		if (id == tldap_msg_msgid(ld->pending[i])) {
			break;
		}
	}
	if (i == num_pending) {
		/* Dump unexpected reply */
		tldap_debug(ld, TLDAP_DEBUG_WARNING, "tldap_msg_received: "
			    "No request pending for msg %d\n", id);
		TALLOC_FREE(data);
		TALLOC_FREE(inbuf);
		goto done;
	}

	req = ld->pending[i];
	state = tevent_req_data(req, struct tldap_msg_state);

	state->inbuf = talloc_move(state, &inbuf);
	state->data = talloc_move(state, &data);

	tldap_msg_unset_pending(req);
	num_pending = talloc_array_length(ld->pending);

	tevent_req_defer_callback(req, state->ev);
	tevent_req_done(req);

 done:
	if (num_pending == 0) {
		return;
	}

	state = tevent_req_data(ld->pending[0],	struct tldap_msg_state);
	ld->read_req = read_ldap_send(ld->pending, state->ev, ld->conn);
	if (ld->read_req == NULL) {
		status = TLDAP_NO_MEMORY;
		goto fail;
	}
	tevent_req_set_callback(ld->read_req, tldap_msg_received, ld);
	return;

 fail:
	tldap_context_disconnect(ld, status);
}

static TLDAPRC tldap_msg_recv(struct tevent_req *req, TALLOC_CTX *mem_ctx,
			      struct tldap_message **pmsg)
{
	struct tldap_msg_state *state = tevent_req_data(
		req, struct tldap_msg_state);
	struct tldap_message *msg;
	TLDAPRC err;
	uint8_t msgtype;

	if (tevent_req_is_ldap_error(req, &err)) {
		return err;
	}

	if (!asn1_peek_uint8(state->data, &msgtype)) {
		return TLDAP_PROTOCOL_ERROR;
	}

	if (pmsg == NULL) {
		return TLDAP_SUCCESS;
	}

	msg = talloc_zero(mem_ctx, struct tldap_message);
	if (msg == NULL) {
		return TLDAP_NO_MEMORY;
	}
	msg->id = state->id;

	msg->inbuf = talloc_move(msg, &state->inbuf);
	msg->data = talloc_move(msg, &state->data);
	msg->type = msgtype;

	*pmsg = msg;
	return TLDAP_SUCCESS;
}

struct tldap_req_state {
	int id;
	struct asn1_data *out;
	struct tldap_message *result;
};

static struct tevent_req *tldap_req_create(TALLOC_CTX *mem_ctx,
					   struct tldap_context *ld,
					   struct tldap_req_state **pstate)
{
	struct tevent_req *req;
	struct tldap_req_state *state;

	req = tevent_req_create(mem_ctx, &state, struct tldap_req_state);
	if (req == NULL) {
		return NULL;
	}
	state->out = asn1_init(state, ASN1_MAX_TREE_DEPTH);
	if (state->out == NULL) {
		goto err;
	}
	state->id = tldap_next_msgid(ld);

	if (!asn1_push_tag(state->out, ASN1_SEQUENCE(0))) goto err;
	if (!asn1_write_Integer(state->out, state->id)) goto err;

	*pstate = state;
	return req;

  err:

	TALLOC_FREE(req);
	return NULL;
}

static void tldap_save_msg(struct tldap_context *ld, struct tevent_req *req)
{
	struct tldap_req_state *state = tevent_req_data(
		req, struct tldap_req_state);

	TALLOC_FREE(ld->last_msg);
	ld->last_msg = talloc_move(ld, &state->result);
}

static char *blob2string_talloc(TALLOC_CTX *mem_ctx, DATA_BLOB blob)
{
	char *result = talloc_array(mem_ctx, char, blob.length+1);

	if (result == NULL) {
		return NULL;
	}

	memcpy(result, blob.data, blob.length);
	result[blob.length] = '\0';
	return result;
}

static bool asn1_read_OctetString_talloc(TALLOC_CTX *mem_ctx,
					 struct asn1_data *data,
					 char **presult)
{
	DATA_BLOB string;
	char *result;
	if (!asn1_read_OctetString(data, mem_ctx, &string))
		return false;

	result = blob2string_talloc(mem_ctx, string);

	data_blob_free(&string);

	if (result == NULL) {
		return false;
	}
	*presult = result;
	return true;
}

static bool tldap_decode_controls(struct tldap_req_state *state);

static bool tldap_decode_response(struct tldap_req_state *state)
{
	struct asn1_data *data = state->result->data;
	struct tldap_message *msg = state->result;
	int rc;
	bool ok = true;

	ok &= asn1_read_enumerated(data, &rc);
	if (ok) {
		msg->lderr = TLDAP_RC(rc);
	}

	ok &= asn1_read_OctetString_talloc(msg, data, &msg->res_matcheddn);
	ok &= asn1_read_OctetString_talloc(msg, data,
					   &msg->res_diagnosticmessage);
	if (!ok) return ok;
	if (asn1_peek_tag(data, ASN1_CONTEXT(3))) {
		ok &= asn1_start_tag(data, ASN1_CONTEXT(3));
		ok &= asn1_read_OctetString_talloc(msg, data,
						   &msg->res_referral);
		ok &= asn1_end_tag(data);
	} else {
		msg->res_referral = NULL;
	}

	return ok;
}

static void tldap_sasl_bind_done(struct tevent_req *subreq);

struct tevent_req *tldap_sasl_bind_send(TALLOC_CTX *mem_ctx,
					struct tevent_context *ev,
					struct tldap_context *ld,
					const char *dn,
					const char *mechanism,
					DATA_BLOB *creds,
					struct tldap_control *sctrls,
					int num_sctrls,
					struct tldap_control *cctrls,
					int num_cctrls)
{
	struct tevent_req *req, *subreq;
	struct tldap_req_state *state;

	req = tldap_req_create(mem_ctx, ld, &state);
	if (req == NULL) {
		return NULL;
	}

	if (dn == NULL) {
		dn = "";
	}

	if (!asn1_push_tag(state->out, TLDAP_REQ_BIND)) goto err;
	if (!asn1_write_Integer(state->out, ld->ld_version)) goto err;
	if (!asn1_write_OctetString(state->out, dn, strlen(dn))) goto err;

	if (mechanism == NULL) {
		if (!asn1_push_tag(state->out, ASN1_CONTEXT_SIMPLE(0))) goto err;
		if (!asn1_write(state->out, creds->data, creds->length)) goto err;
		if (!asn1_pop_tag(state->out)) goto err;
	} else {
		if (!asn1_push_tag(state->out, ASN1_CONTEXT(3))) goto err;
		if (!asn1_write_OctetString(state->out, mechanism,
				       strlen(mechanism))) goto err;
		if ((creds != NULL) && (creds->data != NULL)) {
			if (!asn1_write_OctetString(state->out, creds->data,
					       creds->length)) goto err;
		}
		if (!asn1_pop_tag(state->out)) goto err;
	}

	if (!asn1_pop_tag(state->out)) goto err;

	subreq = tldap_msg_send(state, ev, ld, state->id, state->out,
				sctrls, num_sctrls);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, tldap_sasl_bind_done, req);
	return req;

  err:

	tevent_req_ldap_error(req, TLDAP_ENCODING_ERROR);
	return tevent_req_post(req, ev);
}

static void tldap_sasl_bind_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct tldap_req_state *state = tevent_req_data(
		req, struct tldap_req_state);
	TLDAPRC rc;
	bool ok;

	rc = tldap_msg_recv(subreq, state, &state->result);
	TALLOC_FREE(subreq);
	if (tevent_req_ldap_error(req, rc)) {
		return;
	}
	if (state->result->type != TLDAP_RES_BIND) {
		tevent_req_ldap_error(req, TLDAP_PROTOCOL_ERROR);
		return;
	}

	ok = asn1_start_tag(state->result->data, TLDAP_RES_BIND);
	ok &= tldap_decode_response(state);

	if (asn1_peek_tag(state->result->data, ASN1_CONTEXT_SIMPLE(7))) {
		int len;

		ok &= asn1_start_tag(state->result->data,
				     ASN1_CONTEXT_SIMPLE(7));
		if (!ok) {
			goto decode_error;
		}

		len = asn1_tag_remaining(state->result->data);
		if (len == -1) {
			goto decode_error;
		}

		state->result->res_serverSaslCreds =
			data_blob_talloc(state->result, NULL, len);
		if (state->result->res_serverSaslCreds.data == NULL) {
			goto decode_error;
		}

		ok = asn1_read(state->result->data,
			       state->result->res_serverSaslCreds.data,
			       state->result->res_serverSaslCreds.length);

		ok &= asn1_end_tag(state->result->data);
	}

	ok &= asn1_end_tag(state->result->data);

	if (!ok) {
		goto decode_error;
	}

	if (!TLDAP_RC_IS_SUCCESS(state->result->lderr) &&
	    !TLDAP_RC_EQUAL(state->result->lderr,
			    TLDAP_SASL_BIND_IN_PROGRESS)) {
		tevent_req_ldap_error(req, state->result->lderr);
		return;
	}
	tevent_req_done(req);
	return;

decode_error:
	tevent_req_ldap_error(req, TLDAP_DECODING_ERROR);
	return;
}

TLDAPRC tldap_sasl_bind_recv(struct tevent_req *req, TALLOC_CTX *mem_ctx,
			     DATA_BLOB *serverSaslCreds)
{
	struct tldap_req_state *state = tevent_req_data(
		req, struct tldap_req_state);
	TLDAPRC rc;

	if (tevent_req_is_ldap_error(req, &rc)) {
		return rc;
	}

	if (serverSaslCreds != NULL) {
		serverSaslCreds->data = talloc_move(
			mem_ctx, &state->result->res_serverSaslCreds.data);
		serverSaslCreds->length =
			state->result->res_serverSaslCreds.length;
	}

	return state->result->lderr;
}

TLDAPRC tldap_sasl_bind(struct tldap_context *ld,
			const char *dn,
			const char *mechanism,
			DATA_BLOB *creds,
			struct tldap_control *sctrls,
			int num_sctrls,
			struct tldap_control *cctrls,
			int num_cctrls,
			TALLOC_CTX *mem_ctx,
			DATA_BLOB *serverSaslCreds)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct tevent_context *ev;
	struct tevent_req *req;
	TLDAPRC rc = TLDAP_NO_MEMORY;

	ev = samba_tevent_context_init(frame);
	if (ev == NULL) {
		goto fail;
	}
	req = tldap_sasl_bind_send(frame, ev, ld, dn, mechanism, creds,
				   sctrls, num_sctrls, cctrls, num_cctrls);
	if (req == NULL) {
		goto fail;
	}
	if (!tevent_req_poll(req, ev)) {
		rc = TLDAP_OPERATIONS_ERROR;
		goto fail;
	}
	rc = tldap_sasl_bind_recv(req, mem_ctx, serverSaslCreds);
	tldap_save_msg(ld, req);
 fail:
	TALLOC_FREE(frame);
	return rc;
}

struct tevent_req *tldap_simple_bind_send(TALLOC_CTX *mem_ctx,
					  struct tevent_context *ev,
					  struct tldap_context *ld,
					  const char *dn,
					  const char *passwd)
{
	DATA_BLOB cred;

	if (passwd != NULL) {
		cred.data = discard_const_p(uint8_t, passwd);
		cred.length = strlen(passwd);
	} else {
		cred.data = discard_const_p(uint8_t, "");
		cred.length = 0;
	}
	return tldap_sasl_bind_send(mem_ctx, ev, ld, dn, NULL, &cred, NULL, 0,
				    NULL, 0);
}

TLDAPRC tldap_simple_bind_recv(struct tevent_req *req)
{
	return tldap_sasl_bind_recv(req, NULL, NULL);
}

TLDAPRC tldap_simple_bind(struct tldap_context *ld, const char *dn,
			  const char *passwd)
{
	DATA_BLOB cred;

	if (passwd != NULL) {
		cred.data = discard_const_p(uint8_t, passwd);
		cred.length = strlen(passwd);
	} else {
		cred.data = discard_const_p(uint8_t, "");
		cred.length = 0;
	}
	return tldap_sasl_bind(ld, dn, NULL, &cred, NULL, 0, NULL, 0,
			       NULL, NULL);
}

/*****************************************************************************/

/* can't use isalpha() as only a strict set is valid for LDAP */

static bool tldap_is_alpha(char c)
{
	return (((c >= 'a') && (c <= 'z')) || \
		((c >= 'A') && (c <= 'Z')));
}

static bool tldap_is_adh(char c)
{
	return tldap_is_alpha(c) || isdigit(c) || (c == '-');
}

#define TLDAP_FILTER_AND  ASN1_CONTEXT(0)
#define TLDAP_FILTER_OR   ASN1_CONTEXT(1)
#define TLDAP_FILTER_NOT  ASN1_CONTEXT(2)
#define TLDAP_FILTER_EQ   ASN1_CONTEXT(3)
#define TLDAP_FILTER_SUB  ASN1_CONTEXT(4)
#define TLDAP_FILTER_LE   ASN1_CONTEXT(5)
#define TLDAP_FILTER_GE   ASN1_CONTEXT(6)
#define TLDAP_FILTER_PRES ASN1_CONTEXT_SIMPLE(7)
#define TLDAP_FILTER_APX  ASN1_CONTEXT(8)
#define TLDAP_FILTER_EXT  ASN1_CONTEXT(9)

#define TLDAP_SUB_INI ASN1_CONTEXT_SIMPLE(0)
#define TLDAP_SUB_ANY ASN1_CONTEXT_SIMPLE(1)
#define TLDAP_SUB_FIN ASN1_CONTEXT_SIMPLE(2)


/* oid's should be numerical only in theory,
 * but apparently some broken servers may have alphanum aliases instead.
 * Do like openldap libraries and allow alphanum aliases for oids, but
 * do not allow Tagging options in that case.
 */
static bool tldap_is_attrdesc(const char *s, int len, bool no_tagopts)
{
	bool is_oid = false;
	bool dot = false;
	int i;

	/* first char has stricter rules */
	if (isdigit(*s)) {
		is_oid = true;
	} else if (!tldap_is_alpha(*s)) {
		/* bad first char */
		return false;
	}

	for (i = 1; i < len; i++) {

		if (is_oid) {
			if (isdigit(s[i])) {
				dot = false;
				continue;
			}
			if (s[i] == '.') {
				if (dot) {
					/* malformed */
					return false;
				}
				dot = true;
				continue;
			}
		} else {
			if (tldap_is_adh(s[i])) {
				continue;
			}
		}

		if (s[i] == ';') {
			if (no_tagopts) {
				/* no tagging options */
				return false;
			}
			if (dot) {
				/* malformed */
				return false;
			}
			if ((i + 1) == len) {
				/* malformed */
				return false;
			}

			is_oid = false;
			continue;
		}
	}

	if (dot) {
		/* malformed */
		return false;
	}

	return true;
}

/* this function copies the value until the closing parenthesis is found. */
static char *tldap_get_val(TALLOC_CTX *memctx,
			   const char *value, const char **_s)
{
	const char *s = value;

	/* find terminator */
	while (*s) {
		s = strchr(s, ')');
		if (s && (*(s - 1) == '\\')) {
			continue;
		}
		break;
	}
	if (!s || !(*s == ')')) {
		/* malformed filter */
		return NULL;
	}

	*_s = s;

	return talloc_strndup(memctx, value, s - value);
}

static int tldap_hex2char(const char *x)
{
	if (isxdigit(x[0]) && isxdigit(x[1])) {
		const char h1 = x[0], h2 = x[1];
		int c = 0;

		if (h1 >= 'a') c = h1 - (int)'a' + 10;
		else if (h1 >= 'A') c = h1 - (int)'A' + 10;
		else if (h1 >= '0') c = h1 - (int)'0';
		c = c << 4;
		if (h2 >= 'a') c += h2 - (int)'a' + 10;
		else if (h2 >= 'A') c += h2 - (int)'A' + 10;
		else if (h2 >= '0') c += h2 - (int)'0';

		return c;
	}

	return -1;
}

static bool tldap_find_first_star(const char *val, const char **star)
{
	const char *s;

	for (s = val; *s; s++) {
		switch (*s) {
		case '\\':
			if (isxdigit(s[1]) && isxdigit(s[2])) {
				s += 2;
				break;
			}
			/* not hex based escape, check older syntax */
			switch (s[1]) {
			case '(':
			case ')':
			case '*':
			case '\\':
				s++;
				break;
			default:
				/* invalid escape sequence */
				return false;
			}
			break;
		case ')':
			/* end of val, nothing found */
			*star = s;
			return true;

		case '*':
			*star = s;
			return true;
		}
	}

	/* string ended without closing parenthesis, filter is malformed */
	return false;
}

static bool tldap_unescape_inplace(char *value, size_t *val_len)
{
	int c;
	size_t i, p;

	for (i = 0,p = 0; i < *val_len; i++) {

		switch (value[i]) {
		case '(':
		case ')':
		case '*':
			/* these must be escaped */
			return false;

		case '\\':
			if (!value[i + 1]) {
				/* invalid EOL */
				return false;
			}
			i++;

			/* LDAPv3 escaped */
			c = tldap_hex2char(&value[i]);
			if (c >= 0 && c < 256) {
				value[p] = c;
				i++;
				p++;
				break;
			}

			/* LDAPv2 escaped */
			switch (value[i]) {
			case '(':
			case ')':
			case '*':
			case '\\':
				value[p] = value[i];
				p++;

				break;
			default:
				/* invalid */
				return false;
			}
			break;

		default:
			value[p] = value[i];
			p++;
		}
	}
	value[p] = '\0';
	*val_len = p;
	return true;
}

static bool tldap_push_filter_basic(struct tldap_context *ld,
				    struct asn1_data *data,
				    const char **_s);
static bool tldap_push_filter_substring(struct tldap_context *ld,
					struct asn1_data *data,
					const char *val,
					const char **_s);
static bool tldap_push_filter_int(struct tldap_context *ld,
				  struct asn1_data *data,
				  const char **_s)
{
	const char *s = *_s;
	bool ret;

	if (*s != '(') {
		tldap_debug(ld, TLDAP_DEBUG_ERROR,
			    "Incomplete or malformed filter\n");
		return false;
	}
	s++;

	/* we are right after a parenthesis,
	 * find out what op we have at hand */
	switch (*s) {
	case '&':
		tldap_debug(ld, TLDAP_DEBUG_TRACE, "Filter op: AND\n");
		if (!asn1_push_tag(data, TLDAP_FILTER_AND)) return false;
		s++;
		break;

	case '|':
		tldap_debug(ld, TLDAP_DEBUG_TRACE, "Filter op: OR\n");
		if (!asn1_push_tag(data, TLDAP_FILTER_OR)) return false;
		s++;
		break;

	case '!':
		tldap_debug(ld, TLDAP_DEBUG_TRACE, "Filter op: NOT\n");
		if (!asn1_push_tag(data, TLDAP_FILTER_NOT)) return false;
		s++;
		ret = tldap_push_filter_int(ld, data, &s);
		if (!ret) {
			return false;
		}
		if (!asn1_pop_tag(data)) return false;
		goto done;

	case '(':
	case ')':
		tldap_debug(ld, TLDAP_DEBUG_ERROR,
			    "Invalid parenthesis '%c'\n", *s);
		return false;

	case '\0':
		tldap_debug(ld, TLDAP_DEBUG_ERROR,
			    "Invalid filter termination\n");
		return false;

	default:
		ret = tldap_push_filter_basic(ld, data, &s);
		if (!ret) {
			return false;
		}
		goto done;
	}

	/* only and/or filters get here.
	 * go through the list of filters */

	if (*s == ')') {
		/* RFC 4526: empty and/or */
		if (!asn1_pop_tag(data)) return false;
		goto done;
	}

	while (*s) {
		ret = tldap_push_filter_int(ld, data, &s);
		if (!ret) {
			return false;
		}

		if (*s == ')') {
			/* end of list, return */
			if (!asn1_pop_tag(data)) return false;
			break;
		}
	}

done:
	if (*s != ')') {
		tldap_debug(ld, TLDAP_DEBUG_ERROR,
			    "Incomplete or malformed filter\n");
		return false;
	}
	s++;

	if (asn1_has_error(data)) {
		return false;
	}

	*_s = s;
	return true;
}


static bool tldap_push_filter_basic(struct tldap_context *ld,
				    struct asn1_data *data,
				    const char **_s)
{
	TALLOC_CTX *tmpctx = talloc_tos();
	const char *s = *_s;
	const char *e;
	const char *eq;
	const char *val;
	const char *type;
	const char *dn;
	const char *rule;
	const char *star;
	size_t type_len = 0;
	char *uval;
	size_t uval_len;
	bool write_octect = true;
	bool ret;

	eq = strchr(s, '=');
	if (!eq) {
		tldap_debug(ld, TLDAP_DEBUG_ERROR,
			    "Invalid filter, missing equal sign\n");
		return false;
	}

	val = eq + 1;
	e = eq - 1;

	switch (*e) {
	case '<':
		if (!asn1_push_tag(data, TLDAP_FILTER_LE)) return false;
		break;

	case '>':
		if (!asn1_push_tag(data, TLDAP_FILTER_GE)) return false;
		break;

	case '~':
		if (!asn1_push_tag(data, TLDAP_FILTER_APX)) return false;
		break;

	case ':':
		if (!asn1_push_tag(data, TLDAP_FILTER_EXT)) return false;
		write_octect = false;

		type = NULL;
		dn = NULL;
		rule = NULL;

		if (*s == ':') { /* [:dn]:rule:= value */
			if (s == e) {
				/* malformed filter */
				return false;
			}
			dn = s;
		} else { /* type[:dn][:rule]:= value */
			type = s;
			dn = strchr(s, ':');
			type_len = dn - type;
			if (dn == e) { /* type:= value */
				dn = NULL;
			}
		}
		if (dn) {
			dn++;

			rule = strchr(dn, ':');
			if (rule == NULL) {
				return false;
			}
			if ((rule == dn + 1) || rule + 1 == e) {
				/* malformed filter, contains "::" */
				return false;
			}

			if (strncasecmp_m(dn, "dn:", 3) != 0) {
				if (rule == e) {
					rule = dn;
					dn = NULL;
				} else {
					/* malformed filter. With two
					 * optionals, the first must be "dn"
					 */
					return false;
				}
			} else {
				if (rule == e) {
					rule = NULL;
				} else {
					rule++;
				}
			}
		}

		if (!type && !dn && !rule) {
			/* malformed filter, there must be at least one */
			return false;
		}

		/*
		  MatchingRuleAssertion ::= SEQUENCE {
		  matchingRule    [1] MatchingRuleID OPTIONAL,
		  type	    [2] AttributeDescription OPTIONAL,
		  matchValue      [3] AssertionValue,
		  dnAttributes    [4] BOOLEAN DEFAULT FALSE
		  }
		*/

		/* check and add rule */
		if (rule) {
			ret = tldap_is_attrdesc(rule, e - rule, true);
			if (!ret) {
				return false;
			}
			if (!asn1_push_tag(data, ASN1_CONTEXT_SIMPLE(1))) return false;
			if (!asn1_write(data, rule, e - rule)) return false;
			if (!asn1_pop_tag(data)) return false;
		}

		/* check and add type */
		if (type) {
			ret = tldap_is_attrdesc(type, type_len, false);
			if (!ret) {
				return false;
			}
			if (!asn1_push_tag(data, ASN1_CONTEXT_SIMPLE(2))) return false;
			if (!asn1_write(data, type, type_len)) return false;
			if (!asn1_pop_tag(data)) return false;
		}

		uval = tldap_get_val(tmpctx, val, _s);
		if (!uval) {
			return false;
		}
		uval_len = *_s - val;
		ret = tldap_unescape_inplace(uval, &uval_len);
		if (!ret) {
			return false;
		}

		if (!asn1_push_tag(data, ASN1_CONTEXT_SIMPLE(3))) return false;
		if (!asn1_write(data, uval, uval_len)) return false;
		if (!asn1_pop_tag(data)) return false;

		if (!asn1_push_tag(data, ASN1_CONTEXT_SIMPLE(4))) return false;
		if (!asn1_write_uint8(data, dn?1:0)) return false;
		if (!asn1_pop_tag(data)) return false;
		break;

	default:
		e = eq;

		ret = tldap_is_attrdesc(s, e - s, false);
		if (!ret) {
			return false;
		}

		if (strncmp(val, "*)", 2) == 0) {
			/* presence */
			if (!asn1_push_tag(data, TLDAP_FILTER_PRES)) return false;
			if (!asn1_write(data, s, e - s)) return false;
			*_s = val + 1;
			write_octect = false;
			break;
		}

		ret = tldap_find_first_star(val, &star);
		if (!ret) {
			return false;
		}
		if (*star == '*') {
			/* substring */
			if (!asn1_push_tag(data, TLDAP_FILTER_SUB)) return false;
			if (!asn1_write_OctetString(data, s, e - s)) return false;
			ret = tldap_push_filter_substring(ld, data, val, &s);
			if (!ret) {
				return false;
			}
			*_s = s;
			write_octect = false;
			break;
		}

		/* if nothing else, then it is just equality */
		if (!asn1_push_tag(data, TLDAP_FILTER_EQ)) return false;
		write_octect = true;
		break;
	}

	if (write_octect) {
		uval = tldap_get_val(tmpctx, val, _s);
		if (!uval) {
			return false;
		}
		uval_len = *_s - val;
		ret = tldap_unescape_inplace(uval, &uval_len);
		if (!ret) {
			return false;
		}

		if (!asn1_write_OctetString(data, s, e - s)) return false;
		if (!asn1_write_OctetString(data, uval, uval_len)) return false;
	}

	if (asn1_has_error(data)) {
		return false;
	}
	return asn1_pop_tag(data);
}

static bool tldap_push_filter_substring(struct tldap_context *ld,
					struct asn1_data *data,
					const char *val,
					const char **_s)
{
	TALLOC_CTX *tmpctx = talloc_tos();
	bool initial = true;
	const char *star;
	char *chunk;
	size_t chunk_len;
	bool ret;

	/*
	  SubstringFilter ::= SEQUENCE {
		  type	    AttributeDescription,
		  -- at least one must be present
		  substrings      SEQUENCE OF CHOICE {
			  initial [0] LDAPString,
			  any     [1] LDAPString,
			  final   [2] LDAPString } }
	*/
	if (!asn1_push_tag(data, ASN1_SEQUENCE(0))) return false;

	do {
		ret = tldap_find_first_star(val, &star);
		if (!ret) {
			return false;
		}
		chunk_len = star - val;

		switch (*star) {
		case '*':
			if (!initial && chunk_len == 0) {
				/* found '**', which is illegal */
				return false;
			}
			break;
		case ')':
			if (initial) {
				/* no stars ?? */
				return false;
			}
			/* we are done */
			break;
		default:
			/* ?? */
			return false;
		}

		if (initial && chunk_len == 0) {
			val = star + 1;
			initial = false;
			continue;
		}

		chunk = talloc_strndup(tmpctx, val, chunk_len);
		if (!chunk) {
			return false;
		}
		ret = tldap_unescape_inplace(chunk, &chunk_len);
		if (!ret) {
			return false;
		}
		switch (*star) {
		case '*':
			if (initial) {
				if (!asn1_push_tag(data, TLDAP_SUB_INI)) return false;
				initial = false;
			} else {
				if (!asn1_push_tag(data, TLDAP_SUB_ANY)) return false;
			}
			break;
		case ')':
			if (!asn1_push_tag(data, TLDAP_SUB_FIN)) return false;
			break;
		default:
			/* ?? */
			return false;
		}
		if (!asn1_write(data, chunk, chunk_len)) return false;
		if (!asn1_pop_tag(data)) return false;

		val = star + 1;

	} while (*star == '*');

	*_s = star;

	/* end of sequence */
	return asn1_pop_tag(data);
}

/* NOTE: although openldap libraries allow for spaces in some places, mosly
 * around parenthesis, we do not allow any spaces (except in values of
 * course) as I couldn't fine any place in RFC 4512 or RFC 4515 where
 * leading or trailing spaces where allowed.
 */
static bool tldap_push_filter(struct tldap_context *ld,
			      struct asn1_data *data,
			      const char *filter)
{
	const char *s = filter;
	bool ret;

	ret = tldap_push_filter_int(ld, data, &s);
	if (ret && *s) {
		tldap_debug(ld, TLDAP_DEBUG_ERROR,
			    "Incomplete or malformed filter\n");
		return false;
	}
	return ret;
}

/*****************************************************************************/

static void tldap_search_done(struct tevent_req *subreq);

struct tevent_req *tldap_search_send(TALLOC_CTX *mem_ctx,
				     struct tevent_context *ev,
				     struct tldap_context *ld,
				     const char *base, int scope,
				     const char *filter,
				     const char **attrs,
				     int num_attrs,
				     int attrsonly,
				     struct tldap_control *sctrls,
				     int num_sctrls,
				     struct tldap_control *cctrls,
				     int num_cctrls,
				     int timelimit,
				     int sizelimit,
				     int deref)
{
	struct tevent_req *req, *subreq;
	struct tldap_req_state *state;
	int i;

	req = tldap_req_create(mem_ctx, ld, &state);
	if (req == NULL) {
		return NULL;
	}

	if (!asn1_push_tag(state->out, TLDAP_REQ_SEARCH)) goto encoding_error;
	if (!asn1_write_OctetString(state->out, base, strlen(base))) goto encoding_error;
	if (!asn1_write_enumerated(state->out, scope)) goto encoding_error;
	if (!asn1_write_enumerated(state->out, deref)) goto encoding_error;
	if (!asn1_write_Integer(state->out, sizelimit)) goto encoding_error;
	if (!asn1_write_Integer(state->out, timelimit)) goto encoding_error;
	if (!asn1_write_BOOLEAN(state->out, attrsonly)) goto encoding_error;

	if (!tldap_push_filter(ld, state->out, filter)) {
		goto encoding_error;
	}

	if (!asn1_push_tag(state->out, ASN1_SEQUENCE(0))) goto encoding_error;
	for (i=0; i<num_attrs; i++) {
		if (!asn1_write_OctetString(state->out, attrs[i], strlen(attrs[i]))) goto encoding_error;
	}
	if (!asn1_pop_tag(state->out)) goto encoding_error;
	if (!asn1_pop_tag(state->out)) goto encoding_error;

	subreq = tldap_msg_send(state, ev, ld, state->id, state->out,
				sctrls, num_sctrls);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, tldap_search_done, req);
	return req;

 encoding_error:
	tevent_req_ldap_error(req, TLDAP_ENCODING_ERROR);
	return tevent_req_post(req, ev);
}

static void tldap_search_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct tldap_req_state *state = tevent_req_data(
		req, struct tldap_req_state);
	TLDAPRC rc;

	rc = tldap_msg_recv(subreq, state, &state->result);
	if (tevent_req_ldap_error(req, rc)) {
		return;
	}
	switch (state->result->type) {
	case TLDAP_RES_SEARCH_ENTRY:
	case TLDAP_RES_SEARCH_REFERENCE:
		if (!tldap_msg_set_pending(subreq)) {
			tevent_req_oom(req);
			return;
		}
		tevent_req_notify_callback(req);
		break;
	case TLDAP_RES_SEARCH_RESULT:
		TALLOC_FREE(subreq);
		if (!asn1_start_tag(state->result->data,
				    state->result->type) ||
		    !tldap_decode_response(state) ||
		    !asn1_end_tag(state->result->data) ||
		    !tldap_decode_controls(state)) {
			tevent_req_ldap_error(req, TLDAP_DECODING_ERROR);
			return;
		}
		tevent_req_done(req);
		break;
	default:
		tevent_req_ldap_error(req, TLDAP_PROTOCOL_ERROR);
		return;
	}
}

TLDAPRC tldap_search_recv(struct tevent_req *req, TALLOC_CTX *mem_ctx,
			  struct tldap_message **pmsg)
{
	struct tldap_req_state *state = tevent_req_data(
		req, struct tldap_req_state);
	TLDAPRC rc;

	if (!tevent_req_is_in_progress(req)
	    && tevent_req_is_ldap_error(req, &rc)) {
		return rc;
	}

	if (tevent_req_is_in_progress(req)) {
		switch (state->result->type) {
		case TLDAP_RES_SEARCH_ENTRY:
		case TLDAP_RES_SEARCH_REFERENCE:
			break;
		default:
			return TLDAP_OPERATIONS_ERROR;
		}
	}

	*pmsg = talloc_move(mem_ctx, &state->result);
	return TLDAP_SUCCESS;
}

struct tldap_search_all_state {
	struct tldap_message **msgs;
	struct tldap_message *result;
};

static void tldap_search_all_done(struct tevent_req *subreq);

struct tevent_req *tldap_search_all_send(
	TALLOC_CTX *mem_ctx, struct tevent_context *ev,
	struct tldap_context *ld, const char *base, int scope,
	const char *filter, const char **attrs, int num_attrs, int attrsonly,
	struct tldap_control *sctrls, int num_sctrls,
	struct tldap_control *cctrls, int num_cctrls,
	int timelimit, int sizelimit, int deref)
{
	struct tevent_req *req, *subreq;
	struct tldap_search_all_state *state;

	req = tevent_req_create(mem_ctx, &state,
				struct tldap_search_all_state);
	if (req == NULL) {
		return NULL;
	}

	subreq = tldap_search_send(state, ev, ld, base, scope, filter,
				   attrs, num_attrs, attrsonly,
				   sctrls, num_sctrls, cctrls, num_cctrls,
				   timelimit, sizelimit, deref);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, tldap_search_all_done, req);
	return req;
}

static void tldap_search_all_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct tldap_search_all_state *state = tevent_req_data(
		req, struct tldap_search_all_state);
	struct tldap_message *msg, **tmp;
	size_t num_msgs;
	TLDAPRC rc;
	int msgtype;

	rc = tldap_search_recv(subreq, state, &msg);
	/* No TALLOC_FREE(subreq), this is multi-step */
	if (tevent_req_ldap_error(req, rc)) {
		return;
	}

	msgtype = tldap_msg_type(msg);
	if (msgtype == TLDAP_RES_SEARCH_RESULT) {
		state->result = msg;
		tevent_req_done(req);
		return;
	}

	num_msgs = talloc_array_length(state->msgs);

	tmp = talloc_realloc(state, state->msgs, struct tldap_message *,
			     num_msgs + 1);
	if (tevent_req_nomem(tmp, req)) {
		return;
	}
	state->msgs = tmp;
	state->msgs[num_msgs] = talloc_move(state->msgs, &msg);
}

TLDAPRC tldap_search_all_recv(struct tevent_req *req, TALLOC_CTX *mem_ctx,
			      struct tldap_message ***msgs,
			      struct tldap_message **result)
{
	struct tldap_search_all_state *state = tevent_req_data(
		req, struct tldap_search_all_state);
	TLDAPRC rc;

	if (tevent_req_is_ldap_error(req, &rc)) {
		return rc;
	}

	if (msgs != NULL) {
		*msgs = talloc_move(mem_ctx, &state->msgs);
	}
	if (result != NULL) {
		*result = talloc_move(mem_ctx, &state->result);
	}

	return TLDAP_SUCCESS;
}

TLDAPRC tldap_search(struct tldap_context *ld,
		     const char *base, int scope, const char *filter,
		     const char **attrs, int num_attrs, int attrsonly,
		     struct tldap_control *sctrls, int num_sctrls,
		     struct tldap_control *cctrls, int num_cctrls,
		     int timelimit, int sizelimit, int deref,
		     TALLOC_CTX *mem_ctx, struct tldap_message ***pmsgs)
{
	TALLOC_CTX *frame;
	struct tevent_context *ev;
	struct tevent_req *req;
	TLDAPRC rc = TLDAP_NO_MEMORY;
	struct tldap_message **msgs;
	struct tldap_message *result;

	if (tldap_pending_reqs(ld)) {
		return TLDAP_BUSY;
	}

	frame = talloc_stackframe();

	ev = samba_tevent_context_init(frame);
	if (ev == NULL) {
		goto fail;
	}
	req = tldap_search_all_send(frame, ev, ld, base, scope, filter,
				    attrs, num_attrs, attrsonly,
				    sctrls, num_sctrls, cctrls, num_cctrls,
				    timelimit, sizelimit, deref);
	if (req == NULL) {
		goto fail;
	}
	if (!tevent_req_poll(req, ev)) {
		rc = TLDAP_OPERATIONS_ERROR;
		goto fail;
	}
	rc = tldap_search_all_recv(req, frame, &msgs, &result);
	TALLOC_FREE(req);
	if (!TLDAP_RC_IS_SUCCESS(rc)) {
		goto fail;
	}

	TALLOC_FREE(ld->last_msg);
	ld->last_msg = talloc_move(ld, &result);

	if (pmsgs != NULL) {
		*pmsgs = talloc_move(mem_ctx, &msgs);
	}
fail:
	TALLOC_FREE(frame);
	return rc;
}

static bool tldap_parse_search_entry(struct tldap_message *msg)
{
	int num_attribs = 0;

	if (msg->type != TLDAP_RES_SEARCH_ENTRY) {
		return false;
	}
	if (!asn1_start_tag(msg->data, TLDAP_RES_SEARCH_ENTRY)) {
		return false;
	}

	/* dn */

	if (!asn1_read_OctetString_talloc(msg, msg->data, &msg->dn)) return false;

	if (msg->dn == NULL) {
		return false;
	}

	/*
	 * Attributes: We overallocate msg->attribs by one, so that while
	 * looping over the attributes we can directly parse into the last
	 * array element. Same for the values in the inner loop.
	 */

	msg->attribs = talloc_array(msg, struct tldap_attribute, 1);
	if (msg->attribs == NULL) {
		return false;
	}

	if (!asn1_start_tag(msg->data, ASN1_SEQUENCE(0))) return false;
	while (asn1_peek_tag(msg->data, ASN1_SEQUENCE(0))) {
		struct tldap_attribute *attrib;
		int num_values = 0;

		attrib = &msg->attribs[num_attribs];
		attrib->values = talloc_array(msg->attribs, DATA_BLOB, 1);
		if (attrib->values == NULL) {
			return false;
		}
		if (!asn1_start_tag(msg->data, ASN1_SEQUENCE(0))) return false;
		if (!asn1_read_OctetString_talloc(msg->attribs, msg->data,
					     &attrib->name)) return false;
		if (!asn1_start_tag(msg->data, ASN1_SET)) return false;

		while (asn1_peek_tag(msg->data, ASN1_OCTET_STRING)) {
			if (!asn1_read_OctetString(msg->data, msg,
					      &attrib->values[num_values])) return false;

			attrib->values = talloc_realloc(
				msg->attribs, attrib->values, DATA_BLOB,
				num_values + 2);
			if (attrib->values == NULL) {
				return false;
			}
			num_values += 1;
		}
		attrib->values = talloc_realloc(msg->attribs, attrib->values,
						DATA_BLOB, num_values);
		attrib->num_values = num_values;

		if (!asn1_end_tag(msg->data)) return false; /* ASN1_SET */
		if (!asn1_end_tag(msg->data)) return false; /* ASN1_SEQUENCE(0) */
		msg->attribs = talloc_realloc(
			msg, msg->attribs, struct tldap_attribute,
			num_attribs + 2);
		if (msg->attribs == NULL) {
			return false;
		}
		num_attribs += 1;
	}
	msg->attribs = talloc_realloc(
		msg, msg->attribs, struct tldap_attribute, num_attribs);
	return asn1_end_tag(msg->data);
}

bool tldap_entry_dn(struct tldap_message *msg, char **dn)
{
	if ((msg->dn == NULL) && (!tldap_parse_search_entry(msg))) {
		return false;
	}
	*dn = msg->dn;
	return true;
}

bool tldap_entry_attributes(struct tldap_message *msg,
			    struct tldap_attribute **attributes,
			    int *num_attributes)
{
	if ((msg->dn == NULL) && (!tldap_parse_search_entry(msg))) {
		return false;
	}
	*attributes = msg->attribs;
	*num_attributes = talloc_array_length(msg->attribs);
	return true;
}

static bool tldap_decode_controls(struct tldap_req_state *state)
{
	struct tldap_message *msg = state->result;
	struct asn1_data *data = msg->data;
	struct tldap_control *sctrls = NULL;
	int num_controls = 0;
	bool ret = false;

	msg->res_sctrls = NULL;

	if (!asn1_peek_tag(data, ASN1_CONTEXT(0))) {
		return true;
	}

	if (!asn1_start_tag(data, ASN1_CONTEXT(0))) goto out;

	while (asn1_peek_tag(data, ASN1_SEQUENCE(0))) {
		struct tldap_control *c;
		char *oid = NULL;

		sctrls = talloc_realloc(msg, sctrls, struct tldap_control,
					num_controls + 1);
		if (sctrls == NULL) {
			goto out;
		}
		c = &sctrls[num_controls];

		if (!asn1_start_tag(data, ASN1_SEQUENCE(0))) goto out;
		if (!asn1_read_OctetString_talloc(msg, data, &oid)) goto out;
		if (asn1_has_error(data) || (oid == NULL)) {
			goto out;
		}
		c->oid = oid;
		if (asn1_peek_tag(data, ASN1_BOOLEAN)) {
			if (!asn1_read_BOOLEAN(data, &c->critical)) goto out;
		} else {
			c->critical = false;
		}
		c->value = data_blob_null;
		if (asn1_peek_tag(data, ASN1_OCTET_STRING) &&
		    !asn1_read_OctetString(data, msg, &c->value)) {
			goto out;
		}
		if (!asn1_end_tag(data)) goto out; /* ASN1_SEQUENCE(0) */

		num_controls += 1;
	}

	if (!asn1_end_tag(data)) goto out; 	/* ASN1_CONTEXT(0) */

	ret = true;

 out:

	if (ret) {
		msg->res_sctrls = sctrls;
	} else {
		TALLOC_FREE(sctrls);
	}
	return ret;
}

static void tldap_simple_done(struct tevent_req *subreq, int type)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct tldap_req_state *state = tevent_req_data(
		req, struct tldap_req_state);
	TLDAPRC rc;

	rc = tldap_msg_recv(subreq, state, &state->result);
	TALLOC_FREE(subreq);
	if (tevent_req_ldap_error(req, rc)) {
		return;
	}
	if (state->result->type != type) {
		tevent_req_ldap_error(req, TLDAP_PROTOCOL_ERROR);
		return;
	}
	if (!asn1_start_tag(state->result->data, state->result->type) ||
	    !tldap_decode_response(state) ||
	    !asn1_end_tag(state->result->data) ||
	    !tldap_decode_controls(state)) {
		tevent_req_ldap_error(req, TLDAP_DECODING_ERROR);
		return;
	}
	if (!TLDAP_RC_IS_SUCCESS(state->result->lderr)) {
		tevent_req_ldap_error(req, state->result->lderr);
		return;
	}
	tevent_req_done(req);
}

static TLDAPRC tldap_simple_recv(struct tevent_req *req)
{
	TLDAPRC rc;
	if (tevent_req_is_ldap_error(req, &rc)) {
		return rc;
	}
	return TLDAP_SUCCESS;
}

static void tldap_add_done(struct tevent_req *subreq);

struct tevent_req *tldap_add_send(TALLOC_CTX *mem_ctx,
				  struct tevent_context *ev,
				  struct tldap_context *ld,
				  const char *dn,
				  struct tldap_mod *attributes,
				  int num_attributes,
				  struct tldap_control *sctrls,
				  int num_sctrls,
				  struct tldap_control *cctrls,
				  int num_cctrls)
{
	struct tevent_req *req, *subreq;
	struct tldap_req_state *state;
	int i, j;

	req = tldap_req_create(mem_ctx, ld, &state);
	if (req == NULL) {
		return NULL;
	}

	if (!asn1_push_tag(state->out, TLDAP_REQ_ADD)) goto err;
	if (!asn1_write_OctetString(state->out, dn, strlen(dn))) goto err;
	if (!asn1_push_tag(state->out, ASN1_SEQUENCE(0))) goto err;

	for (i=0; i<num_attributes; i++) {
		struct tldap_mod *attrib = &attributes[i];
		if (!asn1_push_tag(state->out, ASN1_SEQUENCE(0))) goto err;
		if (!asn1_write_OctetString(state->out, attrib->attribute,
				       strlen(attrib->attribute))) goto err;
		if (!asn1_push_tag(state->out, ASN1_SET)) goto err;
		for (j=0; j<attrib->num_values; j++) {
			if (!asn1_write_OctetString(state->out,
					       attrib->values[j].data,
					       attrib->values[j].length)) goto err;
		}
		if (!asn1_pop_tag(state->out)) goto err;
		if (!asn1_pop_tag(state->out)) goto err;
	}

	if (!asn1_pop_tag(state->out)) goto err;
	if (!asn1_pop_tag(state->out)) goto err;

	subreq = tldap_msg_send(state, ev, ld, state->id, state->out,
				sctrls, num_sctrls);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, tldap_add_done, req);
	return req;

  err:

	tevent_req_ldap_error(req, TLDAP_ENCODING_ERROR);
	return tevent_req_post(req, ev);
}

static void tldap_add_done(struct tevent_req *subreq)
{
	tldap_simple_done(subreq, TLDAP_RES_ADD);
}

TLDAPRC tldap_add_recv(struct tevent_req *req)
{
	return tldap_simple_recv(req);
}

TLDAPRC tldap_add(struct tldap_context *ld, const char *dn,
		  struct tldap_mod *attributes, int num_attributes,
		  struct tldap_control *sctrls, int num_sctrls,
		  struct tldap_control *cctrls, int num_cctrls)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct tevent_context *ev;
	struct tevent_req *req;
	TLDAPRC rc = TLDAP_NO_MEMORY;

	ev = samba_tevent_context_init(frame);
	if (ev == NULL) {
		goto fail;
	}
	req = tldap_add_send(frame, ev, ld, dn, attributes, num_attributes,
			     sctrls, num_sctrls, cctrls, num_cctrls);
	if (req == NULL) {
		goto fail;
	}
	if (!tevent_req_poll(req, ev)) {
		rc = TLDAP_OPERATIONS_ERROR;
		goto fail;
	}
	rc = tldap_add_recv(req);
	tldap_save_msg(ld, req);
 fail:
	TALLOC_FREE(frame);
	return rc;
}

static void tldap_modify_done(struct tevent_req *subreq);

struct tevent_req *tldap_modify_send(TALLOC_CTX *mem_ctx,
				     struct tevent_context *ev,
				     struct tldap_context *ld,
				     const char *dn,
				     struct tldap_mod *mods, int num_mods,
				     struct tldap_control *sctrls,
				     int num_sctrls,
				     struct tldap_control *cctrls,
				     int num_cctrls)
{
	struct tevent_req *req, *subreq;
	struct tldap_req_state *state;
	int i, j;

	req = tldap_req_create(mem_ctx, ld, &state);
	if (req == NULL) {
		return NULL;
	}

	if (!asn1_push_tag(state->out, TLDAP_REQ_MODIFY)) goto err;
	if (!asn1_write_OctetString(state->out, dn, strlen(dn))) goto err;
	if (!asn1_push_tag(state->out, ASN1_SEQUENCE(0))) goto err;

	for (i=0; i<num_mods; i++) {
		struct tldap_mod *mod = &mods[i];
		if (!asn1_push_tag(state->out, ASN1_SEQUENCE(0))) goto err;
		if (!asn1_write_enumerated(state->out, mod->mod_op)) goto err;
		if (!asn1_push_tag(state->out, ASN1_SEQUENCE(0))) goto err;
		if (!asn1_write_OctetString(state->out, mod->attribute,
				       strlen(mod->attribute))) goto err;
		if (!asn1_push_tag(state->out, ASN1_SET)) goto err;
		for (j=0; j<mod->num_values; j++) {
			if (!asn1_write_OctetString(state->out,
					       mod->values[j].data,
					       mod->values[j].length)) goto err;
		}
		if (!asn1_pop_tag(state->out)) goto err;
		if (!asn1_pop_tag(state->out)) goto err;
		if (!asn1_pop_tag(state->out)) goto err;
	}

	if (!asn1_pop_tag(state->out)) goto err;
	if (!asn1_pop_tag(state->out)) goto err;

	subreq = tldap_msg_send(state, ev, ld, state->id, state->out,
				sctrls, num_sctrls);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, tldap_modify_done, req);
	return req;

  err:

	tevent_req_ldap_error(req, TLDAP_ENCODING_ERROR);
	return tevent_req_post(req, ev);
}

static void tldap_modify_done(struct tevent_req *subreq)
{
	tldap_simple_done(subreq, TLDAP_RES_MODIFY);
}

TLDAPRC tldap_modify_recv(struct tevent_req *req)
{
	return tldap_simple_recv(req);
}

TLDAPRC tldap_modify(struct tldap_context *ld, const char *dn,
		     struct tldap_mod *mods, int num_mods,
		     struct tldap_control *sctrls, int num_sctrls,
		     struct tldap_control *cctrls, int num_cctrls)
 {
	TALLOC_CTX *frame = talloc_stackframe();
	struct tevent_context *ev;
	struct tevent_req *req;
	TLDAPRC rc = TLDAP_NO_MEMORY;

	ev = samba_tevent_context_init(frame);
	if (ev == NULL) {
		goto fail;
	}
	req = tldap_modify_send(frame, ev, ld, dn, mods, num_mods,
				sctrls, num_sctrls, cctrls, num_cctrls);
	if (req == NULL) {
		goto fail;
	}
	if (!tevent_req_poll(req, ev)) {
		rc = TLDAP_OPERATIONS_ERROR;
		goto fail;
	}
	rc = tldap_modify_recv(req);
	tldap_save_msg(ld, req);
 fail:
	TALLOC_FREE(frame);
	return rc;
}

static void tldap_delete_done(struct tevent_req *subreq);

struct tevent_req *tldap_delete_send(TALLOC_CTX *mem_ctx,
				     struct tevent_context *ev,
				     struct tldap_context *ld,
				     const char *dn,
				     struct tldap_control *sctrls,
				     int num_sctrls,
				     struct tldap_control *cctrls,
				     int num_cctrls)
{
	struct tevent_req *req, *subreq;
	struct tldap_req_state *state;

	req = tldap_req_create(mem_ctx, ld, &state);
	if (req == NULL) {
		return NULL;
	}

	if (!asn1_push_tag(state->out, TLDAP_REQ_DELETE)) goto err;
	if (!asn1_write(state->out, dn, strlen(dn))) goto err;
	if (!asn1_pop_tag(state->out)) goto err;

	subreq = tldap_msg_send(state, ev, ld, state->id, state->out,
				sctrls, num_sctrls);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, tldap_delete_done, req);
	return req;

  err:

	tevent_req_ldap_error(req, TLDAP_ENCODING_ERROR);
	return tevent_req_post(req, ev);
}

static void tldap_delete_done(struct tevent_req *subreq)
{
	tldap_simple_done(subreq, TLDAP_RES_DELETE);
}

TLDAPRC tldap_delete_recv(struct tevent_req *req)
{
	return tldap_simple_recv(req);
}

TLDAPRC tldap_delete(struct tldap_context *ld, const char *dn,
		     struct tldap_control *sctrls, int num_sctrls,
		     struct tldap_control *cctrls, int num_cctrls)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct tevent_context *ev;
	struct tevent_req *req;
	TLDAPRC rc = TLDAP_NO_MEMORY;

	ev = samba_tevent_context_init(frame);
	if (ev == NULL) {
		goto fail;
	}
	req = tldap_delete_send(frame, ev, ld, dn, sctrls, num_sctrls,
				cctrls, num_cctrls);
	if (req == NULL) {
		goto fail;
	}
	if (!tevent_req_poll(req, ev)) {
		rc = TLDAP_OPERATIONS_ERROR;
		goto fail;
	}
	rc = tldap_delete_recv(req);
	tldap_save_msg(ld, req);
 fail:
	TALLOC_FREE(frame);
	return rc;
}

int tldap_msg_id(const struct tldap_message *msg)
{
	return msg->id;
}

int tldap_msg_type(const struct tldap_message *msg)
{
	return msg->type;
}

const char *tldap_msg_matcheddn(struct tldap_message *msg)
{
	if (msg == NULL) {
		return NULL;
	}
	return msg->res_matcheddn;
}

const char *tldap_msg_diagnosticmessage(struct tldap_message *msg)
{
	if (msg == NULL) {
		return NULL;
	}
	return msg->res_diagnosticmessage;
}

const char *tldap_msg_referral(struct tldap_message *msg)
{
	if (msg == NULL) {
		return NULL;
	}
	return msg->res_referral;
}

void tldap_msg_sctrls(struct tldap_message *msg, int *num_sctrls,
		      struct tldap_control **sctrls)
{
	if (msg == NULL) {
		*sctrls = NULL;
		*num_sctrls = 0;
		return;
	}
	*sctrls = msg->res_sctrls;
	*num_sctrls = talloc_array_length(msg->res_sctrls);
}

struct tldap_message *tldap_ctx_lastmsg(struct tldap_context *ld)
{
	return ld->last_msg;
}

static const struct { TLDAPRC rc; const char *string; } tldaprc_errmap[] =
{
	{ TLDAP_SUCCESS,
	  "TLDAP_SUCCESS" },
	{ TLDAP_OPERATIONS_ERROR,
	  "TLDAP_OPERATIONS_ERROR" },
	{ TLDAP_PROTOCOL_ERROR,
	  "TLDAP_PROTOCOL_ERROR" },
	{ TLDAP_TIMELIMIT_EXCEEDED,
	  "TLDAP_TIMELIMIT_EXCEEDED" },
	{ TLDAP_SIZELIMIT_EXCEEDED,
	  "TLDAP_SIZELIMIT_EXCEEDED" },
	{ TLDAP_COMPARE_FALSE,
	  "TLDAP_COMPARE_FALSE" },
	{ TLDAP_COMPARE_TRUE,
	  "TLDAP_COMPARE_TRUE" },
	{ TLDAP_STRONG_AUTH_NOT_SUPPORTED,
	  "TLDAP_STRONG_AUTH_NOT_SUPPORTED" },
	{ TLDAP_STRONG_AUTH_REQUIRED,
	  "TLDAP_STRONG_AUTH_REQUIRED" },
	{ TLDAP_REFERRAL,
	  "TLDAP_REFERRAL" },
	{ TLDAP_ADMINLIMIT_EXCEEDED,
	  "TLDAP_ADMINLIMIT_EXCEEDED" },
	{ TLDAP_UNAVAILABLE_CRITICAL_EXTENSION,
	  "TLDAP_UNAVAILABLE_CRITICAL_EXTENSION" },
	{ TLDAP_CONFIDENTIALITY_REQUIRED,
	  "TLDAP_CONFIDENTIALITY_REQUIRED" },
	{ TLDAP_SASL_BIND_IN_PROGRESS,
	  "TLDAP_SASL_BIND_IN_PROGRESS" },
	{ TLDAP_NO_SUCH_ATTRIBUTE,
	  "TLDAP_NO_SUCH_ATTRIBUTE" },
	{ TLDAP_UNDEFINED_TYPE,
	  "TLDAP_UNDEFINED_TYPE" },
	{ TLDAP_INAPPROPRIATE_MATCHING,
	  "TLDAP_INAPPROPRIATE_MATCHING" },
	{ TLDAP_CONSTRAINT_VIOLATION,
	  "TLDAP_CONSTRAINT_VIOLATION" },
	{ TLDAP_TYPE_OR_VALUE_EXISTS,
	  "TLDAP_TYPE_OR_VALUE_EXISTS" },
	{ TLDAP_INVALID_SYNTAX,
	  "TLDAP_INVALID_SYNTAX" },
	{ TLDAP_NO_SUCH_OBJECT,
	  "TLDAP_NO_SUCH_OBJECT" },
	{ TLDAP_ALIAS_PROBLEM,
	  "TLDAP_ALIAS_PROBLEM" },
	{ TLDAP_INVALID_DN_SYNTAX,
	  "TLDAP_INVALID_DN_SYNTAX" },
	{ TLDAP_IS_LEAF,
	  "TLDAP_IS_LEAF" },
	{ TLDAP_ALIAS_DEREF_PROBLEM,
	  "TLDAP_ALIAS_DEREF_PROBLEM" },
	{ TLDAP_INAPPROPRIATE_AUTH,
	  "TLDAP_INAPPROPRIATE_AUTH" },
	{ TLDAP_INVALID_CREDENTIALS,
	  "TLDAP_INVALID_CREDENTIALS" },
	{ TLDAP_INSUFFICIENT_ACCESS,
	  "TLDAP_INSUFFICIENT_ACCESS" },
	{ TLDAP_BUSY,
	  "TLDAP_BUSY" },
	{ TLDAP_UNAVAILABLE,
	  "TLDAP_UNAVAILABLE" },
	{ TLDAP_UNWILLING_TO_PERFORM,
	  "TLDAP_UNWILLING_TO_PERFORM" },
	{ TLDAP_LOOP_DETECT,
	  "TLDAP_LOOP_DETECT" },
	{ TLDAP_NAMING_VIOLATION,
	  "TLDAP_NAMING_VIOLATION" },
	{ TLDAP_OBJECT_CLASS_VIOLATION,
	  "TLDAP_OBJECT_CLASS_VIOLATION" },
	{ TLDAP_NOT_ALLOWED_ON_NONLEAF,
	  "TLDAP_NOT_ALLOWED_ON_NONLEAF" },
	{ TLDAP_NOT_ALLOWED_ON_RDN,
	  "TLDAP_NOT_ALLOWED_ON_RDN" },
	{ TLDAP_ALREADY_EXISTS,
	  "TLDAP_ALREADY_EXISTS" },
	{ TLDAP_NO_OBJECT_CLASS_MODS,
	  "TLDAP_NO_OBJECT_CLASS_MODS" },
	{ TLDAP_RESULTS_TOO_LARGE,
	  "TLDAP_RESULTS_TOO_LARGE" },
	{ TLDAP_AFFECTS_MULTIPLE_DSAS,
	  "TLDAP_AFFECTS_MULTIPLE_DSAS" },
	{ TLDAP_OTHER,
	  "TLDAP_OTHER" },
	{ TLDAP_SERVER_DOWN,
	  "TLDAP_SERVER_DOWN" },
	{ TLDAP_LOCAL_ERROR,
	  "TLDAP_LOCAL_ERROR" },
	{ TLDAP_ENCODING_ERROR,
	  "TLDAP_ENCODING_ERROR" },
	{ TLDAP_DECODING_ERROR,
	  "TLDAP_DECODING_ERROR" },
	{ TLDAP_TIMEOUT,
	  "TLDAP_TIMEOUT" },
	{ TLDAP_AUTH_UNKNOWN,
	  "TLDAP_AUTH_UNKNOWN" },
	{ TLDAP_FILTER_ERROR,
	  "TLDAP_FILTER_ERROR" },
	{ TLDAP_USER_CANCELLED,
	  "TLDAP_USER_CANCELLED" },
	{ TLDAP_PARAM_ERROR,
	  "TLDAP_PARAM_ERROR" },
	{ TLDAP_NO_MEMORY,
	  "TLDAP_NO_MEMORY" },
	{ TLDAP_CONNECT_ERROR,
	  "TLDAP_CONNECT_ERROR" },
	{ TLDAP_NOT_SUPPORTED,
	  "TLDAP_NOT_SUPPORTED" },
	{ TLDAP_CONTROL_NOT_FOUND,
	  "TLDAP_CONTROL_NOT_FOUND" },
	{ TLDAP_NO_RESULTS_RETURNED,
	  "TLDAP_NO_RESULTS_RETURNED" },
	{ TLDAP_MORE_RESULTS_TO_RETURN,
	  "TLDAP_MORE_RESULTS_TO_RETURN" },
	{ TLDAP_CLIENT_LOOP,
	  "TLDAP_CLIENT_LOOP" },
	{ TLDAP_REFERRAL_LIMIT_EXCEEDED,
	  "TLDAP_REFERRAL_LIMIT_EXCEEDED" },
};

const char *tldap_rc2string(TLDAPRC rc)
{
	size_t i;

	for (i=0; i<ARRAY_SIZE(tldaprc_errmap); i++) {
		if (TLDAP_RC_EQUAL(rc, tldaprc_errmap[i].rc)) {
			return tldaprc_errmap[i].string;
		}
	}

	return "Unknown LDAP Error";
}
