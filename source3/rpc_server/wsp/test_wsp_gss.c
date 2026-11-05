/*
 * Unix SMB/CIFS implementation.
 *
 * Unit tests for the WSP server code in wsp_gss.c
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <setjmp.h>
#include <cmocka.h>

/*
 * wsp_request_send() gets its backend from get_backend_impl(): give it
 * the fake backend below instead of the configured one.
 */
#define get_backend_impl test_backend_impl

#include "wsp_gss.c"

static struct wsp_abstract_interface fake_if;

struct wsp_abstract_interface *test_backend_impl(int backend)
{
	return &fake_if;
}

/*
 * A backend request stays pending, like one waiting for a reply from
 * the search backend, until the test completes it.
 */
static struct tevent_req *pending_backend_req;

/* Set once the client has closed the pipe */
static bool pipe_closed;

/* Set if the request of the message completes */
static bool request_done_called;

struct fake_pending_state {
	struct tevent_req *req;
};

static int fake_pending_state_destructor(struct fake_pending_state *state)
{
	if (pending_backend_req == state->req) {
		pending_backend_req = NULL;
	}
	return 0;
}

static struct tevent_req *fake_pending_send(TALLOC_CTX *ctx)
{
	struct tevent_req *req = NULL;
	struct fake_pending_state *state = NULL;

	req = tevent_req_create(ctx, &state, struct fake_pending_state);
	if (req == NULL) {
		return NULL;
	}
	state->req = req;
	pending_backend_req = req;
	talloc_set_destructor(state, fake_pending_state_destructor);
	return req;
}

/*
 * Each recv function of the fake backend starts here: the server is
 * collecting the backend's reply to fill in the response to the
 * message. Once the client has closed the pipe, that response has been
 * freed, so the reply must not be collected any more. Fail the test
 * here, before the handler writes the reply into the freed response
 * and completes into the freed request: that use after free could
 * crash the test binary, or go unnoticed without AddressSanitizer.
 */
static void fake_reply_received(struct tevent_req *req)
{
	if (pipe_closed) {
		fail_msg("backend reply collected after the client closed "
			 "the pipe, for a response that was freed with it");
	}
	tevent_req_received(req);
}

static bool fake_has_cursor(struct wspd_client_state *client,
			    uint32_t handle,
			    uint32_t hcursor)
{
	return true;
}

static bool fake_hasbindings(struct wspd_client_state *client,
			     uint32_t handle,
			     uint32_t hcursor)
{
	return true;
}

static struct wsp_ctablecolumn *fake_getbindings(
			struct wspd_client_state *client,
			uint32_t handle,
			uint32_t hcursor,
			uint32_t *ncols)
{
	*ncols = 0;
	return NULL;
}

static uint32_t fake_getnextgetrowsposition(struct wspd_client_state *client,
					    uint32_t handle,
					    uint32_t hcursor,
					    uint32_t chapter)
{
	return 0;
}

static void fake_setnextgetrowsposition(struct wspd_client_state *client,
					uint32_t handle,
					uint32_t hcursor,
					uint32_t chapter,
					uint32_t pos)
{
}

static struct tevent_req *fake_getstate_send(
			TALLOC_CTX *ctx,
			struct tevent_context *ev,
			struct wspd_client_state *client_state)
{
	return fake_pending_send(ctx);
}

static HRESULT fake_getstate_recv(struct tevent_req *req,
				  struct wsp_cpmcistateinout *out)
{
	fake_reply_received(req);
	*out = (struct wsp_cpmcistateinout) {
		.cbstruct = 60,
		.cdocuments = 1,
		.ctotaldocuments = 1,
	};
	return HRES_OK;
}

static struct tevent_req *fake_getquerystatus_send(
			TALLOC_CTX *ctx,
			struct tevent_context *ev,
			struct wspd_client_state *client_state,
			uint32_t queryidentifier)
{
	return fake_pending_send(ctx);
}

static HRESULT fake_getquerystatus_recv(struct tevent_req *req,
					uint32_t *querystatus)
{
	fake_reply_received(req);
	*querystatus = 0;
	return HRES_OK;
}

static struct tevent_req *fake_getratiofinished_send(
			TALLOC_CTX *ctx,
			struct tevent_context *ev,
			struct wspd_client_state *client_state,
			uint32_t queryidentifier,
			uint32_t cursorhandle)
{
	return fake_pending_send(ctx);
}

static HRESULT fake_getratiofinished_recv(struct tevent_req *req,
					  uint32_t *denominator,
					  uint32_t *numerator,
					  uint32_t *crows,
					  uint32_t *fnewrows)
{
	fake_reply_received(req);
	*denominator = 1;
	*numerator = 1;
	*crows = 0;
	*fnewrows = 0;
	return HRES_OK;
}

static struct tevent_req *fake_getrows_send(
			TALLOC_CTX *ctx,
			struct tevent_context *ev,
			struct wspd_client_state *client_state,
			uint32_t queryidentifier,
			uint32_t cursorhandle,
			uint32_t numrowsrequested,
			uint32_t fetchforward)
{
	return fake_pending_send(ctx);
}

static HRESULT fake_getrows_recv(struct tevent_req *req,
				 TALLOC_CTX *ctx,
				 struct wsp_cbasestoragevariant ***rowsarray,
				 bool *nomorerowstoreturn,
				 uint32_t *numrowsreturned)
{
	fake_reply_received(req);
	*rowsarray = NULL;
	*nomorerowstoreturn = true;
	*numrowsreturned = 0;
	return HRES_OK;
}

struct test_ctx {
	struct tevent_context *ev;
	struct wsp_gss_state *gss_state;
	struct auth_session_info *session_info;
	struct wspd_client_state *client;
};

static int setup(void **state)
{
	struct test_ctx *t = talloc_zero(NULL, struct test_ctx);

	assert_non_null(t);
	t->ev = tevent_context_init(t);
	assert_non_null(t->ev);
	t->gss_state = wsp_gss_state_create(t->ev);
	assert_non_null(t->gss_state);
	t->session_info = talloc_zero(t, struct auth_session_info);
	assert_non_null(t->session_info);
	t->client = wsp_gss_client_state_create(t->session_info,
						t->gss_state);
	assert_non_null(t->client);

	fake_if = (struct wsp_abstract_interface) {
		.clientqueryhascursorhandle = fake_has_cursor,
		.hasbindings = fake_hasbindings,
		.getbindings = fake_getbindings,
		.getnextgetrowsposition = fake_getnextgetrowsposition,
		.setnextgetrowsposition = fake_setnextgetrowsposition,
		.getstate_send = fake_getstate_send,
		.getstate_recv = fake_getstate_recv,
		.getquerystatus_send = fake_getquerystatus_send,
		.getquerystatus_recv = fake_getquerystatus_recv,
		.getratiofinishedparams_send = fake_getratiofinished_send,
		.getratiofinishedparams_recv = fake_getratiofinished_recv,
		.getrows_send = fake_getrows_send,
		.getrows_recv = fake_getrows_recv,
	};

	pending_backend_req = NULL;
	pipe_closed = false;
	request_done_called = false;
	*state = t;
	return 0;
}

static int teardown(void **state)
{
	struct test_ctx *t = *state;

	TALLOC_FREE(t->client);
	TALLOC_FREE(t->gss_state);
	TALLOC_FREE(t);
	return 0;
}

/* As if CPMConnect had succeeded on this pipe */
static void setup_connected(struct test_ctx *t)
{
	uint32_t handle = t->client->client_data->fid;
	struct uint32_list *item = NULL;
	struct client_version_map *version = NULL;

	item = talloc_zero(t->gss_state, struct uint32_list);
	assert_non_null(item);
	item->number = handle;
	DLIST_ADD_END(t->gss_state->connectedclientsidentifiers, item);

	version = talloc_zero(t->gss_state, struct client_version_map);
	assert_non_null(version);
	version->fid_handle = handle;
	version->version = WINDOWS_32_BIT;
	DLIST_ADD_END(t->gss_state->connectedclientversions, version);
}

/*
 * As if CPMConnect, CPMCreateQuery and CPMSetBindingsIn had succeeded
 * on this pipe.
 */
static void setup_query(struct test_ctx *t)
{
	struct wsp_client_data *client_data = t->client->client_data;
	const uint32_t prev[] = {
		CPMCONNECT, CPMCREATEQUERY, CPMSETBINDINGSIN,
	};
	struct uint32_list *item = NULL;
	struct query_rows_info *info = NULL;
	size_t i;

	setup_connected(t);

	info = talloc_zero(t->gss_state, struct query_rows_info);
	assert_non_null(info);
	info->handle = client_data->fid;
	DLIST_ADD_END(t->gss_state->query_info_map, info);

	for (i = 0; i < ARRAY_SIZE(prev); i++) {
		item = talloc_zero(client_data, struct uint32_list);
		assert_non_null(item);
		item->number = prev[i];
		DLIST_ADD_END(client_data->prev_msgs, item);
	}
}

/* A message as read from the pipe: the header, with its checksum */
static DATA_BLOB make_msg(TALLOC_CTX *mem_ctx, uint32_t msgid,
			  const uint8_t *payload, size_t len)
{
	DATA_BLOB blob = data_blob_talloc_zero(mem_ctx, MSG_HEADER_SIZE + len);
	struct wsp_header header = {
		.msg = msgid,
	};

	assert_non_null(blob.data);
	memcpy(blob.data + MSG_HEADER_SIZE, payload, len);
	SIVAL(blob.data, 0, msgid);
	SIVAL(blob.data, 8, calculate_checksum(&blob, &header));
	return blob;
}

static void request_done(struct tevent_req *req)
{
	request_done_called = true;
}

/*
 * The client closes the pipe while the handler of its message waits for
 * the backend, and the backend answers later.
 *
 * npsd_wsp_server.c watches the pipe with tstream_monitor_send() for the
 * whole connection. When the client goes away, the connection is freed
 * and wsp_server_connection_destructor() frees the wsp_request_send()
 * request of the message in progress, together with the response,
 * header and output blob it owns. Nothing of the message may then be
 * left behind: no backend reply may be collected for it, and nothing of
 * it may stay on the long-lived wsp_gss_state.
 */
static void close_pipe_while_backend_works(struct test_ctx *t,
					   uint32_t msgid,
					   const uint8_t *payload,
					   size_t len)
{
	TALLOC_CTX *conn = talloc_new(t);
	DATA_BLOB in = make_msg(conn, msgid, payload, len);
	size_t server_blocks = talloc_total_blocks(t->gss_state);
	struct tevent_req *req = NULL;

	/* as wsp_server_connection_in_done() */
	req = wsp_request_send(t->client, t->ev, t->client, &in);
	assert_non_null(req);
	tevent_req_set_callback(req, request_done, NULL);
	assert_true(tevent_req_is_in_progress(req));
	assert_non_null(pending_backend_req);

	/* the client closes the pipe */
	TALLOC_FREE(req);
	TALLOC_FREE(conn);
	pipe_closed = true;

	/* the backend answers */
	if (pending_backend_req != NULL) {
		tevent_req_done(pending_backend_req);
	}

	assert_false(request_done_called);
	assert_int_equal(talloc_total_blocks(t->gss_state), server_blocks);
}

static void test_cistateinout_close_pipe(void **state)
{
	/* CPMCiStateInOut: cbStruct, then the counters (before CPMConnect) */
	const uint8_t payload[60] = { 60, 0, 0, 0 };

	close_pipe_while_backend_works(*state, CPMCISTATEOUT,
				       payload, sizeof(payload));
}

static void test_querystatus_close_pipe(void **state)
{
	/* CPMGetQueryStatusIn: hCursor */
	const uint8_t payload[4] = { 1, 0, 0, 0 };

	setup_query(*state);
	close_pipe_while_backend_works(*state, CPMGETQUERYSTATUS,
				       payload, sizeof(payload));
}

static void test_querystatusex_close_pipe(void **state)
{
	/* CPMGetQueryStatusExIn: hCursor, bmk */
	const uint8_t payload[8] = { 1, 0, 0, 0, 0xfc, 0xff, 0xff, 0xff };

	setup_query(*state);
	close_pipe_while_backend_works(*state, CPMGETQUERYSTATUSEX,
				       payload, sizeof(payload));
}

static void test_ratiofinished_close_pipe(void **state)
{
	/* CPMRatioFinishedIn: hCursor, fQuick */
	const uint8_t payload[8] = { 1, 0, 0, 0, 0, 0, 0, 0 };

	setup_query(*state);
	close_pipe_while_backend_works(*state, CPMRATIOFINISHED,
				       payload, sizeof(payload));
}

static void test_getrows_close_pipe(void **state)
{
	/*
	 * CPMGetRowsIn for one row from the current position
	 * (eType EROWSEEKNONE, so no seek description)
	 */
	uint8_t payload[40] = { 0 };

	SIVAL(payload, 0, 1);		/* hCursor */
	SIVAL(payload, 4, 1);		/* cRowsToTransfer */
	SIVAL(payload, 8, 16);		/* cbRowWidth */
	SIVAL(payload, 16, MSG_HEADER_SIZE + MSG_GETROWOUT_MAXSEEK);
					/* cbReserved */
	SIVAL(payload, 20, 0x1000);	/* cbReadBuffer */

	setup_query(*state);
	close_pipe_while_backend_works(*state, CPMGETROWS,
				       payload, sizeof(payload));
}

#define ROW_WIDTH 16

static void setup_vector_column(TALLOC_CTX *mem_ctx,
				struct wsp_ctablecolumn *col,
				struct wsp_cbasestoragevariant *val)
{
	struct vt_lpwstr *data = NULL;

	*col = (struct wsp_ctablecolumn) {
		.vtype = VT_VARIANT,
		.valueused = 1,
		.valueoffset.value = 0,
	};

	data = talloc_zero_array(mem_ctx, struct vt_lpwstr, 1);
	assert_non_null(data);
	data[0].value = talloc_strdup(data, "Document");
	assert_non_null(data[0].value);

	*val = (struct wsp_cbasestoragevariant) {
		.vtype = VT_VECTOR | VT_LPWSTR,
		.vvalue.vt_lpwstr_v.vvector_elements = 1,
		.vvalue.vt_lpwstr_v.vvector_data = data,
	};
}

/*
 * A vector value that fits into the remaining buffer is stored at the
 * end of the buffer, followed by its address list.
 */
static void test_push_column_vector_fits(void **state)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct wsp_ctablecolumn col;
	struct wsp_cbasestoragevariant val;
	DATA_BLOB blob = data_blob_talloc_zero(mem_ctx, 128);
	uint32_t end_pos = blob.length;
	enum ndr_err_code err;

	setup_vector_column(mem_ctx, &col, &val);

	err = push_column(mem_ctx, &col, &val, &blob, &end_pos,
			  0, 0, ROW_WIDTH, false);
	assert_int_equal(err, NDR_ERR_SUCCESS);
	assert_true(end_pos > ROW_WIDTH);
	assert_true(end_pos < blob.length);

	TALLOC_FREE(mem_ctx);
}

/*
 * A vector value larger than the space left between the end of the
 * row and the variable data already stored must be rejected without
 * moving the end position.
 */
static void test_push_column_vector_too_big(void **state)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct wsp_ctablecolumn col;
	struct wsp_cbasestoragevariant val;
	DATA_BLOB blob = data_blob_talloc_zero(mem_ctx, ROW_WIDTH + 4);
	uint32_t end_pos = blob.length;
	enum ndr_err_code err;

	setup_vector_column(mem_ctx, &col, &val);

	err = push_column(mem_ctx, &col, &val, &blob, &end_pos,
			  0, 0, ROW_WIDTH, false);
	assert_int_not_equal(err, NDR_ERR_SUCCESS);
	assert_int_equal(end_pos, blob.length);

	TALLOC_FREE(mem_ctx);
}

/* The same for the 64 bit layout, which uses 8 byte addresses */
static void test_push_column_vector_too_big_64bit(void **state)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct wsp_ctablecolumn col;
	struct wsp_cbasestoragevariant val;
	DATA_BLOB blob = data_blob_talloc_zero(mem_ctx, ROW_WIDTH + 4);
	uint32_t end_pos = blob.length;
	enum ndr_err_code err;

	setup_vector_column(mem_ctx, &col, &val);

	err = push_column(mem_ctx, &col, &val, &blob, &end_pos,
			  0, 0, ROW_WIDTH, true);
	assert_int_not_equal(err, NDR_ERR_SUCCESS);
	assert_int_equal(end_pos, blob.length);

	TALLOC_FREE(mem_ctx);
}

int main(int argc, const char **argv)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test_setup_teardown(
			test_cistateinout_close_pipe, setup, teardown),
		cmocka_unit_test_setup_teardown(
			test_querystatus_close_pipe, setup, teardown),
		cmocka_unit_test_setup_teardown(
			test_querystatusex_close_pipe, setup, teardown),
		cmocka_unit_test_setup_teardown(
			test_ratiofinished_close_pipe, setup, teardown),
		cmocka_unit_test_setup_teardown(
			test_getrows_close_pipe, setup, teardown),
		cmocka_unit_test(test_push_column_vector_fits),
		cmocka_unit_test(test_push_column_vector_too_big),
		cmocka_unit_test(test_push_column_vector_too_big_64bit),
	};

	cmocka_set_message_output(CM_OUTPUT_SUBUNIT);
	return cmocka_run_group_tests(tests, NULL, NULL);
}
