/*
 * Unix SMB/CIFS implementation.
 *
 * Unit tests for gensec_spnego
 *
 * Copyright (C) 2026 Andreas Schneider <asn@samba.org>
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

#include "lib/util/cmocka_samba.h"
#include "auth/gensec/spnego.c"

/*
 * gensec_may_reset_crypto() is hidden (_PRIVATE_) in libgensec, so it is
 * not visible to this standalone test binary. It is only reachable from
 * gensec_spnego_update_post(), which none of these tests exercise.
 */
NTSTATUS gensec_may_reset_crypto(struct gensec_security *gensec_security,
				 bool full_reset)
{
	fail_msg("gensec_may_reset_crypto() is not implemented in this test");
	return NT_STATUS_NOT_IMPLEMENTED;
}

static struct spnego_state *make_spnego_state(TALLOC_CTX *mem_ctx,
					      size_t num_targs)
{
	struct spnego_state *spnego_state = talloc_zero(mem_ctx,
							struct spnego_state);

	assert_non_null(spnego_state);

	spnego_state->neg_oid = OID_KERBEROS5;
	spnego_state->num_targs = num_targs;

	return spnego_state;
}

static struct spnego_negTokenTarg parse_negTokenTarg(TALLOC_CTX *mem_ctx,
						     DATA_BLOB out)
{
	struct spnego_data spnego_out = {};
	ssize_t len;

	len = spnego_read_data(mem_ctx, out, &spnego_out);
	assert_true(len > 0);
	assert_int_equal(spnego_out.type, SPNEGO_NEG_TOKEN_TARG);

	return spnego_out.negTokenTarg;
}

/*
 * Windows only sends supportedMech on the first NEG_TOKEN_TARG of a
 * negotiation. A multi-round exchange (e.g. IAKerb relayed through a KDC)
 * must not repeat it on later legs, or a real Windows client resets the
 * connection.
 */
static void test_server_response_first_targ_more_processing(void **state)
{
	TALLOC_CTX *mem_ctx = *state;
	struct spnego_state *spnego_state = make_spnego_state(mem_ctx, 0);
	DATA_BLOB unwrapped_out = data_blob_string_const("resp-token");
	struct spnego_negTokenTarg targ;
	DATA_BLOB out = data_blob_null;
	NTSTATUS status;

	status = gensec_spnego_server_response(
		spnego_state,
		mem_ctx,
		NT_STATUS_MORE_PROCESSING_REQUIRED,
		unwrapped_out,
		data_blob_null,
		&out);
	assert_ntstatus_equal(status, NT_STATUS_MORE_PROCESSING_REQUIRED);
	assert_int_equal(spnego_state->num_targs, 1);
	assert_int_equal(spnego_state->state_position, SPNEGO_SERVER_TARG);

	targ = parse_negTokenTarg(mem_ctx, out);
	assert_non_null(targ.supportedMech);
	assert_string_equal(targ.supportedMech, OID_KERBEROS5);
	assert_int_equal(targ.negResult, SPNEGO_ACCEPT_INCOMPLETE);
}

static void test_server_response_later_targ_more_processing(void **state)
{
	TALLOC_CTX *mem_ctx = *state;
	struct spnego_state *spnego_state = make_spnego_state(mem_ctx, 1);
	DATA_BLOB unwrapped_out = data_blob_string_const("resp-token");
	struct spnego_negTokenTarg targ;
	DATA_BLOB out = data_blob_null;
	NTSTATUS status;

	status = gensec_spnego_server_response(
		spnego_state,
		mem_ctx,
		NT_STATUS_MORE_PROCESSING_REQUIRED,
		unwrapped_out,
		data_blob_null,
		&out);
	assert_ntstatus_equal(status, NT_STATUS_MORE_PROCESSING_REQUIRED);
	assert_int_equal(spnego_state->num_targs, 2);
	assert_int_equal(spnego_state->state_position, SPNEGO_SERVER_TARG);

	targ = parse_negTokenTarg(mem_ctx, out);
	assert_null(targ.supportedMech);
	assert_int_equal(targ.negResult, SPNEGO_ACCEPT_INCOMPLETE);
}

static void test_server_response_first_targ_ok(void **state)
{
	TALLOC_CTX *mem_ctx = *state;
	struct spnego_state *spnego_state = make_spnego_state(mem_ctx, 0);
	DATA_BLOB unwrapped_out = data_blob_string_const("resp-token");
	struct spnego_negTokenTarg targ;
	DATA_BLOB out = data_blob_null;
	NTSTATUS status;

	status = gensec_spnego_server_response(spnego_state,
					       mem_ctx,
					       NT_STATUS_OK,
					       unwrapped_out,
					       data_blob_null,
					       &out);
	assert_ntstatus_ok(status);
	assert_int_equal(spnego_state->num_targs, 1);
	assert_int_equal(spnego_state->state_position, SPNEGO_DONE);

	targ = parse_negTokenTarg(mem_ctx, out);
	assert_non_null(targ.supportedMech);
	assert_string_equal(targ.supportedMech, OID_KERBEROS5);
	assert_int_equal(targ.negResult, SPNEGO_ACCEPT_COMPLETED);
}

static void test_server_response_later_targ_ok(void **state)
{
	TALLOC_CTX *mem_ctx = *state;
	struct spnego_state *spnego_state = make_spnego_state(mem_ctx, 1);
	DATA_BLOB unwrapped_out = data_blob_string_const("resp-token");
	struct spnego_negTokenTarg targ;
	DATA_BLOB out = data_blob_null;
	NTSTATUS status;

	status = gensec_spnego_server_response(spnego_state,
					       mem_ctx,
					       NT_STATUS_OK,
					       unwrapped_out,
					       data_blob_null,
					       &out);
	assert_ntstatus_ok(status);
	assert_int_equal(spnego_state->num_targs, 2);
	assert_int_equal(spnego_state->state_position, SPNEGO_DONE);

	targ = parse_negTokenTarg(mem_ctx, out);
	assert_null(targ.supportedMech);
	assert_int_equal(targ.negResult, SPNEGO_ACCEPT_COMPLETED);
}

static void test_server_response_ok_no_data(void **state)
{
	TALLOC_CTX *mem_ctx = *state;
	struct spnego_state *spnego_state = make_spnego_state(mem_ctx, 0);
	struct spnego_negTokenTarg targ;
	DATA_BLOB out = data_blob_null;
	NTSTATUS status;

	status = gensec_spnego_server_response(spnego_state,
					       mem_ctx,
					       NT_STATUS_OK,
					       data_blob_null,
					       data_blob_null,
					       &out);
	assert_ntstatus_ok(status);
	assert_int_equal(spnego_state->num_targs, 1);

	targ = parse_negTokenTarg(mem_ctx, out);
	assert_null(targ.supportedMech);
	assert_int_equal(targ.negResult, SPNEGO_ACCEPT_COMPLETED);
}

int main(int argc, char *argv[])
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(
			test_server_response_first_targ_more_processing),
		cmocka_unit_test(
			test_server_response_later_targ_more_processing),
		cmocka_unit_test(test_server_response_first_targ_ok),
		cmocka_unit_test(test_server_response_later_targ_ok),
		cmocka_unit_test(test_server_response_ok_no_data),
	};

	if (argc == 2) {
		cmocka_set_test_filter(argv[1]);
	}
	cmocka_set_message_output(CM_OUTPUT_SUBUNIT);

	return cmocka_run_group_tests(tests,
				      setup_talloc_context,
				      teardown_talloc_context);
}
