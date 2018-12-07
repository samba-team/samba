/*
   Unix SMB/CIFS implementation.
   Test cleanup behaviour
   Copyright (C) Volker Lendecke 2011

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

#include "includes.h"
#include "locking/proto.h"
#include "torture/proto.h"
#include "system/filesys.h"
#include "system/select.h"
#include "libsmb/libsmb.h"
#include "libcli/smb/smbXcli_base.h"
#include "libcli/security/security.h"
#include "lib/util/tevent_ntstatus.h"

struct create_cancel_state {
	uint8_t dummy;
};

static void create_cancel_done(struct tevent_req *subreq);

static struct tevent_req *create_cancel_send(
	TALLOC_CTX *mem_ctx, struct tevent_context *ev,
	struct cli_state *cli, const char *fname)
{
	struct tevent_req *req, *subreq;
	struct create_cancel_state *state;

	req = tevent_req_create(mem_ctx, &state, struct create_cancel_state);
	if (req == NULL) {
		return NULL;
	}

	subreq = cli_ntcreate_send(
		mem_ctx, ev, cli, fname, 0, FILE_GENERIC_READ,
		FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ|FILE_SHARE_WRITE,
		FILE_OPEN_IF, 0, SMB2_IMPERSONATION_IMPERSONATION, 0);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	if (!tevent_req_cancel(subreq)) {
		tevent_req_oom(req);
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, create_cancel_done, req);
	return req;
}

static void create_cancel_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	NTSTATUS status;

	status = cli_ntcreate_recv(subreq, NULL, NULL);
	TALLOC_FREE(subreq);
	if (!NT_STATUS_EQUAL(status, NT_STATUS_CANCELLED)) {
		if (NT_STATUS_IS_OK(status)) {
			status = NT_STATUS_UNSUCCESSFUL;
		}
		tevent_req_nterror(req, status);
		return;
	}
	tevent_req_done(req);
}

static NTSTATUS create_cancel_recv(struct tevent_req *req)
{
	return tevent_req_simple_recv_ntstatus(req);
}

static NTSTATUS create_cancel(struct cli_state *cli, const char *fname)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct tevent_context *ev;
	struct tevent_req *req;
	NTSTATUS status = NT_STATUS_NO_MEMORY;

	ev = samba_tevent_context_init(frame);
	if (ev == NULL) {
		goto fail;
	}
	req = create_cancel_send(frame, ev, cli, fname);
	if (req == NULL) {
		goto fail;
	}
	if (!tevent_req_poll_ntstatus(req, ev, &status)) {
		goto fail;
	}
	status = create_cancel_recv(req);
 fail:
	TALLOC_FREE(frame);
	return status;
}

bool run_oplock_cancel(int dummy)
{
	struct cli_state *cli1, *cli2;
	const char *fname = "oplock-cancel";
	uint16_t fnum1;
	NTSTATUS status;
	/*
	 * Currently this test seems to work only
	 * with SMB2/3 and only against Samba.
	 *
	 * TODO: we should change our server
	 * to ignore cancel for SMB2 Create
	 * and behave like Windows.
	 */
	int flags = CLI_FULL_CONNECTION_DISABLE_SMB1;

	if (!torture_open_connection_flags(&cli1, 0, flags)) {
		return false;
	}
	cli1->use_oplocks = true;

	if (!torture_open_connection_flags(&cli2, 0, flags)) {
		return false;
	}
	cli2->use_oplocks = true;

	status = cli_ntcreate(
		cli1, fname, 0, FILE_GENERIC_READ, FILE_ATTRIBUTE_NORMAL,
		FILE_SHARE_READ|FILE_SHARE_WRITE, FILE_OPEN_IF, 0, 0,
		&fnum1, NULL);
	if (!NT_STATUS_IS_OK(status)) {
		d_printf("cli_ntcreate failed: %s\n", nt_errstr(status));
		return false;
	}

	status = create_cancel(cli2, fname);
	if (!NT_STATUS_IS_OK(status)) {
		d_printf("create_cancel failed: %s\n", nt_errstr(status));
		return false;
	}

	TALLOC_FREE(cli1);

	/*
	 * Give cli1's smbd time to inform cli2's smbd
	 */
	smb_msleep(5000);

	status = cli_unlink(cli2, fname,
			    FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN);
	if (!NT_STATUS_IS_OK(status)) {
		d_printf("cli_unlink failed: %s\n", nt_errstr(status));
		return false;
	}

	return true;
}
