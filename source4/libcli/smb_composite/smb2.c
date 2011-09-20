/* 
   Unix SMB/CIFS implementation.

   Copyright (C) Andrew Tridgell 2008
   
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
  a composite API for making SMB-like calls using SMB2. This is useful
  as SMB2 often requires more than one requests where a single SMB
  request would do. In converting code that uses SMB to use SMB2,
  these routines make life a lot easier
*/


#include "includes.h"
#include <tevent.h>
#include "lib/util/tevent_ntstatus.h"
#include "libcli/raw/libcliraw.h"
#include "libcli/raw/raw_proto.h"
#include "libcli/composite/composite.h"
#include "libcli/smb_composite/smb_composite.h"
#include "libcli/smb2/smb2_calls.h"

/*
  continue after a SMB2 close
 */
static void continue_close(struct smb2_request *req)
{
	struct composite_context *ctx = talloc_get_type(req->async.private_data, 
							struct composite_context);
	NTSTATUS status;
	struct smb2_close close_parm;

	status = smb2_close_recv(req, &close_parm);
	composite_error(ctx, status);	
}

/*
  continue after the create in a composite unlink
 */
static void continue_unlink(struct smb2_request *req)
{
	struct composite_context *ctx = talloc_get_type(req->async.private_data, 
							struct composite_context);
	struct smb2_tree *tree = req->tree;
	struct smb2_create create_parm;
	struct smb2_close close_parm;
	NTSTATUS status;

	status = smb2_create_recv(req, ctx, &create_parm);
	if (!NT_STATUS_IS_OK(status)) {
		composite_error(ctx, status);
		return;
	}

	ZERO_STRUCT(close_parm);
	close_parm.in.file.handle = create_parm.out.file.handle;
	
	req = smb2_close_send(tree, &close_parm);
	composite_continue_smb2(ctx, req, continue_close, ctx);
}

/*
  composite SMB2 unlink call
*/
struct composite_context *smb2_composite_unlink_send(struct smb2_tree *tree, 
						     union smb_unlink *io)
{
	struct composite_context *ctx;
	struct smb2_create create_parm;
	struct smb2_request *req;

	ctx = composite_create(tree, tree->session->transport->ev);
	if (ctx == NULL) return NULL;

	/* check for wildcards - we could support these with a
	   search, but for now they aren't necessary */
	if (strpbrk(io->unlink.in.pattern, "*?<>") != NULL) {
		composite_error(ctx, NT_STATUS_NOT_SUPPORTED);
		return ctx;
	}

	ZERO_STRUCT(create_parm);
	create_parm.in.desired_access     = SEC_STD_DELETE;
	create_parm.in.create_disposition = NTCREATEX_DISP_OPEN;
	create_parm.in.share_access = 
		NTCREATEX_SHARE_ACCESS_DELETE|
		NTCREATEX_SHARE_ACCESS_READ|
		NTCREATEX_SHARE_ACCESS_WRITE;
	create_parm.in.create_options = 
		NTCREATEX_OPTIONS_DELETE_ON_CLOSE |
		NTCREATEX_OPTIONS_NON_DIRECTORY_FILE;
	create_parm.in.fname = io->unlink.in.pattern;
	if (create_parm.in.fname[0] == '\\') {
		create_parm.in.fname++;
	}

	req = smb2_create_send(tree, &create_parm);

	composite_continue_smb2(ctx, req, continue_unlink, ctx);
	return ctx;
}


/*
  composite unlink call - sync interface
*/
NTSTATUS smb2_composite_unlink(struct smb2_tree *tree, union smb_unlink *io)
{
	struct composite_context *c = smb2_composite_unlink_send(tree, io);
	return composite_wait_free(c);
}




/*
  continue after the create in a composite mkdir
 */
static void continue_mkdir(struct smb2_request *req)
{
	struct composite_context *ctx = talloc_get_type(req->async.private_data, 
							struct composite_context);
	struct smb2_tree *tree = req->tree;
	struct smb2_create create_parm;
	struct smb2_close close_parm;
	NTSTATUS status;

	status = smb2_create_recv(req, ctx, &create_parm);
	if (!NT_STATUS_IS_OK(status)) {
		composite_error(ctx, status);
		return;
	}

	ZERO_STRUCT(close_parm);
	close_parm.in.file.handle = create_parm.out.file.handle;
	
	req = smb2_close_send(tree, &close_parm);
	composite_continue_smb2(ctx, req, continue_close, ctx);
}

/*
  composite SMB2 mkdir call
*/
struct composite_context *smb2_composite_mkdir_send(struct smb2_tree *tree, 
						     union smb_mkdir *io)
{
	struct composite_context *ctx;
	struct smb2_create create_parm;
	struct smb2_request *req;

	ctx = composite_create(tree, tree->session->transport->ev);
	if (ctx == NULL) return NULL;

	ZERO_STRUCT(create_parm);

	create_parm.in.desired_access = SEC_FLAG_MAXIMUM_ALLOWED;
	create_parm.in.share_access = 
		NTCREATEX_SHARE_ACCESS_READ|
		NTCREATEX_SHARE_ACCESS_WRITE;
	create_parm.in.create_options = NTCREATEX_OPTIONS_DIRECTORY;
	create_parm.in.file_attributes   = FILE_ATTRIBUTE_DIRECTORY;
	create_parm.in.create_disposition = NTCREATEX_DISP_CREATE;
	create_parm.in.fname = io->mkdir.in.path;
	if (create_parm.in.fname[0] == '\\') {
		create_parm.in.fname++;
	}

	req = smb2_create_send(tree, &create_parm);

	composite_continue_smb2(ctx, req, continue_mkdir, ctx);

	return ctx;
}


/*
  composite mkdir call - sync interface
*/
NTSTATUS smb2_composite_mkdir(struct smb2_tree *tree, union smb_mkdir *io)
{
	struct composite_context *c = smb2_composite_mkdir_send(tree, io);
	return composite_wait_free(c);
}



/*
  continue after the create in a composite rmdir
 */
static void continue_rmdir(struct smb2_request *req)
{
	struct composite_context *ctx = talloc_get_type(req->async.private_data, 
							struct composite_context);
	struct smb2_tree *tree = req->tree;
	struct smb2_create create_parm;
	struct smb2_close close_parm;
	NTSTATUS status;

	status = smb2_create_recv(req, ctx, &create_parm);
	if (!NT_STATUS_IS_OK(status)) {
		composite_error(ctx, status);
		return;
	}

	ZERO_STRUCT(close_parm);
	close_parm.in.file.handle = create_parm.out.file.handle;
	
	req = smb2_close_send(tree, &close_parm);
	composite_continue_smb2(ctx, req, continue_close, ctx);
}

/*
  composite SMB2 rmdir call
*/
struct composite_context *smb2_composite_rmdir_send(struct smb2_tree *tree, 
						    struct smb_rmdir *io)
{
	struct composite_context *ctx;
	struct smb2_create create_parm;
	struct smb2_request *req;

	ctx = composite_create(tree, tree->session->transport->ev);
	if (ctx == NULL) return NULL;

	ZERO_STRUCT(create_parm);
	create_parm.in.desired_access     = SEC_STD_DELETE;
	create_parm.in.create_disposition = NTCREATEX_DISP_OPEN;
	create_parm.in.share_access = 
		NTCREATEX_SHARE_ACCESS_DELETE|
		NTCREATEX_SHARE_ACCESS_READ|
		NTCREATEX_SHARE_ACCESS_WRITE;
	create_parm.in.create_options = 
		NTCREATEX_OPTIONS_DIRECTORY |
		NTCREATEX_OPTIONS_DELETE_ON_CLOSE;
	create_parm.in.fname = io->in.path;
	if (create_parm.in.fname[0] == '\\') {
		create_parm.in.fname++;
	}

	req = smb2_create_send(tree, &create_parm);

	composite_continue_smb2(ctx, req, continue_rmdir, ctx);
	return ctx;
}


/*
  composite rmdir call - sync interface
*/
NTSTATUS smb2_composite_rmdir(struct smb2_tree *tree, struct smb_rmdir *io)
{
	struct composite_context *c = smb2_composite_rmdir_send(tree, io);
	return composite_wait_free(c);
}

struct smb2_composite_setpathinfo_state {
	struct smb2_tree *tree;
	union smb_setfileinfo io;
	NTSTATUS set_status;
	struct smb2_create cr;
	struct smb2_close cl;
};

static void smb2_composite_setpathinfo_create_done(struct smb2_request *smb2req);

/*
  composite SMB2 setpathinfo call
*/
struct tevent_req *smb2_composite_setpathinfo_send(TALLOC_CTX *mem_ctx,
						   struct tevent_context *ev,
						   struct smb2_tree *tree,
						   const union smb_setfileinfo *io)
{
	struct tevent_req *req;
	struct smb2_composite_setpathinfo_state *state;
	struct smb2_request *smb2req;

	req = tevent_req_create(mem_ctx, &state,
				struct smb2_composite_setpathinfo_state);
	if (req == NULL) {
		return NULL;
	}

	state->tree = tree;
	state->io = *io;

	state->cr.in.desired_access     = SEC_FLAG_MAXIMUM_ALLOWED;
	state->cr.in.create_disposition = NTCREATEX_DISP_OPEN;
	state->cr.in.share_access =
		NTCREATEX_SHARE_ACCESS_DELETE|
		NTCREATEX_SHARE_ACCESS_READ|
		NTCREATEX_SHARE_ACCESS_WRITE;
	state->cr.in.create_options = 0;
	state->cr.in.fname = state->io.generic.in.file.path;
	if (state->cr.in.fname[0] == '\\') {
		state->cr.in.fname++;
	}

	smb2req = smb2_create_send(tree, &state->cr);
	if (tevent_req_nomem(smb2req, req)) {
		return tevent_req_post(req, ev);
	}
	smb2req->async.fn = smb2_composite_setpathinfo_create_done;
	smb2req->async.private_data = req;

	return req;
}

static void smb2_composite_setpathinfo_setinfo_done(struct smb2_request *smb2req);

static void smb2_composite_setpathinfo_create_done(struct smb2_request *smb2req)
{
	struct tevent_req *req =
		talloc_get_type_abort(smb2req->async.private_data,
		struct tevent_req);
	struct smb2_composite_setpathinfo_state *state =
		tevent_req_data(req,
		struct smb2_composite_setpathinfo_state);
	NTSTATUS status;

	status = smb2_create_recv(smb2req, state, &state->cr);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	state->io.generic.in.file.handle = state->cr.out.file.handle;

	smb2req = smb2_setinfo_file_send(state->tree, &state->io);
	if (tevent_req_nomem(smb2req, req)) {
		return;
	}
	smb2req->async.fn = smb2_composite_setpathinfo_setinfo_done;
	smb2req->async.private_data = req;
}

static void smb2_composite_setpathinfo_close_done(struct smb2_request *smb2req);

static void smb2_composite_setpathinfo_setinfo_done(struct smb2_request *smb2req)
{
	struct tevent_req *req =
		talloc_get_type_abort(smb2req->async.private_data,
		struct tevent_req);
	struct smb2_composite_setpathinfo_state *state =
		tevent_req_data(req,
		struct smb2_composite_setpathinfo_state);
	NTSTATUS status;

	status = smb2_setinfo_recv(smb2req);
	state->set_status = status;

	state->cl.in.file.handle = state->io.generic.in.file.handle;

	smb2req = smb2_close_send(state->tree, &state->cl);
	if (tevent_req_nomem(smb2req, req)) {
		return;
	}
	smb2req->async.fn = smb2_composite_setpathinfo_close_done;
	smb2req->async.private_data = req;
}

static void smb2_composite_setpathinfo_close_done(struct smb2_request *smb2req)
{
	struct tevent_req *req =
		talloc_get_type_abort(smb2req->async.private_data,
		struct tevent_req);
	struct smb2_composite_setpathinfo_state *state =
		tevent_req_data(req,
		struct smb2_composite_setpathinfo_state);
	NTSTATUS status;

	status = smb2_close_recv(smb2req, &state->cl);

	if (tevent_req_nterror(req, state->set_status)) {
		return;
	}

	if (tevent_req_nterror(req, status)) {
		return;
	}

	tevent_req_done(req);
}

NTSTATUS smb2_composite_setpathinfo_recv(struct tevent_req *req)
{
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		tevent_req_received(req);
		return status;
	}

	tevent_req_received(req);
	return NT_STATUS_OK;
}

/*
  composite setpathinfo call
 */
NTSTATUS smb2_composite_setpathinfo(struct smb2_tree *tree, union smb_setfileinfo *io)
{
	struct tevent_req *subreq;
	NTSTATUS status;
	bool ok;
	TALLOC_CTX *frame = talloc_stackframe();
	struct tevent_context *ev = tree->session->transport->ev;

	if (frame == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	subreq = smb2_composite_setpathinfo_send(frame, ev, tree, io);
	if (subreq == NULL) {
		TALLOC_FREE(frame);
		return NT_STATUS_NO_MEMORY;
	}

	ok = tevent_req_poll(subreq, ev);
	if (!ok) {
		status = map_nt_error_from_unix_common(errno);
		TALLOC_FREE(frame);
		return status;
	}

	status = smb2_composite_setpathinfo_recv(subreq);
	TALLOC_FREE(subreq);
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(frame);
		return status;
	}

	TALLOC_FREE(frame);
	return NT_STATUS_OK;
}
