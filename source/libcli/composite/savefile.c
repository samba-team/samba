/* 
   Unix SMB/CIFS implementation.

   Copyright (C) Andrew Tridgell 2005
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/
/*
  a composite API for saving a whole file from memory
*/

#include "includes.h"
#include "libcli/raw/libcliraw.h"
#include "libcli/composite/composite.h"
#include "librpc/gen_ndr/ndr_security.h"

/* the stages of this call */
enum savefile_stage {SAVEFILE_OPEN, SAVEFILE_WRITE, SAVEFILE_CLOSE};


static void savefile_handler(struct smbcli_request *req);

struct savefile_state {
	off_t total_written;
	struct smb_composite_savefile *io;
	union smb_open *io_open;
	union smb_write *io_write;
};


/*
  setup for the close
*/
static NTSTATUS setup_close(struct smbcli_composite *c, 
			    struct smbcli_tree *tree, uint16_t fnum)
{
	union smb_close *io_close;
	struct smbcli_request *req = c->req;

	/* nothing to write, setup the close */
	io_close = talloc(c, union smb_close);
	NT_STATUS_HAVE_NO_MEMORY(io_close);
	
	io_close->close.level = RAW_CLOSE_CLOSE;
	io_close->close.in.fnum = fnum;
	io_close->close.in.write_time = 0;

	req = smb_raw_close_send(tree, io_close);
	NT_STATUS_HAVE_NO_MEMORY(req);

	/* call the handler again when the close is done */
	c->stage = SAVEFILE_CLOSE;
	req->async.fn = savefile_handler;
	req->async.private = c;
	c->req = req;

	return NT_STATUS_OK;
}

/*
  called when the open is done - pull the results and setup for the
  first writex, or close if the file is zero size
*/
static NTSTATUS savefile_open(struct smbcli_composite *c, 
			      struct smb_composite_savefile *io)
{
	struct savefile_state *state = c->private;
	union smb_write *io_write;
	struct smbcli_request *req = c->req;
	struct smbcli_tree *tree = req->tree;
	NTSTATUS status;
	uint32_t max_xmit = tree->session->transport->negotiate.max_xmit;

	status = smb_raw_open_recv(c->req, c, state->io_open);
	NT_STATUS_NOT_OK_RETURN(status);
	
	if (io->in.size == 0) {
		return setup_close(c, tree, state->io_open->ntcreatex.out.fnum);
	}

	/* setup for the first write */
	io_write = talloc(c, union smb_write);
	NT_STATUS_HAVE_NO_MEMORY(io_write);
	
	io_write->writex.level        = RAW_WRITE_WRITEX;
	io_write->writex.in.fnum      = state->io_open->ntcreatex.out.fnum;
	io_write->writex.in.offset    = 0;
	io_write->writex.in.wmode     = 0;
	io_write->writex.in.remaining = 0;
	io_write->writex.in.count     = MIN(max_xmit - 100, io->in.size);
	io_write->writex.in.data      = io->in.data;
	state->io_write = io_write;

	req = smb_raw_write_send(tree, io_write);
	NT_STATUS_HAVE_NO_MEMORY(req);

	/* call the handler again when the first write is done */
	c->stage = SAVEFILE_WRITE;
	req->async.fn = savefile_handler;
	req->async.private = c;
	c->req = req;
	talloc_free(state->io_open);

	return NT_STATUS_OK;
}


/*
  called when a write is done - pull the results and setup for the
  next write, or close if the file is all done
*/
static NTSTATUS savefile_write(struct smbcli_composite *c, 
			      struct smb_composite_savefile *io)
{
	struct savefile_state *state = c->private;
	struct smbcli_request *req = c->req;
	struct smbcli_tree *tree = req->tree;
	NTSTATUS status;
	uint32_t max_xmit = tree->session->transport->negotiate.max_xmit;

	status = smb_raw_write_recv(c->req, state->io_write);
	NT_STATUS_NOT_OK_RETURN(status);

	state->total_written += state->io_write->writex.out.nwritten;
	
	/* we might be done */
	if (state->io_write->writex.out.nwritten != state->io_write->writex.in.count ||
	    state->total_written == io->in.size) {
		return setup_close(c, tree, state->io_write->writex.in.fnum);
	}

	/* setup for the next write */
	state->io_write->writex.in.offset = state->total_written;
	state->io_write->writex.in.count = MIN(max_xmit - 100, 
					       io->in.size - state->total_written);
	state->io_write->writex.in.data = io->in.data + state->total_written;

	req = smb_raw_write_send(tree, state->io_write);
	NT_STATUS_HAVE_NO_MEMORY(req);

	/* call the handler again when the write is done */
	req->async.fn = savefile_handler;
	req->async.private = c;
	c->req = req;

	return NT_STATUS_OK;
}

/*
  called when the close is done, check the status and cleanup
*/
static NTSTATUS savefile_close(struct smbcli_composite *c, 
			       struct smb_composite_savefile *io)
{
	struct savefile_state *state = c->private;
	NTSTATUS status;

	status = smbcli_request_simple_recv(c->req);
	NT_STATUS_NOT_OK_RETURN(status);

	if (state->total_written != io->in.size) {
		return NT_STATUS_DISK_FULL;
	}
	
	c->state = SMBCLI_REQUEST_DONE;
	if (c->async.fn) {
		c->async.fn(c);
	}

	return NT_STATUS_OK;
}
						     

/*
  handler for completion of a sub-request in savefile
*/
static void savefile_handler(struct smbcli_request *req)
{
	struct smbcli_composite *c = req->async.private;
	struct savefile_state *state = c->private;

	/* when this handler is called, the stage indicates what
	   call has just finished */
	switch (c->stage) {
	case SAVEFILE_OPEN:
		c->status = savefile_open(c, state->io);
		break;

	case SAVEFILE_WRITE:
		c->status = savefile_write(c, state->io);
		break;

	case SAVEFILE_CLOSE:
		c->status = savefile_close(c, state->io);
		break;
	}

	if (!NT_STATUS_IS_OK(c->status)) {
		c->state = SMBCLI_REQUEST_ERROR;
		if (c->async.fn) {
			c->async.fn(c);
		}
	}
}

/*
  composite savefile call - does an openx followed by a number of writex calls,
  followed by a close
*/
struct smbcli_composite *smb_composite_savefile_send(struct smbcli_tree *tree, 
						     struct smb_composite_savefile *io)
{
	struct smbcli_composite *c;
	struct savefile_state *state;
	struct smbcli_request *req;
	union smb_open *io_open;

	c = talloc_zero(tree, struct smbcli_composite);
	if (c == NULL) goto failed;

	c->state = SMBCLI_REQUEST_SEND;
	c->stage = SAVEFILE_OPEN;
	c->event_ctx = tree->session->transport->socket->event.ctx;

	state = talloc(c, struct savefile_state);
	if (state == NULL) goto failed;

	state->total_written = 0;
	state->io = io;

	/* setup for the open */
	io_open = talloc_zero(c, union smb_open);
	if (io_open == NULL) goto failed;
	
	io_open->ntcreatex.level               = RAW_OPEN_NTCREATEX;
	io_open->ntcreatex.in.flags            = NTCREATEX_FLAGS_EXTENDED;
	io_open->ntcreatex.in.access_mask      = SEC_FILE_WRITE_DATA;
	io_open->ntcreatex.in.file_attr        = FILE_ATTRIBUTE_NORMAL;
	io_open->ntcreatex.in.share_access     = NTCREATEX_SHARE_ACCESS_READ | NTCREATEX_SHARE_ACCESS_WRITE;
	io_open->ntcreatex.in.open_disposition = NTCREATEX_DISP_OPEN_IF;
	io_open->ntcreatex.in.impersonation    = NTCREATEX_IMPERSONATION_ANONYMOUS;
	io_open->ntcreatex.in.fname            = io->in.fname;
	state->io_open = io_open;

	/* send the open on its way */
	req = smb_raw_open_send(tree, io_open);
	if (req == NULL) goto failed;

	/* setup the callback handler */
	req->async.fn = savefile_handler;
	req->async.private = c;
	c->private = state;
	c->req = req;

	return c;

failed:
	talloc_free(c);
	return NULL;
}


/*
  composite savefile call - recv side
*/
NTSTATUS smb_composite_savefile_recv(struct smbcli_composite *c)
{
	NTSTATUS status;
	status = smb_composite_wait(c);
	talloc_free(c);
	return status;
}


/*
  composite savefile call - sync interface
*/
NTSTATUS smb_composite_savefile(struct smbcli_tree *tree, 
				struct smb_composite_savefile *io)
{
	struct smbcli_composite *c = smb_composite_savefile_send(tree, io);
	return smb_composite_savefile_recv(c);
}
