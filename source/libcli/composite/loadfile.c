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
  a composite API for loading a whole file into memory
*/

#include "includes.h"
#include "libcli/raw/libcliraw.h"
#include "libcli/composite/composite.h"
#include "librpc/gen_ndr/ndr_security.h"

/* the stages of this call */
enum loadfile_stage {LOADFILE_OPEN, LOADFILE_READ, LOADFILE_CLOSE};


static void loadfile_handler(struct smbcli_request *req);


/*
  setup for the close
*/
static NTSTATUS setup_close(struct smbcli_composite *c, 
			    struct smbcli_tree *tree, uint16_t fnum)
{
	union smb_close *io_close;

	/* nothing to read, setup the close */
	io_close = talloc(c, union smb_close);
	NT_STATUS_HAVE_NO_MEMORY(io_close);
	
	io_close->close.level = RAW_CLOSE_CLOSE;
	io_close->close.in.fnum = fnum;
	io_close->close.in.write_time = 0;

	c->req = smb_raw_close_send(tree, io_close);
	NT_STATUS_HAVE_NO_MEMORY(c->req);

	/* call the handler again when the close is done */
	c->stage = LOADFILE_CLOSE;
	c->req->async.fn = loadfile_handler;
	c->req->async.private = c;
	c->req_parms = io_close;

	return NT_STATUS_OK;
}

/*
  called when the open is done - pull the results and setup for the
  first readx, or close if the file is zero size
*/
static NTSTATUS loadfile_open(struct smbcli_composite *c, 
			      struct smb_composite_loadfile *io)
{
	union smb_open *io_open = c->req_parms;
	struct smbcli_tree *tree = c->req->tree;
	union smb_read *io_read;
	NTSTATUS status;

	status = smb_raw_open_recv(c->req, c, io_open);
	NT_STATUS_NOT_OK_RETURN(status);
	
	/* don't allow stupidly large loads */
	if (io_open->ntcreatex.out.size > 100*1000*1000) {
		return NT_STATUS_INSUFFICIENT_RESOURCES;
	}

	/* allocate space for the file data */
	io->out.size = io_open->ntcreatex.out.size;
	io->out.data = talloc_array(c, uint8_t, io->out.size);
	NT_STATUS_HAVE_NO_MEMORY(io->out.data);

	if (io->out.size == 0) {
		return setup_close(c, tree, io_open->ntcreatex.out.fnum);
	}

	/* setup for the read */
	io_read = talloc(c, union smb_read);
	NT_STATUS_HAVE_NO_MEMORY(io_read);
	
	io_read->readx.level        = RAW_READ_READX;
	io_read->readx.in.fnum      = io_open->ntcreatex.out.fnum;
	io_read->readx.in.offset    = 0;
	io_read->readx.in.mincnt    = MIN(32768, io->out.size);
	io_read->readx.in.maxcnt    = io_read->readx.in.mincnt;
	io_read->readx.in.remaining = 0;
	io_read->readx.out.data     = io->out.data;

	c->req = smb_raw_read_send(tree, io_read);
	NT_STATUS_HAVE_NO_MEMORY(c->req);

	/* call the handler again when the first read is done */
	c->stage = LOADFILE_READ;
	c->req->async.fn = loadfile_handler;
	c->req->async.private = c;
	c->req_parms = io_read;
	talloc_free(io_open);

	return NT_STATUS_OK;
}


/*
  called when a read is done - pull the results and setup for the
  next read, or close if the file is all done
*/
static NTSTATUS loadfile_read(struct smbcli_composite *c, 
			      struct smb_composite_loadfile *io)
{
	union smb_read *io_read = c->req_parms;
	struct smbcli_tree *tree = c->req->tree;
	NTSTATUS status;

	status = smb_raw_read_recv(c->req, io_read);
	NT_STATUS_NOT_OK_RETURN(status);
	
	/* we might be done */
	if (io_read->readx.in.offset +
	    io_read->readx.out.nread == io->out.size) {
		return setup_close(c, tree, io_read->readx.in.fnum);
	}

	/* setup for the next read */
	io_read->readx.in.offset += io_read->readx.out.nread;
	io_read->readx.in.mincnt = MIN(32768, io->out.size - io_read->readx.in.offset);
	io_read->readx.out.data = io->out.data + io_read->readx.in.offset;

	c->req = smb_raw_read_send(tree, io_read);
	NT_STATUS_HAVE_NO_MEMORY(c->req);

	/* call the handler again when the read is done */
	c->req->async.fn = loadfile_handler;
	c->req->async.private = c;

	return NT_STATUS_OK;
}

/*
  called when the close is done, check the status and cleanup
*/
static NTSTATUS loadfile_close(struct smbcli_composite *c, 
			       struct smb_composite_loadfile *io)
{
	NTSTATUS status;

	status = smbcli_request_simple_recv(c->req);
	NT_STATUS_NOT_OK_RETURN(status);
	
	c->state = SMBCLI_REQUEST_DONE;
	if (c->async.fn) {
		c->async.fn(c);
	}

	return NT_STATUS_OK;
}
						     

/*
  handler for completion of a sub-request in loadfile
*/
static void loadfile_handler(struct smbcli_request *req)
{
	struct smbcli_composite *c = req->async.private;
	struct smb_composite_loadfile *io = c->composite_parms;

	/* when this handler is called, the stage indicates what
	   call has just finished */
	switch (c->stage) {
	case LOADFILE_OPEN:
		c->status = loadfile_open(c, io);
		break;

	case LOADFILE_READ:
		c->status = loadfile_read(c, io);
		break;

	case LOADFILE_CLOSE:
		c->status = loadfile_close(c, io);
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
  composite loadfile call - does an openx followed by a number of readx calls,
  followed by a close
*/
struct smbcli_composite *smb_composite_loadfile_send(struct smbcli_tree *tree, 
						     struct smb_composite_loadfile *io)
{
	struct smbcli_composite *c;
	union smb_open *io_open;

	c = talloc_zero(tree, struct smbcli_composite);
	if (c == NULL) goto failed;

	c->state = SMBCLI_REQUEST_SEND;
	c->stage = LOADFILE_OPEN;
	c->composite_parms = io;

	/* setup for the open */
	io_open = talloc_zero(c, union smb_open);
	if (io_open == NULL) goto failed;
	
	io_open->ntcreatex.level               = RAW_OPEN_NTCREATEX;
	io_open->ntcreatex.in.flags            = NTCREATEX_FLAGS_EXTENDED;
	io_open->ntcreatex.in.access_mask      = SEC_FILE_READ_DATA;
	io_open->ntcreatex.in.file_attr        = FILE_ATTRIBUTE_NORMAL;
	io_open->ntcreatex.in.share_access     = NTCREATEX_SHARE_ACCESS_READ | NTCREATEX_SHARE_ACCESS_WRITE;
	io_open->ntcreatex.in.open_disposition = NTCREATEX_DISP_OPEN;
	io_open->ntcreatex.in.impersonation    = NTCREATEX_IMPERSONATION_ANONYMOUS;
	io_open->ntcreatex.in.fname            = io->in.fname;

	/* send the open on its way */
	c->req = smb_raw_open_send(tree, io_open);
	if (c->req == NULL) goto failed;

	/* setup the callback handler */
	c->req->async.fn = loadfile_handler;
	c->req->async.private = c;
	c->req_parms = io_open;

	return c;

failed:
	talloc_free(c);
	return NULL;
}


/*
  composite loadfile call - recv side
*/
NTSTATUS smb_composite_loadfile_recv(struct smbcli_composite *c, TALLOC_CTX *mem_ctx)
{
	NTSTATUS status;

	if (!c) return NT_STATUS_NO_MEMORY;

	while (c->state < SMBCLI_REQUEST_DONE) {
		if (event_loop_once(c->req->transport->event.ctx) != 0) {
			return NT_STATUS_UNSUCCESSFUL;
		}
	}

	if (NT_STATUS_IS_OK(c->status)) {
		struct smb_composite_loadfile *io = c->composite_parms;
		talloc_steal(mem_ctx, io->out.data);
	}

	status = c->status;
	talloc_free(c);

	return status;
}


/*
  composite loadfile call - sync interface
*/
NTSTATUS smb_composite_loadfile(struct smbcli_tree *tree, 
				TALLOC_CTX *mem_ctx,
				struct smb_composite_loadfile *io)
{
	struct smbcli_composite *c = smb_composite_loadfile_send(tree, io);
	return smb_composite_loadfile_recv(c, mem_ctx);
}
