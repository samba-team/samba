/* 
   Unix SMB/CIFS implementation.
   SMBsearch handling
   Copyright (C) Andrew Tridgell 2003
   Copyright (C) James J Myers 2003 <myersjj@samba.org>

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
   This file handles the parsing of transact2 requests
*/

#include "includes.h"

/* check req->async.status and if not OK then send an error reply */
#define CHECK_ASYNC_STATUS do { \
	if (!NT_STATUS_IS_OK(req->async_states->status)) { \
		req_reply_error(req, req->async_states->status); \
		return; \
	}} while (0)
	
/* 
   check if the backend wants to handle the request asynchronously.
   if it wants it handled synchronously then call the send function
   immediately
*/
#define REQ_ASYNC_TAIL do { \
	if (!(req->async_states->state & NTVFS_ASYNC_STATE_ASYNC)) { \
		req->async_states->send_fn(req); \
	}} while (0)

/* useful wrapper for talloc with NO_MEMORY reply */
#define REQ_TALLOC(ptr) do { \
	ptr = talloc(req, sizeof(*(ptr))); \
	if (!ptr) { \
		req_reply_error(req, NT_STATUS_NO_MEMORY); \
		return; \
	}} while (0)
		
#define CHECK_MIN_BLOB_SIZE(blob, size) do { \
	if ((blob)->length < (size)) { \
		return NT_STATUS_INFO_LENGTH_MISMATCH; \
	}} while (0)

/* a structure to encapsulate the state information about 
 * an in-progress search first/next operation */
struct search_state {
	struct smbsrv_request *req;
	union smb_search_data *file;
	uint16_t last_entry_offset;
};

/*
  fill a single entry in a search find reply 
*/
static void find_fill_info(struct smbsrv_request *req,
			   union smb_search_data *file)
{
	char *p;
	
	req_grow_data(req, req->out.data_size + 43);
	p = req->out.data + req->out.data_size - 43;

	SCVAL(p,  0, file->search.id.reserved);
	memcpy(p+1, file->search.id.name, 11);
	SCVAL(p, 12, file->search.id.handle);
	SIVAL(p, 13, file->search.id.server_cookie);
	SIVAL(p, 17, file->search.id.client_cookie);
	SCVAL(p, 21, file->search.attrib);
	srv_push_dos_date(req->smb_conn, p, 22, file->search.write_time);
	SIVAL(p, 26, file->search.size);
	memset(p+30, ' ', 12);
	memcpy(p+30, file->search.name, MIN(strlen(file->search.name)+1, 12));
	SCVAL(p,42,0);
}

/* callback function for search first/next */
static BOOL find_callback(void *private, union smb_search_data *file)
{
	struct search_state *state = (struct search_state *)private;

	find_fill_info(state->req, file);

	return True;
}

/****************************************************************************
 Reply to a search.
****************************************************************************/
void reply_search(struct smbsrv_request *req)
{
	union smb_search_first *sf;
	union smb_search_next *sn;
	uint16_t resume_key_length;
	struct search_state state;
	char *p;
	NTSTATUS status;
	enum smb_search_level level = RAW_SEARCH_SEARCH;
	uint8_t op = CVAL(req->in.hdr,HDR_COM);

	if (op == SMBffirst) {
		level = RAW_SEARCH_FFIRST;
	} else if (op == SMBfunique) {
		level = RAW_SEARCH_FUNIQUE;
	}

	REQ_TALLOC(sf);
	
	/* parse request */
	if (req->in.wct != 2) {
		req_reply_error(req, NT_STATUS_INVALID_PARAMETER);
		return;
	}
	
	p = req->in.data;
	p += req_pull_ascii4(req, &sf->search_first.in.pattern, 
			     p, STR_TERMINATE);
	if (!sf->search_first.in.pattern) {
		req_reply_error(req, NT_STATUS_OBJECT_NAME_NOT_FOUND);
		return;
	}

	if (req_data_oob(req, p, 3)) {
		req_reply_error(req, NT_STATUS_INVALID_PARAMETER);
		return;
	}
	if (*p != 5) {
		req_reply_error(req, NT_STATUS_INVALID_PARAMETER);
		return;
	}
	resume_key_length = SVAL(p, 1);
	p += 3;
	
	/* setup state for callback */
	state.req = req;
	state.file = NULL;
	state.last_entry_offset = 0;
	
	/* construct reply */
	req_setup_reply(req, 1, 0);
	req_append_var_block(req, NULL, 0);

	if (resume_key_length != 0) {
		if (resume_key_length != 21 || 
		    req_data_oob(req, p, 21) ||
		    level == RAW_SEARCH_FUNIQUE) {
			req_reply_error(req, NT_STATUS_INVALID_PARAMETER);
			return;
		}

		/* do a search next operation */
		REQ_TALLOC(sn);

		sn->search_next.in.id.reserved      = CVAL(p, 0);
		memcpy(sn->search_next.in.id.name,    p+1, 11);
		sn->search_next.in.id.handle        = CVAL(p, 12);
		sn->search_next.in.id.server_cookie = IVAL(p, 13);
		sn->search_next.in.id.client_cookie = IVAL(p, 17);

		sn->search_next.level = level;
		sn->search_next.in.max_count     = SVAL(req->in.vwv, VWV(0));
		sn->search_next.in.search_attrib = SVAL(req->in.vwv, VWV(1));
		
		/* call backend */
		status = ntvfs_search_next(req, sn, &state, find_callback);
		SSVAL(req->out.vwv, VWV(0), sn->search_next.out.count);
	} else {
		/* do a search first operation */
		sf->search_first.level = level;
		sf->search_first.in.search_attrib = SVAL(req->in.vwv, VWV(1));
		sf->search_first.in.max_count     = SVAL(req->in.vwv, VWV(0));
		
		/* call backend */
		status = ntvfs_search_first(req, sf, &state, find_callback);
		SSVAL(req->out.vwv, VWV(0), sf->search_first.out.count);
	}

	if (!NT_STATUS_IS_OK(status)) {
		req_reply_error(req, status);
		return;
	}

	req_send_reply(req);
}


/****************************************************************************
 Reply to a fclose (async reply)
****************************************************************************/
static void reply_fclose_send(struct smbsrv_request *req)
{
	CHECK_ASYNC_STATUS;
	
	/* construct reply */
	req_setup_reply(req, 1, 0);

	SSVAL(req->out.vwv, VWV(0), 0);

	req_send_reply(req);
}


/****************************************************************************
 Reply to fclose (stop directory search).
****************************************************************************/
void reply_fclose(struct smbsrv_request *req)
{
	union smb_search_close *sc;
	uint16_t resume_key_length;
	char *p;
	const char *pattern;

	REQ_TALLOC(sc);

	/* parse request */
	if (req->in.wct != 2) {
		req_reply_error(req, NT_STATUS_INVALID_PARAMETER);
		return;
	}
	
	p = req->in.data;
	p += req_pull_ascii4(req, &pattern, p, STR_TERMINATE);
	if (pattern && *pattern) {
		req_reply_error(req, NT_STATUS_INVALID_PARAMETER);
		return;
	}
	
	if (req_data_oob(req, p, 3)) {
		req_reply_error(req, NT_STATUS_INVALID_PARAMETER);
		return;
	}
	if (*p != 5) {
		req_reply_error(req, NT_STATUS_INVALID_PARAMETER);
		return;
	}
	resume_key_length = SVAL(p, 1);
	p += 3;

	if (resume_key_length != 21) {
		req_reply_error(req, NT_STATUS_INVALID_PARAMETER);
		return;
	}

	if (req_data_oob(req, p, 21)) {
		req_reply_error(req, NT_STATUS_INVALID_PARAMETER);
		return;
	}

	sc->fclose.level               = RAW_FINDCLOSE_FCLOSE;
	sc->fclose.in.max_count        = SVAL(req->in.vwv, VWV(0));
	sc->fclose.in.search_attrib    = SVAL(req->in.vwv, VWV(1));
	sc->fclose.in.id.reserved      = CVAL(p, 0);
	memcpy(sc->fclose.in.id.name,    p+1, 11);
	sc->fclose.in.id.handle        = CVAL(p, 12);
	sc->fclose.in.id.server_cookie = IVAL(p, 13);
	sc->fclose.in.id.client_cookie = IVAL(p, 17);

	/* do a search close operation */
	req->async_states->state |= NTVFS_ASYNC_STATE_MAY_ASYNC;
	req->async_states->send_fn = reply_fclose_send;
	req->async_states->private_data = sc;

	/* call backend */
	req->async_states->status = ntvfs_search_close(req, sc);

	REQ_ASYNC_TAIL;
}
