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
	if (!NT_STATUS_IS_OK(req->async.status)) { \
		req_reply_error(req, req->async.status); \
		return; \
	}} while (0)
	
/* 
   check if the backend wants to handle the request asynchronously.
   if it wants it handled synchronously then call the send function
   immediately
*/
#define REQ_ASYNC_TAIL do { \
	if (!(req->control_flags & REQ_CONTROL_ASYNC)) { \
		req->async.send_fn(req); \
	}} while (0)

/* useful wrapper for talloc with NO_MEMORY reply */
#define REQ_TALLOC(ptr, size) do { \
	ptr = talloc(req->mem_ctx, size); \
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
	struct request_context *req;
	union smb_search_data *file;
	uint16_t last_entry_offset;
};

/*
  fill a single entry in a search find reply 
*/
static void find_fill_info(struct request_context *req,
			   union smb_search_data *file)
{
	char *p = req->out.data + req->out.data_size;
	uint32_t dos_date;
	char search_name[13];
	
	DEBUG(9,("find_fill_info: input file data: attr=0x%x size=%u time=0x%x name=%13s\n",
		file->search.attrib, file->search.size,
		(uint32_t)file->search.write_time, file->search.name));

	p += req_append_bytes(req, file->search.search_id.data, 21);
	p += req_append_bytes(req, (char*)&file->search.attrib, 1);
	srv_push_dos_date3(req->smb, (uint8 *)&dos_date, 0, file->search.write_time);
	p += req_append_bytes(req, (char*)&dos_date, 4);
	p += req_append_bytes(req, (char*)&file->search.size, 4);
	memset(&search_name[0], ' ', 13);
	memcpy(&search_name[0], file->search.name, 
		MAX(13, strlen(file->search.name)));
	p += req_append_bytes(req, &search_name[0], 13);
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
void reply_search(struct request_context *req)
{
	union smb_search_first *sf;
	union smb_search_next *sn;
	DATA_BLOB resume_key;
	uint16_t resume_key_length;
	struct search_state state;
	char *p;

	REQ_TALLOC(sf, sizeof(*sf));
	
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
	/* pull in type 5 byte and length */
	if (!req_pull_blob(req, p, 3, &resume_key))
		req_reply_error(req, NT_STATUS_INVALID_PARAMETER);
	resume_key_length = SVAL(resume_key.data, 1);
	p += 3;
	DEBUG(19,("reply_search: pattern=%s, key_length=%d\n",
		sf->search_first.in.pattern, resume_key_length));
	
	/* setup state for callback */
	state.req = req;
	state.file = NULL;
	state.last_entry_offset = 0;
	
	/* construct reply */
	req_setup_reply(req, 1, 0);
	req_append_var_block(req, NULL, 0);

	if (resume_key_length > 0) {
		/* do a search next operation */
		REQ_TALLOC(sn, sizeof(*sn));
		sn->search_next.level = RAW_SEARCH_SEARCH;
		req->async.private = sn;
		if (!req_pull_blob(req, req->in.data, resume_key_length, 
				&(sn->search_next.in.search_id)))
			req_reply_error(req, NT_STATUS_INVALID_PARAMETER);
		sn->search_next.in.search_attrib = SVAL(req->in.vwv, VWV(1));
		sn->search_next.in.max_count     = SVAL(req->in.vwv, VWV(0));
		
		/* call backend */
		req->async.status = req->conn->ntvfs_ops->search_next(req, 
			sn, &state, find_callback);
		SSVAL(req->out.vwv, VWV(0), sn->search_next.out.count);
	} else {
		/* do a search first operation */
		req->async.private = sf;
		sf->search_first.level = RAW_SEARCH_SEARCH;
		sf->search_first.in.search_attrib = SVAL(req->in.vwv, VWV(1));
		sf->search_first.in.max_count     = SVAL(req->in.vwv, VWV(0));
		
		/* call backend */
		req->async.status = req->conn->ntvfs_ops->search_first(req, 
			sf, &state, find_callback);
		SSVAL(req->out.vwv, VWV(0), sf->search_first.out.count);
	}

	req_send_reply(req);
}


/****************************************************************************
 Reply to a fclose (async reply)
****************************************************************************/
static void reply_fclose_send(struct request_context *req)
{
	CHECK_ASYNC_STATUS;
	
	/* construct reply */
	req_setup_reply(req, 1, 0);

	req_send_reply(req);
}


/****************************************************************************
 Reply to fclose (stop directory search).
****************************************************************************/
void reply_fclose(struct request_context *req)
{
	union smb_search_next *sn;
	DATA_BLOB resume_key;
	uint16_t resume_key_length;

	REQ_TALLOC(sn, sizeof(*sn));

	/* parse request */
	if (req->in.wct != 2) {
		req_reply_error(req, NT_STATUS_INVALID_PARAMETER);
		return;
	}
	
	sn->search_next.level = RAW_SEARCH_FCLOSE;
	
	/* pull in type 5 byte and length */
	if (!req_pull_blob(req, req->in.data, 3, &resume_key))
		req_reply_error(req, NT_STATUS_INVALID_PARAMETER);
	resume_key_length = SVAL(resume_key.data, 1);
	if (resume_key_length > 0) {
		/* do a search close operation */
		if (!req_pull_blob(req, req->in.data, resume_key_length, 
				&(sn->search_next.in.search_id)))
			req_reply_error(req, NT_STATUS_INVALID_PARAMETER);
	} else
		req_reply_error(req, NT_STATUS_INVALID_PARAMETER);

	req->async.send_fn = reply_fclose_send;
	req->async.private = sn;

	/* call backend */
	req->async.status = req->conn->ntvfs_ops->search_next(req, sn,
		NULL, NULL);

	REQ_ASYNC_TAIL;
}
