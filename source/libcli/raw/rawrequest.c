/* 
   Unix SMB/CIFS implementation.
   
   Copyright (C) Andrew Tridgell  2003
   Copyright (C) James Myers 2003 <myersjj@samba.org>
   
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
  this file implements functions for manipulating the 'struct cli_request' structure in libsmb
*/

#include "includes.h"

/* we over allocate the data buffer to prevent too many realloc calls */
#define REQ_OVER_ALLOCATION 256

/* assume that a character will not consume more than 3 bytes per char */
#define MAX_BYTES_PER_CHAR 3

/* destroy a request structure and return final status */
NTSTATUS cli_request_destroy(struct cli_request *req)
{
	NTSTATUS status;

	/* this is the error code we give the application for when a
	   _send() call fails completely */
	if (!req) return NT_STATUS_UNSUCCESSFUL;

	if (req->transport) {
		/* remove it from the list of pending requests (a null op if
		   its not in the list) */
		DLIST_REMOVE(req->transport->pending_requests, req);
	}

	/* ahh, its so nice to destroy a complex structure in such a
	   simple way! */
	status = req->status;
	talloc_destroy(req->mem_ctx);
	return status;
}


/*
  low-level function to setup a request buffer for a non-SMB packet 
  at the transport level
*/
struct cli_request *cli_request_setup_nonsmb(struct cli_transport *transport, uint_t size)
{
	struct cli_request *req;
	TALLOC_CTX *mem_ctx;
	
	/* each request gets its own talloc context. The request
	   structure itself is also allocated inside this context,
	   so we need to allocate it before we construct the request
	*/
	mem_ctx = talloc_init("cli_request");
	if (!mem_ctx) {
		return NULL;
	}

	req = talloc(mem_ctx, sizeof(struct cli_request));
	if (!req) {
		return NULL;
	}
	ZERO_STRUCTP(req);

	/* setup the request context */
	req->mem_ctx = mem_ctx;
	req->transport = transport;
	req->session = NULL;
	req->tree = NULL;
	req->out.size = size;

	/* over allocate by a small amount */
	req->out.allocated = req->out.size + REQ_OVER_ALLOCATION; 

	req->out.buffer = talloc(req->mem_ctx, req->out.allocated);
	if (!req->out.buffer) {
		return NULL;
	}

	SIVAL(req->out.buffer, 0, 0);

	return req;
}


/*
  setup a SMB packet at transport level
*/
struct cli_request *cli_request_setup_transport(struct cli_transport *transport,
						uint8 command, unsigned wct, unsigned buflen)
{
	struct cli_request *req;

	req = cli_request_setup_nonsmb(transport, NBT_HDR_SIZE + MIN_SMB_SIZE + wct*2 + buflen);

	if (!req) return NULL;
	
	req->out.hdr = req->out.buffer + NBT_HDR_SIZE;
	req->out.vwv = req->out.hdr + HDR_VWV;
	req->out.wct = wct;
	req->out.data = req->out.vwv + VWV(wct) + 2;
	req->out.data_size = buflen;
	req->out.ptr = req->out.data;

	SCVAL(req->out.hdr, HDR_WCT, wct);
	SSVAL(req->out.vwv, VWV(wct), buflen);

	memcpy(req->out.hdr, "\377SMB", 4);
	SCVAL(req->out.hdr,HDR_COM,command);

	SCVAL(req->out.hdr,HDR_FLG, FLAG_CASELESS_PATHNAMES);
	SSVAL(req->out.hdr,HDR_FLG2, 0);

	/* assign a mid */
	req->mid = cli_transport_next_mid(transport);

	/* copy the pid, uid and mid to the request */
	SSVAL(req->out.hdr, HDR_PID, 0);
	SSVAL(req->out.hdr, HDR_UID, 0);
	SSVAL(req->out.hdr, HDR_MID, req->mid);
	SSVAL(req->out.hdr, HDR_TID,0);
	SSVAL(req->out.hdr, HDR_PIDHIGH,0);
	SIVAL(req->out.hdr, HDR_RCLS, 0);
	memset(req->out.hdr+HDR_SS_FIELD, 0, 10);
	
	return req;
}

/*
  setup a reply in req->out with the given word count and initial data
  buffer size.  the caller will then fill in the command words and
  data before calling cli_request_send() to send the reply on its
  way. This interface is used before a session is setup.
*/
struct cli_request *cli_request_setup_session(struct cli_session *session,
					      uint8 command, unsigned wct, unsigned buflen)
{
	struct cli_request *req;
	uint16_t flags2;
	uint32_t capabilities;

	req = cli_request_setup_transport(session->transport, command, wct, buflen);

	if (!req) return NULL;

	req->session = session;
	
	flags2 = FLAGS2_LONG_PATH_COMPONENTS;
	capabilities = session->transport->negotiate.capabilities;

	if (capabilities & CAP_UNICODE) {
		flags2 |= FLAGS2_UNICODE_STRINGS;
	}
	if (capabilities & CAP_STATUS32) {
		flags2 |= FLAGS2_32_BIT_ERROR_CODES;
	}
	if (capabilities & CAP_EXTENDED_SECURITY) {
		flags2 |= FLAGS2_EXTENDED_SECURITY;
	}
	if (session->transport->negotiate.sign_info.doing_signing) {
		flags2 |= FLAGS2_SMB_SECURITY_SIGNATURES;
	}

	SSVAL(req->out.hdr, HDR_FLG2, flags2);
	SSVAL(req->out.hdr, HDR_PID, session->pid & 0xFFFF);
	SSVAL(req->out.hdr, HDR_PIDHIGH, session->pid >> 16);
	SSVAL(req->out.hdr, HDR_UID, session->vuid);
	
	return req;
}

/*
  setup a request for tree based commands
*/
struct cli_request *cli_request_setup(struct cli_tree *tree,
				      uint8 command, 
				      unsigned wct, unsigned buflen)
{
	struct cli_request *req;

	req = cli_request_setup_session(tree->session, command, wct, buflen);
	if (req) {
		req->tree = tree;
		SSVAL(req->out.hdr,HDR_TID,tree->tid);
	}
	return req;
}

/*
  grow the allocation of the data buffer portion of a reply
  packet. Note that as this can reallocate the packet buffer this
  invalidates any local pointers into the packet.

  To cope with this req->out.ptr is supplied. This will be updated to
  point at the same offset into the packet as before this call
*/
static void cli_req_grow_allocation(struct cli_request *req, unsigned new_size)
{
	int delta;
	char *buf2;

	delta = new_size - req->out.data_size;
	if (delta + req->out.size <= req->out.allocated) {
		/* it fits in the preallocation */
		return;
	}

	/* we need to realloc */
	req->out.allocated = req->out.size + delta + REQ_OVER_ALLOCATION;
	buf2 = talloc_realloc(req->mem_ctx, req->out.buffer, req->out.allocated);
	if (buf2 == NULL) {
		smb_panic("out of memory in req_grow_allocation");
	}

	if (buf2 == req->out.buffer) {
		/* the malloc library gave us the same pointer */
		return;
	}
	
	/* update the pointers into the packet */
	req->out.data = buf2 + PTR_DIFF(req->out.data, req->out.buffer);
	req->out.ptr  = buf2 + PTR_DIFF(req->out.ptr,  req->out.buffer);
	req->out.vwv  = buf2 + PTR_DIFF(req->out.vwv,  req->out.buffer);
	req->out.hdr  = buf2 + PTR_DIFF(req->out.hdr,  req->out.buffer);

	req->out.buffer = buf2;
}


/*
  grow the data buffer portion of a reply packet. Note that as this
  can reallocate the packet buffer this invalidates any local pointers
  into the packet. 

  To cope with this req->out.ptr is supplied. This will be updated to
  point at the same offset into the packet as before this call
*/
static void cli_req_grow_data(struct cli_request *req, unsigned new_size)
{
	int delta;

	cli_req_grow_allocation(req, new_size);

	delta = new_size - req->out.data_size;

	req->out.size += delta;
	req->out.data_size += delta;

	/* set the BCC to the new data size */
	SSVAL(req->out.vwv, VWV(req->out.wct), new_size);
}

/*
  send a message
*/
BOOL cli_request_send(struct cli_request *req)
{
	uint_t ret;

	if (IVAL(req->out.buffer, 0) == 0) {
		_smb_setlen(req->out.buffer, req->out.size - NBT_HDR_SIZE);
	}

	cli_request_calculate_sign_mac(req);

	ret = cli_sock_write(req->transport->socket, req->out.buffer, req->out.size);

	if (req->out.size != ret) {
		req->transport->error.etype = ETYPE_SOCKET;
		req->transport->error.e.socket_error = SOCKET_WRITE_ERROR;
		DEBUG(0,("Error writing %d bytes to server - %s\n",
			 (int)req->out.size, strerror(errno)));
		return False;
	}

	/* add it to the list of pending requests */
	DLIST_ADD(req->transport->pending_requests, req);
	
	return True;
}


/*
  receive a response to a packet
*/
BOOL cli_request_receive(struct cli_request *req)
{
	/* req can be NULL when a send has failed. This eliminates lots of NULL
	   checks in each module */
	if (!req) return False;

	/* keep receiving packets until this one is replied to */
	while (!req->in.buffer) {
		if (!cli_transport_select(req->transport)) {
			req->status = NT_STATUS_UNSUCCESSFUL;
			return False;
		}

		if (!cli_request_receive_next(req->transport)) {
			cli_transport_dead(req->transport);
			req->status = NT_STATUS_UNEXPECTED_NETWORK_ERROR;
			return False;
		}
	}

	return True;
}


/*
  handle oplock break requests from the server - return True if the request was
  an oplock break
*/
static BOOL handle_oplock_break(struct cli_transport *transport, uint_t len, const char *hdr, const char *vwv)
{
	/* we must be very fussy about what we consider an oplock break to avoid
	   matching readbraw replies */
	if (len != MIN_SMB_SIZE + VWV(8) ||
	    (CVAL(hdr, HDR_FLG) & FLAG_REPLY) ||
	    CVAL(hdr,HDR_COM) != SMBlockingX ||
	    SVAL(hdr, HDR_MID) != 0xFFFF ||
	    SVAL(vwv,VWV(6)) != 0 ||
	    SVAL(vwv,VWV(7)) != 0) {
		return False;
	}

	if (transport->oplock.handler) {
		uint16_t tid = SVAL(hdr, HDR_TID);
		uint16_t fnum = SVAL(vwv,VWV(2));
		uint8 level = CVAL(vwv,VWV(3)+1);
		transport->oplock.handler(transport, tid, fnum, level, transport->oplock.private);
	}

	return True;
}


/*
  receive an async message from the server
  this function assumes that the caller already knows that the socket is readable
  and that there is a packet waiting

  The packet is not actually returned by this function, instead any
  registered async message handlers are called

  return True if a packet was successfully received and processed
  return False if the socket appears to be dead
*/
BOOL cli_request_receive_next(struct cli_transport *transport)
{
	BOOL ret;
	int len;
	char header[NBT_HDR_SIZE];
	char *buffer, *hdr, *vwv;
	TALLOC_CTX *mem_ctx;
	struct cli_request *req;
	uint16_t wct, mid = 0;

	len = cli_sock_read(transport->socket, header, 4);
	if (len != 4) {
		return False;
	}
	
	len = smb_len(header);

	mem_ctx = talloc_init("cli_request_receive_next");
	
	/* allocate the incoming buffer at the right size */
	buffer = talloc(mem_ctx, len+NBT_HDR_SIZE);
	if (!buffer) {
		talloc_destroy(mem_ctx);
		return False;
	}

	/* fill in the already received header */
	memcpy(buffer, header, NBT_HDR_SIZE);

	ret = cli_sock_read(transport->socket, buffer + NBT_HDR_SIZE, len);
	/* If the server is not responding, note that now */
	if (ret != len) {
		return False;
	}

	hdr = buffer+NBT_HDR_SIZE;
	vwv = hdr + HDR_VWV;

	/* see if it could be an oplock break request */
	if (handle_oplock_break(transport, len, hdr, vwv)) {
		goto done;
	}

	/* at this point we need to check for a readbraw reply, as these can be any length */
	if (transport->readbraw_pending) {
		transport->readbraw_pending = 0;

		/* it must match the first entry in the pending queue as the client is not allowed
		   to have outstanding readbraw requests */
		req = transport->pending_requests;
		if (!req) goto done;

		req->in.buffer = buffer;
		talloc_steal(mem_ctx, req->mem_ctx, buffer);
		req->in.size = len + NBT_HDR_SIZE;
		req->in.allocated = req->in.size;
		goto async;
	}

	if (len >= MIN_SMB_SIZE) {
		/* extract the mid for matching to pending requests */
		mid = SVAL(hdr, HDR_MID);
		wct = CVAL(hdr, HDR_WCT);
	}

	/* match the incoming request against the list of pending requests */
	for (req=transport->pending_requests; req; req=req->next) {
		if (req->mid == mid) break;
	}

	if (!req) {
		DEBUG(3,("Discarding unmatched reply with mid %d\n", mid));
		goto done;
	}

	/* fill in the 'in' portion of the matching request */
	req->in.buffer = buffer;
	talloc_steal(mem_ctx, req->mem_ctx, buffer);
	req->in.size = len + NBT_HDR_SIZE;
	req->in.allocated = req->in.size;

	/* handle non-SMB replies */
	if (req->in.size < NBT_HDR_SIZE + MIN_SMB_SIZE) {
		goto done;
	}

	if (req->in.size < NBT_HDR_SIZE + MIN_SMB_SIZE + VWV(wct)) {
		DEBUG(2,("bad reply size for mid %d\n", mid));
		req->status = NT_STATUS_UNSUCCESSFUL;
		goto done;
	}

	req->in.hdr = hdr;
	req->in.vwv = vwv;
	req->in.wct = wct;
	if (req->in.size >= NBT_HDR_SIZE + MIN_SMB_SIZE + VWV(wct)) {
		req->in.data = req->in.vwv + VWV(wct) + 2;
		req->in.data_size = SVAL(req->in.vwv, VWV(wct));
		if (req->in.size < NBT_HDR_SIZE + MIN_SMB_SIZE + VWV(wct) + req->in.data_size) {
			DEBUG(3,("bad data size for mid %d\n", mid));
			/* blergh - w2k3 gives a bogus data size values in some
			   openX replies */
			req->in.data_size = req->in.size - (NBT_HDR_SIZE + MIN_SMB_SIZE + VWV(wct));
		}
	}
	req->in.ptr = req->in.data;
	req->flags2 = SVAL(req->in.hdr, HDR_FLG2);

	if (!(req->flags2 & FLAGS2_32_BIT_ERROR_CODES)) {
		transport->error.etype = ETYPE_DOS;
		transport->error.e.dos.eclass = CVAL(req->in.hdr,HDR_RCLS);
		transport->error.e.dos.ecode = SVAL(req->in.hdr,HDR_ERR);
		req->status = dos_to_ntstatus(transport->error.e.dos.eclass, 
					      transport->error.e.dos.ecode);
	} else {
		transport->error.etype = ETYPE_NT;
		transport->error.e.nt_status = NT_STATUS(IVAL(req->in.hdr, HDR_RCLS));
		req->status = transport->error.e.nt_status;
	}

	if (!cli_request_check_sign_mac(req)) {
		transport->error.etype = ETYPE_SOCKET;
		transport->error.e.socket_error = SOCKET_READ_BAD_SIG;
		return False;
	};

async:
	/* if this request has an async handler then call that to
	   notify that the reply has been received. This might destroy
	   the request so it must happen last */
	if (req->async.fn) {
		req->async.fn(req);
	}

done:
	talloc_destroy(mem_ctx);
	return True;
}


/*
  wait for a reply to be received for a packet that just returns an error
  code and nothing more
*/
NTSTATUS cli_request_simple_recv(struct cli_request *req)
{
	cli_request_receive(req);
	return cli_request_destroy(req);
}


/* Return true if the last packet was in error */
BOOL cli_request_is_error(struct cli_request *req)
{
	return NT_STATUS_IS_ERR(req->status);
}

/*
  append a string into the data portion of the request packet

  return the number of bytes added to the packet
*/
size_t cli_req_append_string(struct cli_request *req, const char *str, unsigned flags)
{
	size_t len;

	/* determine string type to use */
	if (!(flags & (STR_ASCII|STR_UNICODE))) {
		flags |= (req->transport->negotiate.capabilities & CAP_UNICODE) ? STR_UNICODE : STR_ASCII;
	}

	len = (strlen(str)+2) * MAX_BYTES_PER_CHAR;		

	cli_req_grow_allocation(req, len + req->out.data_size);

	len = push_string(NULL, req->out.data + req->out.data_size, str, len, flags);

	cli_req_grow_data(req, len + req->out.data_size);

	return len;
}

/*
  this is like cli_req_append_string but it also return the
  non-terminated string byte length, which can be less than the number
  of bytes consumed in the packet for 2 reasons:

   1) the string in the packet may be null terminated
   2) the string in the packet may need a 1 byte UCS2 alignment

 this is used in places where the non-terminated string byte length is
 placed in the packet as a separate field  
*/
size_t cli_req_append_string_len(struct cli_request *req, const char *str, unsigned flags, int *len)
{
	int diff = 0;
	size_t ret;

	/* determine string type to use */
	if (!(flags & (STR_ASCII|STR_UNICODE))) {
		flags |= (req->transport->negotiate.capabilities & CAP_UNICODE) ? STR_UNICODE : STR_ASCII;
	}

	/* see if an alignment byte will be used */
	if ((flags & STR_UNICODE) && !(flags & STR_NOALIGN)) {
		diff = ucs2_align(NULL, req->out.data + req->out.data_size, flags);
	}

	/* do the hard work */
	ret = cli_req_append_string(req, str, flags);

	/* see if we need to subtract the termination */
	if (flags & STR_TERMINATE) {
		diff += (flags & STR_UNICODE) ? 2 : 1;
	}

	if (ret >= diff) {
		(*len) = ret - diff;
	} else {
		(*len) = ret;
	}

	return ret;
}


/*
  push a string into the data portion of the request packet, growing it if necessary
  this gets quite tricky - please be very careful to cover all cases when modifying this

  if dest is NULL, then put the string at the end of the data portion of the packet

  if dest_len is -1 then no limit applies
*/
size_t cli_req_append_ascii4(struct cli_request *req, const char *str, unsigned flags)
{
	size_t size;
	cli_req_append_bytes(req, (const uint8 *)"\4", 1);
	size = cli_req_append_string(req, str, flags);
	return size + 1;
}


/*
  push a blob into the data portion of the request packet, growing it if necessary
  this gets quite tricky - please be very careful to cover all cases when modifying this

  if dest is NULL, then put the blob at the end of the data portion of the packet
*/
size_t cli_req_append_blob(struct cli_request *req, const DATA_BLOB *blob)
{
	cli_req_grow_allocation(req, req->out.data_size + blob->length);
	memcpy(req->out.data + req->out.data_size, blob->data, blob->length);
	cli_req_grow_data(req, req->out.data_size + blob->length);
	return blob->length;
}

/*
  append raw bytes into the data portion of the request packet
  return the number of bytes added
*/
size_t cli_req_append_bytes(struct cli_request *req, const uint8 *bytes, size_t byte_len)
{
	cli_req_grow_allocation(req, byte_len + req->out.data_size);
	memcpy(req->out.data + req->out.data_size, bytes, byte_len);
	cli_req_grow_data(req, byte_len + req->out.data_size);
	return byte_len;
}

/*
  append variable block (type 5 buffer) into the data portion of the request packet
  return the number of bytes added
*/
size_t cli_req_append_var_block(struct cli_request *req, const uint8 *bytes, uint16_t byte_len)
{
	cli_req_grow_allocation(req, byte_len + 3 + req->out.data_size);
	SCVAL(req->out.data + req->out.data_size, 0, 5);
	SSVAL(req->out.data + req->out.data_size, 1, byte_len);		/* add field length */
	if (byte_len > 0) {
		memcpy(req->out.data + req->out.data_size + 3, bytes, byte_len);
	}
	cli_req_grow_data(req, byte_len + 3 + req->out.data_size);
	return byte_len + 3;
}


/*
  pull a UCS2 string from a request packet, returning a talloced unix string

  the string length is limited by the 3 things:
   - the data size in the request (end of packet)
   - the passed 'byte_len' if it is not -1
   - the end of string (null termination)

  Note that 'byte_len' is the number of bytes in the packet

  on failure zero is returned and *dest is set to NULL, otherwise the number
  of bytes consumed in the packet is returned
*/
static size_t cli_req_pull_ucs2(struct cli_request *req, TALLOC_CTX *mem_ctx,
				char **dest, const char *src, int byte_len, unsigned flags)
{
	int src_len, src_len2, alignment=0;
	ssize_t ret;

	if (!(flags & STR_NOALIGN) && ucs2_align(req->in.buffer, src, flags)) {
		src++;
		alignment=1;
		if (byte_len != -1) {
			byte_len--;
		}
	}

	src_len = req->in.data_size - PTR_DIFF(src, req->in.data);
	if (src_len < 0) {
		*dest = NULL;
		return 0;
	}
	if (byte_len != -1 && src_len > byte_len) {
		src_len = byte_len;
	}

	src_len2 = strnlen_w((const smb_ucs2_t *)src, src_len/2) * 2;
	if (src_len2 < src_len - 2) {
		/* include the termination if we didn't reach the end of the packet */
		src_len2 += 2;
	}

	/* ucs2 strings must be at least 2 bytes long */
	if (src_len2 < 2) {
		*dest = NULL;
		return 0;
	}

	ret = convert_string_talloc(mem_ctx, CH_UCS2, CH_UNIX, src, src_len2, (const void **)dest);
	if (ret == -1) {
		*dest = NULL;
		return 0;
	}

	return src_len2 + alignment;
}

/*
  pull a ascii string from a request packet, returning a talloced string

  the string length is limited by the 3 things:
   - the data size in the request (end of packet)
   - the passed 'byte_len' if it is not -1
   - the end of string (null termination)

  Note that 'byte_len' is the number of bytes in the packet

  on failure zero is returned and *dest is set to NULL, otherwise the number
  of bytes consumed in the packet is returned
*/
size_t cli_req_pull_ascii(struct cli_request *req, TALLOC_CTX *mem_ctx,
			  char **dest, const char *src, int byte_len, unsigned flags)
{
	int src_len, src_len2;
	ssize_t ret;

	src_len = req->in.data_size - PTR_DIFF(src, req->in.data);
	if (src_len < 0) {
		*dest = NULL;
		return 0;
	}
	if (byte_len != -1 && src_len > byte_len) {
		src_len = byte_len;
	}
	src_len2 = strnlen(src, src_len);
	if (src_len2 < src_len - 1) {
		/* include the termination if we didn't reach the end of the packet */
		src_len2++;
	}

	ret = convert_string_talloc(mem_ctx, CH_DOS, CH_UNIX, src, src_len2, (const void **)dest);

	if (ret == -1) {
		*dest = NULL;
		return 0;
	}

	return ret;
}

/*
  pull a string from a request packet, returning a talloced string

  the string length is limited by the 3 things:
   - the data size in the request (end of packet)
   - the passed 'byte_len' if it is not -1
   - the end of string (null termination)

  Note that 'byte_len' is the number of bytes in the packet

  on failure zero is returned and *dest is set to NULL, otherwise the number
  of bytes consumed in the packet is returned
*/
size_t cli_req_pull_string(struct cli_request *req, TALLOC_CTX *mem_ctx, 
			   char **dest, const char *src, int byte_len, unsigned flags)
{
	if (!(flags & STR_ASCII) && 
	    (((flags & STR_UNICODE) || (req->flags2 & FLAGS2_UNICODE_STRINGS)))) {
		return cli_req_pull_ucs2(req, mem_ctx, dest, src, byte_len, flags);
	}

	return cli_req_pull_ascii(req, mem_ctx, dest, src, byte_len, flags);
}


/*
  pull a DATA_BLOB from a reply packet, returning a talloced blob
  make sure we don't go past end of packet

  if byte_len is -1 then limit the blob only by packet size
*/
DATA_BLOB cli_req_pull_blob(struct cli_request *req, TALLOC_CTX *mem_ctx, const char *src, int byte_len)
{
	int src_len;

	src_len = req->in.data_size - PTR_DIFF(src, req->in.data);

	if (src_len < 0) {
		return data_blob(NULL, 0);
	}

	if (byte_len != -1 && src_len > byte_len) {
		src_len = byte_len;
	}

	return data_blob_talloc(mem_ctx, src, src_len);
}

/* check that a lump of data in a request is within the bounds of the data section of
   the packet */
static BOOL cli_req_data_oob(struct cli_request *req, const char *ptr, uint32_t count)
{
	/* be careful with wraparound! */
	if (ptr < req->in.data ||
	    ptr >= req->in.data + req->in.data_size ||
	    count > req->in.data_size ||
	    ptr + count > req->in.data + req->in.data_size) {
		return True;
	}
	return False;
}

/*
  pull a lump of data from a request packet

  return False if any part is outside the data portion of the packet
*/
BOOL cli_raw_pull_data(struct cli_request *req, const char *src, int len, char *dest)
{
	if (len == 0) return True;

	if (cli_req_data_oob(req, src, len)) {
		return False;
	}

	memcpy(dest, src, len);
	return True;
}


/*
  put a NTTIME into a packet
*/
void cli_push_nttime(void *base, uint16_t offset, NTTIME t)
{
	SBVAL(base, offset, t);
}

/*
  pull a NTTIME from a packet
*/
NTTIME cli_pull_nttime(void *base, uint16_t offset)
{
	NTTIME ret = BVAL(base, offset);
	return ret;
}

/*
  pull a UCS2 string from a blob, returning a talloced unix string

  the string length is limited by the 3 things:
   - the data size in the blob
   - the passed 'byte_len' if it is not -1
   - the end of string (null termination)

  Note that 'byte_len' is the number of bytes in the packet

  on failure zero is returned and *dest is set to NULL, otherwise the number
  of bytes consumed in the blob is returned
*/
static size_t cli_blob_pull_ucs2(TALLOC_CTX* mem_ctx,
				 DATA_BLOB *blob, const char **dest, 
				 const char *src, int byte_len, unsigned flags)
{
	int src_len, src_len2, alignment=0;
	ssize_t ret;

	if (src < (const char *)blob->data ||
	    src >= (const char *)(blob->data + blob->length)) {
		*dest = NULL;
		return 0;
	}

	src_len = blob->length - PTR_DIFF(src, blob->data);

	if (byte_len != -1 && src_len > byte_len) {
		src_len = byte_len;
	}

	if (!(flags & STR_NOALIGN) && ucs2_align(blob->data, src, flags)) {
		src++;
		alignment=1;
		src_len--;
	}

	if (src_len < 2) {
		*dest = NULL;
		return 0;
	}

	src_len2 = strnlen_w((const smb_ucs2_t *)src, src_len/2) * 2;

	if (src_len2 < src_len - 2) {
		/* include the termination if we didn't reach the end of the packet */
		src_len2 += 2;
	}

	ret = convert_string_talloc(mem_ctx, CH_UCS2, CH_UNIX, src, src_len2, (const void **)dest);
	if (ret == -1) {
		*dest = NULL;
		return 0;
	}

	return src_len2 + alignment;
}

/*
  pull a ascii string from a blob, returning a talloced string

  the string length is limited by the 3 things:
   - the data size in the blob
   - the passed 'byte_len' if it is not -1
   - the end of string (null termination)

  Note that 'byte_len' is the number of bytes in the blob

  on failure zero is returned and *dest is set to NULL, otherwise the number
  of bytes consumed in the blob is returned
*/
static size_t cli_blob_pull_ascii(TALLOC_CTX *mem_ctx,
				  DATA_BLOB *blob, const char **dest, 
				  const char *src, int byte_len, unsigned flags)
{
	int src_len, src_len2;
	ssize_t ret;

	src_len = blob->length - PTR_DIFF(src, blob->data);
	if (src_len < 0) {
		*dest = NULL;
		return 0;
	}
	if (byte_len != -1 && src_len > byte_len) {
		src_len = byte_len;
	}
	src_len2 = strnlen(src, src_len);

	if (src_len2 < src_len - 1) {
		/* include the termination if we didn't reach the end of the packet */
		src_len2++;
	}

	ret = convert_string_talloc(mem_ctx, CH_DOS, CH_UNIX, src, src_len2, (const void **)dest);

	if (ret == -1) {
		*dest = NULL;
		return 0;
	}

	return ret;
}

/*
  pull a string from a blob, returning a talloced WIRE_STRING

  the string length is limited by the 3 things:
   - the data size in the blob
   - length field on the wire
   - the end of string (null termination)

   if STR_LEN8BIT is set in the flags then assume the length field is
   8 bits, instead of 32

  on failure zero is returned and dest->s is set to NULL, otherwise the number
  of bytes consumed in the blob is returned
*/
size_t cli_blob_pull_string(struct cli_session *session,
			    TALLOC_CTX *mem_ctx,
			    DATA_BLOB *blob, 
			    WIRE_STRING *dest, 
			    uint16_t len_offset, uint16_t str_offset, 
			    unsigned flags)
{
	int extra;
	dest->s = NULL;
	
	if (len_offset > blob->length-4) {
		return 0;
	}
	if (flags & STR_LEN8BIT) {
		dest->private_length = CVAL(blob->data, len_offset);
	} else {
		dest->private_length = IVAL(blob->data, len_offset);
	}
	extra = 0;
	dest->s = NULL;
	if (!(flags & STR_ASCII) && 
	    ((flags & STR_UNICODE) || 
	     (session->transport->negotiate.capabilities & CAP_UNICODE))) {
		int align = 0;
		if ((str_offset&1) && !(flags & STR_NOALIGN)) {
			align = 1;
		}
		if (flags & STR_LEN_NOTERM) {
			extra = 2;
		}
		return align + extra + cli_blob_pull_ucs2(mem_ctx, blob, &dest->s, 
							  blob->data+str_offset+align, 
							  dest->private_length, flags);
	}

	if (flags & STR_LEN_NOTERM) {
		extra = 1;
	}

	return extra + cli_blob_pull_ascii(mem_ctx, blob, &dest->s, 
					   blob->data+str_offset, dest->private_length, flags);
}

/*
  pull a string from a blob, returning a talloced char *

  Currently only used by the UNIX search info level.

  the string length is limited by 2 things:
   - the data size in the blob
   - the end of string (null termination)

  on failure zero is returned and dest->s is set to NULL, otherwise the number
  of bytes consumed in the blob is returned
*/
size_t cli_blob_pull_unix_string(struct cli_session *session,
			    TALLOC_CTX *mem_ctx,
			    DATA_BLOB *blob, 
			    const char **dest, 
			    uint16_t str_offset, 
			    unsigned flags)
{
	int extra = 0;
	*dest = NULL;
	
	if (!(flags & STR_ASCII) && 
	    ((flags & STR_UNICODE) || 
	     (session->transport->negotiate.capabilities & CAP_UNICODE))) {
		int align = 0;
		if ((str_offset&1) && !(flags & STR_NOALIGN)) {
			align = 1;
		}
		if (flags & STR_LEN_NOTERM) {
			extra = 2;
		}
		return align + extra + cli_blob_pull_ucs2(mem_ctx, blob, dest, 
							  blob->data+str_offset+align, 
							  -1, flags);
	}

	if (flags & STR_LEN_NOTERM) {
		extra = 1;
	}

	return extra + cli_blob_pull_ascii(mem_ctx, blob, dest,
					   blob->data+str_offset, -1, flags);
}


/*
  append a string into a blob
*/
size_t cli_blob_append_string(struct cli_session *session,
			      TALLOC_CTX *mem_ctx, DATA_BLOB *blob, 
			      const char *str, unsigned flags)
{
	size_t max_len;
	int len;

	if (!str) return 0;

	/* determine string type to use */
	if (!(flags & (STR_ASCII|STR_UNICODE))) {
		flags |= (session->transport->negotiate.capabilities & CAP_UNICODE) ? STR_UNICODE : STR_ASCII;
	}

	max_len = (strlen(str)+2) * MAX_BYTES_PER_CHAR;		

	blob->data = talloc_realloc(mem_ctx, blob->data, blob->length + max_len);
	if (!blob->data) {
		return 0;
	}

	len = push_string(NULL, blob->data + blob->length, str, max_len, flags);

	blob->length += len;

	return len;
}
