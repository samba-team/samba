/* 
   Unix SMB/CIFS implementation.
   
   Copyright (C) Andrew Tridgell              2003
   
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
  this file implements functions for manipulating the 'struct smbsrv_request' structure in smbd
*/

#include "includes.h"

/* we over allocate the data buffer to prevent too many realloc calls */
#define REQ_OVER_ALLOCATION 256

/* destroy a request structure */
void req_destroy(struct smbsrv_request *req)
{
	/* ahh, its so nice to destroy a complex structure in such a
	 * simple way! */
	talloc_free(req);
}

/****************************************************************************
construct a basic request packet, mostly used to construct async packets
such as change notify and oplock break requests
****************************************************************************/
struct smbsrv_request *init_smb_request(struct smbsrv_connection *smb_conn)
{
	struct smbsrv_request *req;

	smb_conn->pkt_count++;

	req = talloc_p(smb_conn, struct smbsrv_request);
	if (!req) {
		return NULL;
	}

	ZERO_STRUCTP(req);

	/* setup the request context */
	req->smb_conn = smb_conn;
	
	return req;
}


/*
  setup a chained reply in req->out with the given word count and initial data buffer size. 
*/
static void req_setup_chain_reply(struct smbsrv_request *req, uint_t wct, uint_t buflen)
{
	uint32_t chain_base_size = req->out.size;

	/* we need room for the wct value, the words, the buffer length and the buffer */
	req->out.size += 1 + VWV(wct) + 2 + buflen;

	/* over allocate by a small amount */
	req->out.allocated = req->out.size + REQ_OVER_ALLOCATION; 

	req->out.buffer = talloc_realloc(req, req->out.buffer, req->out.allocated);
	if (!req->out.buffer) {
		smbsrv_terminate_connection(req->smb_conn, "allocation failed");
	}

	req->out.hdr = req->out.buffer + NBT_HDR_SIZE;
	req->out.vwv = req->out.buffer + chain_base_size + 1;
	req->out.wct = wct;
	req->out.data = req->out.vwv + VWV(wct) + 2;
	req->out.data_size = buflen;
	req->out.ptr = req->out.data;

	SCVAL(req->out.buffer, chain_base_size, wct);
	SSVAL(req->out.vwv, VWV(wct), buflen);
}


/*
  setup a reply in req->out with the given word count and initial data buffer size. 
  the caller will then fill in the command words and data before calling req_send_reply() to 
  send the reply on its way
*/
void req_setup_reply(struct smbsrv_request *req, uint_t wct, uint_t buflen)
{
	if (req->chain_count != 0) {
		req_setup_chain_reply(req, wct, buflen);
		return;
	}

	req->out.size = NBT_HDR_SIZE + MIN_SMB_SIZE + wct*2 + buflen;

	/* over allocate by a small amount */
	req->out.allocated = req->out.size + REQ_OVER_ALLOCATION; 

	req->out.buffer = talloc(req, req->out.allocated);
	if (!req->out.buffer) {
		smbsrv_terminate_connection(req->smb_conn, "allocation failed");
	}

	req->out.hdr = req->out.buffer + NBT_HDR_SIZE;
	req->out.vwv = req->out.hdr + HDR_VWV;
	req->out.wct = wct;
	req->out.data = req->out.vwv + VWV(wct) + 2;
	req->out.data_size = buflen;
	req->out.ptr = req->out.data;

	SIVAL(req->out.hdr, HDR_RCLS, 0);

	SCVAL(req->out.hdr, HDR_WCT, wct);
	SSVAL(req->out.vwv, VWV(wct), buflen);


	memcpy(req->out.hdr, "\377SMB", 4);
	SCVAL(req->out.hdr,HDR_FLG, FLAG_REPLY | FLAG_CASELESS_PATHNAMES); 
	SSVAL(req->out.hdr,HDR_FLG2, 
	      (req->flags2 & FLAGS2_UNICODE_STRINGS) |
	      FLAGS2_LONG_PATH_COMPONENTS | FLAGS2_32_BIT_ERROR_CODES | FLAGS2_EXTENDED_SECURITY);

	SSVAL(req->out.hdr,HDR_PIDHIGH,0);
	memset(req->out.hdr + HDR_SS_FIELD, 0, 10);

	if (req->in.hdr) {
		/* copy the cmd, tid, pid, uid and mid from the request */
		SCVAL(req->out.hdr,HDR_COM,CVAL(req->in.hdr,HDR_COM));	
		SSVAL(req->out.hdr,HDR_TID,SVAL(req->in.hdr,HDR_TID));
		SSVAL(req->out.hdr,HDR_PID,SVAL(req->in.hdr,HDR_PID));
		SSVAL(req->out.hdr,HDR_UID,SVAL(req->in.hdr,HDR_UID));
		SSVAL(req->out.hdr,HDR_MID,SVAL(req->in.hdr,HDR_MID));
	} else {
		SSVAL(req->out.hdr,HDR_TID,0);
		SSVAL(req->out.hdr,HDR_PID,0);
		SSVAL(req->out.hdr,HDR_UID,0);
		SSVAL(req->out.hdr,HDR_MID,0);
	}
}

/*
  work out the maximum data size we will allow for this reply, given
  the negotiated max_xmit. The basic reply packet must be setup before
  this call

  note that this is deliberately a signed integer reply
*/
int req_max_data(struct smbsrv_request *req)
{
	int ret;
	ret = req->smb_conn->negotiate.max_send;
	ret -= PTR_DIFF(req->out.data, req->out.hdr);
	if (ret < 0) ret = 0;
	return ret;
}


/*
  grow the allocation of the data buffer portion of a reply
  packet. Note that as this can reallocate the packet buffer this
  invalidates any local pointers into the packet.

  To cope with this req->out.ptr is supplied. This will be updated to
  point at the same offset into the packet as before this call
*/
static void req_grow_allocation(struct smbsrv_request *req, uint_t new_size)
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
	buf2 = talloc_realloc(req, req->out.buffer, req->out.allocated);
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
void req_grow_data(struct smbsrv_request *req, uint_t new_size)
{
	int delta;

	if (!(req->control_flags & REQ_CONTROL_LARGE) && new_size > req_max_data(req)) {
		smb_panic("reply buffer too large!");
	}

	req_grow_allocation(req, new_size);

	delta = new_size - req->out.data_size;

	req->out.size += delta;
	req->out.data_size += delta;

	/* set the BCC to the new data size */
	SSVAL(req->out.vwv, VWV(req->out.wct), new_size);
}

/*
  send a reply and destroy the request buffer

  note that this only looks at req->out.buffer and req->out.size, allowing manually 
  constructed packets to be sent
*/
void req_send_reply_nosign(struct smbsrv_request *req)
{
	NTSTATUS status;
	DATA_BLOB tmp_blob;
	size_t sendlen;

	if (req->out.size > NBT_HDR_SIZE) {
		_smb_setlen(req->out.buffer, req->out.size - NBT_HDR_SIZE);
	}

	tmp_blob.data = req->out.buffer;
	tmp_blob.length = req->out.size;

	status = socket_send(req->smb_conn->connection->socket, req, &tmp_blob, &sendlen, SOCKET_FLAG_BLOCK);
	if (!NT_STATUS_IS_OK(status) || (req->out.size != sendlen)) {
		smbsrv_terminate_connection(req->smb_conn, "failed to send reply\n");
		return;
	}

	req_destroy(req);
}

/*
  possibly sign a message then send a reply and destroy the request buffer

  note that this only looks at req->out.buffer and req->out.size, allowing manually 
  constructed packets to be sent
*/
void req_send_reply(struct smbsrv_request *req)
{
	req_sign_packet(req);

	req_send_reply_nosign(req);
}



/* 
   construct and send an error packet with a forced DOS error code
   this is needed to match win2000 behaviour for some parts of the protocol
*/
void req_reply_dos_error(struct smbsrv_request *req, uint8_t eclass, uint16_t ecode)
{
	/* if the basic packet hasn't been setup yet then do it now */
	if (req->out.buffer == NULL) {
		req_setup_reply(req, 0, 0);
	}

	SCVAL(req->out.hdr, HDR_RCLS, eclass);
	SSVAL(req->out.hdr, HDR_ERR, ecode);
	SSVAL(req->out.hdr, HDR_FLG2, SVAL(req->out.hdr, HDR_FLG2) & ~FLAGS2_32_BIT_ERROR_CODES);	
	req_send_reply(req);
}

/* 
   setup the header of a reply to include an NTSTATUS code
*/
void req_setup_error(struct smbsrv_request *req, NTSTATUS status)
{
	if (!lp_nt_status_support() || !(req->smb_conn->negotiate.client_caps & CAP_STATUS32)) {
		/* convert to DOS error codes */
		uint8_t eclass;
		uint32_t ecode;
		ntstatus_to_dos(status, &eclass, &ecode);
		SCVAL(req->out.hdr, HDR_RCLS, eclass);
		SSVAL(req->out.hdr, HDR_ERR, ecode);
		SSVAL(req->out.hdr, HDR_FLG2, SVAL(req->out.hdr, HDR_FLG2) & ~FLAGS2_32_BIT_ERROR_CODES);
		return;
	}

	if (NT_STATUS_IS_DOS(status)) {
		/* its a encoded DOS error, using the reserved range */
		SSVAL(req->out.hdr, HDR_RCLS, NT_STATUS_DOS_CLASS(status));
		SSVAL(req->out.hdr, HDR_ERR,  NT_STATUS_DOS_CODE(status));
		SSVAL(req->out.hdr, HDR_FLG2, SVAL(req->out.hdr, HDR_FLG2) & ~FLAGS2_32_BIT_ERROR_CODES);
	} else {
		SIVAL(req->out.hdr, HDR_RCLS, NT_STATUS_V(status));
		SSVAL(req->out.hdr, HDR_FLG2, SVAL(req->out.hdr, HDR_FLG2) | FLAGS2_32_BIT_ERROR_CODES);
	}
}

/* 
   construct and send an error packet, then destroy the request 
   auto-converts to DOS error format when appropriate
*/
void req_reply_error(struct smbsrv_request *req, NTSTATUS status)
{
	req_setup_reply(req, 0, 0);

	/* error returns never have any data */
	req_grow_data(req, 0);

	req_setup_error(req, status);
	req_send_reply(req);
}


/*
  push a string into the data portion of the request packet, growing it if necessary
  this gets quite tricky - please be very careful to cover all cases when modifying this

  if dest is NULL, then put the string at the end of the data portion of the packet

  if dest_len is -1 then no limit applies
*/
size_t req_push_str(struct smbsrv_request *req, char *dest, const char *str, int dest_len, uint_t flags)
{
	size_t len;
	uint_t grow_size;
	char *buf0;
	const int max_bytes_per_char = 3;

	if (!(flags & (STR_ASCII|STR_UNICODE))) {
		flags |= (req->flags2 & FLAGS2_UNICODE_STRINGS) ? STR_UNICODE : STR_ASCII;
	}

	if (dest == NULL) {
		dest = req->out.data + req->out.data_size;
	}

	if (dest_len != -1) {
		len = dest_len;
	} else {
		len = (strlen(str)+2) * max_bytes_per_char;
	}

	grow_size = len + PTR_DIFF(dest, req->out.data);
	buf0 = req->out.buffer;

	req_grow_allocation(req, grow_size);

	if (buf0 != req->out.buffer) {
		dest = req->out.buffer + PTR_DIFF(dest, buf0);
	}

	len = push_string(dest, str, len, flags);

	grow_size = len + PTR_DIFF(dest, req->out.data);

	if (grow_size > req->out.data_size) {
		req_grow_data(req, grow_size);
	}

	return len;
}

/*
  append raw bytes into the data portion of the request packet
  return the number of bytes added
*/
size_t req_append_bytes(struct smbsrv_request *req, 
			const uint8_t *bytes, size_t byte_len)
{
	req_grow_allocation(req, byte_len + req->out.data_size);
	memcpy(req->out.data + req->out.data_size, bytes, byte_len);
	req_grow_data(req, byte_len + req->out.data_size);
	return byte_len;
}
/*
  append variable block (type 5 buffer) into the data portion of the request packet
  return the number of bytes added
*/
size_t req_append_var_block(struct smbsrv_request *req, 
		const uint8_t *bytes, uint16_t byte_len)
{
	req_grow_allocation(req, byte_len + 3 + req->out.data_size);
	SCVAL(req->out.data + req->out.data_size, 0, 5);
	SSVAL(req->out.data + req->out.data_size, 1, byte_len);		/* add field length */
	if (byte_len > 0) {
		memcpy(req->out.data + req->out.data_size + 3, bytes, byte_len);
	}
	req_grow_data(req, byte_len + 3 + req->out.data_size);
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
static size_t req_pull_ucs2(struct smbsrv_request *req, const char **dest, const char *src, int byte_len, uint_t flags)
{
	int src_len, src_len2, alignment=0;
	ssize_t ret;
	char *dest2;

	if (!(flags & STR_NOALIGN) && ucs2_align(req->in.buffer, src, flags)) {
		src++;
		alignment=1;
		if (byte_len != -1) {
			byte_len--;
		}
	}

	if (flags & STR_NO_RANGE_CHECK) {
		src_len = byte_len;
	} else {
		src_len = req->in.data_size - PTR_DIFF(src, req->in.data);
		if (src_len < 0) {
			*dest = NULL;
			return 0;
		}

		if (byte_len != -1 && src_len > byte_len) {
			src_len = byte_len;
		}
	}

	src_len2 = utf16_len_n(src, src_len);
	ret = convert_string_talloc(req, CH_UTF16, CH_UNIX, src, src_len2, (void **)&dest2);

	if (ret == -1) {
		*dest = NULL;
		return 0;
	}
	*dest = dest2;

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
static size_t req_pull_ascii(struct smbsrv_request *req, const char **dest, const char *src, int byte_len, uint_t flags)
{
	int src_len, src_len2;
	ssize_t ret;
	char *dest2;

	if (flags & STR_NO_RANGE_CHECK) {
		src_len = byte_len;
	} else {
		src_len = req->in.data_size - PTR_DIFF(src, req->in.data);
		if (src_len < 0) {
			*dest = NULL;
			return 0;
		}
		if (byte_len != -1 && src_len > byte_len) {
			src_len = byte_len;
		}
	}

	src_len2 = strnlen(src, src_len);
	if (src_len2 <= src_len - 1) {
		/* include the termination if we didn't reach the end of the packet */
		src_len2++;
	}

	ret = convert_string_talloc(req, CH_DOS, CH_UNIX, src, src_len2, (void **)&dest2);

	if (ret == -1) {
		*dest = NULL;
		return 0;
	}
	*dest = dest2;

	return src_len2;
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
size_t req_pull_string(struct smbsrv_request *req, const char **dest, const char *src, int byte_len, uint_t flags)
{
	if (!(flags & STR_ASCII) && 
	    (((flags & STR_UNICODE) || (req->flags2 & FLAGS2_UNICODE_STRINGS)))) {
		return req_pull_ucs2(req, dest, src, byte_len, flags);
	}

	return req_pull_ascii(req, dest, src, byte_len, flags);
}


/*
  pull a ASCII4 string buffer from a request packet, returning a talloced string
  
  an ASCII4 buffer is a null terminated string that has a prefix
  of the character 0x4. It tends to be used in older parts of the protocol.

  on failure *dest is set to the zero length string. This seems to
  match win2000 behaviour
*/
size_t req_pull_ascii4(struct smbsrv_request *req, const char **dest, const char *src, uint_t flags)
{
	ssize_t ret;

	if (PTR_DIFF(src, req->in.data) + 1 > req->in.data_size) {
		/* win2000 treats this as the NULL string! */
		(*dest) = talloc_strdup(req, "");
		return 0;
	}

	/* this consumes the 0x4 byte. We don't check whether the byte
	   is actually 0x4 or not. This matches win2000 server
	   behaviour */
	src++;

	ret = req_pull_string(req, dest, src, -1, flags);
	if (ret == -1) {
		(*dest) = talloc_strdup(req, "");
		return 1;
	}
	
	return ret + 1;
}

/*
  pull a DATA_BLOB from a request packet, returning a talloced blob

  return False if any part is outside the data portion of the packet
*/
BOOL req_pull_blob(struct smbsrv_request *req, const char *src, int len, DATA_BLOB *blob)
{
	if (len != 0 && req_data_oob(req, src, len)) {
		return False;
	}

	(*blob) = data_blob_talloc(req, src, len);

	return True;
}

/* check that a lump of data in a request is within the bounds of the data section of
   the packet */
BOOL req_data_oob(struct smbsrv_request *req, const char *ptr, uint32_t count)
{
	if (count == 0) {
		return False;
	}
	
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
   pull an open file handle from a packet, taking account of the chained_fnum
*/
uint16_t req_fnum(struct smbsrv_request *req, const char *base, uint_t offset)
{
	if (req->chained_fnum != -1) {
		return req->chained_fnum;
	}
	return SVAL(base, offset);
}
