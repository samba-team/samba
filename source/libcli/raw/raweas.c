/* 
   Unix SMB/CIFS implementation.
   parsing of EA (extended attribute) lists
   Copyright (C) Andrew Tridgell 2003
   
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

#include "includes.h"

/*
  work out how many bytes on the wire a ea list will consume. 
  This assumes the names are strict ascii, which should be a
  reasonable assumption
*/
uint_t ea_list_size(uint_t num_eas, struct ea_struct *eas)
{
	uint_t total = 4;
	int i;
	for (i=0;i<num_eas;i++) {
		total += 4 + strlen(eas[i].name.s)+1 + eas[i].value.length;
	}
	return total;
}

/*
  put a ea_list into a pre-allocated buffer - buffer must be at least
  of size ea_list_size()
*/
void ea_put_list(char *data, uint_t num_eas, struct ea_struct *eas)
{
	int i;
	uint32_t ea_size;

	ea_size = ea_list_size(num_eas, eas);

	SIVAL(data, 0, ea_size);
	data += 4;

	for (i=0;i<num_eas;i++) {
		uint_t nlen = strlen(eas[i].name.s);
		SCVAL(data, 0, eas[i].flags);
		SCVAL(data, 1, nlen);
		SSVAL(data, 2, eas[i].value.length);
		memcpy(data+4, eas[i].name.s, nlen+1);
		memcpy(data+4+nlen+1, eas[i].value.data, eas[i].value.length);
		data += 4+nlen+1+eas[i].value.length;
	}
}


/*
  pull a ea_struct from a buffer. Return the number of bytes consumed
*/
uint_t ea_pull_struct(const DATA_BLOB *blob, 
		      TALLOC_CTX *mem_ctx,
		      struct ea_struct *ea)
{
	uint8_t nlen;
	uint16_t vlen;

	if (blob->length < 6) {
		return 0;
	}

	ea->flags = CVAL(blob->data, 0);
	nlen = CVAL(blob->data, 1);
	vlen = SVAL(blob->data, 2);

	if (nlen+1+vlen > blob->length-4) {
		return 0;
	}

	ea->name.s = talloc_strndup(mem_ctx, blob->data+4, nlen);
	ea->name.private_length = nlen;
	ea->value = data_blob_talloc(mem_ctx, NULL, vlen+1);
	if (!ea->value.data) return 0;
	if (vlen) {
		memcpy(ea->value.data, blob->data+4+nlen+1, vlen);
	}
	ea->value.data[vlen] = 0;
	ea->value.length--;

	return 4 + nlen+1 + vlen;
}


/*
  pull a ea_list from a buffer
*/
NTSTATUS ea_pull_list(const DATA_BLOB *blob, 
		      TALLOC_CTX *mem_ctx,
		      uint_t *num_eas, struct ea_struct **eas)
{
	int n;
	uint32_t ea_size, ofs;

	if (blob->length < 4) {
		return NT_STATUS_INFO_LENGTH_MISMATCH;
	}

	ea_size = IVAL(blob->data, 0);
	if (ea_size > blob->length) {
		return NT_STATUS_INVALID_PARAMETER;
	}
	
	ofs = 4;	
	n = 0;
	*num_eas = 0;
	*eas = NULL;

	while (ofs < ea_size) {
		uint_t len;
		DATA_BLOB blob2;

		blob2.data = blob->data + ofs;
		blob2.length = ea_size - ofs;

		*eas = talloc_realloc(mem_ctx, *eas, sizeof(**eas) * (n+1));
		if (! *eas) return NT_STATUS_NO_MEMORY;

		len = ea_pull_struct(&blob2, mem_ctx, &(*eas)[n]);
		if (len == 0) {
			return NT_STATUS_INVALID_PARAMETER;
		}

		ofs += len;
		n++;
	}

	*num_eas = n;

	return NT_STATUS_OK;
}

