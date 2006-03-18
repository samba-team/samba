/* 
   Unix SMB/CIFS implementation.

   libndr obfuscate support (MAPI)

   Copyright (C) Stefan Metzmacher 2005
   
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
#include "librpc/ndr/libndr.h"

/*
  handle obfuscated subcontext buffers, which in midl land are user-marshalled, but
  we use magic in pidl to make them easier to cope with
*/
NTSTATUS ndr_pull_obfuscation_start(struct ndr_pull *ndr, uint8_t salt)
{
	uint32_t i;

	for (i=0; i<ndr->data_size; i++) {
		ndr->data[i] ^= salt;
	}

	return NT_STATUS_OK;
}

NTSTATUS ndr_pull_obfuscation_end(struct ndr_pull *ndr, uint8_t salt)
{
	return NT_STATUS_OK;
}

NTSTATUS ndr_push_obfuscation_start(struct ndr_push *ndr, uint8_t salt)
{
	return NT_STATUS_OK;
}

/*
  push a obfuscated subcontext
*/
NTSTATUS ndr_push_obfuscation_end(struct ndr_push *ndr, uint8_t salt)
{
	uint32_t i;

	for (i=0; i<ndr->offset; i++) {
		ndr->data[i] ^= salt;
	}

	return NT_STATUS_OK;
}
