/* 
   Unix SMB/CIFS implementation.

   routines for marshalling/unmarshalling spoolss subcontext buffer structures

   Copyright (C) Andrew Tridgell 2003
   Copyright (C) Tim Potter 2003
   
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

NTSTATUS pull_spoolss_PrinterInfoArray(DATA_BLOB *blob, TALLOC_CTX *mem_ctx,
				       uint32_t level, uint32_t count,
				       union spoolss_PrinterInfo **info)
{
	int i;
	struct ndr_pull *ndr;
	ndr = ndr_pull_init_blob(blob, mem_ctx);
	if (!ndr) {
		return NT_STATUS_NO_MEMORY;
	}
	NDR_ALLOC_N(ndr, *info, count);
	for (i=0;i<count;i++) {
		ndr->data += ndr->offset;
		ndr->offset = 0;
		NDR_CHECK(ndr_pull_spoolss_PrinterInfo(ndr, NDR_SCALARS|NDR_BUFFERS, level, &(*info)[i]));
	}
	return NT_STATUS_OK;
}

NTSTATUS pull_spoolss_FormInfoArray(DATA_BLOB *blob, TALLOC_CTX *mem_ctx,
				    uint32_t level, uint32_t count,
				    union spoolss_FormInfo **info)
{
	int i;
	struct ndr_pull *ndr;
	ndr = ndr_pull_init_blob(blob, mem_ctx);
	if (!ndr) {
		return NT_STATUS_NO_MEMORY;
	}
	NDR_ALLOC_N(ndr, *info, count);
	for (i=0;i<count;i++) {
		NDR_CHECK(ndr_pull_spoolss_FormInfo(ndr, NDR_SCALARS|NDR_BUFFERS, level, &(*info)[i]));
	}
	return NT_STATUS_OK;
}

NTSTATUS pull_spoolss_JobInfoArray(DATA_BLOB *blob, TALLOC_CTX *mem_ctx,
				   uint32_t level, uint32_t count,
				   union spoolss_JobInfo **info)
{
	int i;
	struct ndr_pull *ndr;
	ndr = ndr_pull_init_blob(blob, mem_ctx);
	if (!ndr) {
		return NT_STATUS_NO_MEMORY;
	}
	NDR_ALLOC_N(ndr, *info, count);
	for (i=0;i<count;i++) {
		NDR_CHECK(ndr_pull_spoolss_JobInfo(ndr, NDR_SCALARS|NDR_BUFFERS, level, &(*info)[i]));
	}
	return NT_STATUS_OK;
}

NTSTATUS pull_spoolss_DriverInfoArray(DATA_BLOB *blob, TALLOC_CTX *mem_ctx,
				      uint32_t level, uint32_t count,
				      union spoolss_DriverInfo **info)
{
	int i;
	struct ndr_pull *ndr;
	ndr = ndr_pull_init_blob(blob, mem_ctx);
	if (!ndr) {
		return NT_STATUS_NO_MEMORY;
	}
	NDR_ALLOC_N(ndr, *info, count);
	for (i=0;i<count;i++) {
		NDR_CHECK(ndr_pull_spoolss_DriverInfo(ndr, NDR_SCALARS|NDR_BUFFERS, level, &(*info)[i]));
	}
	return NT_STATUS_OK;
}

NTSTATUS pull_spoolss_PortInfoArray(DATA_BLOB *blob, TALLOC_CTX *mem_ctx,
				      uint32_t level, uint32_t count,
				      union spoolss_PortInfo **info)
{
	int i;
	struct ndr_pull *ndr;
	ndr = ndr_pull_init_blob(blob, mem_ctx);
	if (!ndr) {
		return NT_STATUS_NO_MEMORY;
	}
	NDR_ALLOC_N(ndr, *info, count);
	for (i=0;i<count;i++) {
		ndr->data += ndr->offset;
		ndr->offset = 0;
		NDR_CHECK(ndr_pull_spoolss_PortInfo(ndr, NDR_SCALARS|NDR_BUFFERS, level, &(*info)[i]));
	}
	return NT_STATUS_OK;
}
