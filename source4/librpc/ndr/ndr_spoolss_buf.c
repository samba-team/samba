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

NTSTATUS ndr_pull_spoolss_PrinterEnum(struct ndr_pull *ndr, int ndr_flags, 
				      uint16 *level, union spoolss_PrinterEnum *info)
{
	switch (*level) {
	case 1:
		NDR_CHECK(ndr_pull_spoolss_PrinterEnum1(ndr, NDR_SCALARS|NDR_BUFFERS, &info->info1));
		break;
	default:
		return NT_STATUS_INVALID_LEVEL;
	}
	return NT_STATUS_OK;
}


void ndr_print_spoolss_PrinterEnum(struct ndr_print *ndr, const char *name, uint16 level,
				   union spoolss_PrinterEnum *info)
{
	ndr_print_struct(ndr, name, "spoolss_PrinterEnum");

	switch (level) {
	case 1:
		ndr_print_spoolss_PrinterEnum1(ndr, "info1", &info->info1);
		break;
	}
}
