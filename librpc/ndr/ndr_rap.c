/*
   Unix SMB/CIFS implementation.

   routines for marshalling/unmarshalling special rap types

   Copyright (C) Guenther Deschner 2010

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "includes.h"
#include "librpc/gen_ndr/ndr_rap.h"

_PUBLIC_ void ndr_print_rap_NetPrintQEnum(struct ndr_print *ndr, const char *name, int flags, const struct rap_NetPrintQEnum *r)
{
	uint32_t cntr_info_1;
	ndr_print_struct(ndr, name, "rap_NetPrintQEnum");
	ndr->depth++;
	if (flags & NDR_SET_VALUES) {
		ndr->flags |= LIBNDR_PRINT_SET_VALUES;
	}
	if (flags & NDR_IN) {
		ndr_print_struct(ndr, "in", "rap_NetPrintQEnum");
		ndr->depth++;
		ndr_print_uint16(ndr, "level", r->in.level);
		ndr_print_uint16(ndr, "bufsize", r->in.bufsize);
		ndr->depth--;
	}
	if (flags & NDR_OUT) {
		ndr_print_struct(ndr, "out", "rap_NetPrintQEnum");
		ndr->depth++;
		ndr_print_WERROR(ndr, "status", W_ERROR(r->out.status));
		ndr_print_uint16(ndr, "convert", r->out.convert);
		ndr_print_uint16(ndr, "count", r->out.count);
		ndr_print_uint16(ndr, "available", r->out.available);
		ndr_print_ptr(ndr, "info", r->out.info);
		ndr->depth++;
		ndr->print(ndr, "%s: ARRAY(%d)", "info", (int)r->out.count);
		ndr->depth++;
		for (cntr_info_1=0;cntr_info_1<r->out.count;cntr_info_1++) {
			char *idx_1=NULL;
			if (asprintf(&idx_1, "[%d]", cntr_info_1) != -1) {
				ndr_print_set_switch_value(ndr, &r->out.info[cntr_info_1], r->in.level);
				ndr_print_rap_printq_info(ndr, "info", &r->out.info[cntr_info_1]);
				free(idx_1);
			}
		}
		ndr->depth--;
		ndr->depth--;
		ndr->depth--;
	}
	ndr->depth--;
}
