/* 
   Unix SMB/CIFS implementation.

   routines for marshalling/unmarshalling DCOM string arrays

   Copyright (C) Jelmer Vernooij 2004
   
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

NTSTATUS ndr_pull_DUALSTRINGARRAY(struct ndr_pull *ndr, int ndr_flags, struct DUALSTRINGARRAY *ar)
{
	uint16_t num_entries, security_offset;
	uint16_t towerid;
	uint32_t towernum = 0, conformant_size;

	if (!(ndr_flags & NDR_SCALARS)) {
		return NT_STATUS_OK;
	}

	NDR_CHECK(ndr_pull_uint32(ndr, &conformant_size));
	NDR_CHECK(ndr_pull_uint16(ndr, &num_entries));
	NDR_CHECK(ndr_pull_uint16(ndr, &security_offset));

	ar->stringbindings = talloc_array_p(ndr, struct STRINGBINDING *, num_entries);
	ar->stringbindings[0] = NULL;

	do {
		/* 'Peek' */
		NDR_CHECK(ndr_pull_uint16(ndr, &towerid));

		if (towerid > 0) {
			ndr->offset -= 2; 
			ar->stringbindings = talloc_realloc_p(ndr, ar->stringbindings, struct STRINGBINDING *, towernum+2);
			ar->stringbindings[towernum] = talloc_p(ndr, struct STRINGBINDING);
			NDR_CHECK(ndr_pull_STRINGBINDING(ndr, ndr_flags, ar->stringbindings[towernum]));
			towernum++;
		}
	} while (towerid != 0);

	ar->stringbindings[towernum] = NULL;
	towernum = 0;

	ar->securitybindings = talloc_array_p(ndr, struct SECURITYBINDING *, num_entries);
	ar->securitybindings[0] = NULL;

	do {
		/* 'Peek' */
		NDR_CHECK(ndr_pull_uint16(ndr, &towerid));

		if (towerid > 0) {
			ndr->offset -= 2; 
			ar->securitybindings = talloc_realloc_p(ndr, ar->securitybindings, struct SECURITYBINDING *, towernum+2);
			ar->securitybindings[towernum] = talloc_p(ndr, struct SECURITYBINDING);
			NDR_CHECK(ndr_pull_SECURITYBINDING(ndr, ndr_flags, ar->securitybindings[towernum]));
			towernum++;
		}
	} while (towerid != 0);
	
	ar->securitybindings[towernum] = NULL;
	
	return NT_STATUS_OK;
}

NTSTATUS ndr_push_DUALSTRINGARRAY(struct ndr_push *ndr, int ndr_flags, struct DUALSTRINGARRAY *ar)
{
	return NT_STATUS_NOT_SUPPORTED;
}

/*
  print a dom_sid
*/
void ndr_print_DUALSTRINGARRAY(struct ndr_print *ndr, const char *name, struct DUALSTRINGARRAY *ar)
{
	int i;
	ndr->print(ndr, "%-25s: DUALSTRINGARRAY", name);
	ndr->depth++;
	ndr->print(ndr, "STRING BINDINGS");
	ndr->depth++;
	for (i=0;ar->stringbindings[i];i++)	{
		char *idx = NULL;
		asprintf(&idx, "[%d]", i);
		if (idx) {
			ndr_print_STRINGBINDING(ndr, idx, ar->stringbindings[i]);
			free(idx);
		}
	}
	ndr->depth--;
	ndr->print(ndr, "SECURITY BINDINGS");
	ndr->depth++;
	for (i=0;ar->securitybindings[i];i++)	{
		char *idx = NULL;
		asprintf(&idx, "[%d]", i);
		if (idx) {
			ndr_print_SECURITYBINDING(ndr, idx, ar->securitybindings[i]);
			free(idx);
		}
	}
	ndr->depth--;
}

NTSTATUS ndr_pull_STRINGARRAY(struct ndr_pull *ndr, int ndr_flags, struct STRINGARRAY *ar)
{
	uint16_t towerid;
	uint32_t towernum = 0;
	uint16_t num_entries;

	if (!(ndr_flags & NDR_SCALARS)) {
		return NT_STATUS_OK;
	}

	NDR_CHECK(ndr_pull_uint16(ndr, &num_entries));

	ar->stringbindings = talloc_array_p(ndr, struct STRINGBINDING *, 1);
	ar->stringbindings[0] = NULL;

	do {
		/* 'Peek' */
		NDR_CHECK(ndr_pull_uint16(ndr, &towerid));

		if (towerid > 0) {
			ndr->offset -= 2; 
			ar->stringbindings = talloc_realloc_p(ndr, ar->stringbindings, struct STRINGBINDING *, towernum+2);
			ar->stringbindings[towernum] = talloc_p(ndr, struct STRINGBINDING);
			NDR_CHECK(ndr_pull_STRINGBINDING(ndr, ndr_flags, ar->stringbindings[towernum]));
			towernum++;
		}
	} while (towerid != 0);

	ar->stringbindings[towernum] = NULL;
	towernum = 0;

	return NT_STATUS_OK;
}

NTSTATUS ndr_push_STRINGARRAY(struct ndr_push *ndr, int ndr_flags, struct STRINGARRAY *ar)
{
	return NT_STATUS_NOT_SUPPORTED;
}

/*
  print a dom_sid
*/
void ndr_print_STRINGARRAY(struct ndr_print *ndr, const char *name, struct STRINGARRAY *ar)
{
	int i;
	ndr->print(ndr, "%-25s: STRINGARRAY", name);
	ndr->depth++;
	for (i=0;ar->stringbindings[i];i++)	{
		char *idx = NULL;
		asprintf(&idx, "[%d]", i);
		if (idx) {
			ndr_print_STRINGBINDING(ndr, idx, ar->stringbindings[i]);
			free(idx);
		}
	}
	ndr->depth--;
}
