/* 
   Unix SMB/CIFS implementation.

   Set NT ACLs on UNIX files.

   Copyright (C) Tim Potter <tpot@samba.org> 2004
   
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
#include "system/filesys.h"

#if (!defined(HAVE_NO_ACLS) || !defined(HAVE_XATTR_SUPPORT))

int main(int argc, char **argv)
{
	printf("ACL support not compiled in.");
	return 1;
}

#else

int main(int argc, char **argv)
{
	char line[255];
	struct ndr_push *ndr;
	struct lsa_SidArray sidarray;
	NTSTATUS status;
	TALLOC_CTX *mem_ctx;

	setup_logging("setnttoken", DEBUG_STDOUT);

	mem_ctx = talloc_init("setnttoken");

	ndr = ndr_push_init();

	sidarray.num_sids = 0;
	sidarray.sids = NULL;

	while(fgets(line, sizeof(line), stdin)) {
		struct dom_sid *sid = dom_sid_parse_talloc(ndr, line);

		if (!sid) {
			fprintf(stderr, "Invalid sid: %s", line);
			continue;
		}

		sidarray.sids = talloc_realloc(mem_ctx, sidarray.sids,
				(sidarray.num_sids + 1) * sizeof(struct lsa_SidPtr));

		sidarray.sids[sidarray.num_sids].sid =
			dom_sid_dup(ndr, sid);

		sidarray.num_sids++;
	}

/*	NDR_PRINT_DEBUG(lsa_SidArray, &sidarray); */

	status = ndr_push_lsa_SidArray(
		ndr, NDR_SCALARS|NDR_BUFFERS, &sidarray);

	fwrite(ndr->data, 1, ndr->offset, stdout);

	return 0;
}

#endif /* HAVE_NO_ACLS */
