/* 
   Unix SMB/CIFS implementation.

   Get NT ACLs from UNIX files.

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

#if (!defined(HAVE_NO_ACLS) || !defined(HAVE_XATTR_SUPPORT))

int main(int argc, char **argv)
{
	printf("ACL support not compiled in.");
	return 1;
}

#else

/* Display a security descriptor in "psec" format which is as follows.

   The first two lines describe the owner user and owner group of the
   object.  If either of these lines are blank then the respective
   owner property is not set.  The remaining lines list the individual
   permissions or ACE entries, one per line.  Each column describes a
   different property of the ACE:

       Column    Description
       -------------------------------------------------------------------
         1       ACE type (allow/deny etc)
         2       ACE flags
         3       ACE mask
         4       SID the ACE applies to

   Example:

       S-1-5-21-1067277791-1719175008-3000797951-500

       1 9 0x10000000 S-1-5-21-1067277791-1719175008-3000797951-501
       1 2 0x10000000 S-1-5-21-1067277791-1719175008-3000797951-501
       0 9 0x10000000 S-1-5-21-1067277791-1719175008-3000797951-500
       0 2 0x10000000 S-1-5-21-1067277791-1719175008-3000797951-500
       0 9 0x10000000 S-1-5-21-1067277791-1719175008-3000797951-513
       0 2 0x00020000 S-1-5-21-1067277791-1719175008-3000797951-513
       0 2 0xe0000000 S-1-1-0
*/

static void print_psec(TALLOC_CTX *mem_ctx, struct security_descriptor *sd)
{
	if (sd->owner_sid)
		printf("%s\n", dom_sid_string(mem_ctx, sd->owner_sid));
	else
		printf("\n");

	if (sd->group_sid)
		printf("%s\n", dom_sid_string(mem_ctx, sd->owner_sid));
	else
		printf("\n");

	/* Note: SACL not displayed */

	if (sd->dacl) {
		int i;

		for (i = 0; i < sd->dacl->num_aces; i++) {
			struct security_ace *ace = &sd->dacl->aces[i];
			
			printf("%d %d 0x%08x %s\n", ace->type, ace->flags,
			       ace->access_mask, 
			       dom_sid_string(mem_ctx, &ace->trustee));
		}
			
	}
}

int main(int argc, char **argv)
{
	TALLOC_CTX *mem_ctx;
	ssize_t size;
	char *data;
	struct security_descriptor sd;
	DATA_BLOB blob;
	struct ndr_pull *ndr;
	NTSTATUS result;

	mem_ctx = talloc_init("getntacl");

	/* Fetch ACL data */

	size = getxattr(argv[1], "security.ntacl", NULL, 0);

	if (size == -1) {
		fprintf(stderr, "%s: %s\n", argv[1], strerror(errno));
		exit(1);
	}

	data = talloc(mem_ctx, size);

	size = getxattr(argv[1], "security.ntacl", data, size);

	blob = data_blob_talloc(mem_ctx, data, size);

	ndr = ndr_pull_init_blob(&blob, mem_ctx);

	result = ndr_pull_security_descriptor(
		ndr, NDR_SCALARS|NDR_BUFFERS, &sd);

	print_psec(data, &sd);
	return 0;
}

#endif /* HAVE_NO_ACLS */
