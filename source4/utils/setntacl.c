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

#ifdef HAVE_NO_ACLS

int main(int argc, char **argv)
{
	printf("ACL support not compiled in.");
	return 1;
}

#else

static void setntacl(char *filename, struct security_descriptor *sd)
{
	NTSTATUS status;
	struct ndr_push *ndr;
	ssize_t result;

	ndr = ndr_push_init();

	status = ndr_push_security_descriptor(
		ndr, NDR_SCALARS|NDR_BUFFERS, sd);

	result = setxattr(
		filename, "security.ntacl", ndr->data, ndr->offset, 0);

	if (result == -1) {
		fprintf(stderr, "%s: %s\n", filename, strerror(errno));
		exit(1);
	}

}

 int main(int argc, char **argv)
{
	char line[255];
	struct security_descriptor *sd;
	TALLOC_CTX *mem_ctx;
	struct security_acl *acl;

	setup_logging("setntacl", DEBUG_STDOUT);

	mem_ctx = talloc_init("setntacl");

	sd = sd_initialise(mem_ctx);

	fgets(line, sizeof(line), stdin);
	sd->owner_sid = dom_sid_parse_talloc(mem_ctx, line);

	fgets(line, sizeof(line), stdin);
	sd->group_sid = dom_sid_parse_talloc(mem_ctx, line);

	acl = talloc(mem_ctx, sizeof(struct security_acl));

	acl->revision = 2;
	acl->size = 0;
	acl->num_aces = 0;
	acl->aces = NULL;

	while(fgets(line, sizeof(line), stdin)) {
		int ace_type, ace_flags;
		uint32 ace_mask;
		char sidstr[255];
		struct dom_sid *sid;
		
		if (sscanf(line, "%d %d 0x%x %s", &ace_type, &ace_flags,
			   &ace_mask, sidstr) != 4) {
			fprintf(stderr, "invalid ACL line\ndr");
			return 1;
		}
		
		acl->aces = talloc_realloc(
			acl->aces, 
			(acl->num_aces + 1) * sizeof(struct security_ace));

		acl->aces[acl->num_aces].type = ace_type;
		acl->aces[acl->num_aces].flags = ace_flags;
		acl->aces[acl->num_aces].access_mask = ace_mask;

		sid = dom_sid_parse_talloc(mem_ctx, sidstr);

		acl->aces[acl->num_aces].trustee = *sid;

		acl->num_aces++;		
	}

	sd->dacl = acl;

	setntacl(argv[1], sd);

	return 0;
}

#endif /* HAVE_NO_ACLS */
