/* 
   Unix SMB/CIFS implementation.

   Get NT ACLs from UNIX files.

   Copyright (C) Tim Potter <tpot@samba.org> 2005
   
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
#include "system/filesys.h"
#include "librpc/gen_ndr/ndr_xattr.h"
#include "lib/util/wrap_xattr.h"

static void ntacl_print_debug_helper(struct ndr_print *ndr, const char *format, ...) PRINTF_ATTRIBUTE(2,3);

static void ntacl_print_debug_helper(struct ndr_print *ndr, const char *format, ...)
{
	va_list ap;
	char *s = NULL;
	int i;

	va_start(ap, format);
	vasprintf(&s, format, ap);
	va_end(ap);

	for (i=0;i<ndr->depth;i++) {
		printf("    ");
	}

	printf("%s\n", s);
	free(s);
}

static NTSTATUS get_ntacl(char *filename, struct xattr_NTACL **ntacl, 
			  ssize_t *ntacl_len)
{
	DATA_BLOB blob;
	ssize_t size;
	NTSTATUS result;
	struct ndr_pull *ndr;
	struct ndr_print *pr;

	*ntacl = talloc(NULL, struct xattr_NTACL);

	size = wrap_getxattr(filename, XATTR_NTACL_NAME, NULL, 0);

	if (size < 0) {
		fprintf(stderr, "get_ntacl: %s\n", strerror(errno));
		return NT_STATUS_INTERNAL_ERROR;
	}

	blob.data = talloc_size(*ntacl, size);
	size = wrap_getxattr(filename, XATTR_NTACL_NAME, blob.data, size);
	if (size < 0) {
		fprintf(stderr, "get_ntacl: %s\n", strerror(errno));
		return NT_STATUS_INTERNAL_ERROR;
	}
	blob.length = size;

	ndr = ndr_pull_init_blob(&blob, NULL);

	result = ndr_pull_xattr_NTACL(ndr, NDR_SCALARS|NDR_BUFFERS, *ntacl);

	if (NT_STATUS_IS_OK(result)) {
		pr = talloc(*ntacl, struct ndr_print);
		pr->print = ntacl_print_debug_helper;
		pr->depth = 0;
		pr->flags = 0;
		
		ndr_print_xattr_NTACL(pr, filename, *ntacl);
	}

	return result;
}

static void print_ntacl(struct xattr_NTACL *ntacl)
{
}

int main(int argc, char *argv[])
{
	struct xattr_NTACL *ntacl;
	ssize_t ntacl_len;

	if (argc != 2) {
		fprintf(stderr, "Usage: getntacl FILENAME\n");
		return 1;
	}


	get_ntacl(argv[1], &ntacl, &ntacl_len);

	print_ntacl(ntacl);

	return 0;
}
