/* 
   Unix SMB/CIFS implementation.
   Samba temporary memory allocation functions -- torturer
   Copyright (C) 2001 by Martin Pool <mbp@samba.org>
   
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

#define NCTX 10
#define NOBJ 20

int main(void)
{
	int i;
	TALLOC_CTX *ctx[NCTX];

	for (i = 0; i < NCTX; i++) {
		ctx[i] = talloc_init("torture(%d)", i);
	}

	for (i = 0; i < NCTX; i++) {
		int j;
		for (j = 0; j < NOBJ; j++) {
			char *p;
			size_t size = 1<<(i/3+j);

			p = talloc(ctx[i], size);
			if (!p) {
				fprintf(stderr,
					"failed to talloc %.0f bytes\n",
					(double) size);
				exit(1);
			}

			memset(p, 'A' + j, size);
		}
	}

	for (i = 0; i < NCTX; i++) {
		printf("talloc@%p %-40s %ldkB\n", ctx[i],
		       talloc_pool_name(ctx[i]),
		       (unsigned long)talloc_pool_size(ctx[i]) >> 10);
	}

	printf("%s", talloc_describe_all(ctx[0]));

	for (i = NCTX - 1; i >= 0; i--)
		talloc_destroy(ctx[i]);

	return 0;
}
