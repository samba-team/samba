/* 
   Unix SMB/CIFS implementation.

   local testing of SDDL parsing

   Copyright (C) Andrew Tridgell 2005
   
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
#include "librpc/gen_ndr/ndr_security.h"


/*
  test one SDDL example
*/
static BOOL test_sddl(TALLOC_CTX *mem_ctx, const char *sddl)
{
	struct security_descriptor *sd;
	sd = sddl_decode(mem_ctx, sddl);
	if (sd == NULL) {
		printf("Failed to decode '%s'\n", sddl);
		return False;
	}
	if (DEBUGLVL(2)) {
		NDR_PRINT_DEBUG(security_descriptor, sd);
	}
	talloc_free(sd);
	return True;
}

static const char *examples[] = {
"D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
};

/* test a set of example SDDL strings */
BOOL torture_local_sddl(void) 
{
	int i;
	BOOL ret = True;
	TALLOC_CTX *mem_ctx = talloc_new(NULL);

	for (i=0;i<ARRAY_SIZE(examples);i++) {
		ret &= test_sddl(mem_ctx, examples[i]);
	}

	talloc_free(mem_ctx);
	return ret;
}
