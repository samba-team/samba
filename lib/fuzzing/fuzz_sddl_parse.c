/*
  Fuzz sddl decoding and encoding
  Copyright (C) Catalyst IT 2023

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
#include "libcli/security/security.h"
#include "fuzzing/fuzzing.h"

#define MAX_LENGTH (100 * 1024 - 1)
static char sddl_string[MAX_LENGTH + 1] = {0};
static struct dom_sid dom_sid = {0};

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	string_to_sid(&dom_sid,
		      "S-1-5-21-2470180966-3899876309-2637894779");
	return 0;
}


int LLVMFuzzerTestOneInput(uint8_t *input, size_t len)
{
	TALLOC_CTX *mem_ctx = NULL;
	struct security_descriptor *sd1 = NULL;
	struct security_descriptor *sd2 = NULL;
	char *result = NULL;
	bool ok;

	if (len > MAX_LENGTH) {
		return 0;
	}

	memcpy(sddl_string, input, len);
	sddl_string[len] = '\0';

	mem_ctx = talloc_new(NULL);

	sd1 = sddl_decode(mem_ctx, sddl_string, &dom_sid);
	if (sd1 == NULL) {
		goto end;
	}
	result = sddl_encode(mem_ctx, sd1, &dom_sid);
	sd2 = sddl_decode(mem_ctx, result, &dom_sid);
	ok = security_descriptor_equal(sd1, sd2);
	if (!ok) {
		abort();
	}
end:
	talloc_free(mem_ctx);
	return 0;
}
