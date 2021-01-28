/*
   Unix SMB/CIFS implementation.

   Fuzz driver (AFL style)

   Copyright (C) Andrew Bartlett 2019

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
#include "lib/util/samba_util.h"
#include "fuzzing.h"

int main(int argc, char *argv[]) {
	int ret;
	size_t size = 0;
	int i;

	ret = LLVMFuzzerInitialize(&argc, &argv);
	if (ret != 0) {
		printf("LLVMFuzzerInitialize returned %d\n", ret);
		return ret;
	}


#ifdef __AFL_LOOP
	while (__AFL_LOOP(1000))
#else
	for (i = 1; i < argc; i++) {
		uint8_t *buf = (uint8_t *)file_load(argv[i],
						    &size,
						    0,
						    NULL);
		ret = LLVMFuzzerTestOneInput(buf, size);
		TALLOC_FREE(buf);
		if (ret != 0) {
			printf("LLVMFuzzerTestOneInput returned %d on argument %d\n",
			       ret, i);
			return ret;
		}
	}
	if (i == 1)
#endif
	{
		uint8_t *buf = (uint8_t *)fd_load(0, &size, 0, NULL);
		if (buf == NULL) {
			exit(1);
		}

		ret = LLVMFuzzerTestOneInput(buf, size);
		TALLOC_FREE(buf);
	}
	return ret;
}
