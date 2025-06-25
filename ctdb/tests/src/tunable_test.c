/*
   Test tunable handling

   Copyright (C) Martin Schwenke, DataDirect Networks  2022

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, see <http://www.gnu.org/licenses/>.
*/

#include "replace.h"
#include "system/filesys.h"

#include <talloc.h>
#include <assert.h>

#include "common/logging.c"

#include "common/tunable.c"

int main(int argc, const char **argv)
{
	TALLOC_CTX *mem_ctx;
	struct ctdb_tunable_list tun_list;
	struct ctdb_var_list *list;
	bool status;
	int ret = 0;
	int i;

	if (argc != 2 && argc != 3) {
		fprintf(stderr, "Usage: %s <filename> [<filename>]\n", argv[0]);
		return 1;
	}

	mem_ctx = talloc_new(NULL);
	assert(mem_ctx != NULL);

	logging_init(mem_ctx, "file:", NULL, "tunable_test");

	ctdb_tunable_set_defaults(&tun_list);

	status = ctdb_tunable_load_file(mem_ctx, &tun_list, argv[1]);
	if (!status) {
		ret = EINVAL;
		goto done;
	}

	if (argc == 3) {
		status = ctdb_tunable_load_file(mem_ctx, &tun_list, argv[2]);
		if (!status) {
			ret = EINVAL;
			goto done;
		}
	}

	list = ctdb_tunable_names(mem_ctx);
	assert(list != NULL);

	for (i = 0; i < list->count; i++) {
		const char *var = list->var[i];
		uint32_t val;

		status = ctdb_tunable_get_value(&tun_list, var, &val);
		if (!status) {
			ret = EIO;
			goto done;
		}

		printf("%s=%"PRIu32"\n", var, val);
		fflush(stdout);
	}

done:
	talloc_free(mem_ctx);
	return ret;
}
