/*
 * Unix SMB/CIFS implementation.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "source3/include/includes.h"
#include <tdb.h>
#include "source3/torture/proto.h"
#include "source3/lib/tdb_validate.h"

static int validate_fn(struct tdb_context *tdb, TDB_DATA key, TDB_DATA value,
		       void *private_data)
{
	struct tdb_validation_status *state = private_data;
	state->success = false;
	printf("validate_fn called\n");
	return -1;
}

bool run_tdb_validate(int dummy)
{
	const char tdb_name[] = "tdb_validate.tdb";
	bool result = false;
	struct tdb_context *tdb = NULL;
	char buf[] = "data";
	TDB_DATA data = { .dptr = (uint8_t *)buf, .dsize = sizeof(buf), };
	int ret;

	unlink(tdb_name);

	tdb = tdb_open(tdb_name, 0, 0, O_CREAT|O_EXCL|O_RDWR, 0600);
	if (tdb == NULL) {
		perror("Could not open tdb");
		goto done;
	}

	ret = tdb_store(tdb, data, data, 0);
	if (ret == -1) {
		perror("tdb_store failed");
		goto done;
	}

	ret = tdb_validate(tdb, validate_fn);
	if (ret == 0) {
		fprintf(stderr,
			"tdb_validate succeeded where it should have "
			"failed\n");
		goto done;
	}

	result = true;
done:
	tdb_close(tdb);
	unlink(tdb_name);
	return result;
}
