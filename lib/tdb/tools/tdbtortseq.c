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

#include "replace.h"
#include "system/filesys.h"
#include <tdb.h>
#include <stdio.h>
#include <errno.h>
#include "system/wait.h"

#define NPROCS 500
#define NUMOPS 1000000

int main(void)
{
	pid_t pids[NPROCS];
	struct tdb_context *tdb = NULL;
	int i;
	uint32_t seqnum_before, seqnum_after;

	tdb = tdb_open("seqnum_test.tdb",
		       10000,
		       TDB_CLEAR_IF_FIRST|
		       TDB_SEQNUM|
		       TDB_INCOMPATIBLE_HASH|
		       TDB_MUTEX_LOCKING,
		       O_CREAT|O_RDWR,
		       0644);
	if (tdb == NULL) {
		perror("tdb_open failed");
		return 1;
	}
	seqnum_before = tdb_get_seqnum(tdb);

	for (i=0; i<NPROCS; i++) {
		pids[i] = fork();
		if (pids[i] == -1) {
			perror("fork failed");
			return 1;
		}
		if (pids[i] == 0) {
			pid_t mypid = getpid();
			int ret;
			int j;

			ret = tdb_reopen(tdb);
			if (ret != 0) {
				perror("tdb_reopen failed");
				return 1;
			}

			for (j=0; j<NUMOPS; j++) {
				TDB_DATA key = {
					.dptr = (uint8_t *)&mypid,
					.dsize = sizeof(mypid),
				};
				TDB_DATA value = {
					.dptr = (uint8_t *)&j,
					.dsize = sizeof(j),
				};
				ret = tdb_store(tdb, key, value, 0);
				if (ret == -1) {
					perror("tdb_store failed");
					return 1;
				}
			}

			return 0;
		}
	}

	for (i=0; i<NPROCS; i++) {
		int wstatus;
		pid_t ret = waitpid(pids[i], &wstatus, 0);

		if (ret == -1) {
			perror("waitpid failed");
			return 1;
		}

		if (!WIFEXITED(wstatus)) {
			fprintf(stderr,
				"pid %d did not exit properly\n",
				(int)pids[i]);
			return 1;
		}

		if (WEXITSTATUS(wstatus) != 0) {
			fprintf(stderr,
				"pid %d returned %d\n",
				(int)pids[i],
				WEXITSTATUS(wstatus));
			return 1;
		}
	}

	seqnum_after = tdb_get_seqnum(tdb);

	printf("seqnum_before=%"PRIu32", seqnum_after=%"PRIu32"\n",
	       seqnum_before,
	       seqnum_after);

	if ((seqnum_after - seqnum_before) != (NPROCS*NUMOPS)) {
		perror("incrementing seqnum failed");
		return 1;
	}

	return 0;
}
