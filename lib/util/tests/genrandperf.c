/*
   Unix SMB/CIFS implementation.
   local testing of random data routines.
   Copyright (C) Volker Lendecke <vl@samba.org> 2015

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

#include "replace.h"
#include "lib/util/genrand.h"

int main(int argc, const char *argv[])
{
	int i, num;
	uint64_t val;

	if (argc != 2) {
		fprintf(stderr, "genrandperf <num>\n");
		exit(1);
	}
	num = atoi(argv[1]);

	for(i=0; i<num; i++) {
		generate_random_buffer((uint8_t *)&val, sizeof(val));
	}
	printf("%"PRIu64"\n", val);
	return 0;
}
