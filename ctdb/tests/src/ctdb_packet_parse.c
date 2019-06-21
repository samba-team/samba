/*
   CTDB protocol parser

   Copyright (C) Amitay Isaacs  2016

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
#include "system/network.h"
#include "system/locale.h"

#include <talloc.h>
#include <tdb.h>

#include "protocol/protocol.h"
#include "protocol/protocol_api.h"

static TDB_DATA strace_parser(char *buf, TALLOC_CTX *mem_ctx)
{
	TDB_DATA data;
	size_t i = 0, j = 0;

	data.dptr = talloc_size(mem_ctx, strlen(buf));
	if (data.dptr == NULL) {
		return tdb_null;
	}

	while (i < strlen(buf)) {
		if (buf[i] == '\\') {
			/* first char after '\' is a digit or other escape */
			if (isdigit(buf[i+1])) {
				char tmp[4] = { '\0', '\0', '\0', '\0' };

				tmp[0] = buf[i+1];
				if (isdigit(buf[i+2])) {
					tmp[1] = buf[i+2];
					if (isdigit(buf[i+3])) {
						tmp[2] = buf[i+3];
						i += 4;
					} else {
						i += 3;
					}
				} else {
					i += 2;
				}
				data.dptr[j] = strtol(tmp, NULL, 8);
			} else if (buf[i+1] == 'a') {
				data.dptr[j] = 7;
				i += 2;
			} else if (buf[i+1] == 'b') {
				data.dptr[j] = 8;
				i += 2;
			} else if (buf[i+1] == 't') {
				data.dptr[j] = 9;
				i += 2;
			} else if (buf[i+1] == 'n') {
				data.dptr[j] = 10;
				i += 2;
			} else if (buf[i+1] == 'v') {
				data.dptr[j] = 11;
				i += 2;
			} else if (buf[i+1] == 'f') {
				data.dptr[j] = 12;
				i += 2;
			} else if (buf[i+1] == 'r') {
				data.dptr[j] = 13;
				i += 2;
			} else {
				fprintf(stderr,
					"Unknown escape \\%c\n",
					buf[i+1]);
				data.dptr[j] = 0;
			}

			j += 1;
		} else if (buf[i] == '\n') {
			i += 1;
		} else if (buf[i] == '\0') {
			break;
		} else {
			data.dptr[j] = buf[i];
			i += 1;
			j += 1;
		}
	}

	data.dsize = j;

	return data;
}

int main(int argc, char *argv[])
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	char line[1024];
	char *ptr;
	TDB_DATA (*parser)(char *, TALLOC_CTX *);

	if (argc != 2) {
		fprintf(stderr, "Usage: %s strace\n", argv[0]);
		exit(1);
	}

	if (strcmp(argv[1], "strace") == 0) {
		parser = strace_parser;
	} else {
		fprintf(stderr, "Unknown input format - %s\n", argv[1]);
		exit(1);
	}

	while ((ptr = fgets(line, sizeof(line), stdin)) != NULL) {
		TDB_DATA data;

		data = parser(ptr, mem_ctx);
		if (data.dptr == NULL) {
			continue;
		}

		ctdb_packet_print(data.dptr, data.dsize, stdout);
		TALLOC_FREE(data.dptr);
	}

	return 0;
}
