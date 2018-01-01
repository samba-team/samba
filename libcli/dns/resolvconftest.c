/*
 *  Unix SMB/CIFS implementation.
 *  Internal DNS query structures
 *  Copyright (C) Volker Lendecke 2018
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include <stdio.h>
#include <string.h>
#include <talloc.h>
#include <errno.h>
#include "libcli/dns/resolvconf.h"
#include "lib/util/memory.h"

static int resolvconftest1(void)
{
	const char *content =
		"#foo\nbar\nnameserver 1.2.3.4\nnameserver 2.3.4.5";
	char *file;
	FILE *fp;
	int ret;
	char **nameservers;
	size_t num_nameservers;

	file = strdup(content);
	if (file == NULL) {
		perror("strdup failed");
		return ENOMEM;
	}
	fp = fmemopen(file, strlen(file), "r");
	if (fp == NULL) {
		perror("fmemopen failed");
		return errno;
	}

	ret = parse_resolvconf_fp(fp, NULL, &nameservers, &num_nameservers);
	if (ret != 0) {
		fprintf(stderr, "parse_resolvconf_fp failed: %s\n",
			strerror(ret));
		return ret;
	}

	if (num_nameservers != 2) {
		fprintf(stderr, "expected 2 nameservers, got %zu\n",
			num_nameservers);
		return EIO;
	}
	if ((strcmp(nameservers[0], "1.2.3.4") != 0) ||
	    (strcmp(nameservers[1], "2.3.4.5") != 0)) {
		fprintf(stderr, "got wrong nameservers\n");
		return EIO;
	}

	TALLOC_FREE(nameservers);
	fclose(fp);
	SAFE_FREE(file);

	return 0;
}

int main(void) {
	int ret;

	ret = resolvconftest1();
	if (ret != 0) {
		return 1;
	}

	return 0;
}
