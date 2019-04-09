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

#include "replace.h"
#include <stdio.h>
#include <errno.h>
#include "libcli/dns/resolvconf.h"
#include "lib/util/memory.h"

int parse_resolvconf_fp(
	FILE *fp,
	TALLOC_CTX *mem_ctx,
	char ***pnameservers,
	size_t *pnum_nameservers)
{
	char *line = NULL;
	size_t len = 0;
	char **nameservers = NULL;
	size_t num_nameservers = 0;
	int ret = 0;

	while (true) {
		char *saveptr = NULL, *option = NULL, *ns = NULL;
		char **tmp = NULL;
		ssize_t n = 0;

		n = getline(&line, &len, fp);
		if (n < 0) {
			if (!feof(fp)) {
				/* real error */
				ret = errno;
			}
			break;
		}
		if ((n > 0) && (line[n-1] == '\n')) {
			line[n-1] = '\0';
		}

		if ((line[0] == '#') || (line[0] == ';')) {
			continue;
		}

		option = strtok_r(line, " \t", &saveptr);
		if (option == NULL) {
			continue;
		}

		if (strcmp(option, "nameserver") != 0) {
			continue;
		}

		ns = strtok_r(NULL, " \t", &saveptr);
		if (ns == NULL) {
			continue;
		}

		tmp = talloc_realloc(
			mem_ctx,
			nameservers,
			char *,
			num_nameservers+1);
		if (tmp == NULL) {
			ret = ENOMEM;
			break;
		}
		nameservers = tmp;

		nameservers[num_nameservers] = talloc_strdup(nameservers, ns);
		if (nameservers[num_nameservers] == NULL) {
			ret = ENOMEM;
			break;
		}
		num_nameservers += 1;
	}

	SAFE_FREE(line);

	if (ret == 0) {
		*pnameservers = nameservers;
		*pnum_nameservers = num_nameservers;
	} else {
		TALLOC_FREE(nameservers);
	}

	return ret;
}

int parse_resolvconf(
	const char *resolvconf,
	TALLOC_CTX *mem_ctx,
	char ***pnameservers,
	size_t *pnum_nameservers)
{
	FILE *fp;
	int ret;

	fp = fopen(resolvconf ? resolvconf : "/etc/resolv.conf", "r");
	if (fp == NULL) {
		return errno;
	}

	ret = parse_resolvconf_fp(fp, mem_ctx, pnameservers, pnum_nameservers);

	fclose(fp);

	return ret;
}
