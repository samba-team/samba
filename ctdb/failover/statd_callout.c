/*
   CTDB NFSv3 rpc.statd HA callout

   Copyright 2023, DataDirect Networks, Inc. All rights reserved.
   Author: Martin Schwenke <mschwenke@ddn.com>

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

#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "replace.h"

/*
 * A configuration file, created by statd_callout_helper, containing
 * at least 1 line of text.
 *
 * The first line is the mode.  Currently supported modes are:
 *
 *   persistent_db
 *
 * In this mode, the file contains 2 subsequent lines of text:
 *
 *   path: directory where files should be created
 *   ips_file: file containing node's currently assigned public IP addresses
 */
#define CONFIG_FILE CTDB_VARDIR "/scripts/statd_callout.conf"

static const char *progname;

struct {
	enum {
		CTDB_SC_MODE_PERSISTENT_DB,
	} mode;
	union {
		struct {
			char *path;
			char *ips_file;
		};
	};
} config;

static bool getline_strip(char **lineptr,
			  size_t *n,
			  FILE *stream)
{
	bool was_null;
	int ret;

	was_null = *lineptr == NULL;

	ret = getline(lineptr, n, stream);
	if (ret == -1 || ret <= 2) {
		if (was_null) {
			free(*lineptr);
			*lineptr = NULL;
			*n = 0;
		}
		return false;
	}

	if ((*lineptr)[ret - 1] == '\n') {
		(*lineptr)[ret - 1] = '\0';
	}

	return true;
}

static void free_config(void)
{
	switch (config.mode) {
	case CTDB_SC_MODE_PERSISTENT_DB:
		free(config.path);
		config.path = NULL;
		free(config.ips_file);
		config.ips_file = NULL;
	}
}

static void read_config(void)
{
	const char *config_file = NULL;
	FILE *f = NULL;
	char *mode = NULL;
	size_t n = 0;
	bool status;

	/* For testing only */
	config_file = getenv("CTDB_STATD_CALLOUT_CONFIG_FILE");
	if (config_file == NULL || strlen(config_file) == 0) {
		config_file = CONFIG_FILE;
	}

	f = fopen(config_file, "r");
	if (f == NULL) {
		fprintf(stderr,
			"%s: unable to open config file (%s)\n",
			progname,
			config_file);
		exit(1);
	}

	status = getline_strip(&mode, &n, f);
	if (!status) {
		fprintf(stderr,
			"%s: error parsing mode in %s\n",
			progname,
			config_file);
		exit(1);
	}
	if (strcmp(mode, "persistent_db") == 0) {
		config.mode = CTDB_SC_MODE_PERSISTENT_DB;
	} else {
		fprintf(stderr,
			"%s: unknown mode=%s in %s\n",
			progname,
			mode,
			config_file);
		free(mode);
		exit(1);
	}
	free(mode);

	switch (config.mode) {
	case CTDB_SC_MODE_PERSISTENT_DB:
		status = getline_strip(&config.path, &n, f);
		if (!status) {
			goto parse_error;
		}

		status = getline_strip(&config.ips_file, &n, f);
		if (!status) {
			goto parse_error;
		}

		break;
	}

	fclose(f);
	return;

parse_error:
	fprintf(stderr,
		"%s: error parsing contents of %s\n",
		progname,
		config_file);
	free_config();
	exit(1);
}

static void for_each_sip(void (*line_func)(const char *sip, const char *cip),
			 const char *cip)
{
	FILE *f = NULL;
	char *line = NULL;
	size_t n = 0;

	f = fopen(config.ips_file, "r");
	if (f == NULL) {
		fprintf(stderr,
			"%s: unable to open IPs file (%s)\n",
			progname,
			config.ips_file);
		exit(1);
	}

	for (;;) {
		bool status;

		status = getline_strip(&line, &n, f);
		if (!status) {
			if (!feof(f)) {
				fprintf(stderr,
					"%s: error parsing contents of %s\n",
					progname,
					config.ips_file);
				free(line);
				exit(1);
			}
			break;
		}

		line_func(line, cip);
	}

	free(line);
	fclose(f);
	return;
}

static void make_path(char *buf,
		      size_t num,
		      const char *sip,
		      const char *cip)
{
	int ret = snprintf(buf,
			   num,
			   "%s/statd-state@%s@%s",
			   config.path,
			   sip,
			   cip);
	if (ret < 0) {
		/* Not possible for snprintf(3)? */
		fprintf(stderr,
			"%s: error constructing path %s/statd-state@%s@%s\n",
			progname,
			config.path,
			sip,
			cip);
		exit(1);
	}
	if ((size_t)ret >= num) {
		fprintf(stderr,
			"%s: path too long %s/statd-state@%s@%s\n",
			progname,
			config.path,
			sip,
			cip);
		exit(1);
	}
}

static void add_client_persistent_db_line(const char *sip, const char *cip)
{
	char path[PATH_MAX];
	FILE *f;
	long long datetime;

	make_path(path, sizeof(path), sip, cip);

	datetime = (long long)time(NULL);

	f = fopen(path, "w");
	if (f == NULL) {
		fprintf(stderr,
			"%s: unable to open for writing %s\n",
			progname,
			path);
		exit(1);
	}
	fprintf(f, "\"statd-state@%s@%s\" \"%lld\"\n", sip, cip, datetime);
	fclose(f);
}

static void add_client_persistent_db(const char *cip)
{
	for_each_sip(add_client_persistent_db_line, cip);
}

static void del_client_persistent_db_line(const char *sip, const char *cip)
{
	char path[PATH_MAX];
	FILE *f;

	make_path(path, sizeof(path), sip, cip);

	f = fopen(path, "w");
	if (f == NULL) {
		fprintf(stderr,
			"%s: unable to open for writing %s\n",
			progname,
			path);
		exit(1);
	}
	fprintf(f, "\"statd-state@%s@%s\" \"\"\n", sip, cip);
	fclose(f);
}

static void del_client_persistent_db(const char *cip)
{
	for_each_sip(del_client_persistent_db_line, cip);
}

static void usage(void)
{
	printf("usage: %s: { add-client | del-client } <client-ip>\n", progname);
	exit(1);
}

int main(int argc, const char *argv[])
{
	const char *event = NULL;
	const char *mon_name = NULL;

	progname = argv[0];
	if (argc < 3) {
		usage();
	}

	read_config();

	event = argv[1];
	if (strcmp(event, "add-client") == 0) {
		mon_name = argv[2];
		switch (config.mode) {
		case CTDB_SC_MODE_PERSISTENT_DB:
			add_client_persistent_db(mon_name);
			break;
		}
	} else if (strcmp(event, "del-client") == 0) {
		mon_name = argv[2];
		switch (config.mode) {
		case CTDB_SC_MODE_PERSISTENT_DB:
			del_client_persistent_db(mon_name);
			break;
		}
	} else {
		usage();
	}

	free_config();
}
