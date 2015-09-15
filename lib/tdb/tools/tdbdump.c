/*
   Unix SMB/CIFS implementation.
   simple tdb dump util
   Copyright (C) Andrew Tridgell              2001

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
#include "system/locale.h"
#include "system/time.h"
#include "system/filesys.h"
#include "system/wait.h"
#include "tdb.h"
#include <regex.h>

static void print_data(TDB_DATA d)
{
	unsigned char *p = (unsigned char *)d.dptr;
	int len = d.dsize;
	while (len--) {
		if (isprint(*p) && !strchr("\"\\", *p)) {
			fputc(*p, stdout);
		} else {
			printf("\\%02X", *p);
		}
		p++;
	}
}

static int traverse_fn(TDB_CONTEXT *tdb, TDB_DATA key, TDB_DATA dbuf, void *state)
{
	printf("{\n");
	printf("key(%d) = \"", (int)key.dsize);
	print_data(key);
	printf("\"\n");
	printf("data(%d) = \"", (int)dbuf.dsize);
	print_data(dbuf);
	printf("\"\n");
	printf("}\n");
	return 0;
}

static void log_stderr(struct tdb_context *tdb, enum tdb_debug_level level,
		       const char *fmt, ...)
{
	va_list ap;
	const char *name = tdb_name(tdb);
	const char *prefix = "";

	if (!name)
		name = "unnamed";

	switch (level) {
	case TDB_DEBUG_ERROR:
		prefix = "ERROR: ";
		break;
	case TDB_DEBUG_WARNING:
		prefix = "WARNING: ";
		break;
	case TDB_DEBUG_TRACE:
		return;

	default:
	case TDB_DEBUG_FATAL:
		prefix = "FATAL: ";
		break;
	}

	va_start(ap, fmt);
	fprintf(stderr, "tdb(%s): %s", name, prefix);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
}

static void emergency_walk(TDB_DATA key, TDB_DATA dbuf, void *keyname)
{
	if (keyname) {
		if (key.dsize != strlen(keyname))
			return;
		if (memcmp(key.dptr, keyname, key.dsize) != 0)
			return;
	}
	traverse_fn(NULL, key, dbuf, NULL);
}

static int dump_tdb(const char *fname, const char *keyname, bool emergency)
{
	TDB_CONTEXT *tdb;
	TDB_DATA key, value;
	struct tdb_logging_context logfn = { log_stderr };
	int tdb_flags = TDB_DEFAULT;

	/*
	 * Note: that O_RDONLY implies TDB_NOLOCK, but we want to make it
	 * explicit as it's important when working on databases which were
	 * created with mutex locking.
	 */
	tdb_flags |= TDB_NOLOCK;

	tdb = tdb_open_ex(fname, 0, tdb_flags, O_RDONLY, 0, &logfn, NULL);
	if (!tdb) {
		printf("Failed to open %s\n", fname);
		return 1;
	}

	if (emergency) {
		return tdb_rescue(tdb, emergency_walk, discard_const(keyname)) == 0;
	}
	if (!keyname) {
		return tdb_traverse(tdb, traverse_fn, NULL) == -1 ? 1 : 0;
	} else {
		key.dptr = discard_const_p(uint8_t, keyname);
		key.dsize = strlen(keyname);
		value = tdb_fetch(tdb, key);
		if (!value.dptr) {
			return 1;
		} else {
			print_data(value);
			free(value.dptr);
		}
	}

	return 0;
}

static bool file_parse_lines(FILE *f,
			     bool (*cb)(char *buf, size_t buflen,
					void *private_data),
			     void *private_data)
{
	char *buf;
	size_t buflen;

	buflen = 1024;
	buf = malloc(1024);
	if (buf == NULL) {
		return false;
	}

	while (true) {
		size_t pos = 0;
		int c;
		bool ok;

		while ((c = fgetc(f)) != EOF) {

			buf[pos++] = c;

			if (pos == (buflen-1)) {
				char *tmp;
				tmp = realloc(buf, buflen*2);
				if (tmp == NULL) {
					free(buf);
					return false;
				}
				buf = tmp;
				buflen *= 2;
			}

			if (c == '\n') {
				break;
			}
		}

		if (c == EOF) {
			free(buf);
			return (pos == 0);
		}

		buf[pos] = '\0';

		ok = cb(buf, buflen, private_data);
		if (!ok) {
			break;
		}
	}
	free(buf);
	return true;
}

struct undump_state {
	struct tdb_context *tdb;
	TDB_DATA key;
	TDB_DATA data;
	int line;
};

static ssize_t match_len(const regmatch_t *m, size_t buflen)
{
	if ((m->rm_eo < m->rm_so) ||
	    (m->rm_eo > buflen) || (m->rm_so > buflen)) {
		return -1;
	}
	return m->rm_eo - m->rm_so;
}

static int nibble(char c)
{
	if ((c >= '0') && (c <= '9')) {
		return c - '0';
	}
	if ((c >= 'A') && (c <= 'F')) {
		return c - 'A' + 10;
	}
	if ((c >= 'a') && (c <= 'f')) {
		return c - 'a' + 10;
	}
	return -1;
}

static bool undump_regmatch(int line, char *buf, size_t buflen,
			    const regmatch_t *nummatch,
			    const regmatch_t *datamatch,
			    TDB_DATA *pret)
{
	ssize_t numlen = match_len(nummatch, buflen);
	ssize_t datalen = match_len(datamatch, buflen);
	long long num;
	size_t col;

	TDB_DATA ret = {0};

	if ((numlen == -1) || (datalen == -1)) {
		fprintf(stderr, "No matches in line %d\n", line);
		return false;
	}

	{
		char numbuf[numlen+1];
		memcpy(numbuf, buf+nummatch->rm_so, numlen);
		numbuf[numlen] = '\0';
		num = atoll(numbuf);
	}

	if (num == 0) {
		*pret = ret;
		return true;
	}

	ret.dptr = malloc(datalen);
	if (ret.dptr == NULL) {
		fprintf(stderr, "malloc failed for line %d\n", line);
		return false;
	}

	col = datamatch->rm_so;
	while (col < datamatch->rm_eo) {
		int n;

		if (buf[col] != '\\') {
			ret.dptr[ret.dsize++] = buf[col++];
			continue;
		}

		if ((datamatch->rm_eo - col) < 3) {
			fprintf(stderr, "hex char too short in line %d, "
				"col %d\n", line, (int)col);
			goto fail;
		}

		n = nibble(buf[col+1]);
		if (n == -1) {
			fprintf(stderr, "Could not convert '%c' in line %d "
				"col %d\n", buf[col+1], line, (int)col);
			goto fail;
		}
		ret.dptr[ret.dsize] = n << 4;

		n = nibble(buf[col+2]);
		if (n == -1) {
			fprintf(stderr, "Could not convert '%c' in line %d, "
				"col %d\n", buf[col+2], line, (int)col);
			goto fail;
		}
		ret.dptr[ret.dsize] |= n;

		ret.dsize += 1;
		col += 3;
	}

	if (ret.dsize != num) {
		fprintf(stderr, "Expected %d chars, got %d in line %d\n",
			(int)num, (int)ret.dsize, line);
		goto fail;
	}

	*pret = ret;
	return true;

fail:
	free(ret.dptr);
	return false;
}

static bool undump_cb(char *buf, size_t buflen, void *private_data)
{
	struct undump_state *state = private_data;
	regex_t regex;
	regmatch_t matches[3];
	int ret;
	bool ok;

	state->line++;

	ret = regcomp(&regex, "^key(\\([[:digit:]]*\\)) = \"\\(.*\\)\"\n$", 0);
	if (ret != 0) {
		return false;
	}

	ret = regexec(&regex, buf, 3, matches, 0);
	if (ret == 0) {
		if (state->key.dsize != 0) {
			fprintf(stderr, "line %d has duplicate key\n",
				state->line);
			regfree(&regex);
			return false;
		}
		ok = undump_regmatch(state->line, buf, buflen,
				     &matches[1], &matches[2],
				     &state->key);
		if (!ok) {
			regfree(&regex);
			return false;
		}
	}
	regfree(&regex);

	ret = regcomp(&regex, "^data(\\([[:digit:]]*\\)) = \"\\(.*\\)\"\n$",
		      0);
	if (ret != 0) {
		return false;
	}

	ret = regexec(&regex, buf, 3, matches, 0);
	if (ret == 0) {
		if (state->key.dsize == 0) {
			fprintf(stderr, "line %d has data without key\n",
				state->line);
			regfree(&regex);
			return false;
		}
		if (state->data.dsize != 0) {
			fprintf(stderr, "line %d has duplicate data\n",
				state->line);
			regfree(&regex);
			return false;
		}
		ok = undump_regmatch(state->line, buf, buflen,
				     &matches[1], &matches[2],
				     &state->data);
		if (!ok) {
			return false;
		}

		ret = tdb_store(state->tdb, state->key, state->data, 0);

		free(state->key.dptr);
		state->key = (TDB_DATA) {0};

		free(state->data.dptr);
		state->data = (TDB_DATA) {0};

		if (ret == -1) {
			fprintf(stderr, "tdb_store for line %d failed: %s\n",
				state->line, tdb_errorstr(state->tdb));
			return false;
		}
	}

	regfree(&regex);

	return true;
}

static int undump_tdb(const char *fname)
{
	struct tdb_logging_context logfn = { log_stderr };
	struct undump_state state = {0};
	bool ok;

	state.tdb = tdb_open_ex(fname, 0, TDB_DEFAULT, O_RDWR|O_CREAT, 0600,
				&logfn, NULL);
	if (state.tdb == NULL) {
		printf("Failed to open %s\n", fname);
		return 1;
	}

	ok = file_parse_lines(stdin, undump_cb, &state);
	if (!ok) {
		printf("Failed to parse stdin\n");
		return 1;
	}

	tdb_close(state.tdb);

	return 0;
}

static void usage( void)
{
	printf( "Usage: tdbdump [options] <filename>\n\n");
	printf( "   -h          this help message\n");
	printf( "   -k keyname  dumps value of keyname\n");
	printf( "   -e          emergency dump, for corrupt databases\n");
	printf( "   -u          undump stdin\n");
}

 int main(int argc, char *argv[])
{
	char *fname, *keyname=NULL;
	bool emergency = false;
	bool undump = false;
	int c;

	if (argc < 2) {
		printf("Usage: tdbdump <fname>\n");
		exit(1);
	}

	while ((c = getopt( argc, argv, "hk:eu")) != -1) {
		switch (c) {
		case 'h':
			usage();
			exit( 0);
		case 'k':
			keyname = optarg;
			break;
		case 'e':
			emergency = true;
			break;
		case 'u':
			undump = true;
			break;
		default:
			usage();
			exit( 1);
		}
	}

	fname = argv[optind];

	if (undump) {
		return undump_tdb(fname);
	}

	return dump_tdb(fname, keyname, emergency);
}
