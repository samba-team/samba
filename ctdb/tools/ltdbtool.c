/*
 * ctdb local tdb tool
 *
 * Copyright (C) Gregor Beck 2011
 * Copyright (C) Michael Adam 2011
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
#include "system/network.h"
#include "system/locale.h"

#include <tdb.h>

#include "protocol/protocol.h"

enum {
	MAX_HEADER_SIZE=24,
	OUT_MODE = S_IRUSR | S_IWUSR,
	OUT_FLAGS = O_EXCL|O_CREAT|O_RDWR,
};

union  ltdb_header {
	struct ctdb_ltdb_header hdr;
	uint32_t uints[MAX_HEADER_SIZE/4];
};

static const union ltdb_header DEFAULT_HDR = {
	.hdr = {
		.dmaster = -1,
	}
};

static int help(const char* cmd)
{
	fprintf(stdout, ""
"Usage: %s [options] <command>\n"
"\n"
"Options:\n"
"   -s {0|32|64}    specify how to determine the ctdb record header size\n"
"                   for the input database:\n"
"                   0: no ctdb header\n"
"                   32: ctdb header size of a 32 bit system (20 bytes)\n"
"                   64: ctdb header size of a 64 bit system (24 bytes)\n"
"                   default: 32 or 64 depending on the system architecture\n"
"\n"
"   -S <num>        the number of bytes to interpret as ctdb record header\n"
"                   for the input database (beware!)\n"
"\n"
"   -o {0|32|64}    specify how to determine the ctdb record header size\n"
"                   for the output database\n"
"                   0: no ctdb header\n"
"                   32: ctdb header size of a 32 bit system (20 bytes)\n"
"                   64: ctdb header size of a 64 bit system (24 bytes)\n"
"                   default: 32 or 64 depending on the system architecture\n"
"\n"
"   -O <num>        the number of bytes to interpret as ctdb record header\n"
"                   for the output database (beware!)\n"
"\n"
"   -e              Include empty records, defaults to off\n"
"\n"
"   -p              print header (for the dump command), defaults to off\n"
"\n"
"   -h              print this help\n"
"\n"
"Commands:\n"
"  help                         print this help\n"
"  dump <db>                    dump the db to stdout\n"
"  convert <in_db> <out_db>     convert the db\n\n", cmd);
	return 0;
}

static int usage(const char* cmd)
{
	fprintf(stderr,
		"Usage: %s dump [-e] [-p] [-s{0|32|64}] <idb>\n"
		"       %s convert [-e] [-s{0|32|64}] [-o{0|32|64}] <idb> <odb>\n"
		"       %s {help|-h}\n"
		, cmd, cmd, cmd);
	return -1;
}

static int
ltdb_traverse(TDB_CONTEXT *tdb, int (*fn)(TDB_CONTEXT*, TDB_DATA, TDB_DATA,
					  struct ctdb_ltdb_header*, void *),
	      void *state, size_t hsize, bool skip_empty);

struct write_record_ctx {
	TDB_CONTEXT* tdb;
	size_t hsize;
	int tdb_store_flags;
};

static int
write_record(TDB_CONTEXT* tdb, TDB_DATA key, TDB_DATA val,
	     struct ctdb_ltdb_header* hdr,
	     void* write_record_ctx);


struct dump_record_ctx {
	FILE* file;
	void (*print_data)(FILE*, TDB_DATA);
	void (*dump_header)(struct dump_record_ctx*, struct ctdb_ltdb_header*);
};

static int dump_record(TDB_CONTEXT* tdb, TDB_DATA key, TDB_DATA val,
		       struct ctdb_ltdb_header* hdr,
		       void* dump_record_ctx);
static void print_data_tdbdump(FILE* file, TDB_DATA data);
static void dump_header_full(struct dump_record_ctx*, struct ctdb_ltdb_header*);
static void dump_header_nop(struct dump_record_ctx* c,
			    struct ctdb_ltdb_header* h)
{}

static int dump_db(const char* iname,
		   FILE* ofile,
		   size_t hsize,
		   bool dump_header,
		   bool empty)
{
	int ret = -1;
	TDB_CONTEXT* idb = tdb_open(iname, 0, TDB_DEFAULT, O_RDONLY, 0);
	if (!idb) {
		perror("tdbopen in");
	} else {
		struct dump_record_ctx dump_ctx = {
			.file = ofile,
			.print_data =  &print_data_tdbdump,
			.dump_header = dump_header ? &dump_header_full
			                           : &dump_header_nop,
		};
		ret = ltdb_traverse(idb, &dump_record, &dump_ctx, hsize, !empty);
		tdb_close(idb);
	}
	return ret;
}

static int conv_db(const char* iname, const char* oname, size_t isize,
		   size_t osize, bool keep_empty)
{
	int ret = -1;
	TDB_CONTEXT* idb = tdb_open(iname, 0, TDB_DEFAULT, O_RDONLY, 0);
	if (!idb) {
		perror("tdbopen in");
	} else {
		TDB_CONTEXT* odb = tdb_open(oname, 0, TDB_DEFAULT, OUT_FLAGS, OUT_MODE);
		if (!odb) {
			perror("tdbopen out");
		} else {
			struct write_record_ctx ctx = {
				.tdb = odb,
				.hsize = osize,
				.tdb_store_flags = TDB_REPLACE,
			};
			ret = ltdb_traverse(idb, &write_record, &ctx, isize, !keep_empty);
			tdb_close(odb);
		}
		tdb_close(idb);
	}
	return ret;
}

static bool parse_size(size_t* size, const char* arg, bool raw) {
	long val;
	errno = 0;
	val = strtol(arg, (char **) NULL, 10);
	if (errno != 0) {
		return false;
	}
	if (!raw) {
		switch(val) {
		case 0:
			break;
		case 32:
			val = 20;
			break;
		case 64:
			val = 24;
			break;
		default:
			return false;
		}
	}
	*size = MIN(val, MAX_HEADER_SIZE);
	return true;
}


int main(int argc, char* argv[])
{
	size_t isize = sizeof(struct ctdb_ltdb_header);
	size_t osize = sizeof(struct ctdb_ltdb_header);
	bool print_header = false;
	bool keep_empty = false;
	int opt;
	const char *cmd, *idb, *odb;

	while ((opt = getopt(argc, argv, "s:o:S:O:phe")) != -1) {
		switch (opt) {
		case 's':
		case 'S':
			if (!parse_size(&isize, optarg, isupper(opt))) {
				return usage(argv[0]);
			}
			break;
		case 'o':
		case 'O':
			if (!parse_size(&osize, optarg, isupper(opt))) {
				return usage(argv[0]);
			}
			break;
		case 'p':
			print_header = true;
			break;
		case 'e':
			keep_empty = true;
			break;
		case 'h':
			return help(argv[0]);
		default:
			return usage(argv[0]);
		}
	}

	if (argc - optind < 1) {
		return usage(argv[0]);
	}

	cmd = argv[optind];

	if (strcmp(cmd, "help") == 0) {
		return help(argv[0]);
	}
	else if (strcmp(cmd, "dump") == 0) {
		int ret;
		if (argc - optind != 2) {
			return usage(argv[0]);
		}
		idb = argv[optind+1];
		ret = dump_db(idb, stdout, isize, print_header, keep_empty);
		return (ret >= 0) ? 0 : ret;
	}
	else if (strcmp(cmd, "convert") == 0) {
		int ret;
		if (argc - optind != 3) {
			return usage(argv[0]);
		}
		idb = argv[optind+1];
		odb = argv[optind+2];
		ret = conv_db(idb, odb, isize, osize, keep_empty);
		return (ret >= 0) ? 0 : ret;
	}

	return usage(argv[0]);
}

struct ltdb_traverse_ctx {
	int (*fn)(TDB_CONTEXT*,TDB_DATA,TDB_DATA,struct ctdb_ltdb_header*,void *);
	void* state;
	size_t hsize;
	bool skip_empty;
	int nempty;
};

static int
ltdb_traverse_fn(TDB_CONTEXT* tdb, TDB_DATA key, TDB_DATA val,
		 void* ltdb_traverse_ctx)
{
	struct ltdb_traverse_ctx* ctx =
		(struct ltdb_traverse_ctx*)ltdb_traverse_ctx;
	union ltdb_header hdr = DEFAULT_HDR;

	const size_t hsize = MIN(sizeof(hdr), ctx->hsize);
	if (val.dsize < hsize) {
		fprintf(stderr, "Value too short to contain a ctdb header: ");
		print_data_tdbdump(stderr, key);
		fprintf(stderr, " = ");
		print_data_tdbdump(stderr, val);
		fputc('\n', stderr);
		return -1;
	}
	if (val.dsize == hsize && ctx->skip_empty) {
		ctx->nempty++;
		return 0;
	}

	memcpy(&hdr, val.dptr, hsize);

	if (hdr.uints[5] != 0) {
		fprintf(stderr, "Warning: header padding isn't zero! Wrong header size?\n");
	}
	val.dptr += ctx->hsize;
	val.dsize -= ctx->hsize;
	return ctx->fn(tdb, key, val, &hdr.hdr, ctx->state);
}

static int ltdb_traverse(TDB_CONTEXT *tdb,
			 int (*fn)(TDB_CONTEXT*, TDB_DATA, TDB_DATA,
				   struct ctdb_ltdb_header*, void *),
			 void *state, size_t hsize, bool skip_empty)
{
	struct ltdb_traverse_ctx ctx = {
		.fn = fn,
		.state = state,
		.hsize = hsize,
		.skip_empty = skip_empty,
		.nempty = 0,
	};
	int ret = tdb_traverse(tdb, &ltdb_traverse_fn, &ctx);

	return (ret < 0) ? ret : (ret - ctx.nempty);
}

static int write_record(TDB_CONTEXT* tdb, TDB_DATA key, TDB_DATA val,
			struct ctdb_ltdb_header* hdr,
			void* write_record_ctx)
{
	struct write_record_ctx* ctx
		= (struct write_record_ctx*)write_record_ctx;
	int ret;

	if (ctx->hsize == 0) {
		ret = tdb_store(ctx->tdb, key, val, ctx->tdb_store_flags);
	} else {
		TDB_DATA rec[2];

		rec[0].dsize = ctx->hsize;
		rec[0].dptr = (uint8_t *)hdr;

		rec[1].dsize = val.dsize;
		rec[1].dptr = val.dptr;

		ret = tdb_storev(ctx->tdb, key, rec, 2, ctx->tdb_store_flags);
	}

	if (ret == -1) {
		fprintf(stderr, "tdb_store: %s\n", tdb_errorstr(ctx->tdb));
		return -1;
	}

	return 0;
}

static int dump_record(TDB_CONTEXT* tdb, TDB_DATA key, TDB_DATA val,
		       struct ctdb_ltdb_header* hdr,
		       void* dump_record_ctx)
{
	struct dump_record_ctx* ctx = (struct dump_record_ctx*)dump_record_ctx;

	fprintf(ctx->file, "{\nkey(%d) = ", (int)key.dsize);
	ctx->print_data(ctx->file, key);
	fputc('\n', ctx->file);
	ctx->dump_header(ctx, hdr);
	fprintf(ctx->file, "data(%d) = ", (int)val.dsize);
	ctx->print_data(ctx->file, val);
	fprintf(ctx->file, "\n}\n");
	return 0;
}

static void dump_header_full(struct dump_record_ctx* c,
			     struct ctdb_ltdb_header* h)
{
	fprintf(c->file, "dmaster: %d\nrsn: %llu\nflags: 0x%X\n",
		(int)h->dmaster,
		(unsigned long long)h->rsn, h->flags);
}

static void print_data_tdbdump(FILE* file, TDB_DATA data)
{
	unsigned char *ptr = data.dptr;
	fputc('"', file);
	while (data.dsize--) {
		if (isprint(*ptr) && !strchr("\"\\", *ptr)) {
			fputc(*ptr, file);
		} else {
			fprintf(file, "\\%02X", *ptr);
		}
		ptr++;
	}
	fputc('"',file);
}

