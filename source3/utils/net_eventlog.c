/*
 * Samba Unix/Linux SMB client library
 * Distributed SMB/CIFS Server Management Utility
 * Local win32 eventlog interface
 *
 * Copyright (C) Guenther Deschner 2009
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

#include "includes.h"
#include "utils/net.h"

/**
 * Dump an *evt win32 eventlog file
 *
 * @param argc  Standard main() style argc.
 * @param argv  Standard main() style argv. Initial components are already
 *              stripped.
 *
 * @return A shell status integer (0 for success).
 **/

static int net_eventlog_dump(struct net_context *c, int argc,
			     const char **argv)
{
	int ret = -1;
	TALLOC_CTX *ctx = talloc_stackframe();
	enum ndr_err_code ndr_err;
	DATA_BLOB blob;
	struct EVENTLOG_EVT_FILE evt;
	char *s;

	if (argc < 1 || c->display_usage) {
		d_fprintf(stderr, "usage: net eventlog dump <file.evt>\n");
		goto done;
	}

	blob.data = (uint8_t *)file_load(argv[0], &blob.length, 0, ctx);
	if (!blob.data) {
		d_fprintf(stderr, "failed to load evt file: %s\n", argv[0]);
		goto done;
	}

	ndr_err = ndr_pull_struct_blob(&blob, ctx, NULL, &evt,
		   (ndr_pull_flags_fn_t)ndr_pull_EVENTLOG_EVT_FILE);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		d_fprintf(stderr, "evt pull failed: %s\n", ndr_errstr(ndr_err));
		goto done;
	}

	s = NDR_PRINT_STRUCT_STRING(ctx, EVENTLOG_EVT_FILE, &evt);
	if (s) {
		printf("%s\n", s);
	}

	ret = 0;
 done:
	TALLOC_FREE(ctx);
	return ret;
}

/**
 * 'net rpc eventlog' entrypoint.
 * @param argc  Standard main() style argc.
 * @param argv  Standard main() style argv. Initial components are already
 *              stripped.
 **/

int net_eventlog(struct net_context *c, int argc, const char **argv)
{
	int ret = -1;

	struct functable func[] = {
		{
			"dump",
			net_eventlog_dump,
			NET_TRANSPORT_LOCAL,
			"Dump eventlog",
			"net eventlog dump\n"
			"    Dump win32 *.evt eventlog file"
		},
	{ NULL, NULL, 0, NULL, NULL }
	};

	ret = net_run_function(c, argc, argv, "net eventlog", func);

	return ret;
}
