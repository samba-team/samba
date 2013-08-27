/* 
   Tests for tools/ctdb.c and libctdb stubs

   Copyright (C) Martin Schwenke 2011

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

#include "ctdb_test.c"
#include "libctdb_test.c"

static void test_read_nodemap(void)
{
	struct ctdb_connection *ctdb = ctdb_connect("foo", NULL, NULL);

	libctdb_test_read_nodemap(ctdb);
	libctdb_test_print_nodemap(ctdb);

	ctdb_disconnect(ctdb);
}

static void test_read_ifaces(void)
{
	struct ctdb_connection *ctdb = ctdb_connect("foo", NULL, NULL);

	libctdb_test_read_ifaces(ctdb);
	libctdb_test_print_ifaces(ctdb);

	ctdb_disconnect(ctdb);
}

static void test_read_vnnmap(void)
{
	struct ctdb_connection *ctdb = ctdb_connect("foo", NULL, NULL);

	libctdb_test_read_vnnmap(ctdb);
	libctdb_test_print_vnnmap(ctdb);

	ctdb_disconnect(ctdb);
}

static void test_fake_setup(void)
{
	bool first = true;
	struct ctdb_connection *ctdb = ctdb_connect("foo", NULL, NULL);

	libctdb_test_fake_setup(ctdb);

	if (ctdb->nodemap != NULL) {
		if (!first) {
			printf("\n");
		}
		printf("NODEMAP\n");
		libctdb_test_print_nodemap(ctdb);
		first = false;
	}

	if (ctdb->ifaces != NULL) {
		if (!first) {
			printf("\n");
		}
		printf("IFACES\n");
		libctdb_test_print_ifaces(ctdb);
		first = false;
	}

	if (ctdb->vnnmap != NULL) {
		if (!first) {
			printf("\n");
		}
		printf("VNNMAP\n");
		libctdb_test_print_vnnmap(ctdb);
		first = false;
	}

	ctdb_disconnect(ctdb);
}

static const char * decode_pnn_mode(uint32_t pnn_mode)
{
	int i;
	static const struct {
		uint32_t mode;
		const char *name;
	} pnn_modes[] = {
		{ CTDB_CURRENT_NODE,        "CURRENT_NODE" },
		{ CTDB_BROADCAST_ALL,       "BROADCAST_ALL" },
		{ CTDB_BROADCAST_VNNMAP,    "BROADCAST_VNNMAP" },
		{ CTDB_BROADCAST_CONNECTED, "BROADCAST_CONNECTED" },
		{ CTDB_MULTICAST,           "MULTICAST" },
	};

	for (i = 0; i < ARRAY_SIZE(pnn_modes); i++) {
		if (pnn_mode == pnn_modes[i].mode) {
			return pnn_modes[i].name;
		}
	}

	return "PNN";
}

static void print_nodes(uint32_t *nodes, uint32_t pnn_mode)
{
	int i;

	printf("NODES:");
	for (i = 0; i < talloc_array_length(nodes); i++) {
		printf(" %lu", (unsigned long) nodes[i]);
	}
	printf("\n");

	printf("PNN MODE: %s (%lu)\n",
	       decode_pnn_mode(pnn_mode), (unsigned long) pnn_mode);
}

static void test_parse_nodestring(const char *nodestring_s,
				  const char *dd_ok_s)
{
	const char *nodestring;
	bool dd_ok;
	struct ctdb_connection *ctdb;
	uint32_t *nodes;
	uint32_t pnn_mode;

	nodestring = strcmp("", nodestring_s) == 0 ? NULL : nodestring_s;

	if (strcasecmp(dd_ok_s, "yes") == 0 ||
	    strcmp(dd_ok_s, "true") == 0) {
		dd_ok = true;
	} else {
		dd_ok = false;
	}

	ctdb  = ctdb_connect("foo", NULL, NULL);

	libctdb_test_read_nodemap(ctdb);

	if (parse_nodestring(NULL, NULL, nodestring, CTDB_CURRENT_NODE, dd_ok,
			     &nodes, &pnn_mode)) {
		print_nodes(nodes, pnn_mode);
	}

	ctdb_disconnect(ctdb);
}

static void usage(void)
{
	fprintf(stderr, "usage: ctdb_tool_libctdb <op>\n");
	exit(1);
}

int main(int argc, const char *argv[])
{
	LogLevel = DEBUG_DEBUG;
	if (getenv("CTDB_TEST_LOGLEVEL")) {
		LogLevel = atoi(getenv("CTDB_TEST_LOGLEVEL"));
	}

	if (argc < 2) {
		usage();
	}

	if (argc == 2 && strcmp(argv[1], "read_nodemap") == 0) {
		test_read_nodemap();
	} else if (argc == 2 && strcmp(argv[1], "read_ifaces") == 0) {
		test_read_ifaces();
	} else if (argc == 2 && strcmp(argv[1], "read_vnnmap") == 0) {
		test_read_vnnmap();
	} else if (argc == 2 && strcmp(argv[1], "fake_setup") == 0) {
		test_fake_setup();
	} else if (argc == 4 && strcmp(argv[1], "parse_nodestring") == 0) {
		test_parse_nodestring(argv[2], argv[3]);
	} else {
		usage();
	}

	return 0;
}
