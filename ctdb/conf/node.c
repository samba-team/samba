/*
   Node file loading

   Copyright (C) Martin Andrew Tridgell  2007
   Copyright (C) Martin Ronnie Sahlberg  2008, 2009
   Copyright (C) Martin Schwenke  2015
   Copyright (C) Amitay Isaacs  2015

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

#ifndef __CTDB_NODE_H__
#define __CTDB_NODE_H__

#include "replace.h"
#include "system/network.h"

#include <talloc.h>

#include "lib/util/util_file.h"
#include "lib/util/util_strlist.h"

#include "protocol/protocol.h"
#include "protocol/protocol_util.h"

#include "conf/node.h"


/* If unset, set port in address to the CTDB port */
static void node_set_port(ctdb_sock_addr *address)
{
	struct servent *se = NULL;
	unsigned int port;

	port = ctdb_sock_addr_port(address);
	if (port != 0) {
		return;
	}

	setservent(0);
	se = getservbyname("ctdb", "tcp");
	endservent();

	if (se == NULL) {
		port = CTDB_PORT;
	} else {
		port = ntohs(se->s_port);
	}

	ctdb_sock_addr_set_port(address, port);
}

/* Append a node to a node map with given address and flags */
static bool node_map_add(struct ctdb_node_map *nodemap,
			 const char *nstr,
			 uint32_t flags)
{
	ctdb_sock_addr addr = {};
	uint32_t num;
	struct ctdb_node_and_flags *n = NULL;
	bool ok;

	ok = ctdb_parse_node_address(nstr, &addr);
	if (!ok) {
		fprintf(stderr, "Invalid node address %s\n", nstr);
		return false;
	}

	num = nodemap->num;
	n = talloc_realloc(nodemap,
			   nodemap->node,
			   struct ctdb_node_and_flags,
			   num + 1);
	if (n == NULL) {
		return false;
	}
	nodemap->node = n;

	n = &nodemap->node[num];
	n->addr = addr;
	n->pnn = num;
	n->flags = flags;

	nodemap->num = num + 1;
	return true;
}

static struct ctdb_node_map *ctdb_parse_nodes_lines(TALLOC_CTX *mem_ctx,
						    char **lines,
						    int nlines)
{
	int i;
	struct ctdb_node_map *nodemap = NULL;

	nodemap = talloc_zero(mem_ctx, struct ctdb_node_map);
	if (nodemap == NULL) {
		return NULL;
	}

	while (nlines > 0 && strcmp(lines[nlines-1], "") == 0) {
		nlines--;
	}

	for (i = 0; i < nlines; i++) {
		char *line;
		const char *node = NULL;
		uint32_t flags;
		size_t len;

		line = lines[i];
		/* strip leading spaces */
		while((*line == ' ') || (*line == '\t')) {
			line++;
		}

		len = strlen(line);

		/* strip trailing spaces */
		while (len > 1 &&
		       (line[len - 1] == ' ' || line[len - 1] == '\t')) {

			line[len - 1] = '\0';
			len--;
		}

		if (len == 0) {
			continue;
		}
		if (*line == '#') {
			/*
			 * A "deleted" node is a node that is
			 * commented out in the nodes file.  This is
			 * used instead of removing a line, which
			 * would cause subsequent nodes to change
			 * their PNN.
			 */
			flags = NODE_FLAGS_DELETED;
			node = "0.0.0.0";
		} else {
			flags = 0;
			node = line;
		}
		if (!node_map_add(nodemap, node, flags)) {
			TALLOC_FREE(nodemap);
			return NULL;
		}
	}

	return nodemap;
}

/* Convert a string containing a command line to an array of strings. Does not
 * handle shell style quoting! A space will always create a new argument.
 */
static char **command_str_to_args(TALLOC_CTX *mem_ctx,
				  const char *argstring)
{
	return str_list_make(mem_ctx, argstring, " \t");
}

/* Read a nodes file into a node map */
static struct ctdb_node_map *ctdb_read_nodes_file(TALLOC_CTX *mem_ctx,
						  const char *nlist)
{
	char **lines = NULL;
	int nlines;
	struct ctdb_node_map *nodemap = NULL;

	lines = file_lines_load(nlist, &nlines, 0, mem_ctx);
	if (lines == NULL) {
		return NULL;
	}

	nodemap = ctdb_parse_nodes_lines(mem_ctx, lines, nlines);
	talloc_free(lines);
	return nodemap;
}

/* Read a nodes file from an external process into a node map */
static struct ctdb_node_map *ctdb_read_nodes_cmd(TALLOC_CTX *mem_ctx,
						 const char *nodes_cmd)
{
	char **lines = NULL;
	int nlines;
	struct ctdb_node_map *nodemap = NULL;
	char **argl = command_str_to_args(mem_ctx, nodes_cmd);

	if (argl == NULL) {
		return NULL;
	}

	lines = file_lines_ploadv(mem_ctx, argl, &nlines);
	if (lines == NULL) {
		return NULL;
	}

	nodemap = ctdb_parse_nodes_lines(mem_ctx, lines, nlines);
	talloc_free(lines);
	return nodemap;
}

bool ctdb_parse_node_address(const char *str, ctdb_sock_addr *address)
{
	int ret;

	ret = ctdb_sock_addr_from_string(str, address, false);
	if (ret != 0) {
		return false;
	}
	node_set_port(address);

	return true;
}

struct ctdb_node_map *ctdb_read_nodes(TALLOC_CTX *mem_ctx,
				      const char *location)
{
	struct ctdb_node_map* nodemap = NULL;

	if (location != NULL && location[0] == '!') {
		nodemap = ctdb_read_nodes_cmd(mem_ctx, &location[1]);
	} else {
		nodemap = ctdb_read_nodes_file(mem_ctx, location);
	}

	return nodemap;
}

#endif /* __CTDB_NODE_H__ */
