/*
   Test stubs and support functions for some libctdb functions

   Copyright (C) Martin Schwenke  2011

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

#include <syslog.h>
#include "ctdb.h"

#define LIBCTDB_TEST_FAKESTATE "fakestate"

/* Can't use the real definition, since including libctdb_private.h
 * causes macro conflicts */
struct ctdb_connection {
	struct ctdb_node_map *nodemap;
	uint32_t current_node;
	uint32_t recmaster;
	struct ctdb_ifaces_list *ifaces;
	struct ctdb_vnn_map *vnnmap;
};


/* Read a nodemap from stdin.  Each line looks like:
 *  <PNN> <FLAGS> [RECMASTER] [CURRENT]
 * EOF or a blank line terminates input.
 */
void libctdb_test_read_nodemap(struct ctdb_connection *ctdb)
{
	char line[1024];

	ctdb->nodemap = (struct ctdb_node_map *) malloc(offsetof(struct ctdb_node_map, nodes));
	if (ctdb->nodemap == NULL) {
		DEBUG(DEBUG_ERR, ("OOM allocating nodemap\n"));
		exit (1);
	}
	ctdb->nodemap->num = 0;

	while ((fgets(line, sizeof(line), stdin) != NULL) &&
	       (line[0] != '\n')) {
		uint32_t pnn, flags;
		char *tok, *t;
		ctdb_sock_addr saddr;

		/* Get rid of pesky newline */
		if ((t = strchr(line, '\n')) != NULL) {
			*t = '\0';
		}

		/* Get PNN */
		tok = strtok(line, " \t");
		if (tok == NULL) {
			DEBUG(DEBUG_ERR, (__location__ " WARNING, bad line (PNN) ignored \"%s\"\n", line));
			continue;
		}
		pnn = (uint32_t)strtoul(tok, NULL, 0);

		/* Get IP */
		tok = strtok(NULL, " \t");
		if (tok == NULL) {
			DEBUG(DEBUG_ERR, (__location__ " WARNING, bad line (no IP) ignored \"%s\"\n", line));
			continue;
		}
		if (!parse_ip(tok, NULL, 0, &saddr)) {
			DEBUG(DEBUG_ERR, (__location__ " WARNING, bad line (IP) ignored \"%s\"\n", line));
			continue;
		}

		/* Get flags */
		tok = strtok(NULL, " \t");
		if (tok == NULL) {
			DEBUG(DEBUG_ERR, (__location__ " WARNING, bad line (flags) ignored \"%s\"\n", line));
			continue;
		}
		flags = (uint32_t)strtoul(tok, NULL, 0);

		tok = strtok(NULL, " \t");
		while (tok != NULL) {
			if (strcmp(tok, "CURRENT") == 0) {
				ctdb->current_node = pnn;
			} else if (strcmp(tok, "RECMASTER") == 0) {
				ctdb->recmaster = pnn;
			}
			tok = strtok(NULL, " \t");
		}

		ctdb->nodemap = (struct ctdb_node_map *) realloc(ctdb->nodemap, offsetof(struct ctdb_node_map, nodes) + (ctdb->nodemap->num + 1) * sizeof(struct ctdb_node_and_flags));
		if (ctdb->nodemap == NULL) {
			DEBUG(DEBUG_ERR, ("OOM allocating nodemap\n"));
			exit (1);
		}

		ctdb->nodemap->nodes[ctdb->nodemap->num].pnn = pnn;
		ctdb->nodemap->nodes[ctdb->nodemap->num].flags = flags;
		memcpy(&(ctdb->nodemap->nodes[ctdb->nodemap->num].addr), &saddr, sizeof(ctdb_sock_addr));
		ctdb->nodemap->num++;
	}
}

void libctdb_test_print_nodemap(struct ctdb_connection *ctdb)
{
	int i;

	for (i = 0; i < ctdb->nodemap->num; i++) {
		printf("%ld\t0x%lx%s%s\n",
		       (unsigned long) ctdb->nodemap->nodes[i].pnn,
		       (unsigned long) ctdb->nodemap->nodes[i].flags,
		       ctdb->nodemap->nodes[i].pnn == ctdb->current_node ? "\tCURRENT" : "",
		       ctdb->nodemap->nodes[i].pnn == ctdb->recmaster ? "\tRECMASTER" : "");
	}
}

/* Read interfaces information.  Same format as "ctdb ifaces -Y"
 * output:
 *   :Name:LinkStatus:References:
 *   :eth2:1:4294967294
 *   :eth1:1:4294967292
 */
void libctdb_test_read_ifaces(struct ctdb_connection *ctdb)
{
	char line[1024];

	ctdb->ifaces = (struct ctdb_ifaces_list *) malloc(offsetof(struct ctdb_ifaces_list, ifaces));
	if (ctdb->ifaces == NULL) {
		DEBUG(DEBUG_ERR, ("OOM allocating ifaces\n"));
		exit (1);
	}
	ctdb->ifaces->num = 0;

	while ((fgets(line, sizeof(line), stdin) != NULL) &&
	       (line[0] != '\n')) {
		uint16_t link_state;
		uint32_t references;
		char *tok, *t, *name;

		/* Get rid of pesky newline */
		if ((t = strchr(line, '\n')) != NULL) {
			*t = '\0';
		}

		if (strcmp(line, ":Name:LinkStatus:References:") == 0) {
			continue;
		}

		/* name */
		//tok = strtok(line, ":"); /* Leading colon... */
		tok = strtok(line, ":");
		if (tok == NULL) {
			DEBUG(DEBUG_ERR, (__location__ " WARNING, bad line ignored \"%s\"\n", line));
			continue;
		}
		name = tok;

		/* link_state */
		tok = strtok(NULL, ":");
		if (tok == NULL) {
			DEBUG(DEBUG_ERR, (__location__ " WARNING, bad line ignored \"%s\"\n", line));
			continue;
		}
		link_state = (uint16_t)strtoul(tok, NULL, 0);

		/* references... */
		tok = strtok(NULL, ":");
		if (tok == NULL) {
			DEBUG(DEBUG_ERR, (__location__ " WARNING, bad line ignored \"%s\"\n", line));
			continue;
		}
		references = (uint32_t)strtoul(tok, NULL, 0);

		ctdb->ifaces = (struct ctdb_ifaces_list *) realloc(ctdb->ifaces, offsetof(struct ctdb_ifaces_list, ifaces) + (ctdb->ifaces->num + 1) * sizeof(struct ctdb_iface_info));
		if (ctdb->ifaces == NULL) {
			DEBUG(DEBUG_ERR, ("OOM allocating ifaces\n"));
			exit (1);
		}

		strcpy(&(ctdb->ifaces->ifaces[ctdb->ifaces->num].name[0]), name);
		ctdb->ifaces->ifaces[ctdb->ifaces->num].link_state = link_state;
		ctdb->ifaces->ifaces[ctdb->ifaces->num].references = references;
		ctdb->ifaces->num++;
	}
}

void libctdb_test_print_ifaces(struct ctdb_connection *ctdb)
{
	int i;

	printf(":Name:LinkStatus:References:\n");
	for (i = 0; i < ctdb->ifaces->num; i++) {
		printf(":%s:%u:%u:\n",
		       ctdb->ifaces->ifaces[i].name,
		       ctdb->ifaces->ifaces[i].link_state,
		       ctdb->ifaces->ifaces[i].references);
	}
}

/* Read vnn map.
 * output:
 *   <GENERATION>
 *   <LMASTER0>
 *   <LMASTER1>
 *   ...
 */
void libctdb_test_read_vnnmap(struct ctdb_connection *ctdb)
{
	char line[1024];

	ctdb->vnnmap = (struct ctdb_vnn_map *) malloc(sizeof(struct ctdb_vnn_map));
	if (ctdb->vnnmap == NULL) {
		DEBUG(DEBUG_ERR, ("OOM allocating vnnmap\n"));
		exit (1);
	}
	ctdb->vnnmap->generation = INVALID_GENERATION;
	ctdb->vnnmap->size = 0;
	ctdb->vnnmap->map = NULL;

	while ((fgets(line, sizeof(line), stdin) != NULL) &&
	       (line[0] != '\n')) {
		uint32_t n;
		char *t;

		/* Get rid of pesky newline */
		if ((t = strchr(line, '\n')) != NULL) {
			*t = '\0';
		}

		n = (uint32_t) strtol(line, NULL, 0);

		/* generation */
		if (ctdb->vnnmap->generation == INVALID_GENERATION) {
			ctdb->vnnmap->generation = n;
			continue;
		}

		ctdb->vnnmap->map = (uint32_t *) realloc(ctdb->vnnmap->map, (ctdb->vnnmap->size + 1) * sizeof(uint32_t));
		if (ctdb->vnnmap->map == NULL) {
			DEBUG(DEBUG_ERR, ("OOM allocating vnnmap->map\n"));
			exit (1);
		}

		ctdb->vnnmap->map[ctdb->vnnmap->size] = n;
		ctdb->vnnmap->size++;
	}
}

void libctdb_test_print_vnnmap(struct ctdb_connection *ctdb)
{
	int i;

	printf("%d\n", ctdb->vnnmap->generation);
	for (i = 0; i < ctdb->vnnmap->size; i++) {
		printf("%d\n", ctdb->vnnmap->map[i]);
	}
}

void libctdb_test_fake_setup(struct ctdb_connection *ctdb)
{
	char line[1024];

	while (fgets(line, sizeof(line), stdin) != NULL) {
		char *t;

		/* Get rid of pesky newline */
		if ((t = strchr(line, '\n')) != NULL) {
			*t = '\0';
		}

		if (strcmp(line, "NODEMAP") == 0) {
			libctdb_test_read_nodemap(ctdb);
		} else if (strcmp(line, "IFACES") == 0) {
			libctdb_test_read_ifaces(ctdb);
		} else if (strcmp(line, "VNNMAP") == 0) {
			libctdb_test_read_vnnmap(ctdb);
		} else {
			printf("Unknown line %s\n", line);
			exit(1);
		}
	}
}

/* Support... */
static bool current_node_is_connected (struct ctdb_connection *ctdb)
{
	int i;
	for (i = 0; i < ctdb->nodemap->num; i++) {
		if (ctdb->nodemap->nodes[i].pnn == ctdb->current_node) {
			if (ctdb->nodemap->nodes[i].flags &
			    (NODE_FLAGS_DISCONNECTED | NODE_FLAGS_DELETED)) {
				return false;
			} else {
				return true;
			}
		}
	}

	/* Shouldn't really happen, so fag an error */
	return false;
}

/* Stubs... */

bool ctdb_getnodemap(struct ctdb_connection *ctdb,
		     uint32_t destnode, struct ctdb_node_map **nodemap)
{
	size_t n;

	if (!current_node_is_connected(ctdb)) {
		*nodemap = NULL;
		return false;
	}

	n = offsetof(struct ctdb_node_map, nodes) + (ctdb->nodemap->num) * sizeof(struct ctdb_node_and_flags);
	*nodemap = (struct ctdb_node_map *) malloc(n);
	memcpy(*nodemap, ctdb->nodemap, n);

	return true;
}

void ctdb_free_nodemap(struct ctdb_node_map *nodemap)
{
	free(nodemap);
}

bool ctdb_getifaces(struct ctdb_connection *ctdb,
		    uint32_t destnode, struct ctdb_ifaces_list **ifaces)
{
	size_t n;

	if (!current_node_is_connected(ctdb)) {
		*ifaces = NULL;
		return false;
	}

	n = offsetof(struct ctdb_ifaces_list, ifaces) + (ctdb->ifaces->num) * sizeof(struct ctdb_iface_info);
	*ifaces = (struct ctdb_ifaces_list *) malloc(n);
	memcpy(*ifaces, ctdb->ifaces, n);

	return true;
}

void ctdb_free_ifaces(struct ctdb_ifaces_list *ifaces)
{
	free(ifaces);
}

bool ctdb_getpnn(struct ctdb_connection *ctdb,
		 uint32_t destnode,
		 uint32_t *pnn)
{
	if (!current_node_is_connected(ctdb)) {
		return false;
	}

	if (destnode == CTDB_CURRENT_NODE) {
		*pnn = ctdb->current_node;
	} else {
		*pnn = destnode;
	}
	return true;
}

bool ctdb_getrecmode(struct ctdb_connection *ctdb,
		     uint32_t destnode,
		     uint32_t *recmode)
{
	if (!current_node_is_connected(ctdb)) {
		return false;
	}

	*recmode = 0;
	return true;
}

bool ctdb_getrecmaster(struct ctdb_connection *ctdb,
		       uint32_t destnode,
		       uint32_t *recmaster)
{
	if (!current_node_is_connected(ctdb)) {
		return false;
	}

	*recmaster = ctdb->recmaster;
	return true;
}

bool ctdb_getvnnmap(struct ctdb_connection *ctdb,
		    uint32_t destnode, struct ctdb_vnn_map **vnnmap)
{
	size_t n;

	if (!current_node_is_connected(ctdb)) {
		*vnnmap = NULL;
		return false;
	}

	*vnnmap = (struct ctdb_vnn_map *) malloc(sizeof(struct ctdb_vnn_map));
	n = ctdb->vnnmap->size * sizeof(uint32_t);
	(*vnnmap)->map = malloc(n);
	memcpy((*vnnmap)->map, ctdb->vnnmap->map, n);
	(*vnnmap)->generation = ctdb->vnnmap->generation;
	(*vnnmap)->size = ctdb->vnnmap->size;

	return true;
}

void ctdb_free_vnnmap(struct ctdb_vnn_map *vnnmap)
{
	free(vnnmap->map);
	free(vnnmap);
}

bool
ctdb_getdbseqnum(struct ctdb_connection *ctdb,
		 uint32_t destnode,
		 uint32_t dbid,
		 uint64_t *seqnum)
{
	*seqnum = 0;
	return false; /* Not implemented */
}

bool
ctdb_check_message_handlers(struct ctdb_connection *ctdb,
			   uint32_t destnode,
			   uint32_t num,
			   uint64_t *mhs,
			   uint8_t *result)
{
	*result = 0;
	return false; /* Not implemented */
}

/* Not a stub, a copy */
void ctdb_log_file(FILE *outf, int priority, const char *format, va_list ap)
{
	fprintf(outf, "%s:",
		priority == LOG_EMERG ? "EMERG" :
		priority == LOG_ALERT ? "ALERT" :
		priority == LOG_CRIT ? "CRIT" :
		priority == LOG_ERR ? "ERR" :
		priority == LOG_WARNING ? "WARNING" :
		priority == LOG_NOTICE ? "NOTICE" :
		priority == LOG_INFO ? "INFO" :
		priority == LOG_DEBUG ? "DEBUG" :
		"Unknown Error Level");

	vfprintf(outf, format, ap);
	if (priority == LOG_ERR) {
		fprintf(outf, " (%s)", strerror(errno));
	}
	fprintf(outf, "\n");
}

/* Remove type-safety macro. */
#undef ctdb_connect
struct ctdb_connection *ctdb_connect(const char *addr,
				     ctdb_log_fn_t log_func, void *log_priv)
{
	struct ctdb_connection *ctdb;

	ctdb = malloc(sizeof(struct ctdb_connection));
	if (ctdb == NULL) {
		DEBUG(DEBUG_ERR, ("OOM allocating ctdb_connection\n"));
		exit (1);
	}

	ctdb->nodemap = NULL;
	ctdb->current_node = 0;
	ctdb->recmaster = 0;
	ctdb->ifaces = NULL;
	ctdb->vnnmap = NULL;

	/* Don't always fake up the state...  but do it on request */
	if (strcmp(addr, LIBCTDB_TEST_FAKESTATE) == 0) {
		libctdb_test_fake_setup(ctdb);
	}

	return ctdb;
}

void ctdb_disconnect(struct ctdb_connection *ctdb)
{
	if (ctdb->nodemap != NULL) {
		free(ctdb->nodemap);
	}
	if (ctdb->ifaces != NULL) {
		free(ctdb->ifaces);
	}
	if (ctdb->vnnmap != NULL) {
		if (ctdb->vnnmap->map != NULL) {
			free(ctdb->vnnmap->map);
		}
		free(ctdb->vnnmap);
	}
	free(ctdb);
}

bool ctdb_getdbstat(struct ctdb_connection *ctdb,
		    uint32_t destnode,
		    uint32_t db_id,
		    struct ctdb_db_statistics **dbstatistics)
{
	if (!current_node_is_connected(ctdb)) {
		return false;
	}

	*dbstatistics = malloc(sizeof(struct ctdb_db_statistics));
	return true;
}

void ctdb_free_dbstat(struct ctdb_db_statistics *dbstatistics)
{
	free(dbstatistics);
}

bool ctdb_getcapabilities(struct ctdb_connection *ctdb,
			  uint32_t destnode, uint32_t *capabilities)
{
	*capabilities = CTDB_CAP_RECMASTER|CTDB_CAP_LMASTER|CTDB_CAP_NATGW;
	return true;
}
