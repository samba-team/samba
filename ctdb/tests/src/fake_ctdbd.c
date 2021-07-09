/*
   Fake CTDB server for testing

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
#include "system/time.h"
#include "system/filesys.h"

#include <popt.h>
#include <talloc.h>
#include <tevent.h>
#include <tdb.h>

#include "lib/util/dlinklist.h"
#include "lib/util/tevent_unix.h"
#include "lib/util/debug.h"
#include "lib/util/samba_util.h"
#include "lib/async_req/async_sock.h"

#include "protocol/protocol.h"
#include "protocol/protocol_api.h"
#include "protocol/protocol_util.h"
#include "protocol/protocol_private.h"

#include "common/comm.h"
#include "common/logging.h"
#include "common/tunable.h"
#include "common/srvid.h"
#include "common/system.h"

#include "ipalloc_read_known_ips.h"


#define CTDB_PORT 4379

/* A fake flag that is only supported by some functions */
#define NODE_FLAGS_FAKE_TIMEOUT 0x80000000

struct node {
	ctdb_sock_addr addr;
	uint32_t pnn;
	uint32_t flags;
	uint32_t capabilities;
	bool recovery_disabled;
	void *recovery_substate;
};

struct node_map {
	uint32_t num_nodes;
	struct node *node;
	uint32_t pnn;
	uint32_t recmaster;
};

struct interface {
	const char *name;
	bool link_up;
	uint32_t references;
};

struct interface_map {
	int num;
	struct interface *iface;
};

struct vnn_map {
	uint32_t recmode;
	uint32_t generation;
	uint32_t size;
	uint32_t *map;
};

struct database {
	struct database *prev, *next;
	const char *name;
	const char *path;
	struct tdb_context *tdb;
	uint32_t id;
	uint8_t flags;
	uint64_t seq_num;
};

struct database_map {
	struct database *db;
	const char *dbdir;
};

struct fake_control_failure {
	struct fake_control_failure  *prev, *next;
	enum ctdb_controls opcode;
	uint32_t pnn;
	const char *error;
	const char *comment;
};

struct ctdb_client {
	struct ctdb_client *prev, *next;
	struct ctdbd_context *ctdb;
	pid_t pid;
	void *state;
};

struct ctdbd_context {
	struct node_map *node_map;
	struct interface_map *iface_map;
	struct vnn_map *vnn_map;
	struct database_map *db_map;
	struct srvid_context *srv;
	int num_clients;
	struct timeval start_time;
	struct timeval recovery_start_time;
	struct timeval recovery_end_time;
	bool takeover_disabled;
	int log_level;
	enum ctdb_runstate runstate;
	struct ctdb_tunable_list tun_list;
	char *reclock;
	struct ctdb_public_ip_list *known_ips;
	struct fake_control_failure *control_failures;
	struct ctdb_client *client_list;
};

/*
 * Parse routines
 */

static struct node_map *nodemap_init(TALLOC_CTX *mem_ctx)
{
	struct node_map *node_map;

	node_map = talloc_zero(mem_ctx, struct node_map);
	if (node_map == NULL) {
		return NULL;
	}

	node_map->pnn = CTDB_UNKNOWN_PNN;
	node_map->recmaster = CTDB_UNKNOWN_PNN;

	return node_map;
}

/* Read a nodemap from stdin.  Each line looks like:
 *  <PNN> <FLAGS> [RECMASTER] [CURRENT] [CAPABILITIES]
 * EOF or a blank line terminates input.
 *
 * By default, capablities for each node are
 * CTDB_CAP_RECMASTER|CTDB_CAP_LMASTER.  These 2
 * capabilities can be faked off by adding, for example,
 * -CTDB_CAP_RECMASTER.
 */

static bool nodemap_parse(struct node_map *node_map)
{
	char line[1024];

	while ((fgets(line, sizeof(line), stdin) != NULL)) {
		uint32_t pnn, flags, capabilities;
		char *tok, *t;
		char *ip;
		ctdb_sock_addr saddr;
		struct node *node;
		int ret;

		if (line[0] == '\n') {
			break;
		}

		/* Get rid of pesky newline */
		if ((t = strchr(line, '\n')) != NULL) {
			*t = '\0';
		}

		/* Get PNN */
		tok = strtok(line, " \t");
		if (tok == NULL) {
			fprintf(stderr, "bad line (%s) - missing PNN\n", line);
			continue;
		}
		pnn = (uint32_t)strtoul(tok, NULL, 0);

		/* Get IP */
		tok = strtok(NULL, " \t");
		if (tok == NULL) {
			fprintf(stderr, "bad line (%s) - missing IP\n", line);
			continue;
		}
		ret = ctdb_sock_addr_from_string(tok, &saddr, false);
		if (ret != 0) {
			fprintf(stderr, "bad line (%s) - invalid IP\n", line);
			continue;
		}
		ctdb_sock_addr_set_port(&saddr, CTDB_PORT);
		ip = talloc_strdup(node_map, tok);
		if (ip == NULL) {
			goto fail;
		}

		/* Get flags */
		tok = strtok(NULL, " \t");
		if (tok == NULL) {
			fprintf(stderr, "bad line (%s) - missing flags\n",
				line);
			continue;
		}
		flags = (uint32_t)strtoul(tok, NULL, 0);
		/* Handle deleted nodes */
		if (flags & NODE_FLAGS_DELETED) {
			talloc_free(ip);
			ip = talloc_strdup(node_map, "0.0.0.0");
			if (ip == NULL) {
				goto fail;
			}
		}
		capabilities = CTDB_CAP_RECMASTER|CTDB_CAP_LMASTER;

		tok = strtok(NULL, " \t");
		while (tok != NULL) {
			if (strcmp(tok, "CURRENT") == 0) {
				node_map->pnn = pnn;
			} else if (strcmp(tok, "RECMASTER") == 0) {
				node_map->recmaster = pnn;
			} else if (strcmp(tok, "-CTDB_CAP_RECMASTER") == 0) {
				capabilities &= ~CTDB_CAP_RECMASTER;
			} else if (strcmp(tok, "-CTDB_CAP_LMASTER") == 0) {
				capabilities &= ~CTDB_CAP_LMASTER;
			} else if (strcmp(tok, "TIMEOUT") == 0) {
				/* This can be done with just a flag
				 * value but it is probably clearer
				 * and less error-prone to fake this
				 * with an explicit token */
				flags |= NODE_FLAGS_FAKE_TIMEOUT;
			}
			tok = strtok(NULL, " \t");
		}

		node_map->node = talloc_realloc(node_map, node_map->node,
						struct node,
						node_map->num_nodes + 1);
		if (node_map->node == NULL) {
			goto fail;
		}
		node = &node_map->node[node_map->num_nodes];

		ret = ctdb_sock_addr_from_string(ip, &node->addr, false);
		if (ret != 0) {
			fprintf(stderr, "bad line (%s) - invalid IP\n", line);
			continue;
		}
		ctdb_sock_addr_set_port(&node->addr, CTDB_PORT);
		node->pnn = pnn;
		node->flags = flags;
		node->capabilities = capabilities;
		node->recovery_disabled = false;
		node->recovery_substate = NULL;

		node_map->num_nodes += 1;
	}

	DEBUG(DEBUG_INFO, ("Parsing nodemap done\n"));
	return true;

fail:
	DEBUG(DEBUG_INFO, ("Parsing nodemap failed\n"));
	return false;

}

/* Append a node to a node map with given address and flags */
static bool node_map_add(struct ctdb_node_map *nodemap,
			 const char *nstr, uint32_t flags)
{
	ctdb_sock_addr addr;
	uint32_t num;
	struct ctdb_node_and_flags *n;
	int ret;

	ret = ctdb_sock_addr_from_string(nstr, &addr, false);
	if (ret != 0) {
		fprintf(stderr, "Invalid IP address %s\n", nstr);
		return false;
	}
	ctdb_sock_addr_set_port(&addr, CTDB_PORT);

	num = nodemap->num;
	nodemap->node = talloc_realloc(nodemap, nodemap->node,
				       struct ctdb_node_and_flags, num+1);
	if (nodemap->node == NULL) {
		return false;
	}

	n = &nodemap->node[num];
	n->addr = addr;
	n->pnn = num;
	n->flags = flags;

	nodemap->num = num+1;
	return true;
}

/* Read a nodes file into a node map */
static struct ctdb_node_map *ctdb_read_nodes_file(TALLOC_CTX *mem_ctx,
						  const char *nlist)
{
	char **lines;
	int nlines;
	int i;
	struct ctdb_node_map *nodemap;

	nodemap = talloc_zero(mem_ctx, struct ctdb_node_map);
	if (nodemap == NULL) {
		return NULL;
	}

	lines = file_lines_load(nlist, &nlines, 0, mem_ctx);
	if (lines == NULL) {
		return NULL;
	}

	while (nlines > 0 && strcmp(lines[nlines-1], "") == 0) {
		nlines--;
	}

	for (i=0; i<nlines; i++) {
		char *node;
		uint32_t flags;
		size_t len;

		node = lines[i];
		/* strip leading spaces */
		while((*node == ' ') || (*node == '\t')) {
			node++;
		}

		len = strlen(node);

		/* strip trailing spaces */
		while ((len > 1) &&
		       ((node[len-1] == ' ') || (node[len-1] == '\t')))
		{
			node[len-1] = '\0';
			len--;
		}

		if (len == 0) {
			continue;
		}
		if (*node == '#') {
			/* A "deleted" node is a node that is
			   commented out in the nodes file.  This is
			   used instead of removing a line, which
			   would cause subsequent nodes to change
			   their PNN. */
			flags = NODE_FLAGS_DELETED;
			node = discard_const("0.0.0.0");
		} else {
			flags = 0;
		}
		if (! node_map_add(nodemap, node, flags)) {
			talloc_free(lines);
			TALLOC_FREE(nodemap);
			return NULL;
		}
	}

	talloc_free(lines);
	return nodemap;
}

static struct ctdb_node_map *read_nodes_file(TALLOC_CTX *mem_ctx,
					     uint32_t pnn)
{
	struct ctdb_node_map *nodemap;
	char nodes_list[PATH_MAX];
	const char *ctdb_base;
	int num;

	ctdb_base = getenv("CTDB_BASE");
	if (ctdb_base == NULL) {
		D_ERR("CTDB_BASE is not set\n");
		return NULL;
	}

	/* read optional node-specific nodes file */
	num = snprintf(nodes_list, sizeof(nodes_list),
		       "%s/nodes.%d", ctdb_base, pnn);
	if (num == sizeof(nodes_list)) {
		D_ERR("nodes file path too long\n");
		return NULL;
	}
	nodemap = ctdb_read_nodes_file(mem_ctx, nodes_list);
	if (nodemap != NULL) {
		/* Fake a load failure for an empty nodemap */
		if (nodemap->num == 0) {
			talloc_free(nodemap);

			D_ERR("Failed to read nodes file \"%s\"\n", nodes_list);
			return NULL;
		}

		return nodemap;
	}

	/* read normal nodes file */
	num = snprintf(nodes_list, sizeof(nodes_list), "%s/nodes", ctdb_base);
	if (num == sizeof(nodes_list)) {
		D_ERR("nodes file path too long\n");
		return NULL;
	}
	nodemap = ctdb_read_nodes_file(mem_ctx, nodes_list);
	if (nodemap != NULL) {
		return nodemap;
	}

	DBG_ERR("Failed to read nodes file \"%s\"\n", nodes_list);
	return NULL;
}

static struct interface_map *interfaces_init(TALLOC_CTX *mem_ctx)
{
	struct interface_map *iface_map;

	iface_map = talloc_zero(mem_ctx, struct interface_map);
	if (iface_map == NULL) {
		return NULL;
	}

	return iface_map;
}

/* Read interfaces information.  Same format as "ctdb ifaces -Y"
 * output:
 *   :Name:LinkStatus:References:
 *   :eth2:1:4294967294
 *   :eth1:1:4294967292
 */

static bool interfaces_parse(struct interface_map *iface_map)
{
	char line[1024];

	while ((fgets(line, sizeof(line), stdin) != NULL)) {
		uint16_t link_state;
		uint32_t references;
		char *tok, *t, *name;
		struct interface *iface;

		if (line[0] == '\n') {
			break;
		}

		/* Get rid of pesky newline */
		if ((t = strchr(line, '\n')) != NULL) {
			*t = '\0';
		}

		if (strcmp(line, ":Name:LinkStatus:References:") == 0) {
			continue;
		}

		/* Leading colon... */
		// tok = strtok(line, ":");

		/* name */
		tok = strtok(line, ":");
		if (tok == NULL) {
			fprintf(stderr, "bad line (%s) - missing name\n", line);
			continue;
		}
		name = tok;

		/* link_state */
		tok = strtok(NULL, ":");
		if (tok == NULL) {
			fprintf(stderr, "bad line (%s) - missing link state\n",
				line);
			continue;
		}
		link_state = (uint16_t)strtoul(tok, NULL, 0);

		/* references... */
		tok = strtok(NULL, ":");
		if (tok == NULL) {
			fprintf(stderr, "bad line (%s) - missing references\n",
				line);
			continue;
		}
		references = (uint32_t)strtoul(tok, NULL, 0);

		iface_map->iface = talloc_realloc(iface_map, iface_map->iface,
						  struct interface,
						  iface_map->num + 1);
		if (iface_map->iface == NULL) {
			goto fail;
		}

		iface = &iface_map->iface[iface_map->num];

		iface->name = talloc_strdup(iface_map, name);
		if (iface->name == NULL) {
			goto fail;
		}
		iface->link_up = link_state;
		iface->references = references;

		iface_map->num += 1;
	}

	DEBUG(DEBUG_INFO, ("Parsing interfaces done\n"));
	return true;

fail:
	fprintf(stderr, "Parsing interfaces failed\n");
	return false;
}

static struct vnn_map *vnnmap_init(TALLOC_CTX *mem_ctx)
{
	struct vnn_map *vnn_map;

	vnn_map = talloc_zero(mem_ctx, struct vnn_map);
	if (vnn_map == NULL) {
		fprintf(stderr, "Memory error\n");
		return NULL;
	}
	vnn_map->recmode = CTDB_RECOVERY_ACTIVE;
	vnn_map->generation = INVALID_GENERATION;

	return vnn_map;
}

/* Read vnn map.
 * output:
 *   <GENERATION>
 *   <LMASTER0>
 *   <LMASTER1>
 *   ...
 */

static bool vnnmap_parse(struct vnn_map *vnn_map)
{
	char line[1024];

	while (fgets(line, sizeof(line), stdin) != NULL) {
		uint32_t n;
		char *t;

		if (line[0] == '\n') {
			break;
		}

		/* Get rid of pesky newline */
		if ((t = strchr(line, '\n')) != NULL) {
			*t = '\0';
		}

		n = (uint32_t) strtol(line, NULL, 0);

		/* generation */
		if (vnn_map->generation == INVALID_GENERATION) {
			vnn_map->generation = n;
			continue;
		}

		vnn_map->map = talloc_realloc(vnn_map, vnn_map->map, uint32_t,
					      vnn_map->size + 1);
		if (vnn_map->map == NULL) {
			fprintf(stderr, "Memory error\n");
			goto fail;
		}

		vnn_map->map[vnn_map->size] = n;
		vnn_map->size += 1;
	}

	DEBUG(DEBUG_INFO, ("Parsing vnnmap done\n"));
	return true;

fail:
	fprintf(stderr, "Parsing vnnmap failed\n");
	return false;
}

static bool reclock_parse(struct ctdbd_context *ctdb)
{
	char line[1024];
	char *t;

	if (fgets(line, sizeof(line), stdin) == NULL) {
		goto fail;
	}

	if (line[0] == '\n') {
		/* Recovery lock remains unset */
		goto ok;
	}

	/* Get rid of pesky newline */
	if ((t = strchr(line, '\n')) != NULL) {
		*t = '\0';
	}

	ctdb->reclock = talloc_strdup(ctdb, line);
	if (ctdb->reclock == NULL) {
		goto fail;
	}
ok:
	/* Swallow possible blank line following section.  Picky
	 * compiler settings don't allow the return value to be
	 * ignored, so make the compiler happy.
	 */
	if (fgets(line, sizeof(line), stdin) == NULL) {
		;
	}
	DEBUG(DEBUG_INFO, ("Parsing reclock done\n"));
	return true;

fail:
	fprintf(stderr, "Parsing reclock failed\n");
	return false;
}

static struct database_map *dbmap_init(TALLOC_CTX *mem_ctx,
				       const char *dbdir)
{
	struct database_map *db_map;

	db_map = talloc_zero(mem_ctx, struct database_map);
	if (db_map == NULL) {
		return NULL;
	}

	db_map->dbdir = talloc_strdup(db_map, dbdir);
	if (db_map->dbdir == NULL) {
		talloc_free(db_map);
		return NULL;
	}

	return db_map;
}

/* Read a database map from stdin.  Each line looks like:
 *  <ID> <NAME> [FLAGS] [SEQ_NUM]
 * EOF or a blank line terminates input.
 *
 * By default, flags and seq_num are 0
 */

static bool dbmap_parse(struct database_map *db_map)
{
	char line[1024];

	while ((fgets(line, sizeof(line), stdin) != NULL)) {
		uint32_t id;
		uint8_t flags = 0;
		uint32_t seq_num = 0;
		char *tok, *t;
		char *name;
		struct database *db;

		if (line[0] == '\n') {
			break;
		}

		/* Get rid of pesky newline */
		if ((t = strchr(line, '\n')) != NULL) {
			*t = '\0';
		}

		/* Get ID */
		tok = strtok(line, " \t");
		if (tok == NULL) {
			fprintf(stderr, "bad line (%s) - missing ID\n", line);
			continue;
		}
		id = (uint32_t)strtoul(tok, NULL, 0);

		/* Get NAME */
		tok = strtok(NULL, " \t");
		if (tok == NULL) {
			fprintf(stderr, "bad line (%s) - missing NAME\n", line);
			continue;
		}
		name = talloc_strdup(db_map, tok);
		if (name == NULL) {
			goto fail;
		}

		/* Get flags */
		tok = strtok(NULL, " \t");
		while (tok != NULL) {
			if (strcmp(tok, "PERSISTENT") == 0) {
				flags |= CTDB_DB_FLAGS_PERSISTENT;
			} else if (strcmp(tok, "STICKY") == 0) {
				flags |= CTDB_DB_FLAGS_STICKY;
			} else if (strcmp(tok, "READONLY") == 0) {
				flags |= CTDB_DB_FLAGS_READONLY;
			} else if (strcmp(tok, "REPLICATED") == 0) {
				flags |= CTDB_DB_FLAGS_REPLICATED;
			} else if (tok[0] >= '0'&& tok[0] <= '9') {
				uint8_t nv = CTDB_DB_FLAGS_PERSISTENT |
					     CTDB_DB_FLAGS_REPLICATED;

				if ((flags & nv) == 0) {
					fprintf(stderr,
						"seq_num for volatile db\n");
					goto fail;
				}
				seq_num = (uint64_t)strtoull(tok, NULL, 0);
			}

			tok = strtok(NULL, " \t");
		}

		db = talloc_zero(db_map, struct database);
		if (db == NULL) {
			goto fail;
		}

		db->id = id;
		db->name = talloc_steal(db, name);
		db->path = talloc_asprintf(db, "%s/%s", db_map->dbdir, name);
		if (db->path == NULL) {
			talloc_free(db);
			goto fail;
		}
		db->flags = flags;
		db->seq_num = seq_num;

		DLIST_ADD_END(db_map->db, db);
	}

	DEBUG(DEBUG_INFO, ("Parsing dbmap done\n"));
	return true;

fail:
	DEBUG(DEBUG_INFO, ("Parsing dbmap failed\n"));
	return false;

}

static struct database *database_find(struct database_map *db_map,
				      uint32_t db_id)
{
	struct database *db;

	for (db = db_map->db; db != NULL; db = db->next) {
		if (db->id == db_id) {
			return db;
		}
	}

	return NULL;
}

static int database_count(struct database_map *db_map)
{
	struct database *db;
	int count = 0;

	for (db = db_map->db; db != NULL; db = db->next) {
		count += 1;
	}

	return count;
}

static int database_flags(uint8_t db_flags)
{
	int tdb_flags = 0;

	if (db_flags & CTDB_DB_FLAGS_PERSISTENT) {
		tdb_flags = TDB_DEFAULT;
	} else {
		/* volatile and replicated use the same flags */
		tdb_flags = TDB_NOSYNC |
			    TDB_CLEAR_IF_FIRST |
			    TDB_INCOMPATIBLE_HASH;
	}

	tdb_flags |= TDB_DISALLOW_NESTING;

	return tdb_flags;
}

static struct database *database_new(struct database_map *db_map,
				     const char *name, uint8_t flags)
{
	struct database *db;
	TDB_DATA key;
	int tdb_flags;

	db = talloc_zero(db_map, struct database);
	if (db == NULL) {
		return NULL;
	}

	db->name = talloc_strdup(db, name);
	if (db->name == NULL) {
		goto fail;
	}

	db->path = talloc_asprintf(db, "%s/%s", db_map->dbdir, name);
	if (db->path == NULL) {
		goto fail;
	}

	key.dsize = strlen(db->name) + 1;
	key.dptr = discard_const(db->name);

	db->id = tdb_jenkins_hash(&key);
	db->flags = flags;

	tdb_flags = database_flags(flags);

	db->tdb = tdb_open(db->path, 8192, tdb_flags, O_CREAT|O_RDWR, 0644);
	if (db->tdb == NULL) {
		DBG_ERR("tdb_open\n");
		goto fail;
	}

	DLIST_ADD_END(db_map->db, db);
	return db;

fail:
	DBG_ERR("Memory error\n");
	talloc_free(db);
	return NULL;

}

static int ltdb_store(struct database *db, TDB_DATA key,
		      struct ctdb_ltdb_header *header, TDB_DATA data)
{
	int ret;
	bool db_volatile = true;
	bool keep = false;

	if (db->tdb == NULL) {
		return EINVAL;
	}

	if ((db->flags & CTDB_DB_FLAGS_PERSISTENT) ||
	    (db->flags & CTDB_DB_FLAGS_REPLICATED)) {
		db_volatile = false;
	}

	if (data.dsize > 0) {
		keep = true;
	} else {
		if (db_volatile && header->rsn == 0) {
			keep = true;
		}
	}

	if (keep) {
		TDB_DATA rec[2];

		rec[0].dsize = ctdb_ltdb_header_len(header);
		rec[0].dptr = (uint8_t *)header;

		rec[1].dsize = data.dsize;
		rec[1].dptr = data.dptr;

		ret = tdb_storev(db->tdb, key, rec, 2, TDB_REPLACE);
	} else {
		if (header->rsn > 0) {
			ret = tdb_delete(db->tdb, key);
		} else {
			ret = 0;
		}
	}

	return ret;
}

static int ltdb_fetch(struct database *db, TDB_DATA key,
		      struct ctdb_ltdb_header *header,
		      TALLOC_CTX *mem_ctx, TDB_DATA *data)
{
	TDB_DATA rec;
	size_t np;
	int ret;

	if (db->tdb == NULL) {
		return EINVAL;
	}

	rec = tdb_fetch(db->tdb, key);
	ret = ctdb_ltdb_header_pull(rec.dptr, rec.dsize, header, &np);
	if (ret != 0) {
		if (rec.dptr != NULL) {
			free(rec.dptr);
		}

		*header = (struct ctdb_ltdb_header) {
			.rsn = 0,
			.dmaster = 0,
			.flags = 0,
		};

		ret = ltdb_store(db, key, header, tdb_null);
		if (ret != 0) {
			return ret;
		}

		*data = tdb_null;
		return 0;
	}

	data->dsize = rec.dsize - ctdb_ltdb_header_len(header);
	data->dptr = talloc_memdup(mem_ctx,
				   rec.dptr + ctdb_ltdb_header_len(header),
				   data->dsize);

	free(rec.dptr);

	if (data->dptr == NULL) {
		return ENOMEM;
	}

	return 0;
}

static int database_seqnum(struct database *db, uint64_t *seqnum)
{
	const char *keyname = CTDB_DB_SEQNUM_KEY;
	TDB_DATA key, data;
	struct ctdb_ltdb_header header;
	size_t np;
	int ret;

	if (db->tdb == NULL) {
		*seqnum = db->seq_num;
		return 0;
	}

	key.dptr = discard_const(keyname);
	key.dsize = strlen(keyname) + 1;

	ret = ltdb_fetch(db, key, &header, db, &data);
	if (ret != 0) {
		return ret;
	}

	if (data.dsize == 0) {
		*seqnum = 0;
		return 0;
	}

	ret = ctdb_uint64_pull(data.dptr, data.dsize, seqnum, &np);
	talloc_free(data.dptr);
	if (ret != 0) {
		*seqnum = 0;
	}

	return ret;
}

static int ltdb_transaction_update(uint32_t reqid,
				   struct ctdb_ltdb_header *no_header,
				   TDB_DATA key, TDB_DATA data,
				   void *private_data)
{
	struct database *db = (struct database *)private_data;
	TALLOC_CTX *tmp_ctx = talloc_new(db);
	struct ctdb_ltdb_header header = { 0 }, oldheader;
	TDB_DATA olddata;
	int ret;

	if (db->tdb == NULL) {
		return EINVAL;
	}

	ret = ctdb_ltdb_header_extract(&data, &header);
	if (ret != 0) {
		return ret;
	}

	ret = ltdb_fetch(db, key, &oldheader, tmp_ctx, &olddata);
	if (ret != 0) {
		return ret;
	}

	if (olddata.dsize > 0) {
		if (oldheader.rsn > header.rsn ||
		    (oldheader.rsn == header.rsn &&
		     olddata.dsize != data.dsize)) {
			return -1;
		}
	}

	talloc_free(tmp_ctx);

	ret = ltdb_store(db, key, &header, data);
	return ret;
}

static int ltdb_transaction(struct database *db,
			    struct ctdb_rec_buffer *recbuf)
{
	int ret;

	if (db->tdb == NULL) {
		return EINVAL;
	}

	ret = tdb_transaction_start(db->tdb);
	if (ret == -1) {
		return ret;
	}

	ret = ctdb_rec_buffer_traverse(recbuf, ltdb_transaction_update, db);
	if (ret != 0) {
		tdb_transaction_cancel(db->tdb);
	}

	ret = tdb_transaction_commit(db->tdb);
	return ret;
}

static bool public_ips_parse(struct ctdbd_context *ctdb,
			     uint32_t numnodes)
{
	bool status;

	if (numnodes == 0) {
		D_ERR("Must initialise nodemap before public IPs\n");
		return false;
	}

	ctdb->known_ips = ipalloc_read_known_ips(ctdb, numnodes, false);

	status = (ctdb->known_ips != NULL);

	if (status) {
		D_INFO("Parsing public IPs done\n");
	} else {
		D_INFO("Parsing public IPs failed\n");
	}

	return status;
}

/* Read information about controls to fail.  Format is:
 *   <opcode> <pnn> {ERROR|TIMEOUT} <comment>
 */
static bool control_failures_parse(struct ctdbd_context *ctdb)
{
	char line[1024];

	while ((fgets(line, sizeof(line), stdin) != NULL)) {
		char *tok, *t;
		enum ctdb_controls opcode;
		uint32_t pnn;
		const char *error;
		const char *comment;
		struct fake_control_failure *failure = NULL;

		if (line[0] == '\n') {
			break;
		}

		/* Get rid of pesky newline */
		if ((t = strchr(line, '\n')) != NULL) {
			*t = '\0';
		}

		/* Get opcode */
		tok = strtok(line, " \t");
		if (tok == NULL) {
			D_ERR("bad line (%s) - missing opcode\n", line);
			continue;
		}
		opcode = (enum ctdb_controls)strtoul(tok, NULL, 0);

		/* Get PNN */
		tok = strtok(NULL, " \t");
		if (tok == NULL) {
			D_ERR("bad line (%s) - missing PNN\n", line);
			continue;
		}
		pnn = (uint32_t)strtoul(tok, NULL, 0);

		/* Get error */
		tok = strtok(NULL, " \t");
		if (tok == NULL) {
			D_ERR("bad line (%s) - missing errno\n", line);
			continue;
		}
		error = talloc_strdup(ctdb, tok);
		if (error == NULL) {
			goto fail;
		}
		if (strcmp(error, "ERROR") != 0 &&
		    strcmp(error, "TIMEOUT") != 0) {
			D_ERR("bad line (%s) "
			      "- error must be \"ERROR\" or \"TIMEOUT\"\n",
			      line);
			goto fail;
		}

		/* Get comment */
		tok = strtok(NULL, "\n"); /* rest of line */
		if (tok == NULL) {
			D_ERR("bad line (%s) - missing comment\n", line);
			continue;
		}
		comment = talloc_strdup(ctdb, tok);
		if (comment == NULL) {
			goto fail;
		}

		failure = talloc_zero(ctdb, struct fake_control_failure);
		if (failure == NULL) {
			goto fail;
		}

		failure->opcode = opcode;
		failure->pnn = pnn;
		failure->error = error;
		failure->comment = comment;

		DLIST_ADD(ctdb->control_failures, failure);
	}

	D_INFO("Parsing fake control failures done\n");
	return true;

fail:
	D_INFO("Parsing fake control failures failed\n");
	return false;
}

/*
 * Manage clients
 */

static int ctdb_client_destructor(struct ctdb_client *client)
{
	DLIST_REMOVE(client->ctdb->client_list, client);
	return 0;
}

static int client_add(struct ctdbd_context *ctdb, pid_t client_pid,
		      void *client_state)
{
	struct ctdb_client *client;

	client = talloc_zero(client_state, struct ctdb_client);
	if (client == NULL) {
		return ENOMEM;
	}

	client->ctdb = ctdb;
	client->pid = client_pid;
	client->state = client_state;

	DLIST_ADD(ctdb->client_list, client);
	talloc_set_destructor(client, ctdb_client_destructor);
	return 0;
}

static void *client_find(struct ctdbd_context *ctdb, pid_t client_pid)
{
	struct ctdb_client *client;

	for (client=ctdb->client_list; client != NULL; client=client->next) {
		if (client->pid == client_pid) {
			return client->state;
		}
	}

	return NULL;
}

/*
 * CTDB context setup
 */

static uint32_t new_generation(uint32_t old_generation)
{
	uint32_t generation;

	while (1) {
		generation = random();
		if (generation != INVALID_GENERATION &&
		    generation != old_generation) {
			break;
		}
	}

	return generation;
}

static struct ctdbd_context *ctdbd_setup(TALLOC_CTX *mem_ctx,
					 const char *dbdir)
{
	struct ctdbd_context *ctdb;
	char line[1024];
	bool status;
	int ret;

	ctdb = talloc_zero(mem_ctx, struct ctdbd_context);
	if (ctdb == NULL) {
		return NULL;
	}

	ctdb->node_map = nodemap_init(ctdb);
	if (ctdb->node_map == NULL) {
		goto fail;
	}

	ctdb->iface_map = interfaces_init(ctdb);
	if (ctdb->iface_map == NULL) {
		goto fail;
	}

	ctdb->vnn_map = vnnmap_init(ctdb);
	if (ctdb->vnn_map == NULL) {
		goto fail;
	}

	ctdb->db_map = dbmap_init(ctdb, dbdir);
	if (ctdb->db_map == NULL) {
		goto fail;
	}

	ret = srvid_init(ctdb, &ctdb->srv);
	if (ret != 0) {
		goto fail;
	}

	while (fgets(line, sizeof(line), stdin) != NULL) {
		char *t;

		if ((t = strchr(line, '\n')) != NULL) {
			*t = '\0';
		}

		if (strcmp(line, "NODEMAP") == 0) {
			status = nodemap_parse(ctdb->node_map);
		} else if (strcmp(line, "IFACES") == 0) {
			status = interfaces_parse(ctdb->iface_map);
		} else if (strcmp(line, "VNNMAP") == 0) {
			status = vnnmap_parse(ctdb->vnn_map);
		} else if (strcmp(line, "DBMAP") == 0) {
			status = dbmap_parse(ctdb->db_map);
		} else if (strcmp(line, "PUBLICIPS") == 0) {
			status = public_ips_parse(ctdb,
						  ctdb->node_map->num_nodes);
		} else if (strcmp(line, "RECLOCK") == 0) {
			status = reclock_parse(ctdb);
		} else if (strcmp(line, "CONTROLFAILS") == 0) {
			status = control_failures_parse(ctdb);
		} else {
			fprintf(stderr, "Unknown line %s\n", line);
			status = false;
		}

		if (! status) {
			goto fail;
		}
	}

	ctdb->start_time = tevent_timeval_current();
	ctdb->recovery_start_time = tevent_timeval_current();
	ctdb->vnn_map->recmode = CTDB_RECOVERY_NORMAL;
	if (ctdb->vnn_map->generation == INVALID_GENERATION) {
		ctdb->vnn_map->generation =
			new_generation(ctdb->vnn_map->generation);
	}
	ctdb->recovery_end_time = tevent_timeval_current();

	ctdb->log_level = DEBUG_ERR;
	ctdb->runstate = CTDB_RUNSTATE_RUNNING;

	ctdb_tunable_set_defaults(&ctdb->tun_list);

	return ctdb;

fail:
	TALLOC_FREE(ctdb);
	return NULL;
}

static bool ctdbd_verify(struct ctdbd_context *ctdb)
{
	struct node *node;
	unsigned int i;

	if (ctdb->node_map->num_nodes == 0) {
		return true;
	}

	/* Make sure all the nodes are in order */
	for (i=0; i<ctdb->node_map->num_nodes; i++) {
		node = &ctdb->node_map->node[i];
		if (node->pnn != i) {
			fprintf(stderr, "Expected node %u, found %u\n",
				i, node->pnn);
			return false;
		}
	}

	node = &ctdb->node_map->node[ctdb->node_map->pnn];
	if (node->flags & NODE_FLAGS_DISCONNECTED) {
		DEBUG(DEBUG_INFO, ("Node disconnected, exiting\n"));
		exit(0);
	}

	return true;
}

/*
 * Doing a recovery
 */

struct recover_state {
	struct tevent_context *ev;
	struct ctdbd_context *ctdb;
};

static int recover_check(struct tevent_req *req);
static void recover_wait_done(struct tevent_req *subreq);
static void recover_done(struct tevent_req *subreq);

static struct tevent_req *recover_send(TALLOC_CTX *mem_ctx,
				       struct tevent_context *ev,
				       struct ctdbd_context *ctdb)
{
	struct tevent_req *req;
	struct recover_state *state;
	int ret;

	req = tevent_req_create(mem_ctx, &state, struct recover_state);
	if (req == NULL) {
		return NULL;
	}

	state->ev = ev;
	state->ctdb = ctdb;

	ret = recover_check(req);
	if (ret != 0) {
		tevent_req_error(req, ret);
		return tevent_req_post(req, ev);
	}

	return req;
}

static int recover_check(struct tevent_req *req)
{
	struct recover_state *state = tevent_req_data(
		req, struct recover_state);
	struct ctdbd_context *ctdb = state->ctdb;
	struct tevent_req *subreq;
	bool recovery_disabled;
	unsigned int i;

	recovery_disabled = false;
	for (i=0; i<ctdb->node_map->num_nodes; i++) {
		if (ctdb->node_map->node[i].recovery_disabled) {
			recovery_disabled = true;
			break;
		}
	}

	subreq = tevent_wakeup_send(state, state->ev,
				    tevent_timeval_current_ofs(1, 0));
	if (subreq == NULL) {
		return ENOMEM;
	}

	if (recovery_disabled) {
		tevent_req_set_callback(subreq, recover_wait_done, req);
	} else {
		ctdb->recovery_start_time = tevent_timeval_current();
		tevent_req_set_callback(subreq, recover_done, req);
	}

	return 0;
}

static void recover_wait_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	int ret;
	bool status;

	status = tevent_wakeup_recv(subreq);
	TALLOC_FREE(subreq);
	if (! status) {
		tevent_req_error(req, EIO);
		return;
	}

	ret = recover_check(req);
	if (ret != 0) {
		tevent_req_error(req, ret);
	}
}

static void recover_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct recover_state *state = tevent_req_data(
		req, struct recover_state);
	struct ctdbd_context *ctdb = state->ctdb;
	bool status;

	status = tevent_wakeup_recv(subreq);
	TALLOC_FREE(subreq);
	if (! status) {
		tevent_req_error(req, EIO);
		return;
	}

	ctdb->vnn_map->recmode = CTDB_RECOVERY_NORMAL;
	ctdb->recovery_end_time = tevent_timeval_current();
	ctdb->vnn_map->generation = new_generation(ctdb->vnn_map->generation);

	tevent_req_done(req);
}

static bool recover_recv(struct tevent_req *req, int *perr)
{
	int err;

	if (tevent_req_is_unix_error(req, &err)) {
		if (perr != NULL) {
			*perr = err;
		}
		return false;
	}

	return true;
}

/*
 * Routines for ctdb_req_header
 */

static void header_fix_pnn(struct ctdb_req_header *header,
			   struct ctdbd_context *ctdb)
{
	if (header->srcnode == CTDB_CURRENT_NODE) {
		header->srcnode = ctdb->node_map->pnn;
	}

	if (header->destnode == CTDB_CURRENT_NODE) {
		header->destnode = ctdb->node_map->pnn;
	}
}

static struct ctdb_req_header header_reply_call(
					struct ctdb_req_header *header,
					struct ctdbd_context *ctdb)
{
	struct ctdb_req_header reply_header;

	reply_header = (struct ctdb_req_header) {
		.ctdb_magic = CTDB_MAGIC,
		.ctdb_version = CTDB_PROTOCOL,
		.generation = ctdb->vnn_map->generation,
		.operation = CTDB_REPLY_CALL,
		.destnode = header->srcnode,
		.srcnode = header->destnode,
		.reqid = header->reqid,
	};

	return reply_header;
}

static struct ctdb_req_header header_reply_control(
					struct ctdb_req_header *header,
					struct ctdbd_context *ctdb)
{
	struct ctdb_req_header reply_header;

	reply_header = (struct ctdb_req_header) {
		.ctdb_magic = CTDB_MAGIC,
		.ctdb_version = CTDB_PROTOCOL,
		.generation = ctdb->vnn_map->generation,
		.operation = CTDB_REPLY_CONTROL,
		.destnode = header->srcnode,
		.srcnode = header->destnode,
		.reqid = header->reqid,
	};

	return reply_header;
}

static struct ctdb_req_header header_reply_message(
					struct ctdb_req_header *header,
					struct ctdbd_context *ctdb)
{
	struct ctdb_req_header reply_header;

	reply_header = (struct ctdb_req_header) {
		.ctdb_magic = CTDB_MAGIC,
		.ctdb_version = CTDB_PROTOCOL,
		.generation = ctdb->vnn_map->generation,
		.operation = CTDB_REQ_MESSAGE,
		.destnode = header->srcnode,
		.srcnode = header->destnode,
		.reqid = 0,
	};

	return reply_header;
}

/*
 * Client state
 */

struct client_state {
	struct tevent_context *ev;
	int fd;
	struct ctdbd_context *ctdb;
	int pnn;
	pid_t pid;
	struct comm_context *comm;
	struct srvid_register_state *rstate;
	int status;
};

/*
 * Send replies to call, controls and messages
 */

static void client_reply_done(struct tevent_req *subreq);

static void client_send_call(struct tevent_req *req,
			     struct ctdb_req_header *header,
			     struct ctdb_reply_call *reply)
{
	struct client_state *state = tevent_req_data(
		req, struct client_state);
	struct ctdbd_context *ctdb = state->ctdb;
	struct tevent_req *subreq;
	struct ctdb_req_header reply_header;
	uint8_t *buf;
	size_t datalen, buflen;
	int ret;

	reply_header = header_reply_call(header, ctdb);

	datalen = ctdb_reply_call_len(&reply_header, reply);
	ret = ctdb_allocate_pkt(state, datalen, &buf, &buflen);
	if (ret != 0) {
		tevent_req_error(req, ret);
		return;
	}

	ret = ctdb_reply_call_push(&reply_header, reply, buf, &buflen);
	if (ret != 0) {
		tevent_req_error(req, ret);
		return;
	}

	subreq = comm_write_send(state, state->ev, state->comm, buf, buflen);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, client_reply_done, req);

	talloc_steal(subreq, buf);
}

static void client_send_message(struct tevent_req *req,
				struct ctdb_req_header *header,
				struct ctdb_req_message_data *message)
{
	struct client_state *state = tevent_req_data(
		req, struct client_state);
	struct ctdbd_context *ctdb = state->ctdb;
	struct tevent_req *subreq;
	struct ctdb_req_header reply_header;
	uint8_t *buf;
	size_t datalen, buflen;
	int ret;

	reply_header = header_reply_message(header, ctdb);

	datalen = ctdb_req_message_data_len(&reply_header, message);
	ret = ctdb_allocate_pkt(state, datalen, &buf, &buflen);
	if (ret != 0) {
		tevent_req_error(req, ret);
		return;
	}

	ret = ctdb_req_message_data_push(&reply_header, message,
					 buf, &buflen);
	if (ret != 0) {
		tevent_req_error(req, ret);
		return;
	}

	DEBUG(DEBUG_INFO, ("message srvid = 0x%"PRIx64"\n", message->srvid));

	subreq = comm_write_send(state, state->ev, state->comm, buf, buflen);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, client_reply_done, req);

	talloc_steal(subreq, buf);
}

static void client_send_control(struct tevent_req *req,
				struct ctdb_req_header *header,
				struct ctdb_reply_control *reply)
{
	struct client_state *state = tevent_req_data(
		req, struct client_state);
	struct ctdbd_context *ctdb = state->ctdb;
	struct tevent_req *subreq;
	struct ctdb_req_header reply_header;
	uint8_t *buf;
	size_t datalen, buflen;
	int ret;

	reply_header = header_reply_control(header, ctdb);

	datalen = ctdb_reply_control_len(&reply_header, reply);
	ret = ctdb_allocate_pkt(state, datalen, &buf, &buflen);
	if (ret != 0) {
		tevent_req_error(req, ret);
		return;
	}

	ret = ctdb_reply_control_push(&reply_header, reply, buf, &buflen);
	if (ret != 0) {
		tevent_req_error(req, ret);
		return;
	}

	DEBUG(DEBUG_INFO, ("reply opcode = %u\n", reply->rdata.opcode));

	subreq = comm_write_send(state, state->ev, state->comm, buf, buflen);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, client_reply_done, req);

	talloc_steal(subreq, buf);
}

static void client_reply_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	int ret;
	bool status;

	status = comm_write_recv(subreq, &ret);
	TALLOC_FREE(subreq);
	if (! status) {
		tevent_req_error(req, ret);
	}
}

/*
 * Handling protocol - controls
 */

static void control_process_exists(TALLOC_CTX *mem_ctx,
				   struct tevent_req *req,
				   struct ctdb_req_header *header,
				   struct ctdb_req_control *request)
{
	struct client_state *state = tevent_req_data(
		req, struct client_state);
	struct ctdbd_context *ctdb = state->ctdb;
	struct client_state *cstate;
	struct ctdb_reply_control reply;

	reply.rdata.opcode = request->opcode;

	cstate = client_find(ctdb, request->rdata.data.pid);
	if (cstate == NULL) {
		reply.status = -1;
		reply.errmsg = "No client for PID";
	} else {
		reply.status = kill(request->rdata.data.pid, 0);
		reply.errmsg = NULL;
	}

	client_send_control(req, header, &reply);
}

static void control_ping(TALLOC_CTX *mem_ctx,
			 struct tevent_req *req,
			 struct ctdb_req_header *header,
			 struct ctdb_req_control *request)
{
	struct client_state *state = tevent_req_data(
		req, struct client_state);
	struct ctdbd_context *ctdb = state->ctdb;
	struct ctdb_reply_control reply;

	reply.rdata.opcode = request->opcode;
	reply.status = ctdb->num_clients;
	reply.errmsg = NULL;

	client_send_control(req, header, &reply);
}

static void control_getdbpath(TALLOC_CTX *mem_ctx,
			      struct tevent_req *req,
			      struct ctdb_req_header *header,
			      struct ctdb_req_control *request)
{
	struct client_state *state = tevent_req_data(
		req, struct client_state);
	struct ctdbd_context *ctdb = state->ctdb;
	struct ctdb_reply_control reply;
	struct database *db;

	reply.rdata.opcode = request->opcode;

	db = database_find(ctdb->db_map, request->rdata.data.db_id);
	if (db == NULL) {
		reply.status = ENOENT;
		reply.errmsg = "Database not found";
	} else {
		reply.rdata.data.db_path =
			talloc_strdup(mem_ctx, db->path);
		if (reply.rdata.data.db_path == NULL) {
			reply.status = ENOMEM;
			reply.errmsg = "Memory error";
		} else {
			reply.status = 0;
			reply.errmsg = NULL;
		}
	}

	client_send_control(req, header, &reply);
}

static void control_getvnnmap(TALLOC_CTX *mem_ctx,
			      struct tevent_req *req,
			      struct ctdb_req_header *header,
			      struct ctdb_req_control *request)
{
	struct client_state *state = tevent_req_data(
		req, struct client_state);
	struct ctdbd_context *ctdb = state->ctdb;
	struct ctdb_reply_control reply;
	struct ctdb_vnn_map *vnnmap;

	reply.rdata.opcode = request->opcode;

	vnnmap = talloc_zero(mem_ctx, struct ctdb_vnn_map);
	if (vnnmap == NULL) {
		reply.status = ENOMEM;
		reply.errmsg = "Memory error";
	} else {
		vnnmap->generation = ctdb->vnn_map->generation;
		vnnmap->size = ctdb->vnn_map->size;
		vnnmap->map = ctdb->vnn_map->map;

		reply.rdata.data.vnnmap = vnnmap;
		reply.status = 0;
		reply.errmsg = NULL;
	}

	client_send_control(req, header, &reply);
}

static void control_get_debug(TALLOC_CTX *mem_ctx,
			      struct tevent_req *req,
			      struct ctdb_req_header *header,
			      struct ctdb_req_control *request)
{
	struct client_state *state = tevent_req_data(
		req, struct client_state);
	struct ctdbd_context *ctdb = state->ctdb;
	struct ctdb_reply_control reply;

	reply.rdata.opcode = request->opcode;
	reply.rdata.data.loglevel = (uint32_t)ctdb->log_level;
	reply.status = 0;
	reply.errmsg = NULL;

	client_send_control(req, header, &reply);
}

static void control_set_debug(TALLOC_CTX *mem_ctx,
			      struct tevent_req *req,
			      struct ctdb_req_header *header,
			      struct ctdb_req_control *request)
{
	struct client_state *state = tevent_req_data(
		req, struct client_state);
	struct ctdbd_context *ctdb = state->ctdb;
	struct ctdb_reply_control reply;

	ctdb->log_level = (int)request->rdata.data.loglevel;

	reply.rdata.opcode = request->opcode;
	reply.status = 0;
	reply.errmsg = NULL;

	client_send_control(req, header, &reply);
}

static void control_get_dbmap(TALLOC_CTX *mem_ctx,
			      struct tevent_req *req,
			       struct ctdb_req_header *header,
			      struct ctdb_req_control *request)
{
	struct client_state *state = tevent_req_data(
		req, struct client_state);
	struct ctdbd_context *ctdb = state->ctdb;
	struct ctdb_reply_control reply;
	struct ctdb_dbid_map *dbmap;
	struct database *db;
	unsigned int i;

	reply.rdata.opcode = request->opcode;

	dbmap = talloc_zero(mem_ctx, struct ctdb_dbid_map);
	if (dbmap == NULL) {
		goto fail;
	}

	dbmap->num = database_count(ctdb->db_map);
	dbmap->dbs = talloc_zero_array(dbmap, struct ctdb_dbid, dbmap->num);
	if (dbmap->dbs == NULL) {
		goto fail;
	}

	db = ctdb->db_map->db;
	for (i = 0; i < dbmap->num; i++) {
		dbmap->dbs[i] = (struct ctdb_dbid) {
			.db_id = db->id,
			.flags = db->flags,
		};

		db = db->next;
	}

	reply.rdata.data.dbmap = dbmap;
	reply.status = 0;
	reply.errmsg = NULL;
	client_send_control(req, header, &reply);
	return;

fail:
	reply.status = -1;
	reply.errmsg = "Memory error";
	client_send_control(req, header, &reply);
}

static void control_get_recmode(TALLOC_CTX *mem_ctx,
				struct tevent_req *req,
				struct ctdb_req_header *header,
				struct ctdb_req_control *request)
{
	struct client_state *state = tevent_req_data(
		req, struct client_state);
	struct ctdbd_context *ctdb = state->ctdb;
	struct ctdb_reply_control reply;

	reply.rdata.opcode = request->opcode;
	reply.status = ctdb->vnn_map->recmode;
	reply.errmsg = NULL;

	client_send_control(req, header, &reply);
}

struct set_recmode_state {
	struct tevent_req *req;
	struct ctdbd_context *ctdb;
	struct ctdb_req_header header;
	struct ctdb_reply_control reply;
};

static void set_recmode_callback(struct tevent_req *subreq)
{
	struct set_recmode_state *substate = tevent_req_callback_data(
		subreq, struct set_recmode_state);
	bool status;
	int ret;

	status = recover_recv(subreq, &ret);
	TALLOC_FREE(subreq);
	if (! status) {
		substate->reply.status = ret;
		substate->reply.errmsg = "recovery failed";
	} else {
		substate->reply.status = 0;
		substate->reply.errmsg = NULL;
	}

	client_send_control(substate->req, &substate->header, &substate->reply);
	talloc_free(substate);
}

static void control_set_recmode(TALLOC_CTX *mem_ctx,
				struct tevent_req *req,
				struct ctdb_req_header *header,
				struct ctdb_req_control *request)
{
	struct client_state *state = tevent_req_data(
		req, struct client_state);
	struct tevent_req *subreq;
	struct ctdbd_context *ctdb = state->ctdb;
	struct set_recmode_state *substate;
	struct ctdb_reply_control reply;

	reply.rdata.opcode = request->opcode;

	if (request->rdata.data.recmode == CTDB_RECOVERY_NORMAL) {
		reply.status = -1;
		reply.errmsg = "Client cannot set recmode to NORMAL";
		goto fail;
	}

	substate = talloc_zero(ctdb, struct set_recmode_state);
	if (substate == NULL) {
		reply.status = -1;
		reply.errmsg = "Memory error";
		goto fail;
	}

	substate->req = req;
	substate->ctdb = ctdb;
	substate->header = *header;
	substate->reply.rdata.opcode = request->opcode;

	subreq = recover_send(substate, state->ev, state->ctdb);
	if (subreq == NULL) {
		talloc_free(substate);
		goto fail;
	}
	tevent_req_set_callback(subreq, set_recmode_callback, substate);

	ctdb->vnn_map->recmode = CTDB_RECOVERY_ACTIVE;
	return;

fail:
	client_send_control(req, header, &reply);

}

static void control_db_attach(TALLOC_CTX *mem_ctx,
			      struct tevent_req *req,
			      struct ctdb_req_header *header,
			      struct ctdb_req_control *request)
{
	struct client_state *state = tevent_req_data(
		req, struct client_state);
	struct ctdbd_context *ctdb = state->ctdb;
	struct ctdb_reply_control reply;
	struct database *db;

	reply.rdata.opcode = request->opcode;

	for (db = ctdb->db_map->db; db != NULL; db = db->next) {
		if (strcmp(db->name, request->rdata.data.db_name) == 0) {
			goto done;
		}
	}

	db = database_new(ctdb->db_map, request->rdata.data.db_name, 0);
	if (db == NULL) {
		reply.status = -1;
		reply.errmsg = "Failed to attach database";
		client_send_control(req, header, &reply);
		return;
	}

done:
	reply.rdata.data.db_id = db->id;
	reply.status = 0;
	reply.errmsg = NULL;
	client_send_control(req, header, &reply);
}

static void srvid_handler(uint64_t srvid, TDB_DATA data, void *private_data)
{
	printf("Received a message for SRVID 0x%"PRIx64"\n", srvid);
}

static void control_register_srvid(TALLOC_CTX *mem_ctx,
				   struct tevent_req *req,
				   struct ctdb_req_header *header,
				   struct ctdb_req_control *request)
{
	struct client_state *state = tevent_req_data(
		req, struct client_state);
	struct ctdbd_context *ctdb = state->ctdb;
	struct ctdb_reply_control reply;
	int ret;

	reply.rdata.opcode = request->opcode;

	ret = srvid_register(ctdb->srv, state, request->srvid,
			     srvid_handler, state);
	if (ret != 0) {
		reply.status = -1;
		reply.errmsg = "Memory error";
		goto fail;
	}

	DEBUG(DEBUG_INFO, ("Register srvid 0x%"PRIx64"\n", request->srvid));

	reply.status = 0;
	reply.errmsg = NULL;

fail:
	client_send_control(req, header, &reply);
}

static void control_deregister_srvid(TALLOC_CTX *mem_ctx,
				     struct tevent_req *req,
				     struct ctdb_req_header *header,
				     struct ctdb_req_control *request)
{
	struct client_state *state = tevent_req_data(
		req, struct client_state);
	struct ctdbd_context *ctdb = state->ctdb;
	struct ctdb_reply_control reply;
	int ret;

	reply.rdata.opcode = request->opcode;

	ret = srvid_deregister(ctdb->srv, request->srvid, state);
	if (ret != 0) {
		reply.status = -1;
		reply.errmsg = "srvid not registered";
		goto fail;
	}

	DEBUG(DEBUG_INFO, ("Deregister srvid 0x%"PRIx64"\n", request->srvid));

	reply.status = 0;
	reply.errmsg = NULL;

fail:
	client_send_control(req, header, &reply);
}

static void control_get_dbname(TALLOC_CTX *mem_ctx,
			       struct tevent_req *req,
			       struct ctdb_req_header *header,
			       struct ctdb_req_control *request)
{
	struct client_state *state = tevent_req_data(
		req, struct client_state);
	struct ctdbd_context *ctdb = state->ctdb;
	struct ctdb_reply_control reply;
	struct database *db;

	reply.rdata.opcode = request->opcode;

	db = database_find(ctdb->db_map, request->rdata.data.db_id);
	if (db == NULL) {
		reply.status = ENOENT;
		reply.errmsg = "Database not found";
	} else {
		reply.rdata.data.db_name = talloc_strdup(mem_ctx, db->name);
		if (reply.rdata.data.db_name == NULL) {
			reply.status = ENOMEM;
			reply.errmsg = "Memory error";
		} else {
			reply.status = 0;
			reply.errmsg = NULL;
		}
	}

	client_send_control(req, header, &reply);
}

static void control_get_pid(TALLOC_CTX *mem_ctx,
			    struct tevent_req *req,
			    struct ctdb_req_header *header,
			    struct ctdb_req_control *request)
{
	struct ctdb_reply_control reply;

	reply.rdata.opcode = request->opcode;
	reply.status = getpid();
	reply.errmsg = NULL;

	client_send_control(req, header, &reply);
}

static void control_get_recmaster(TALLOC_CTX *mem_ctx,
				  struct tevent_req *req,
				  struct ctdb_req_header *header,
				  struct ctdb_req_control *request)
{
	struct client_state *state = tevent_req_data(
		req, struct client_state);
	struct ctdbd_context *ctdb = state->ctdb;
	struct ctdb_reply_control reply;

	reply.rdata.opcode = request->opcode;
	reply.status = ctdb->node_map->recmaster;
	reply.errmsg = NULL;

	client_send_control(req, header, &reply);
}

static void control_get_pnn(TALLOC_CTX *mem_ctx,
			    struct tevent_req *req,
			    struct ctdb_req_header *header,
			    struct ctdb_req_control *request)
{
	struct ctdb_reply_control reply;

	reply.rdata.opcode = request->opcode;
	reply.status = header->destnode;
	reply.errmsg = NULL;

	client_send_control(req, header, &reply);
}

static void control_shutdown(TALLOC_CTX *mem_ctx,
			     struct tevent_req *req,
			     struct ctdb_req_header *hdr,
			     struct ctdb_req_control *request)
{
	struct client_state *state = tevent_req_data(
		req, struct client_state);

	state->status = 99;
}

static void control_set_tunable(TALLOC_CTX *mem_ctx,
				struct tevent_req *req,
				struct ctdb_req_header *header,
				struct ctdb_req_control *request)
{
	struct client_state *state = tevent_req_data(
		req, struct client_state);
	struct ctdbd_context *ctdb = state->ctdb;
	struct ctdb_reply_control reply;
	bool ret, obsolete;

	reply.rdata.opcode = request->opcode;
	reply.errmsg = NULL;

	ret = ctdb_tunable_set_value(&ctdb->tun_list,
				     request->rdata.data.tunable->name,
				     request->rdata.data.tunable->value,
				     &obsolete);
	if (! ret) {
		reply.status = -1;
	} else if (obsolete) {
		reply.status = 1;
	} else {
		reply.status = 0;
	}

	client_send_control(req, header, &reply);
}

static void control_get_tunable(TALLOC_CTX *mem_ctx,
				struct tevent_req *req,
				struct ctdb_req_header *header,
				struct ctdb_req_control *request)
{
	struct client_state *state = tevent_req_data(
		req, struct client_state);
	struct ctdbd_context *ctdb = state->ctdb;
	struct ctdb_reply_control reply;
	uint32_t value;
	bool ret;

	reply.rdata.opcode = request->opcode;
	reply.errmsg = NULL;

	ret = ctdb_tunable_get_value(&ctdb->tun_list,
				     request->rdata.data.tun_var, &value);
	if (! ret) {
		reply.status = -1;
	} else {
		reply.rdata.data.tun_value = value;
		reply.status = 0;
	}

	client_send_control(req, header, &reply);
}

static void control_list_tunables(TALLOC_CTX *mem_ctx,
				  struct tevent_req *req,
				  struct ctdb_req_header *header,
				  struct ctdb_req_control *request)
{
	struct ctdb_reply_control reply;
	struct ctdb_var_list *var_list;

	reply.rdata.opcode = request->opcode;
	reply.errmsg = NULL;

	var_list = ctdb_tunable_names(mem_ctx);
	if (var_list == NULL) {
		reply.status = -1;
	} else {
		reply.rdata.data.tun_var_list = var_list;
		reply.status = 0;
	}

	client_send_control(req, header, &reply);
}

static void control_modify_flags(TALLOC_CTX *mem_ctx,
				 struct tevent_req *req,
				 struct ctdb_req_header *header,
				 struct ctdb_req_control *request)
{
	struct client_state *state = tevent_req_data(
		req, struct client_state);
	struct ctdbd_context *ctdb = state->ctdb;
	struct ctdb_node_flag_change *change = request->rdata.data.flag_change;
	struct ctdb_reply_control reply;
	struct node *node;

	reply.rdata.opcode = request->opcode;

	if ((change->old_flags & ~NODE_FLAGS_PERMANENTLY_DISABLED) ||
	    (change->new_flags & ~NODE_FLAGS_PERMANENTLY_DISABLED) != 0) {
		DEBUG(DEBUG_INFO,
		      ("MODIFY_FLAGS control not for PERMANENTLY_DISABLED\n"));
		reply.status = EINVAL;
		reply.errmsg = "Failed to MODIFY_FLAGS";
		client_send_control(req, header, &reply);
		return;
	}

	/* There's all sorts of broadcast weirdness here.  Only change
	 * the specified node, not the destination node of the
	 * control. */
	node = &ctdb->node_map->node[change->pnn];

	if ((node->flags &
	     change->old_flags & NODE_FLAGS_PERMANENTLY_DISABLED) == 0 &&
	    (change->new_flags & NODE_FLAGS_PERMANENTLY_DISABLED) != 0) {
		DEBUG(DEBUG_INFO,("Disabling node %d\n", header->destnode));
		node->flags |= NODE_FLAGS_PERMANENTLY_DISABLED;
		goto done;
	}

	if ((node->flags &
	     change->old_flags & NODE_FLAGS_PERMANENTLY_DISABLED) != 0 &&
	    (change->new_flags & NODE_FLAGS_PERMANENTLY_DISABLED) == 0) {
		DEBUG(DEBUG_INFO,("Enabling node %d\n", header->destnode));
		node->flags &= ~NODE_FLAGS_PERMANENTLY_DISABLED;
		goto done;
	}

	DEBUG(DEBUG_INFO, ("Flags unchanged for node %d\n", header->destnode));

done:
	reply.status = 0;
	reply.errmsg = NULL;
	client_send_control(req, header, &reply);
}

static void control_get_all_tunables(TALLOC_CTX *mem_ctx,
				     struct tevent_req *req,
				     struct ctdb_req_header *header,
				     struct ctdb_req_control *request)
{
	struct client_state *state = tevent_req_data(
		req, struct client_state);
	struct ctdbd_context *ctdb = state->ctdb;
	struct ctdb_reply_control reply;

	reply.rdata.opcode = request->opcode;
	reply.rdata.data.tun_list = &ctdb->tun_list;
	reply.status = 0;
	reply.errmsg = NULL;

	client_send_control(req, header, &reply);
}

static void control_db_attach_persistent(TALLOC_CTX *mem_ctx,
					 struct tevent_req *req,
					 struct ctdb_req_header *header,
					 struct ctdb_req_control *request)
{
	struct client_state *state = tevent_req_data(
		req, struct client_state);
	struct ctdbd_context *ctdb = state->ctdb;
	struct ctdb_reply_control reply;
	struct database *db;

	reply.rdata.opcode = request->opcode;

	for (db = ctdb->db_map->db; db != NULL; db = db->next) {
		if (strcmp(db->name, request->rdata.data.db_name) == 0) {
			goto done;
		}
	}

	db = database_new(ctdb->db_map, request->rdata.data.db_name,
			  CTDB_DB_FLAGS_PERSISTENT);
	if (db == NULL) {
		reply.status = -1;
		reply.errmsg = "Failed to attach database";
		client_send_control(req, header, &reply);
		return;
	}

done:
	reply.rdata.data.db_id = db->id;
	reply.status = 0;
	reply.errmsg = NULL;
	client_send_control(req, header, &reply);
}

static void control_uptime(TALLOC_CTX *mem_ctx,
			   struct tevent_req *req,
			   struct ctdb_req_header *header,
			   struct ctdb_req_control *request)
{
	struct client_state *state = tevent_req_data(
		req, struct client_state);
	struct ctdbd_context *ctdb = state->ctdb;
	struct ctdb_reply_control reply;
	struct ctdb_uptime *uptime;;

	reply.rdata.opcode = request->opcode;

	uptime = talloc_zero(mem_ctx, struct ctdb_uptime);
	if (uptime == NULL) {
		goto fail;
	}

	uptime->current_time = tevent_timeval_current();
	uptime->ctdbd_start_time = ctdb->start_time;
	uptime->last_recovery_started = ctdb->recovery_start_time;
	uptime->last_recovery_finished = ctdb->recovery_end_time;

	reply.rdata.data.uptime = uptime;
	reply.status = 0;
	reply.errmsg = NULL;
	client_send_control(req, header, &reply);
	return;

fail:
	reply.status = -1;
	reply.errmsg = "Memory error";
	client_send_control(req, header, &reply);
}

static void control_reload_nodes_file(TALLOC_CTX *mem_ctx,
				      struct tevent_req *req,
				      struct ctdb_req_header *header,
				      struct ctdb_req_control *request)
{
	struct client_state *state = tevent_req_data(
		req, struct client_state);
	struct ctdbd_context *ctdb = state->ctdb;
	struct ctdb_reply_control reply;
	struct ctdb_node_map *nodemap;
	struct node_map *node_map = ctdb->node_map;
	unsigned int i;

	reply.rdata.opcode = request->opcode;

	nodemap = read_nodes_file(mem_ctx, header->destnode);
	if (nodemap == NULL) {
		goto fail;
	}

	for (i=0; i<nodemap->num; i++) {
		struct node *node;

		if (i < node_map->num_nodes &&
		    ctdb_sock_addr_same(&nodemap->node[i].addr,
					&node_map->node[i].addr)) {
			continue;
		}

		if (nodemap->node[i].flags & NODE_FLAGS_DELETED) {
			int ret;

			node = &node_map->node[i];

			node->flags |= NODE_FLAGS_DELETED;
			ret = ctdb_sock_addr_from_string("0.0.0.0", &node->addr,
							 false);
			if (ret != 0) {
				/* Can't happen, but Coverity... */
				goto fail;
			}

			continue;
		}

		if (i < node_map->num_nodes &&
		    node_map->node[i].flags & NODE_FLAGS_DELETED) {
			node = &node_map->node[i];

			node->flags &= ~NODE_FLAGS_DELETED;
			node->addr = nodemap->node[i].addr;

			continue;
		}

		node_map->node = talloc_realloc(node_map, node_map->node,
						struct node,
						node_map->num_nodes+1);
		if (node_map->node == NULL) {
			goto fail;
		}
		node = &node_map->node[node_map->num_nodes];

		node->addr = nodemap->node[i].addr;
		node->pnn = nodemap->node[i].pnn;
		node->flags = 0;
		node->capabilities = CTDB_CAP_DEFAULT;
		node->recovery_disabled = false;
		node->recovery_substate = NULL;

		node_map->num_nodes += 1;
	}

	talloc_free(nodemap);

	reply.status = 0;
	reply.errmsg = NULL;
	client_send_control(req, header, &reply);
	return;

fail:
	reply.status = -1;
	reply.errmsg = "Memory error";
	client_send_control(req, header, &reply);
}

static void control_get_capabilities(TALLOC_CTX *mem_ctx,
				     struct tevent_req *req,
				     struct ctdb_req_header *header,
				     struct ctdb_req_control *request)
{
	struct client_state *state = tevent_req_data(
		req, struct client_state);
	struct ctdbd_context *ctdb = state->ctdb;
	struct ctdb_reply_control reply;
	struct node *node;
	uint32_t caps = 0;

	reply.rdata.opcode = request->opcode;

	node = &ctdb->node_map->node[header->destnode];
	caps = node->capabilities;

	if (node->flags & NODE_FLAGS_FAKE_TIMEOUT) {
		/* Don't send reply */
		return;
	}

	reply.rdata.data.caps = caps;
	reply.status = 0;
	reply.errmsg = NULL;

	client_send_control(req, header, &reply);
}

static void control_release_ip(TALLOC_CTX *mem_ctx,
			       struct tevent_req *req,
			       struct ctdb_req_header *header,
			       struct ctdb_req_control *request)
{
	struct client_state *state = tevent_req_data(
		req, struct client_state);
	struct ctdbd_context *ctdb = state->ctdb;
	struct ctdb_public_ip *ip = request->rdata.data.pubip;
	struct ctdb_reply_control reply;
	struct ctdb_public_ip_list *ips = NULL;
	struct ctdb_public_ip *t = NULL;
	unsigned int i;

	reply.rdata.opcode = request->opcode;

	if (ctdb->known_ips == NULL) {
		D_INFO("RELEASE_IP %s - not a public IP\n",
		       ctdb_sock_addr_to_string(mem_ctx, &ip->addr, false));
		goto done;
	}

	ips = &ctdb->known_ips[header->destnode];

	t = NULL;
	for (i = 0; i < ips->num; i++) {
		if (ctdb_sock_addr_same_ip(&ips->ip[i].addr, &ip->addr)) {
			t = &ips->ip[i];
			break;
		}
	}
	if (t == NULL) {
		D_INFO("RELEASE_IP %s - not a public IP\n",
		       ctdb_sock_addr_to_string(mem_ctx, &ip->addr, false));
		goto done;
	}

	if (t->pnn != header->destnode) {
		if (header->destnode == ip->pnn) {
			D_ERR("error: RELEASE_IP %s - to TAKE_IP node %d\n",
			      ctdb_sock_addr_to_string(mem_ctx,
						       &ip->addr, false),
			      ip->pnn);
			reply.status = -1;
			reply.errmsg = "RELEASE_IP to TAKE_IP node";
			client_send_control(req, header, &reply);
			return;
		}

		D_INFO("RELEASE_IP %s - to node %d - redundant\n",
		       ctdb_sock_addr_to_string(mem_ctx, &ip->addr, false),
		       ip->pnn);
		t->pnn = ip->pnn;
	} else {
		D_NOTICE("RELEASE_IP %s - to node %d\n",
			 ctdb_sock_addr_to_string(mem_ctx, &ip->addr, false),
			  ip->pnn);
		t->pnn = ip->pnn;
	}

done:
	reply.status = 0;
	reply.errmsg = NULL;
	client_send_control(req, header, &reply);
}

static void control_takeover_ip(TALLOC_CTX *mem_ctx,
				struct tevent_req *req,
				struct ctdb_req_header *header,
				struct ctdb_req_control *request)
{
	struct client_state *state = tevent_req_data(
		req, struct client_state);
	struct ctdbd_context *ctdb = state->ctdb;
	struct ctdb_public_ip *ip = request->rdata.data.pubip;
	struct ctdb_reply_control reply;
	struct ctdb_public_ip_list *ips = NULL;
	struct ctdb_public_ip *t = NULL;
	unsigned int i;

	reply.rdata.opcode = request->opcode;

	if (ctdb->known_ips == NULL) {
		D_INFO("TAKEOVER_IP %s - not a public IP\n",
		       ctdb_sock_addr_to_string(mem_ctx, &ip->addr, false));
		goto done;
	}

	ips = &ctdb->known_ips[header->destnode];

	t = NULL;
	for (i = 0; i < ips->num; i++) {
		if (ctdb_sock_addr_same_ip(&ips->ip[i].addr, &ip->addr)) {
			t = &ips->ip[i];
			break;
		}
	}
	if (t == NULL) {
		D_INFO("TAKEOVER_IP %s - not a public IP\n",
		       ctdb_sock_addr_to_string(mem_ctx, &ip->addr, false));
		goto done;
	}

	if (t->pnn == header->destnode) {
		D_INFO("TAKEOVER_IP %s - redundant\n",
		       ctdb_sock_addr_to_string(mem_ctx, &ip->addr, false));
	} else {
		D_NOTICE("TAKEOVER_IP %s\n",
			 ctdb_sock_addr_to_string(mem_ctx, &ip->addr, false));
		t->pnn = ip->pnn;
	}

done:
	reply.status = 0;
	reply.errmsg = NULL;
	client_send_control(req, header, &reply);
}

static void control_get_public_ips(TALLOC_CTX *mem_ctx,
				   struct tevent_req *req,
				   struct ctdb_req_header *header,
				   struct ctdb_req_control *request)
{
	struct client_state *state = tevent_req_data(
		req, struct client_state);
	struct ctdbd_context *ctdb = state->ctdb;
	struct ctdb_reply_control reply;
	struct ctdb_public_ip_list *ips = NULL;

	reply.rdata.opcode = request->opcode;

	if (ctdb->known_ips == NULL) {
		/* No IPs defined so create a dummy empty struct and ship it */
		ips = talloc_zero(mem_ctx, struct ctdb_public_ip_list);;
		if (ips == NULL) {
			reply.status = ENOMEM;
			reply.errmsg = "Memory error";
			goto done;
		}
		goto ok;
	}

	ips = &ctdb->known_ips[header->destnode];

	if (request->flags & CTDB_PUBLIC_IP_FLAGS_ONLY_AVAILABLE) {
		/* If runstate is not RUNNING or a node is then return
		 * no available IPs.  Don't worry about interface
		 * states here - we're not faking down to that level.
		 */
		uint32_t flags = ctdb->node_map->node[header->destnode].flags;
		if (ctdb->runstate != CTDB_RUNSTATE_RUNNING ||
		    ((flags & (NODE_FLAGS_INACTIVE|NODE_FLAGS_DISABLED)) != 0)) {
			/* No available IPs: return dummy empty struct */
			ips = talloc_zero(mem_ctx, struct ctdb_public_ip_list);;
			if (ips == NULL) {
				reply.status = ENOMEM;
				reply.errmsg = "Memory error";
				goto done;
			}
		}
	}

ok:
	reply.rdata.data.pubip_list = ips;
	reply.status = 0;
	reply.errmsg = NULL;

done:
	client_send_control(req, header, &reply);
}

static void control_get_nodemap(TALLOC_CTX *mem_ctx,
				struct tevent_req *req,
				struct ctdb_req_header *header,
				struct ctdb_req_control *request)
{
	struct client_state *state = tevent_req_data(
		req, struct client_state);
	struct ctdbd_context *ctdb = state->ctdb;
	struct ctdb_reply_control reply;
	struct ctdb_node_map *nodemap;
	struct node *node;
	unsigned int i;

	reply.rdata.opcode = request->opcode;

	nodemap = talloc_zero(mem_ctx, struct ctdb_node_map);
	if (nodemap == NULL) {
		goto fail;
	}

	nodemap->num = ctdb->node_map->num_nodes;
	nodemap->node = talloc_array(nodemap, struct ctdb_node_and_flags,
				     nodemap->num);
	if (nodemap->node == NULL) {
		goto fail;
	}

	for (i=0; i<nodemap->num; i++) {
		node = &ctdb->node_map->node[i];
		nodemap->node[i] = (struct ctdb_node_and_flags) {
			.pnn = node->pnn,
			.flags = node->flags,
			.addr = node->addr,
		};
	}

	reply.rdata.data.nodemap = nodemap;
	reply.status = 0;
	reply.errmsg = NULL;
	client_send_control(req, header, &reply);
	return;

fail:
	reply.status = -1;
	reply.errmsg = "Memory error";
	client_send_control(req, header, &reply);
}

static void control_get_reclock_file(TALLOC_CTX *mem_ctx,
				     struct tevent_req *req,
				     struct ctdb_req_header *header,
				     struct ctdb_req_control *request)
{
	struct client_state *state = tevent_req_data(
		req, struct client_state);
	struct ctdbd_context *ctdb = state->ctdb;
	struct ctdb_reply_control reply;

	reply.rdata.opcode = request->opcode;

	if (ctdb->reclock != NULL) {
		reply.rdata.data.reclock_file =
			talloc_strdup(mem_ctx, ctdb->reclock);
		if (reply.rdata.data.reclock_file == NULL) {
			reply.status = ENOMEM;
			reply.errmsg = "Memory error";
			goto done;
		}
	} else {
		reply.rdata.data.reclock_file = NULL;
	}

	reply.status = 0;
	reply.errmsg = NULL;

done:
	client_send_control(req, header, &reply);
}

static void control_stop_node(TALLOC_CTX *mem_ctx,
			      struct tevent_req *req,
			      struct ctdb_req_header *header,
			      struct ctdb_req_control *request)
{
	struct client_state *state = tevent_req_data(
		req, struct client_state);
	struct ctdbd_context *ctdb = state->ctdb;
	struct ctdb_reply_control reply;

	reply.rdata.opcode = request->opcode;

	DEBUG(DEBUG_INFO, ("Stopping node\n"));
	ctdb->node_map->node[header->destnode].flags |= NODE_FLAGS_STOPPED;

	reply.status = 0;
	reply.errmsg = NULL;

	client_send_control(req, header, &reply);
	return;
}

static void control_continue_node(TALLOC_CTX *mem_ctx,
				  struct tevent_req *req,
				  struct ctdb_req_header *header,
				  struct ctdb_req_control *request)
{
	struct client_state *state = tevent_req_data(
		req, struct client_state);
	struct ctdbd_context *ctdb = state->ctdb;
	struct ctdb_reply_control reply;

	reply.rdata.opcode = request->opcode;

	DEBUG(DEBUG_INFO, ("Continue node\n"));
	ctdb->node_map->node[header->destnode].flags &= ~NODE_FLAGS_STOPPED;

	reply.status = 0;
	reply.errmsg = NULL;

	client_send_control(req, header, &reply);
	return;
}

static void set_ban_state_callback(struct tevent_req *subreq)
{
	struct node *node = tevent_req_callback_data(
		subreq, struct node);
	bool status;

	status = tevent_wakeup_recv(subreq);
	TALLOC_FREE(subreq);
	if (! status) {
		DEBUG(DEBUG_INFO, ("tevent_wakeup_recv failed\n"));
	}

	node->flags &= ~NODE_FLAGS_BANNED;
}

static void control_set_ban_state(TALLOC_CTX *mem_ctx,
				  struct tevent_req *req,
				  struct ctdb_req_header *header,
				  struct ctdb_req_control *request)
{
	struct client_state *state = tevent_req_data(
		req, struct client_state);
	struct tevent_req *subreq;
	struct ctdbd_context *ctdb = state->ctdb;
	struct ctdb_ban_state *ban = request->rdata.data.ban_state;
	struct ctdb_reply_control reply;
	struct node *node;

	reply.rdata.opcode = request->opcode;

	if (ban->pnn != header->destnode) {
		DEBUG(DEBUG_INFO,
		      ("SET_BAN_STATE control for PNN %d rejected\n",
		       ban->pnn));
		reply.status = EINVAL;
		goto fail;
	}

	node = &ctdb->node_map->node[header->destnode];

	if (ban->time == 0) {
		DEBUG(DEBUG_INFO,("Unbanning this node\n"));
		node->flags &= ~NODE_FLAGS_BANNED;
		goto done;
	}

	subreq = tevent_wakeup_send(ctdb->node_map, state->ev,
				    tevent_timeval_current_ofs(
					    ban->time, 0));
	if (subreq == NULL) {
		reply.status = ENOMEM;
		goto fail;
	}
	tevent_req_set_callback(subreq, set_ban_state_callback, node);

	DEBUG(DEBUG_INFO, ("Banning this node for %d seconds\n", ban->time));
	node->flags |= NODE_FLAGS_BANNED;
	ctdb->vnn_map->generation = INVALID_GENERATION;

done:
	reply.status = 0;
	reply.errmsg = NULL;

	client_send_control(req, header, &reply);
	return;

fail:
	reply.errmsg = "Failed to ban node";
}

static void control_trans3_commit(TALLOC_CTX *mem_ctx,
				  struct tevent_req *req,
				  struct ctdb_req_header *header,
				  struct ctdb_req_control *request)
{
	struct client_state *state = tevent_req_data(
		req, struct client_state);
	struct ctdbd_context *ctdb = state->ctdb;
	struct ctdb_reply_control reply;
	struct database *db;
	int ret;

	reply.rdata.opcode = request->opcode;

	db = database_find(ctdb->db_map, request->rdata.data.recbuf->db_id);
	if (db == NULL) {
		reply.status = -1;
		reply.errmsg = "Unknown database";
		client_send_control(req, header, &reply);
		return;
	}

	if (! (db->flags &
	       (CTDB_DB_FLAGS_PERSISTENT|CTDB_DB_FLAGS_REPLICATED))) {
		reply.status = -1;
		reply.errmsg = "Transactions on volatile database";
		client_send_control(req, header, &reply);
		return;
	}

	ret = ltdb_transaction(db, request->rdata.data.recbuf);
	if (ret != 0) {
		reply.status = -1;
		reply.errmsg = "Transaction failed";
		client_send_control(req, header, &reply);
		return;
	}

	reply.status = 0;
	reply.errmsg = NULL;
	client_send_control(req, header, &reply);
}

static void control_get_db_seqnum(TALLOC_CTX *mem_ctx,
			       struct tevent_req *req,
			       struct ctdb_req_header *header,
			       struct ctdb_req_control *request)
{
	struct client_state *state = tevent_req_data(
		req, struct client_state);
	struct ctdbd_context *ctdb = state->ctdb;
	struct ctdb_reply_control reply;
	struct database *db;
	int ret;

	reply.rdata.opcode = request->opcode;

	db = database_find(ctdb->db_map, request->rdata.data.db_id);
	if (db == NULL) {
		reply.status = ENOENT;
		reply.errmsg = "Database not found";
	} else {
		uint64_t seqnum;

		ret = database_seqnum(db, &seqnum);
		if (ret == 0) {
			reply.rdata.data.seqnum = seqnum;
			reply.status = 0;
			reply.errmsg = NULL;
		} else {
			reply.status = ret;
			reply.errmsg = "Failed to get seqnum";
		}
	}

	client_send_control(req, header, &reply);
}

static void control_db_get_health(TALLOC_CTX *mem_ctx,
				  struct tevent_req *req,
				  struct ctdb_req_header *header,
				  struct ctdb_req_control *request)
{
	struct client_state *state = tevent_req_data(
		req, struct client_state);
	struct ctdbd_context *ctdb = state->ctdb;
	struct ctdb_reply_control reply;
	struct database *db;

	reply.rdata.opcode = request->opcode;

	db = database_find(ctdb->db_map, request->rdata.data.db_id);
	if (db == NULL) {
		reply.status = ENOENT;
		reply.errmsg = "Database not found";
	} else {
		reply.rdata.data.reason = NULL;
		reply.status = 0;
		reply.errmsg = NULL;
	}

	client_send_control(req, header, &reply);
}

static struct ctdb_iface_list *get_ctdb_iface_list(TALLOC_CTX *mem_ctx,
						   struct ctdbd_context *ctdb)
{
	struct ctdb_iface_list *iface_list;
	struct interface *iface;
	unsigned int i;

	iface_list = talloc_zero(mem_ctx, struct ctdb_iface_list);
	if (iface_list == NULL) {
		goto done;
	}

	iface_list->num = ctdb->iface_map->num;
	iface_list->iface = talloc_array(iface_list, struct ctdb_iface,
					 iface_list->num);
	if (iface_list->iface == NULL) {
		TALLOC_FREE(iface_list);
		goto done;
	}

	for (i=0; i<iface_list->num; i++) {
		iface = &ctdb->iface_map->iface[i];
		iface_list->iface[i] = (struct ctdb_iface) {
			.link_state = iface->link_up,
			.references = iface->references,
		};
		strlcpy(iface_list->iface[i].name, iface->name,
			sizeof(iface_list->iface[i].name));
	}

done:
	return iface_list;
}

static void control_get_public_ip_info(TALLOC_CTX *mem_ctx,
				       struct tevent_req *req,
				       struct ctdb_req_header *header,
				       struct ctdb_req_control *request)
{
	struct client_state *state = tevent_req_data(
		req, struct client_state);
	struct ctdbd_context *ctdb = state->ctdb;
	struct ctdb_reply_control reply;
	ctdb_sock_addr *addr = request->rdata.data.addr;
	struct ctdb_public_ip_list *known = NULL;
	struct ctdb_public_ip_info *info = NULL;
	unsigned i;

	reply.rdata.opcode = request->opcode;

	info = talloc_zero(mem_ctx, struct ctdb_public_ip_info);
	if (info == NULL) {
		reply.status = ENOMEM;
		reply.errmsg = "Memory error";
		goto done;
	}

	reply.rdata.data.ipinfo = info;

	if (ctdb->known_ips != NULL) {
		known = &ctdb->known_ips[header->destnode];
	} else {
		/* No IPs defined so create a dummy empty struct and
		 * fall through.  The given IP won't be matched
		 * below...
		 */
		known = talloc_zero(mem_ctx, struct ctdb_public_ip_list);;
		if (known == NULL) {
			reply.status = ENOMEM;
			reply.errmsg = "Memory error";
			goto done;
		}
	}

	for (i = 0; i < known->num; i++) {
		if (ctdb_sock_addr_same_ip(&known->ip[i].addr,
					   addr)) {
			break;
		}
	}

	if (i == known->num) {
		D_ERR("GET_PUBLIC_IP_INFO: not known public IP %s\n",
		      ctdb_sock_addr_to_string(mem_ctx, addr, false));
		reply.status = -1;
		reply.errmsg = "Unknown address";
		goto done;
	}

	info->ip = known->ip[i];

	/* The fake PUBLICIPS stanza and resulting known_ips data
	 * don't know anything about interfaces, so completely fake
	 * this.
	 */
	info->active_idx = 0;

	info->ifaces = get_ctdb_iface_list(mem_ctx, ctdb);
	if (info->ifaces == NULL) {
		reply.status = ENOMEM;
		reply.errmsg = "Memory error";
		goto done;
	}

	reply.status = 0;
	reply.errmsg = NULL;

done:
	client_send_control(req, header, &reply);
}

static void control_get_ifaces(TALLOC_CTX *mem_ctx,
			       struct tevent_req *req,
			       struct ctdb_req_header *header,
			       struct ctdb_req_control *request)
{
	struct client_state *state = tevent_req_data(
		req, struct client_state);
	struct ctdbd_context *ctdb = state->ctdb;
	struct ctdb_reply_control reply;
	struct ctdb_iface_list *iface_list;

	reply.rdata.opcode = request->opcode;

	iface_list = get_ctdb_iface_list(mem_ctx, ctdb);
	if (iface_list == NULL) {
		goto fail;
	}

	reply.rdata.data.iface_list = iface_list;
	reply.status = 0;
	reply.errmsg = NULL;
	client_send_control(req, header, &reply);
	return;

fail:
	reply.status = -1;
	reply.errmsg = "Memory error";
	client_send_control(req, header, &reply);
}

static void control_set_iface_link_state(TALLOC_CTX *mem_ctx,
					 struct tevent_req *req,
					 struct ctdb_req_header *header,
					 struct ctdb_req_control *request)
{
	struct client_state *state = tevent_req_data(
		req, struct client_state);
	struct ctdbd_context *ctdb = state->ctdb;
	struct ctdb_reply_control reply;
	struct ctdb_iface *in_iface;
	struct interface *iface = NULL;
	bool link_up = false;
	int i;

	reply.rdata.opcode = request->opcode;

	in_iface = request->rdata.data.iface;

	if (in_iface->name[CTDB_IFACE_SIZE] != '\0') {
		reply.errmsg = "interface name not terminated";
		goto fail;
	}

	switch (in_iface->link_state) {
		case 0:
			link_up = false;
			break;

		case 1:
			link_up = true;
			break;

		default:
			reply.errmsg = "invalid link state";
			goto fail;
	}

	if (in_iface->references != 0) {
		reply.errmsg = "references should be 0";
		goto fail;
	}

	for (i=0; i<ctdb->iface_map->num; i++) {
		if (strcmp(ctdb->iface_map->iface[i].name,
			   in_iface->name) == 0) {
			iface = &ctdb->iface_map->iface[i];
			break;
		}
	}

	if (iface == NULL) {
		reply.errmsg = "interface not found";
		goto fail;
	}

	iface->link_up = link_up;

	reply.status = 0;
	reply.errmsg = NULL;
	client_send_control(req, header, &reply);
	return;

fail:
	reply.status = -1;
	client_send_control(req, header, &reply);
}

static void control_set_db_readonly(TALLOC_CTX *mem_ctx,
				    struct tevent_req *req,
				    struct ctdb_req_header *header,
				    struct ctdb_req_control *request)
{
	struct client_state *state = tevent_req_data(
		req, struct client_state);
	struct ctdbd_context *ctdb = state->ctdb;
	struct ctdb_reply_control reply;
	struct database *db;

	reply.rdata.opcode = request->opcode;

	db = database_find(ctdb->db_map, request->rdata.data.db_id);
	if (db == NULL) {
		reply.status = ENOENT;
		reply.errmsg = "Database not found";
		goto done;
	}

	if (db->flags & CTDB_DB_FLAGS_PERSISTENT) {
		reply.status = EINVAL;
		reply.errmsg = "Can not set READONLY on persistent db";
		goto done;
	}

	db->flags |= CTDB_DB_FLAGS_READONLY;
	reply.status = 0;
	reply.errmsg = NULL;

done:
	client_send_control(req, header, &reply);
}

struct traverse_start_ext_state {
	struct tevent_req *req;
	struct ctdb_req_header *header;
	uint32_t reqid;
	uint64_t srvid;
	bool withemptyrecords;
	int status;
};

static int traverse_start_ext_handler(struct tdb_context *tdb,
				      TDB_DATA key, TDB_DATA data,
				      void *private_data)
{
	struct traverse_start_ext_state *state =
		(struct traverse_start_ext_state *)private_data;
	struct ctdb_rec_data rec;
	struct ctdb_req_message_data message;
	size_t np;

	if (data.dsize < sizeof(struct ctdb_ltdb_header)) {
		return 0;
	}

	if ((data.dsize == sizeof(struct ctdb_ltdb_header)) &&
	    (!state->withemptyrecords)) {
		return 0;
	}

	rec = (struct ctdb_rec_data) {
		.reqid = state->reqid,
		.header = NULL,
		.key = key,
		.data = data,
	};

	message.srvid = state->srvid;
	message.data.dsize = ctdb_rec_data_len(&rec);
	message.data.dptr = talloc_size(state->req, message.data.dsize);
	if (message.data.dptr == NULL) {
		state->status = ENOMEM;
		return 1;
	}

	ctdb_rec_data_push(&rec, message.data.dptr, &np);
	client_send_message(state->req, state->header, &message);

	talloc_free(message.data.dptr);

	return 0;
}

static void control_traverse_start_ext(TALLOC_CTX *mem_ctx,
				       struct tevent_req *req,
				       struct ctdb_req_header *header,
				       struct ctdb_req_control *request)
{
	struct client_state *state = tevent_req_data(
		req, struct client_state);
	struct ctdbd_context *ctdb = state->ctdb;
	struct ctdb_reply_control reply;
	struct database *db;
	struct ctdb_traverse_start_ext *ext;
	struct traverse_start_ext_state t_state;
	struct ctdb_rec_data rec;
	struct ctdb_req_message_data message;
	uint8_t buffer[32];
	size_t np;
	int ret;

	reply.rdata.opcode = request->opcode;

	ext = request->rdata.data.traverse_start_ext;

	db = database_find(ctdb->db_map, ext->db_id);
	if (db == NULL) {
		reply.status = -1;
		reply.errmsg = "Unknown database";
		client_send_control(req, header, &reply);
		return;
	}

	t_state = (struct traverse_start_ext_state) {
		.req = req,
		.header = header,
		.reqid = ext->reqid,
		.srvid = ext->srvid,
		.withemptyrecords = ext->withemptyrecords,
	};

	ret = tdb_traverse_read(db->tdb, traverse_start_ext_handler, &t_state);
	DEBUG(DEBUG_INFO, ("traversed %d records\n", ret));
	if (t_state.status != 0) {
		reply.status = -1;
		reply.errmsg = "Memory error";
		client_send_control(req, header, &reply);
	}

	reply.status = 0;
	client_send_control(req, header, &reply);

	rec = (struct ctdb_rec_data) {
		.reqid = ext->reqid,
		.header = NULL,
		.key = tdb_null,
		.data = tdb_null,
	};

	message.srvid = ext->srvid;
	message.data.dsize = ctdb_rec_data_len(&rec);
	ctdb_rec_data_push(&rec, buffer, &np);
	message.data.dptr = buffer;
	client_send_message(req, header, &message);
}

static void control_set_db_sticky(TALLOC_CTX *mem_ctx,
				    struct tevent_req *req,
				    struct ctdb_req_header *header,
				    struct ctdb_req_control *request)
{
	struct client_state *state = tevent_req_data(
		req, struct client_state);
	struct ctdbd_context *ctdb = state->ctdb;
	struct ctdb_reply_control reply;
	struct database *db;

	reply.rdata.opcode = request->opcode;

	db = database_find(ctdb->db_map, request->rdata.data.db_id);
	if (db == NULL) {
		reply.status = ENOENT;
		reply.errmsg = "Database not found";
		goto done;
	}

	if (db->flags & CTDB_DB_FLAGS_PERSISTENT) {
		reply.status = EINVAL;
		reply.errmsg = "Can not set STICKY on persistent db";
		goto done;
	}

	db->flags |= CTDB_DB_FLAGS_STICKY;
	reply.status = 0;
	reply.errmsg = NULL;

done:
	client_send_control(req, header, &reply);
}

static void control_ipreallocated(TALLOC_CTX *mem_ctx,
				  struct tevent_req *req,
				  struct ctdb_req_header *header,
				  struct ctdb_req_control *request)
{
	struct ctdb_reply_control reply;

	/* Always succeed */
	reply.rdata.opcode = request->opcode;
	reply.status = 0;
	reply.errmsg = NULL;

	client_send_control(req, header, &reply);
}

static void control_get_runstate(TALLOC_CTX *mem_ctx,
				 struct tevent_req *req,
				 struct ctdb_req_header *header,
				 struct ctdb_req_control *request)
{
	struct client_state *state = tevent_req_data(
		req, struct client_state);
	struct ctdbd_context *ctdb = state->ctdb;
	struct ctdb_reply_control reply;

	reply.rdata.opcode = request->opcode;
	reply.rdata.data.runstate = ctdb->runstate;
	reply.status = 0;
	reply.errmsg = NULL;

	client_send_control(req, header, &reply);
}

static void control_get_nodes_file(TALLOC_CTX *mem_ctx,
				   struct tevent_req *req,
				   struct ctdb_req_header *header,
				   struct ctdb_req_control *request)
{
	struct ctdb_reply_control reply;
	struct ctdb_node_map *nodemap;

	reply.rdata.opcode = request->opcode;

	nodemap = read_nodes_file(mem_ctx, header->destnode);
	if (nodemap == NULL) {
		goto fail;
	}

	reply.rdata.data.nodemap = nodemap;
	reply.status = 0;
	reply.errmsg = NULL;
	client_send_control(req, header, &reply);
	return;

fail:
	reply.status = -1;
	reply.errmsg = "Failed to read nodes file";
	client_send_control(req, header, &reply);
}

static void control_db_open_flags(TALLOC_CTX *mem_ctx,
				  struct tevent_req *req,
				  struct ctdb_req_header *header,
				  struct ctdb_req_control *request)
{
	struct client_state *state = tevent_req_data(
		req, struct client_state);
	struct ctdbd_context *ctdb = state->ctdb;
	struct ctdb_reply_control reply;
	struct database *db;

	reply.rdata.opcode = request->opcode;

	db = database_find(ctdb->db_map, request->rdata.data.db_id);
	if (db == NULL) {
		reply.status = ENOENT;
		reply.errmsg = "Database not found";
	} else {
		reply.rdata.data.tdb_flags = database_flags(db->flags);
		reply.status = 0;
		reply.errmsg = NULL;
	}

	client_send_control(req, header, &reply);
}

static void control_db_attach_replicated(TALLOC_CTX *mem_ctx,
					 struct tevent_req *req,
					 struct ctdb_req_header *header,
					 struct ctdb_req_control *request)
{
	struct client_state *state = tevent_req_data(
		req, struct client_state);
	struct ctdbd_context *ctdb = state->ctdb;
	struct ctdb_reply_control reply;
	struct database *db;

	reply.rdata.opcode = request->opcode;

	for (db = ctdb->db_map->db; db != NULL; db = db->next) {
		if (strcmp(db->name, request->rdata.data.db_name) == 0) {
			goto done;
		}
	}

	db = database_new(ctdb->db_map, request->rdata.data.db_name,
			  CTDB_DB_FLAGS_REPLICATED);
	if (db == NULL) {
		reply.status = -1;
		reply.errmsg = "Failed to attach database";
		client_send_control(req, header, &reply);
		return;
	}

done:
	reply.rdata.data.db_id = db->id;
	reply.status = 0;
	reply.errmsg = NULL;
	client_send_control(req, header, &reply);
}

static void control_check_pid_srvid(TALLOC_CTX *mem_ctx,
				    struct tevent_req *req,
				    struct ctdb_req_header *header,
				    struct ctdb_req_control *request)
{
	struct client_state *state = tevent_req_data(
		req, struct client_state);
	struct ctdbd_context *ctdb = state->ctdb;
	struct ctdb_client *client;
	struct client_state *cstate;
	struct ctdb_reply_control reply;
	bool pid_found, srvid_found;
	int ret;

	reply.rdata.opcode = request->opcode;

	pid_found = false;
	srvid_found = false;

	for (client=ctdb->client_list; client != NULL; client=client->next) {
		if (client->pid == request->rdata.data.pid_srvid->pid) {
			pid_found = true;
			cstate = (struct client_state *)client->state;
			ret = srvid_exists(ctdb->srv,
					   request->rdata.data.pid_srvid->srvid,
					   cstate);
			if (ret == 0) {
				srvid_found = true;
				ret = kill(cstate->pid, 0);
				if (ret != 0) {
					reply.status = ret;
					reply.errmsg = strerror(errno);
				} else {
					reply.status = 0;
					reply.errmsg = NULL;
				}
			}
		}
	}

	if (! pid_found) {
		reply.status = -1;
		reply.errmsg = "No client for PID";
	} else if (! srvid_found) {
		reply.status = -1;
		reply.errmsg = "No client for PID and SRVID";
	}

	client_send_control(req, header, &reply);
}

static void control_disable_node(TALLOC_CTX *mem_ctx,
				 struct tevent_req *req,
				 struct ctdb_req_header *header,
				 struct ctdb_req_control *request)
{
	struct client_state *state = tevent_req_data(
		req, struct client_state);
	struct ctdbd_context *ctdb = state->ctdb;
	struct ctdb_reply_control reply;

	reply.rdata.opcode = request->opcode;

	DEBUG(DEBUG_INFO, ("Disabling node\n"));
	ctdb->node_map->node[header->destnode].flags |=
		NODE_FLAGS_PERMANENTLY_DISABLED;

	reply.status = 0;
	reply.errmsg = NULL;

	client_send_control(req, header, &reply);
	return;
}

static void control_enable_node(TALLOC_CTX *mem_ctx,
				  struct tevent_req *req,
				  struct ctdb_req_header *header,
				  struct ctdb_req_control *request)
{
	struct client_state *state = tevent_req_data(
		req, struct client_state);
	struct ctdbd_context *ctdb = state->ctdb;
	struct ctdb_reply_control reply;

	reply.rdata.opcode = request->opcode;

	DEBUG(DEBUG_INFO, ("Enable node\n"));
	ctdb->node_map->node[header->destnode].flags &=
		~NODE_FLAGS_PERMANENTLY_DISABLED;

	reply.status = 0;
	reply.errmsg = NULL;

	client_send_control(req, header, &reply);
	return;
}

static bool fake_control_failure(TALLOC_CTX *mem_ctx,
				 struct tevent_req *req,
				 struct ctdb_req_header *header,
				 struct ctdb_req_control *request)
{
	struct client_state *state = tevent_req_data(
		req, struct client_state);
	struct ctdbd_context *ctdb = state->ctdb;
	struct ctdb_reply_control reply;
	struct fake_control_failure *f = NULL;

	D_DEBUG("Checking fake control failure for control %u on node %u\n",
		request->opcode, header->destnode);
	for (f = ctdb->control_failures; f != NULL; f = f->next) {
		if (f->opcode == request->opcode &&
		    (f->pnn == header->destnode ||
		     f->pnn == CTDB_UNKNOWN_PNN)) {

			reply.rdata.opcode = request->opcode;
			if (strcmp(f->error, "TIMEOUT") == 0) {
				/* Causes no reply */
				D_ERR("Control %u fake timeout on node %u\n",
				      request->opcode, header->destnode);
				return true;
			} else if (strcmp(f->error, "ERROR") == 0) {
				D_ERR("Control %u fake error on node %u\n",
				      request->opcode, header->destnode);
				reply.status = -1;
				reply.errmsg = f->comment;
				client_send_control(req, header, &reply);
				return true;
			}
		}
	}

	return false;
}

static void control_error(TALLOC_CTX *mem_ctx,
			  struct tevent_req *req,
			  struct ctdb_req_header *header,
			  struct ctdb_req_control *request)
{
	struct ctdb_reply_control reply;

	D_DEBUG("Control %u not implemented\n", request->opcode);

	reply.rdata.opcode = request->opcode;
	reply.status = -1;
	reply.errmsg = "Not implemented";

	client_send_control(req, header, &reply);
}

/*
 * Handling protocol - messages
 */

struct disable_recoveries_state {
	struct node *node;
};

static void disable_recoveries_callback(struct tevent_req *subreq)
{
	struct disable_recoveries_state *substate = tevent_req_callback_data(
		subreq, struct disable_recoveries_state);
	bool status;

	status = tevent_wakeup_recv(subreq);
	TALLOC_FREE(subreq);
	if (! status) {
		DEBUG(DEBUG_INFO, ("tevent_wakeup_recv failed\n"));
	}

	substate->node->recovery_disabled = false;
	TALLOC_FREE(substate->node->recovery_substate);
}

static void message_disable_recoveries(TALLOC_CTX *mem_ctx,
				       struct tevent_req *req,
				       struct ctdb_req_header *header,
				       struct ctdb_req_message *request)
{
	struct client_state *state = tevent_req_data(
		req, struct client_state);
	struct tevent_req *subreq;
	struct ctdbd_context *ctdb = state->ctdb;
	struct disable_recoveries_state *substate;
	struct ctdb_disable_message *disable = request->data.disable;
	struct ctdb_req_message_data reply;
	struct node *node;
	int ret = -1;
	TDB_DATA data;

	node = &ctdb->node_map->node[header->destnode];

	if (disable->timeout == 0) {
		TALLOC_FREE(node->recovery_substate);
		node->recovery_disabled = false;
		DEBUG(DEBUG_INFO, ("Enabled recoveries on node %u\n",
				   header->destnode));
		goto done;
	}

	substate = talloc_zero(ctdb->node_map,
			       struct disable_recoveries_state);
	if (substate == NULL) {
		goto fail;
	}

	substate->node = node;

	subreq = tevent_wakeup_send(substate, state->ev,
				    tevent_timeval_current_ofs(
					    disable->timeout, 0));
	if (subreq == NULL) {
		talloc_free(substate);
		goto fail;
	}
	tevent_req_set_callback(subreq, disable_recoveries_callback, substate);

	DEBUG(DEBUG_INFO, ("Disabled recoveries for %d seconds on node %u\n",
			   disable->timeout, header->destnode));
	node->recovery_substate = substate;
	node->recovery_disabled = true;

done:
	ret = header->destnode;

fail:
	reply.srvid = disable->srvid;
	data.dptr = (uint8_t *)&ret;
	data.dsize = sizeof(int);
	reply.data = data;

	client_send_message(req, header, &reply);
}

static void message_takeover_run(TALLOC_CTX *mem_ctx,
				 struct tevent_req *req,
				 struct ctdb_req_header *header,
				 struct ctdb_req_message *request)
{
	struct client_state *state = tevent_req_data(
		req, struct client_state);
	struct ctdbd_context *ctdb = state->ctdb;
	struct ctdb_srvid_message *srvid = request->data.msg;
	struct ctdb_req_message_data reply;
	int ret = -1;
	TDB_DATA data;

	if (header->destnode != ctdb->node_map->recmaster) {
		/* No reply! Only recmaster replies... */
		return;
	}

	DEBUG(DEBUG_INFO, ("IP takover run on node %u\n",
			   header->destnode));
	ret = header->destnode;

	reply.srvid = srvid->srvid;
	data.dptr = (uint8_t *)&ret;
	data.dsize = sizeof(int);
	reply.data = data;

	client_send_message(req, header, &reply);
}

/*
 * Handle a single client
 */

static void client_read_handler(uint8_t *buf, size_t buflen,
				void *private_data);
static void client_dead_handler(void *private_data);
static void client_process_packet(struct tevent_req *req,
				  uint8_t *buf, size_t buflen);
static void client_process_call(struct tevent_req *req,
				uint8_t *buf, size_t buflen);
static void client_process_message(struct tevent_req *req,
				   uint8_t *buf, size_t buflen);
static void client_process_control(struct tevent_req *req,
				   uint8_t *buf, size_t buflen);
static void client_reply_done(struct tevent_req *subreq);

static struct tevent_req *client_send(TALLOC_CTX *mem_ctx,
				      struct tevent_context *ev,
				      int fd, struct ctdbd_context *ctdb,
				      int pnn)
{
	struct tevent_req *req;
	struct client_state *state;
	int ret;

	req = tevent_req_create(mem_ctx, &state, struct client_state);
	if (req == NULL) {
		return NULL;
	}

	state->ev = ev;
	state->fd = fd;
	state->ctdb = ctdb;
	state->pnn = pnn;

	(void) ctdb_get_peer_pid(fd, &state->pid);

	ret = comm_setup(state, ev, fd, client_read_handler, req,
			 client_dead_handler, req, &state->comm);
	if (ret != 0) {
		tevent_req_error(req, ret);
		return tevent_req_post(req, ev);
	}

	ret = client_add(ctdb, state->pid, state);
	if (ret != 0) {
		tevent_req_error(req, ret);
		return tevent_req_post(req, ev);
	}

	DEBUG(DEBUG_INFO, ("New client fd=%d\n", fd));

	return req;
}

static void client_read_handler(uint8_t *buf, size_t buflen,
				void *private_data)
{
	struct tevent_req *req = talloc_get_type_abort(
		private_data, struct tevent_req);
	struct client_state *state = tevent_req_data(
		req, struct client_state);
	struct ctdbd_context *ctdb = state->ctdb;
	struct ctdb_req_header header;
	size_t np;
	unsigned int i;
	int ret;

	ret = ctdb_req_header_pull(buf, buflen, &header, &np);
	if (ret != 0) {
		return;
	}

	if (buflen != header.length) {
		return;
	}

	ret = ctdb_req_header_verify(&header, 0);
	if (ret != 0) {
		return;
	}

	header_fix_pnn(&header, ctdb);

	if (header.destnode == CTDB_BROADCAST_ALL) {
		for (i=0; i<ctdb->node_map->num_nodes; i++) {
			header.destnode = i;

			ctdb_req_header_push(&header, buf, &np);
			client_process_packet(req, buf, buflen);
		}
		return;
	}

	if (header.destnode == CTDB_BROADCAST_CONNECTED) {
		for (i=0; i<ctdb->node_map->num_nodes; i++) {
			if (ctdb->node_map->node[i].flags &
			    NODE_FLAGS_DISCONNECTED) {
				continue;
			}

			header.destnode = i;

			ctdb_req_header_push(&header, buf, &np);
			client_process_packet(req, buf, buflen);
		}
		return;
	}

	if (header.destnode > ctdb->node_map->num_nodes) {
		fprintf(stderr, "Invalid destination pnn 0x%x\n",
			header.destnode);
		return;
	}


	if (ctdb->node_map->node[header.destnode].flags & NODE_FLAGS_DISCONNECTED) {
		fprintf(stderr, "Packet for disconnected node pnn %u\n",
			header.destnode);
		return;
	}

	ctdb_req_header_push(&header, buf, &np);
	client_process_packet(req, buf, buflen);
}

static void client_dead_handler(void *private_data)
{
	struct tevent_req *req = talloc_get_type_abort(
		private_data, struct tevent_req);

	tevent_req_done(req);
}

static void client_process_packet(struct tevent_req *req,
				  uint8_t *buf, size_t buflen)
{
	struct ctdb_req_header header;
	size_t np;
	int ret;

	ret = ctdb_req_header_pull(buf, buflen, &header, &np);
	if (ret != 0) {
		return;
	}

	switch (header.operation) {
	case CTDB_REQ_CALL:
		client_process_call(req, buf, buflen);
		break;

	case CTDB_REQ_MESSAGE:
		client_process_message(req, buf, buflen);
		break;

	case CTDB_REQ_CONTROL:
		client_process_control(req, buf, buflen);
		break;

	default:
		break;
	}
}

static void client_process_call(struct tevent_req *req,
				uint8_t *buf, size_t buflen)
{
	struct client_state *state = tevent_req_data(
		req, struct client_state);
	struct ctdbd_context *ctdb = state->ctdb;
	TALLOC_CTX *mem_ctx;
	struct ctdb_req_header header;
	struct ctdb_req_call request;
	struct ctdb_reply_call reply;
	struct database *db;
	struct ctdb_ltdb_header hdr;
	TDB_DATA data;
	int ret;

	mem_ctx = talloc_new(state);
	if (tevent_req_nomem(mem_ctx, req)) {
		return;
	}

	ret = ctdb_req_call_pull(buf, buflen, &header, mem_ctx, &request);
	if (ret != 0) {
		talloc_free(mem_ctx);
		tevent_req_error(req, ret);
		return;
	}

	header_fix_pnn(&header, ctdb);

	if (header.destnode >= ctdb->node_map->num_nodes) {
		goto fail;
	}

	DEBUG(DEBUG_INFO, ("call db_id = %u\n", request.db_id));

	db = database_find(ctdb->db_map, request.db_id);
	if (db == NULL) {
		goto fail;
	}

	ret = ltdb_fetch(db, request.key, &hdr, mem_ctx, &data);
	if (ret != 0) {
		goto fail;
	}

	/* Fake migration */
	if (hdr.dmaster != ctdb->node_map->pnn) {
		hdr.dmaster = ctdb->node_map->pnn;

		ret = ltdb_store(db, request.key, &hdr, data);
		if (ret != 0) {
			goto fail;
		}
	}

	talloc_free(mem_ctx);

	reply.status = 0;
	reply.data = tdb_null;

	client_send_call(req, &header, &reply);
	return;

fail:
	talloc_free(mem_ctx);
	reply.status = -1;
	reply.data = tdb_null;

	client_send_call(req, &header, &reply);
}

static void client_process_message(struct tevent_req *req,
				   uint8_t *buf, size_t buflen)
{
	struct client_state *state = tevent_req_data(
		req, struct client_state);
	struct ctdbd_context *ctdb = state->ctdb;
	TALLOC_CTX *mem_ctx;
	struct ctdb_req_header header;
	struct ctdb_req_message request;
	uint64_t srvid;
	int ret;

	mem_ctx = talloc_new(state);
	if (tevent_req_nomem(mem_ctx, req)) {
		return;
	}

	ret = ctdb_req_message_pull(buf, buflen, &header, mem_ctx, &request);
	if (ret != 0) {
		talloc_free(mem_ctx);
		tevent_req_error(req, ret);
		return;
	}

	header_fix_pnn(&header, ctdb);

	if (header.destnode >= ctdb->node_map->num_nodes) {
		/* Many messages are not replied to, so just behave as
		 * though this message was not received */
		fprintf(stderr, "Invalid node %d\n", header.destnode);
		talloc_free(mem_ctx);
		return;
	}

	srvid = request.srvid;
	DEBUG(DEBUG_INFO, ("request srvid = 0x%"PRIx64"\n", srvid));

	if (srvid == CTDB_SRVID_DISABLE_RECOVERIES) {
		message_disable_recoveries(mem_ctx, req, &header, &request);
	} else if (srvid == CTDB_SRVID_TAKEOVER_RUN) {
		message_takeover_run(mem_ctx, req, &header, &request);
	} else {
		D_DEBUG("Message id 0x%"PRIx64" not implemented\n", srvid);
	}

	/* check srvid */
	talloc_free(mem_ctx);
}

static void client_process_control(struct tevent_req *req,
				   uint8_t *buf, size_t buflen)
{
	struct client_state *state = tevent_req_data(
		req, struct client_state);
	struct ctdbd_context *ctdb = state->ctdb;
	TALLOC_CTX *mem_ctx;
	struct ctdb_req_header header;
	struct ctdb_req_control request;
	int ret;

	mem_ctx = talloc_new(state);
	if (tevent_req_nomem(mem_ctx, req)) {
		return;
	}

	ret = ctdb_req_control_pull(buf, buflen, &header, mem_ctx, &request);
	if (ret != 0) {
		talloc_free(mem_ctx);
		tevent_req_error(req, ret);
		return;
	}

	header_fix_pnn(&header, ctdb);

	if (header.destnode >= ctdb->node_map->num_nodes) {
		struct ctdb_reply_control reply;

		reply.rdata.opcode = request.opcode;
		reply.errmsg = "Invalid node";
		reply.status = -1;
		client_send_control(req, &header, &reply);
		return;
	}

	DEBUG(DEBUG_INFO, ("request opcode = %u, reqid = %u\n",
			   request.opcode, header.reqid));

	if (fake_control_failure(mem_ctx, req, &header, &request)) {
		goto done;
	}

	switch (request.opcode) {
	case CTDB_CONTROL_PROCESS_EXISTS:
		control_process_exists(mem_ctx, req, &header, &request);
		break;

	case CTDB_CONTROL_PING:
		control_ping(mem_ctx, req, &header, &request);
		break;

	case CTDB_CONTROL_GETDBPATH:
		control_getdbpath(mem_ctx, req, &header, &request);
		break;

	case CTDB_CONTROL_GETVNNMAP:
		control_getvnnmap(mem_ctx, req, &header, &request);
		break;

	case CTDB_CONTROL_GET_DEBUG:
		control_get_debug(mem_ctx, req, &header, &request);
		break;

	case CTDB_CONTROL_SET_DEBUG:
		control_set_debug(mem_ctx, req, &header, &request);
		break;

	case CTDB_CONTROL_GET_DBMAP:
		control_get_dbmap(mem_ctx, req, &header, &request);
		break;

	case CTDB_CONTROL_GET_RECMODE:
		control_get_recmode(mem_ctx, req, &header, &request);
		break;

	case CTDB_CONTROL_SET_RECMODE:
		control_set_recmode(mem_ctx, req, &header, &request);
		break;

	case CTDB_CONTROL_DB_ATTACH:
		control_db_attach(mem_ctx, req, &header, &request);
		break;

	case CTDB_CONTROL_REGISTER_SRVID:
		control_register_srvid(mem_ctx, req, &header, &request);
		break;

	case CTDB_CONTROL_DEREGISTER_SRVID:
		control_deregister_srvid(mem_ctx, req, &header, &request);
		break;

	case CTDB_CONTROL_GET_DBNAME:
		control_get_dbname(mem_ctx, req, &header, &request);
		break;

	case CTDB_CONTROL_GET_PID:
		control_get_pid(mem_ctx, req, &header, &request);
		break;

	case CTDB_CONTROL_GET_RECMASTER:
		control_get_recmaster(mem_ctx, req, &header, &request);
		break;

	case CTDB_CONTROL_GET_PNN:
		control_get_pnn(mem_ctx, req, &header, &request);
		break;

	case CTDB_CONTROL_SHUTDOWN:
		control_shutdown(mem_ctx, req, &header, &request);
		break;

	case CTDB_CONTROL_SET_TUNABLE:
		control_set_tunable(mem_ctx, req, &header, &request);
		break;

	case CTDB_CONTROL_GET_TUNABLE:
		control_get_tunable(mem_ctx, req, &header, &request);
		break;

	case CTDB_CONTROL_LIST_TUNABLES:
		control_list_tunables(mem_ctx, req, &header, &request);
		break;

	case CTDB_CONTROL_MODIFY_FLAGS:
		control_modify_flags(mem_ctx, req, &header, &request);
		break;

	case CTDB_CONTROL_GET_ALL_TUNABLES:
		control_get_all_tunables(mem_ctx, req, &header, &request);
		break;

	case CTDB_CONTROL_DB_ATTACH_PERSISTENT:
		control_db_attach_persistent(mem_ctx, req, &header, &request);
		break;

	case CTDB_CONTROL_UPTIME:
		control_uptime(mem_ctx, req, &header, &request);
		break;

	case CTDB_CONTROL_RELOAD_NODES_FILE:
		control_reload_nodes_file(mem_ctx, req, &header, &request);
		break;

	case CTDB_CONTROL_GET_CAPABILITIES:
		control_get_capabilities(mem_ctx, req, &header, &request);
		break;

	case CTDB_CONTROL_RELEASE_IP:
		control_release_ip(mem_ctx, req, &header, &request);
		break;

	case CTDB_CONTROL_TAKEOVER_IP:
		control_takeover_ip(mem_ctx, req, &header, &request);
		break;

	case CTDB_CONTROL_GET_PUBLIC_IPS:
		control_get_public_ips(mem_ctx, req, &header, &request);
		break;

	case CTDB_CONTROL_GET_NODEMAP:
		control_get_nodemap(mem_ctx, req, &header, &request);
		break;

	case CTDB_CONTROL_GET_RECLOCK_FILE:
		control_get_reclock_file(mem_ctx, req, &header, &request);
		break;

	case CTDB_CONTROL_STOP_NODE:
		control_stop_node(mem_ctx, req, &header, &request);
		break;

	case CTDB_CONTROL_CONTINUE_NODE:
		control_continue_node(mem_ctx, req, &header, &request);
		break;

	case CTDB_CONTROL_SET_BAN_STATE:
		control_set_ban_state(mem_ctx, req, &header, &request);
		break;

	case CTDB_CONTROL_TRANS3_COMMIT:
		control_trans3_commit(mem_ctx, req, &header, &request);
		break;

	case CTDB_CONTROL_GET_DB_SEQNUM:
		control_get_db_seqnum(mem_ctx, req, &header, &request);
		break;

	case CTDB_CONTROL_DB_GET_HEALTH:
		control_db_get_health(mem_ctx, req, &header, &request);
		break;

	case CTDB_CONTROL_GET_PUBLIC_IP_INFO:
		control_get_public_ip_info(mem_ctx, req, &header, &request);
		break;

	case CTDB_CONTROL_GET_IFACES:
		control_get_ifaces(mem_ctx, req, &header, &request);
		break;

	case CTDB_CONTROL_SET_IFACE_LINK_STATE:
		control_set_iface_link_state(mem_ctx, req, &header, &request);
		break;

	case CTDB_CONTROL_SET_DB_READONLY:
		control_set_db_readonly(mem_ctx, req, &header, &request);
		break;

	case CTDB_CONTROL_TRAVERSE_START_EXT:
		control_traverse_start_ext(mem_ctx, req, &header, &request);
		break;

	case CTDB_CONTROL_SET_DB_STICKY:
		control_set_db_sticky(mem_ctx, req, &header, &request);
		break;

	case CTDB_CONTROL_IPREALLOCATED:
		control_ipreallocated(mem_ctx, req, &header, &request);
		break;

	case CTDB_CONTROL_GET_RUNSTATE:
		control_get_runstate(mem_ctx, req, &header, &request);
		break;

	case CTDB_CONTROL_GET_NODES_FILE:
		control_get_nodes_file(mem_ctx, req, &header, &request);
		break;

	case CTDB_CONTROL_DB_OPEN_FLAGS:
		control_db_open_flags(mem_ctx, req, &header, &request);
		break;

	case CTDB_CONTROL_DB_ATTACH_REPLICATED:
		control_db_attach_replicated(mem_ctx, req, &header, &request);
		break;

	case CTDB_CONTROL_CHECK_PID_SRVID:
		control_check_pid_srvid(mem_ctx, req, &header, &request);
		break;

	case CTDB_CONTROL_DISABLE_NODE:
		control_disable_node(mem_ctx, req, &header, &request);
		break;

	case CTDB_CONTROL_ENABLE_NODE:
		control_enable_node(mem_ctx, req, &header, &request);
		break;

	default:
		if (! (request.flags & CTDB_CTRL_FLAG_NOREPLY)) {
			control_error(mem_ctx, req, &header, &request);
		}
		break;
	}

done:
	talloc_free(mem_ctx);
}

static int client_recv(struct tevent_req *req, int *perr)
{
	struct client_state *state = tevent_req_data(
		req, struct client_state);
	int err;

	DEBUG(DEBUG_INFO, ("Client done fd=%d\n", state->fd));
	close(state->fd);

	if (tevent_req_is_unix_error(req, &err)) {
		if (perr != NULL) {
			*perr = err;
		}
		return -1;
	}

	return state->status;
}

/*
 * Fake CTDB server
 */

struct server_state {
	struct tevent_context *ev;
	struct ctdbd_context *ctdb;
	int fd;
};

static void server_new_client(struct tevent_req *subreq);
static void server_client_done(struct tevent_req *subreq);

static struct tevent_req *server_send(TALLOC_CTX *mem_ctx,
				      struct tevent_context *ev,
				      struct ctdbd_context *ctdb,
				      int fd)
{
	struct tevent_req *req, *subreq;
	struct server_state *state;

	req = tevent_req_create(mem_ctx, &state, struct server_state);
	if (req == NULL) {
		return NULL;
	}

	state->ev = ev;
	state->ctdb = ctdb;
	state->fd = fd;

	subreq = accept_send(state, ev, fd);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, server_new_client, req);

	return req;
}

static void server_new_client(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct server_state *state = tevent_req_data(
		req, struct server_state);
	struct ctdbd_context *ctdb = state->ctdb;
	int client_fd;
	int ret = 0;

	client_fd = accept_recv(subreq, NULL, NULL, &ret);
	TALLOC_FREE(subreq);
	if (client_fd == -1) {
		tevent_req_error(req, ret);
		return;
	}

	subreq = client_send(state, state->ev, client_fd,
			     ctdb, ctdb->node_map->pnn);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, server_client_done, req);

	ctdb->num_clients += 1;

	subreq = accept_send(state, state->ev, state->fd);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, server_new_client, req);
}

static void server_client_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct server_state *state = tevent_req_data(
		req, struct server_state);
	struct ctdbd_context *ctdb = state->ctdb;
	int ret = 0;
	int status;

	status = client_recv(subreq, &ret);
	TALLOC_FREE(subreq);
	if (status < 0) {
		tevent_req_error(req, ret);
		return;
	}

	ctdb->num_clients -= 1;

	if (status == 99) {
		/* Special status, to shutdown server */
		DEBUG(DEBUG_INFO, ("Shutting down server\n"));
		tevent_req_done(req);
	}
}

static bool server_recv(struct tevent_req *req, int *perr)
{
	int err;

	if (tevent_req_is_unix_error(req, &err)) {
		if (perr != NULL) {
			*perr = err;
		}
		return false;
	}
	return true;
}

/*
 * Main functions
 */

static int socket_init(const char *sockpath)
{
	struct sockaddr_un addr;
	size_t len;
	int ret, fd;

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;

	len = strlcpy(addr.sun_path, sockpath, sizeof(addr.sun_path));
	if (len >= sizeof(addr.sun_path)) {
		fprintf(stderr, "path too long: %s\n", sockpath);
		return -1;
	}

	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd == -1) {
		fprintf(stderr, "socket failed - %s\n", sockpath);
		return -1;
	}

	ret = bind(fd, (struct sockaddr *)&addr, sizeof(addr));
	if (ret != 0) {
		fprintf(stderr, "bind failed - %s\n", sockpath);
		goto fail;
	}

	ret = listen(fd, 10);
	if (ret != 0) {
		fprintf(stderr, "listen failed\n");
		goto fail;
	}

	DEBUG(DEBUG_INFO, ("Socket init done\n"));

	return fd;

fail:
	if (fd != -1) {
		close(fd);
	}
	return -1;
}

static struct options {
	const char *dbdir;
	const char *sockpath;
	const char *pidfile;
	const char *debuglevel;
} options;

static struct poptOption cmdline_options[] = {
	POPT_AUTOHELP
	{ "dbdir", 'D', POPT_ARG_STRING, &options.dbdir, 0,
		"Database directory", "directory" },
	{ "socket", 's', POPT_ARG_STRING, &options.sockpath, 0,
		"Unix domain socket path", "filename" },
	{ "pidfile", 'p', POPT_ARG_STRING, &options.pidfile, 0,
		"pid file", "filename" } ,
	{ "debug", 'd', POPT_ARG_STRING, &options.debuglevel, 0,
		"debug level", "ERR|WARNING|NOTICE|INFO|DEBUG" } ,
	POPT_TABLEEND
};

static void cleanup(void)
{
	unlink(options.sockpath);
	unlink(options.pidfile);
}

static void signal_handler(int sig)
{
	cleanup();
	exit(0);
}

static void start_server(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
			 struct ctdbd_context *ctdb, int fd, int pfd)
{
	struct tevent_req *req;
	int ret = 0;
	ssize_t len;

	atexit(cleanup);
	signal(SIGTERM, signal_handler);

	req = server_send(mem_ctx, ev, ctdb, fd);
	if (req == NULL) {
		fprintf(stderr, "Memory error\n");
		exit(1);
	}

	len = write(pfd, &ret, sizeof(ret));
	if (len != sizeof(ret)) {
		fprintf(stderr, "Failed to send message to parent\n");
		exit(1);
	}
	close(pfd);

	tevent_req_poll(req, ev);

	server_recv(req, &ret);
	if (ret != 0) {
		exit(1);
	}
}

int main(int argc, const char *argv[])
{
	TALLOC_CTX *mem_ctx;
	struct ctdbd_context *ctdb;
	struct tevent_context *ev;
	poptContext pc;
	int opt, fd, ret, pfd[2];
	ssize_t len;
	pid_t pid;
	FILE *fp;

	pc = poptGetContext(argv[0], argc, argv, cmdline_options,
			    POPT_CONTEXT_KEEP_FIRST);
	while ((opt = poptGetNextOpt(pc)) != -1) {
		fprintf(stderr, "Invalid option %s\n", poptBadOption(pc, 0));
		exit(1);
	}

	if (options.dbdir == NULL) {
		fprintf(stderr, "Please specify database directory\n");
		poptPrintHelp(pc, stdout, 0);
		exit(1);
	}

	if (options.sockpath == NULL) {
		fprintf(stderr, "Please specify socket path\n");
		poptPrintHelp(pc, stdout, 0);
		exit(1);
	}

	if (options.pidfile == NULL) {
		fprintf(stderr, "Please specify pid file\n");
		poptPrintHelp(pc, stdout, 0);
		exit(1);
	}

	mem_ctx = talloc_new(NULL);
	if (mem_ctx == NULL) {
		fprintf(stderr, "Memory error\n");
		exit(1);
	}

	ret = logging_init(mem_ctx, "file:", options.debuglevel, "fake-ctdbd");
	if (ret != 0) {
		fprintf(stderr, "Invalid debug level\n");
		poptPrintHelp(pc, stdout, 0);
		exit(1);
	}

	ctdb = ctdbd_setup(mem_ctx, options.dbdir);
	if (ctdb == NULL) {
		exit(1);
	}

	if (! ctdbd_verify(ctdb)) {
		exit(1);
	}

	ev = tevent_context_init(mem_ctx);
	if (ev == NULL) {
		fprintf(stderr, "Memory error\n");
		exit(1);
	}

	fd = socket_init(options.sockpath);
	if (fd == -1) {
		exit(1);
	}

	ret = pipe(pfd);
	if (ret != 0) {
		fprintf(stderr, "Failed to create pipe\n");
		cleanup();
		exit(1);
	}

	pid = fork();
	if (pid == -1) {
		fprintf(stderr, "Failed to fork\n");
		cleanup();
		exit(1);
	}

	if (pid == 0) {
		/* Child */
		close(pfd[0]);
		start_server(mem_ctx, ev, ctdb, fd, pfd[1]);
		exit(1);
	}

	/* Parent */
	close(pfd[1]);

	len = read(pfd[0], &ret, sizeof(ret));
	close(pfd[0]);
	if (len != sizeof(ret)) {
		fprintf(stderr, "len = %zi\n", len);
		fprintf(stderr, "Failed to get message from child\n");
		kill(pid, SIGTERM);
		exit(1);
	}

	fp = fopen(options.pidfile, "w");
	if (fp == NULL) {
		fprintf(stderr, "Failed to open pid file %s\n",
			options.pidfile);
		kill(pid, SIGTERM);
		exit(1);
	}
	fprintf(fp, "%d\n", pid);
	fclose(fp);

	return 0;
}
