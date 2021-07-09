/*
   CTDB control tool

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

#include "replace.h"
#include "system/network.h"
#include "system/filesys.h"
#include "system/time.h"
#include "system/wait.h"
#include "system/dir.h"

#include <ctype.h>
#include <popt.h>
#include <talloc.h>
#include <tevent.h>
#include <tdb.h>

#include "version.h"
#include "lib/util/debug.h"
#include "lib/util/samba_util.h"
#include "lib/util/sys_rw.h"

#include "common/db_hash.h"
#include "common/logging.h"
#include "common/path.h"
#include "protocol/protocol.h"
#include "protocol/protocol_api.h"
#include "protocol/protocol_util.h"
#include "common/system_socket.h"
#include "client/client.h"
#include "client/client_sync.h"

#define TIMEOUT()	timeval_current_ofs(options.timelimit, 0)

#define SRVID_CTDB_TOOL    (CTDB_SRVID_TOOL_RANGE | 0x0001000000000000LL)
#define SRVID_CTDB_PUSHDB  (CTDB_SRVID_TOOL_RANGE | 0x0002000000000000LL)

static struct {
	const char *debuglevelstr;
	int timelimit;
	int pnn;
	int machinereadable;
	const char *sep;
	int machineparsable;
	int verbose;
	int maxruntime;
	int printemptyrecords;
	int printdatasize;
	int printlmaster;
	int printhash;
	int printrecordflags;
} options;

static poptContext pc;

struct ctdb_context {
	struct tevent_context *ev;
	struct ctdb_client_context *client;
	struct ctdb_node_map *nodemap;
	uint32_t pnn, cmd_pnn;
	uint64_t srvid;
};

static void usage(const char *command);

/*
 * Utility Functions
 */

static double timeval_delta(struct timeval *tv2, struct timeval *tv)
{
	return (tv2->tv_sec - tv->tv_sec) +
	       (tv2->tv_usec - tv->tv_usec) * 1.0e-6;
}

static struct ctdb_node_and_flags *get_node_by_pnn(
					struct ctdb_node_map *nodemap,
					uint32_t pnn)
{
	unsigned int i;

	for (i=0; i<nodemap->num; i++) {
		if (nodemap->node[i].pnn == pnn) {
			return &nodemap->node[i];
		}
	}
	return NULL;
}

static const char *pretty_print_flags(TALLOC_CTX *mem_ctx, uint32_t flags)
{
	static const struct {
		uint32_t flag;
		const char *name;
	} flag_names[] = {
		{ NODE_FLAGS_DISCONNECTED,	    "DISCONNECTED" },
		{ NODE_FLAGS_PERMANENTLY_DISABLED,  "DISABLED" },
		{ NODE_FLAGS_BANNED,		    "BANNED" },
		{ NODE_FLAGS_UNHEALTHY,		    "UNHEALTHY" },
		{ NODE_FLAGS_DELETED,		    "DELETED" },
		{ NODE_FLAGS_STOPPED,		    "STOPPED" },
		{ NODE_FLAGS_INACTIVE,		    "INACTIVE" },
	};
	char *flags_str = NULL;
	size_t i;

	for (i=0; i<ARRAY_SIZE(flag_names); i++) {
		if (flags & flag_names[i].flag) {
			if (flags_str == NULL) {
				flags_str = talloc_asprintf(mem_ctx,
						"%s", flag_names[i].name);
			} else {
				flags_str = talloc_asprintf_append(flags_str,
						"|%s", flag_names[i].name);
			}
			if (flags_str == NULL) {
				return "OUT-OF-MEMORY";
			}
		}
	}
	if (flags_str == NULL) {
		return "OK";
	}

	return flags_str;
}

static uint64_t next_srvid(struct ctdb_context *ctdb)
{
	ctdb->srvid += 1;
	return ctdb->srvid;
}

/*
 * Get consistent nodemap information.
 *
 * If nodemap is already cached, use that. If not get it.
 * If the current node is BANNED, then get nodemap from "better" node.
 */
static struct ctdb_node_map *get_nodemap(struct ctdb_context *ctdb, bool force)
{
	TALLOC_CTX *tmp_ctx;
	struct ctdb_node_map *nodemap;
	struct ctdb_node_and_flags *node;
	uint32_t current_node;
	int ret;

	if (force) {
		TALLOC_FREE(ctdb->nodemap);
	}

	if (ctdb->nodemap != NULL) {
		return ctdb->nodemap;
	}

	tmp_ctx = talloc_new(ctdb);
	if (tmp_ctx == NULL) {
		return false;
	}

	current_node = ctdb->pnn;
again:
	ret = ctdb_ctrl_get_nodemap(tmp_ctx, ctdb->ev, ctdb->client,
				    current_node, TIMEOUT(), &nodemap);
	if (ret != 0) {
		fprintf(stderr, "Failed to get nodemap from node %u\n",
			current_node);
		goto failed;
	}

	node = get_node_by_pnn(nodemap, current_node);
	if (node->flags & NODE_FLAGS_BANNED) {
		/* Pick next node */
		do {
			current_node = (current_node + 1) % nodemap->num;
			node = get_node_by_pnn(nodemap, current_node);
			if (! (node->flags &
			      (NODE_FLAGS_DELETED|NODE_FLAGS_DISCONNECTED))) {
				break;
			}
		} while (current_node != ctdb->pnn);

		if (current_node == ctdb->pnn) {
			/* Tried all nodes in the cluster */
			fprintf(stderr, "Warning: All nodes are banned.\n");
			goto failed;
		}

		goto again;
	}

	ctdb->nodemap = talloc_steal(ctdb, nodemap);
	return nodemap;

failed:
	talloc_free(tmp_ctx);
	return NULL;
}

static bool verify_pnn(struct ctdb_context *ctdb, int pnn)
{
	struct ctdb_node_map *nodemap;
	bool found;
	unsigned int i;

	if (pnn == -1) {
		return false;
	}

	nodemap = get_nodemap(ctdb, false);
	if (nodemap == NULL) {
		return false;
	}

	found = false;
	for (i=0; i<nodemap->num; i++) {
		if (nodemap->node[i].pnn == (uint32_t)pnn) {
			found = true;
			break;
		}
	}
	if (! found) {
		fprintf(stderr, "Node %u does not exist\n", pnn);
		return false;
	}

	if (nodemap->node[i].flags &
	    (NODE_FLAGS_DISCONNECTED|NODE_FLAGS_DELETED)) {
		fprintf(stderr, "Node %u has status %s\n", pnn,
			pretty_print_flags(ctdb, nodemap->node[i].flags));
		return false;
	}

	return true;
}

static struct ctdb_node_map *talloc_nodemap(TALLOC_CTX *mem_ctx,
					    struct ctdb_node_map *nodemap)
{
	struct ctdb_node_map *nodemap2;

	nodemap2 = talloc_zero(mem_ctx, struct ctdb_node_map);
	if (nodemap2 == NULL) {
		return NULL;
	}

	nodemap2->node = talloc_array(nodemap2, struct ctdb_node_and_flags,
				      nodemap->num);
	if (nodemap2->node == NULL) {
		talloc_free(nodemap2);
		return NULL;
	}

	return nodemap2;
}

/*
 * Get the number and the list of matching nodes
 *
 *   nodestring :=  NULL | all | pnn,[pnn,...]
 *
 * If nodestring is NULL, use the current node.
 */
static bool parse_nodestring(TALLOC_CTX *mem_ctx, struct ctdb_context *ctdb,
			     const char *nodestring,
			     struct ctdb_node_map **out)
{
	struct ctdb_node_map *nodemap, *nodemap2;
	struct ctdb_node_and_flags *node;
	unsigned int i;

	nodemap = get_nodemap(ctdb, false);
	if (nodemap == NULL) {
		return false;
	}

	nodemap2 = talloc_nodemap(mem_ctx, nodemap);
	if (nodemap2 == NULL) {
		return false;
	}

	if (nodestring == NULL) {
		for (i=0; i<nodemap->num; i++) {
			if (nodemap->node[i].pnn == ctdb->cmd_pnn) {
				nodemap2->node[0] = nodemap->node[i];
				break;
			}
		}
		nodemap2->num = 1;

		goto done;
	}

	if (strcmp(nodestring, "all") == 0) {
		for (i=0; i<nodemap->num; i++) {
			nodemap2->node[i] = nodemap->node[i];
		}
		nodemap2->num = nodemap->num;

		goto done;
	} else {
		char *ns, *tok;
		int error = 0;

		ns = talloc_strdup(mem_ctx, nodestring);
		if (ns == NULL) {
			return false;
		}

		tok = strtok(ns, ",");
		while (tok != NULL) {
			uint32_t pnn;

			pnn = (uint32_t)smb_strtoul(tok,
						    NULL,
						    0,
						    &error,
						    SMB_STR_STANDARD);
			if (error != 0) {
				fprintf(stderr, "Invalid node %s\n", tok);
					return false;
			}

			node = get_node_by_pnn(nodemap, pnn);
			if (node == NULL) {
				fprintf(stderr, "Node %u does not exist\n",
					pnn);
				return false;
			}

			nodemap2->node[nodemap2->num] = *node;
			nodemap2->num += 1;

			tok = strtok(NULL, ",");
		}
	}

done:
	*out = nodemap2;
	return true;
}

/* Compare IP address */
static bool ctdb_same_ip(ctdb_sock_addr *ip1, ctdb_sock_addr *ip2)
{
	bool ret = false;

	if (ip1->sa.sa_family != ip2->sa.sa_family) {
		return false;
	}

	switch (ip1->sa.sa_family) {
	case AF_INET:
		ret = (memcmp(&ip1->ip.sin_addr, &ip2->ip.sin_addr,
			      sizeof(struct in_addr)) == 0);
		break;

	case AF_INET6:
		ret = (memcmp(&ip1->ip6.sin6_addr, &ip2->ip6.sin6_addr,
			      sizeof(struct in6_addr)) == 0);
		break;
	}

	return ret;
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

static struct ctdb_node_map *read_nodes_file(TALLOC_CTX *mem_ctx, uint32_t pnn)
{
	struct ctdb_node_map *nodemap;
	const char *nodes_list = NULL;

	const char *basedir = getenv("CTDB_BASE");
	if (basedir == NULL) {
		basedir = CTDB_ETCDIR;
	}
	nodes_list = talloc_asprintf(mem_ctx, "%s/nodes", basedir);
	if (nodes_list == NULL) {
		fprintf(stderr, "Memory allocation error\n");
		return NULL;
	}

	nodemap = ctdb_read_nodes_file(mem_ctx, nodes_list);
	if (nodemap == NULL) {
		fprintf(stderr, "Failed to read nodes file \"%s\"\n",
			nodes_list);
		return NULL;
	}

	return nodemap;
}

static struct ctdb_dbid *db_find(TALLOC_CTX *mem_ctx,
				 struct ctdb_context *ctdb,
				 struct ctdb_dbid_map *dbmap,
				 const char *db_name)
{
	struct ctdb_dbid *db = NULL;
	const char *name;
	unsigned int i;
	int ret;

	for (i=0; i<dbmap->num; i++) {
		ret = ctdb_ctrl_get_dbname(mem_ctx, ctdb->ev, ctdb->client,
					   ctdb->pnn, TIMEOUT(),
					   dbmap->dbs[i].db_id, &name);
		if (ret != 0) {
			return false;
		}

		if (strcmp(db_name, name) == 0) {
			talloc_free(discard_const(name));
			db = &dbmap->dbs[i];
			break;
		}
	}

	return db;
}

static bool db_exists(TALLOC_CTX *mem_ctx, struct ctdb_context *ctdb,
		      const char *db_arg, uint32_t *db_id,
		      const char **db_name, uint8_t *db_flags)
{
	struct ctdb_dbid_map *dbmap;
	struct ctdb_dbid *db = NULL;
	uint32_t id = 0;
	const char *name = NULL;
	unsigned int i;
	int ret = 0;

	ret = ctdb_ctrl_get_dbmap(mem_ctx, ctdb->ev, ctdb->client,
				  ctdb->pnn, TIMEOUT(), &dbmap);
	if (ret != 0) {
		return false;
	}

	if (strncmp(db_arg, "0x", 2) == 0) {
		id = smb_strtoul(db_arg, NULL, 0, &ret, SMB_STR_STANDARD);
		if (ret != 0) {
			return false;
		}
		for (i=0; i<dbmap->num; i++) {
			if (id == dbmap->dbs[i].db_id) {
				db = &dbmap->dbs[i];
				break;
			}
		}
	} else {
		name = db_arg;
		db = db_find(mem_ctx, ctdb, dbmap, name);
	}

	if (db == NULL) {
		fprintf(stderr, "No database matching '%s' found\n", db_arg);
		return false;
	}

	if (name == NULL) {
		ret = ctdb_ctrl_get_dbname(mem_ctx, ctdb->ev, ctdb->client,
					   ctdb->pnn, TIMEOUT(), id, &name);
		if (ret != 0) {
			return false;
		}
	}

	if (db_id != NULL) {
		*db_id = db->db_id;
	}
	if (db_name != NULL) {
		*db_name = talloc_strdup(mem_ctx, name);
	}
	if (db_flags != NULL) {
		*db_flags = db->flags;
	}
	return true;
}

static int h2i(char h)
{
	if (h >= 'a' && h <= 'f') {
		return h - 'a' + 10;
	}
	if (h >= 'A' && h <= 'F') {
		return h - 'A' + 10;
	}
	return h - '0';
}

static int hex_to_data(const char *str, size_t len, TALLOC_CTX *mem_ctx,
		       TDB_DATA *out)
{
	unsigned int i;
	TDB_DATA data;

	if (len & 0x01) {
		fprintf(stderr, "Key (%s) contains odd number of hex digits\n",
			str);
		return EINVAL;
	}

	data.dsize = len / 2;
	data.dptr = talloc_size(mem_ctx, data.dsize);
	if (data.dptr == NULL) {
		return ENOMEM;
	}

	for (i=0; i<data.dsize; i++) {
		data.dptr[i] = h2i(str[i*2]) << 4 | h2i(str[i*2+1]);
	}

	*out = data;
	return 0;
}

static int str_to_data(const char *str, size_t len, TALLOC_CTX *mem_ctx,
		       TDB_DATA *out)
{
	TDB_DATA data;
	int ret = 0;

	if (strncmp(str, "0x", 2) == 0) {
		ret = hex_to_data(str+2, len-2, mem_ctx, &data);
		if (ret != 0) {
			return ret;
		}
	} else {
		data.dptr = talloc_memdup(mem_ctx, str, len);
		if (data.dptr == NULL) {
			return ENOMEM;
		}
		data.dsize = len;
	}

	*out = data;
	return 0;
}

static int run_helper(TALLOC_CTX *mem_ctx, const char *command,
		      const char *path, int argc, const char **argv)
{
	pid_t pid;
	int save_errno, status, ret;
	const char **new_argv;
	int i;

	new_argv = talloc_array(mem_ctx, const char *, argc + 2);
	if (new_argv == NULL) {
		return ENOMEM;
	}

	new_argv[0] = path;
	for (i=0; i<argc; i++) {
		new_argv[i+1] = argv[i];
	}
	new_argv[argc+1] = NULL;

	pid = fork();
	if (pid < 0) {
		save_errno = errno;
		talloc_free(new_argv);
		fprintf(stderr, "Failed to fork %s (%s) - %s\n",
			command, path, strerror(save_errno));
		return save_errno;
	}

	if (pid == 0) {
		ret = execv(path, discard_const(new_argv));
		if (ret == -1) {
			_exit(64+errno);
		}
		/* Should not happen */
		_exit(64+ENOEXEC);
	}

	talloc_free(new_argv);

	ret = waitpid(pid, &status, 0);
	if (ret == -1) {
		save_errno = errno;
		fprintf(stderr, "waitpid() failed for %s - %s\n",
			command, strerror(save_errno));
		return save_errno;
	}

	if (WIFEXITED(status)) {
		int pstatus = WEXITSTATUS(status);
		if (WIFSIGNALED(status)) {
			fprintf(stderr, "%s terminated with signal %d\n",
				command, WTERMSIG(status));
			ret = EINTR;
		} else if (pstatus >= 64 && pstatus < 255) {
			fprintf(stderr, "%s failed with error %d\n",
				command, pstatus-64);
			ret = pstatus - 64;
		} else {
			ret = pstatus;
		}
		return ret;
	} else if (WIFSIGNALED(status)) {
		fprintf(stderr, "%s terminated with signal %d\n",
			command, WTERMSIG(status));
		return EINTR;
	}

	return 0;
}

/*
 * Command Functions
 */

static int control_version(TALLOC_CTX *mem_ctx, struct ctdb_context *ctdb,
			   int argc, const char **argv)
{
	printf("%s\n", SAMBA_VERSION_STRING);
	return 0;
}

static bool partially_online(TALLOC_CTX *mem_ctx,
			     struct ctdb_context *ctdb,
			     struct ctdb_node_and_flags *node)
{
	struct ctdb_iface_list *iface_list;
	unsigned int i;
	int ret;
	bool status = false;

	if (node->flags != 0) {
		return false;
	}

	ret = ctdb_ctrl_get_ifaces(mem_ctx, ctdb->ev, ctdb->client,
				   node->pnn, TIMEOUT(), &iface_list);
	if (ret != 0) {
		return false;
	}

	status = false;
	for (i=0; i < iface_list->num; i++) {
		if (iface_list->iface[i].link_state == 0) {
			status = true;
			break;
		}
	}

	return status;
}

static void print_nodemap_machine(TALLOC_CTX *mem_ctx,
				  struct ctdb_context *ctdb,
				  struct ctdb_node_map *nodemap,
				  uint32_t mypnn)
{
	struct ctdb_node_and_flags *node;
	unsigned int i;

	printf("%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s\n",
	       options.sep,
	       "Node", options.sep,
	       "IP", options.sep,
	       "Disconnected", options.sep,
	       "Banned", options.sep,
	       "Disabled", options.sep,
	       "Unhealthy", options.sep,
	       "Stopped", options.sep,
	       "Inactive", options.sep,
	       "PartiallyOnline", options.sep,
	       "ThisNode", options.sep);

	for (i=0; i<nodemap->num; i++) {
		node = &nodemap->node[i];
		if (node->flags & NODE_FLAGS_DELETED) {
			continue;
		}

		printf("%s%u%s%s%s%d%s%d%s%d%s%d%s%d%s%d%s%d%s%c%s\n",
		       options.sep,
		       node->pnn, options.sep,
		       ctdb_sock_addr_to_string(mem_ctx, &node->addr, false),
		       options.sep,
		       !! (node->flags & NODE_FLAGS_DISCONNECTED), options.sep,
		       !! (node->flags & NODE_FLAGS_BANNED), options.sep,
		       !! (node->flags & NODE_FLAGS_PERMANENTLY_DISABLED),
		       options.sep,
		       !! (node->flags & NODE_FLAGS_UNHEALTHY), options.sep,
		       !! (node->flags & NODE_FLAGS_STOPPED), options.sep,
		       !! (node->flags & NODE_FLAGS_INACTIVE), options.sep,
		       partially_online(mem_ctx, ctdb, node), options.sep,
		       (node->pnn == mypnn)?'Y':'N', options.sep);
	}

}

static void print_nodemap(TALLOC_CTX *mem_ctx, struct ctdb_context *ctdb,
			  struct ctdb_node_map *nodemap, uint32_t mypnn,
			  bool print_header)
{
	struct ctdb_node_and_flags *node;
	int num_deleted_nodes = 0;
	unsigned int i;

	for (i=0; i<nodemap->num; i++) {
		if (nodemap->node[i].flags & NODE_FLAGS_DELETED) {
			num_deleted_nodes++;
		}
	}

	if (print_header) {
		if (num_deleted_nodes == 0) {
			printf("Number of nodes:%d\n", nodemap->num);
		} else {
			printf("Number of nodes:%d "
			       "(including %d deleted nodes)\n",
			       nodemap->num, num_deleted_nodes);
		}
	}

	for (i=0; i<nodemap->num; i++) {
		node = &nodemap->node[i];
		if (node->flags & NODE_FLAGS_DELETED) {
			continue;
		}

		printf("pnn:%u %-16s %s%s\n",
		       node->pnn,
		       ctdb_sock_addr_to_string(mem_ctx, &node->addr, false),
		       partially_online(mem_ctx, ctdb, node) ?
				"PARTIALLYONLINE" :
				pretty_print_flags(mem_ctx, node->flags),
		       node->pnn == mypnn ? " (THIS NODE)" : "");
	}
}

static void print_status(TALLOC_CTX *mem_ctx, struct ctdb_context *ctdb,
			 struct ctdb_node_map *nodemap, uint32_t mypnn,
			 struct ctdb_vnn_map *vnnmap, int recmode,
			 uint32_t recmaster)
{
	unsigned int i;

	print_nodemap(mem_ctx, ctdb, nodemap, mypnn, true);

	if (vnnmap->generation == INVALID_GENERATION) {
		printf("Generation:INVALID\n");
	} else {
		printf("Generation:%u\n", vnnmap->generation);
	}
	printf("Size:%d\n", vnnmap->size);
	for (i=0; i<vnnmap->size; i++) {
		printf("hash:%d lmaster:%d\n", i, vnnmap->map[i]);
	}

	printf("Recovery mode:%s (%d)\n",
	       recmode == CTDB_RECOVERY_NORMAL ? "NORMAL" : "RECOVERY",
	       recmode);
	printf("Recovery master:%d\n", recmaster);
}

static int control_status(TALLOC_CTX *mem_ctx, struct ctdb_context *ctdb,
			  int argc, const char **argv)
{
	struct ctdb_node_map *nodemap;
	struct ctdb_vnn_map *vnnmap;
	int recmode;
	uint32_t recmaster;
	int ret;

	if (argc != 0) {
		usage("status");
	}

	nodemap = get_nodemap(ctdb, false);
	if (nodemap == NULL) {
		return 1;
	}

	if (options.machinereadable == 1) {
		print_nodemap_machine(mem_ctx, ctdb, nodemap, ctdb->cmd_pnn);
		return 0;
	}

	ret = ctdb_ctrl_getvnnmap(mem_ctx, ctdb->ev, ctdb->client,
				  ctdb->cmd_pnn, TIMEOUT(), &vnnmap);
	if (ret != 0) {
		return ret;
	}

	ret = ctdb_ctrl_get_recmode(mem_ctx, ctdb->ev, ctdb->client,
				    ctdb->cmd_pnn, TIMEOUT(), &recmode);
	if (ret != 0) {
		return ret;
	}

	ret = ctdb_ctrl_get_recmaster(mem_ctx, ctdb->ev, ctdb->client,
				      ctdb->cmd_pnn, TIMEOUT(), &recmaster);
	if (ret != 0) {
		return ret;
	}

	print_status(mem_ctx, ctdb, nodemap, ctdb->cmd_pnn, vnnmap,
		     recmode, recmaster);
	return 0;
}

static int control_uptime(TALLOC_CTX *mem_ctx, struct ctdb_context *ctdb,
			  int argc, const char **argv)
{
	struct ctdb_uptime *uptime;
	int ret, tmp, days, hours, minutes, seconds;

	ret = ctdb_ctrl_uptime(mem_ctx, ctdb->ev, ctdb->client,
			       ctdb->cmd_pnn, TIMEOUT(), &uptime);
	if (ret != 0) {
		return ret;
	}

	printf("Current time of node %-4u     :                %s",
	       ctdb->cmd_pnn, ctime(&uptime->current_time.tv_sec));

	tmp = uptime->current_time.tv_sec - uptime->ctdbd_start_time.tv_sec;
	seconds = tmp % 60; tmp /= 60;
	minutes = tmp % 60; tmp /= 60;
	hours = tmp % 24; tmp /= 24;
	days = tmp;

	printf("Ctdbd start time              : (%03d %02d:%02d:%02d) %s",
	       days, hours, minutes, seconds,
	       ctime(&uptime->ctdbd_start_time.tv_sec));

	tmp = uptime->current_time.tv_sec - uptime->last_recovery_finished.tv_sec;
	seconds = tmp % 60; tmp /= 60;
	minutes = tmp % 60; tmp /= 60;
	hours = tmp % 24; tmp /= 24;
	days = tmp;

	printf("Time of last recovery/failover: (%03d %02d:%02d:%02d) %s",
	       days, hours, minutes, seconds,
	       ctime(&uptime->last_recovery_finished.tv_sec));

	printf("Duration of last recovery/failover: %lf seconds\n",
	       timeval_delta(&uptime->last_recovery_finished,
			     &uptime->last_recovery_started));

	return 0;
}

static int control_ping(TALLOC_CTX *mem_ctx, struct ctdb_context *ctdb,
			int argc, const char **argv)
{
	struct timeval tv;
	int ret, num_clients;

	tv = timeval_current();
	ret = ctdb_ctrl_ping(mem_ctx, ctdb->ev, ctdb->client,
			     ctdb->cmd_pnn, TIMEOUT(), &num_clients);
	if (ret != 0) {
		return ret;
	}

	printf("response from %u time=%.6f sec  (%d clients)\n",
	       ctdb->cmd_pnn, timeval_elapsed(&tv), num_clients);
	return 0;
}

const char *runstate_to_string(enum ctdb_runstate runstate);
enum ctdb_runstate runstate_from_string(const char *runstate_str);

static int control_runstate(TALLOC_CTX *mem_ctx, struct ctdb_context *ctdb,
			    int argc, const char **argv)
{
	enum ctdb_runstate runstate;
	bool found;
	int ret, i;

	ret = ctdb_ctrl_get_runstate(mem_ctx, ctdb->ev, ctdb->client,
				     ctdb->cmd_pnn, TIMEOUT(), &runstate);
	if (ret != 0) {
		return ret;
	}

	found = true;
	for (i=0; i<argc; i++) {
		enum ctdb_runstate t;

		found = false;
		t = ctdb_runstate_from_string(argv[i]);
		if (t == CTDB_RUNSTATE_UNKNOWN) {
			printf("Invalid run state (%s)\n", argv[i]);
			return 1;
		}

		if (t == runstate) {
			found = true;
			break;
		}
	}

	if (! found) {
		printf("CTDB not in required run state (got %s)\n",
		       ctdb_runstate_to_string(runstate));
		return 1;
	}

	printf("%s\n", ctdb_runstate_to_string(runstate));
	return 0;
}

static int control_getvar(TALLOC_CTX *mem_ctx, struct ctdb_context *ctdb,
			  int argc, const char **argv)
{
	struct ctdb_var_list *tun_var_list;
	uint32_t value;
	int ret, i;
	bool found;

	if (argc != 1) {
		usage("getvar");
	}

	ret = ctdb_ctrl_list_tunables(mem_ctx, ctdb->ev, ctdb->client,
				      ctdb->cmd_pnn, TIMEOUT(), &tun_var_list);
	if (ret != 0) {
		fprintf(stderr,
			"Failed to get list of variables from node %u\n",
			ctdb->cmd_pnn);
		return ret;
	}

	found = false;
	for (i=0; i<tun_var_list->count; i++) {
		if (strcasecmp(tun_var_list->var[i], argv[0]) == 0) {
			found = true;
			break;
		}
	}

	if (! found) {
		printf("No such tunable %s\n", argv[0]);
		return 1;
	}

	ret = ctdb_ctrl_get_tunable(mem_ctx, ctdb->ev, ctdb->client,
				    ctdb->cmd_pnn, TIMEOUT(), argv[0], &value);
	if (ret != 0) {
		return ret;
	}

	printf("%-26s = %u\n", argv[0], value);
	return 0;
}

static int control_setvar(TALLOC_CTX *mem_ctx, struct ctdb_context *ctdb,
			  int argc, const char **argv)
{
	struct ctdb_var_list *tun_var_list;
	struct ctdb_tunable tunable;
	bool found;
	int i;
	int ret = 0;

	if (argc != 2) {
		usage("setvar");
	}

	ret = ctdb_ctrl_list_tunables(mem_ctx, ctdb->ev, ctdb->client,
				      ctdb->cmd_pnn, TIMEOUT(), &tun_var_list);
	if (ret != 0) {
		fprintf(stderr,
			"Failed to get list of variables from node %u\n",
			ctdb->cmd_pnn);
		return ret;
	}

	found = false;
	for (i=0; i<tun_var_list->count; i++) {
		if (strcasecmp(tun_var_list->var[i], argv[0]) == 0) {
			found = true;
			break;
		}
	}

	if (! found) {
		printf("No such tunable %s\n", argv[0]);
		return 1;
	}

	tunable.name = argv[0];
	tunable.value = smb_strtoul(argv[1], NULL, 0, &ret, SMB_STR_STANDARD);
	if (ret != 0) {
		return ret;
	}

	ret = ctdb_ctrl_set_tunable(mem_ctx, ctdb->ev, ctdb->client,
				    ctdb->cmd_pnn, TIMEOUT(), &tunable);
	if (ret != 0) {
		if (ret == 1) {
			fprintf(stderr,
			        "Setting obsolete tunable variable '%s'\n",
			       tunable.name);
			return 0;
		}
	}

	return ret;
}

static int control_listvars(TALLOC_CTX *mem_ctx, struct ctdb_context *ctdb,
			    int argc, const char **argv)
{
	struct ctdb_var_list *tun_var_list;
	int ret, i;

	if (argc != 0) {
		usage("listvars");
	}

	ret = ctdb_ctrl_list_tunables(mem_ctx, ctdb->ev, ctdb->client,
				      ctdb->cmd_pnn, TIMEOUT(), &tun_var_list);
	if (ret != 0) {
		return ret;
	}

	for (i=0; i<tun_var_list->count; i++) {
		control_getvar(mem_ctx, ctdb, 1, &tun_var_list->var[i]);
	}

	return 0;
}

const struct {
	const char *name;
	uint32_t offset;
} stats_fields[] = {
#define STATISTICS_FIELD(n) { #n, offsetof(struct ctdb_statistics, n) }
	STATISTICS_FIELD(num_clients),
	STATISTICS_FIELD(frozen),
	STATISTICS_FIELD(recovering),
	STATISTICS_FIELD(num_recoveries),
	STATISTICS_FIELD(client_packets_sent),
	STATISTICS_FIELD(client_packets_recv),
	STATISTICS_FIELD(node_packets_sent),
	STATISTICS_FIELD(node_packets_recv),
	STATISTICS_FIELD(keepalive_packets_sent),
	STATISTICS_FIELD(keepalive_packets_recv),
	STATISTICS_FIELD(node.req_call),
	STATISTICS_FIELD(node.reply_call),
	STATISTICS_FIELD(node.req_dmaster),
	STATISTICS_FIELD(node.reply_dmaster),
	STATISTICS_FIELD(node.reply_error),
	STATISTICS_FIELD(node.req_message),
	STATISTICS_FIELD(node.req_control),
	STATISTICS_FIELD(node.reply_control),
	STATISTICS_FIELD(node.req_tunnel),
	STATISTICS_FIELD(client.req_call),
	STATISTICS_FIELD(client.req_message),
	STATISTICS_FIELD(client.req_control),
	STATISTICS_FIELD(client.req_tunnel),
	STATISTICS_FIELD(timeouts.call),
	STATISTICS_FIELD(timeouts.control),
	STATISTICS_FIELD(timeouts.traverse),
	STATISTICS_FIELD(locks.num_calls),
	STATISTICS_FIELD(locks.num_current),
	STATISTICS_FIELD(locks.num_pending),
	STATISTICS_FIELD(locks.num_failed),
	STATISTICS_FIELD(total_calls),
	STATISTICS_FIELD(pending_calls),
	STATISTICS_FIELD(childwrite_calls),
	STATISTICS_FIELD(pending_childwrite_calls),
	STATISTICS_FIELD(memory_used),
	STATISTICS_FIELD(max_hop_count),
	STATISTICS_FIELD(total_ro_delegations),
	STATISTICS_FIELD(total_ro_revokes),
};

#define LATENCY_AVG(v)	((v).num ? (v).total / (v).num : 0.0 )

static void print_statistics_machine(struct ctdb_statistics *s,
				     bool show_header)
{
	size_t i;

	if (show_header) {
		printf("CTDB version%s", options.sep);
		printf("Current time of statistics%s", options.sep);
		printf("Statistics collected since%s", options.sep);
		for (i=0; i<ARRAY_SIZE(stats_fields); i++) {
			printf("%s%s", stats_fields[i].name, options.sep);
		}
		printf("num_reclock_ctdbd_latency%s", options.sep);
		printf("min_reclock_ctdbd_latency%s", options.sep);
		printf("avg_reclock_ctdbd_latency%s", options.sep);
		printf("max_reclock_ctdbd_latency%s", options.sep);

		printf("num_reclock_recd_latency%s", options.sep);
		printf("min_reclock_recd_latency%s", options.sep);
		printf("avg_reclock_recd_latency%s", options.sep);
		printf("max_reclock_recd_latency%s", options.sep);

		printf("num_call_latency%s", options.sep);
		printf("min_call_latency%s", options.sep);
		printf("avg_call_latency%s", options.sep);
		printf("max_call_latency%s", options.sep);

		printf("num_lockwait_latency%s", options.sep);
		printf("min_lockwait_latency%s", options.sep);
		printf("avg_lockwait_latency%s", options.sep);
		printf("max_lockwait_latency%s", options.sep);

		printf("num_childwrite_latency%s", options.sep);
		printf("min_childwrite_latency%s", options.sep);
		printf("avg_childwrite_latency%s", options.sep);
		printf("max_childwrite_latency%s", options.sep);
		printf("\n");
	}

	printf("%u%s", CTDB_PROTOCOL, options.sep);
	printf("%u%s", (uint32_t)s->statistics_current_time.tv_sec, options.sep);
	printf("%u%s", (uint32_t)s->statistics_start_time.tv_sec, options.sep);
	for (i=0;i<ARRAY_SIZE(stats_fields);i++) {
		printf("%u%s",
		       *(uint32_t *)(stats_fields[i].offset+(uint8_t *)s),
		       options.sep);
	}
	printf("%u%s", s->reclock.ctdbd.num, options.sep);
	printf("%.6f%s", s->reclock.ctdbd.min, options.sep);
	printf("%.6f%s", LATENCY_AVG(s->reclock.ctdbd), options.sep);
	printf("%.6f%s", s->reclock.ctdbd.max, options.sep);

	printf("%u%s", s->reclock.recd.num, options.sep);
	printf("%.6f%s", s->reclock.recd.min, options.sep);
	printf("%.6f%s", LATENCY_AVG(s->reclock.recd), options.sep);
	printf("%.6f%s", s->reclock.recd.max, options.sep);

	printf("%d%s", s->call_latency.num, options.sep);
	printf("%.6f%s", s->call_latency.min, options.sep);
	printf("%.6f%s", LATENCY_AVG(s->call_latency), options.sep);
	printf("%.6f%s", s->call_latency.max, options.sep);

	printf("%u%s", s->locks.latency.num, options.sep);
	printf("%.6f%s", s->locks.latency.min, options.sep);
	printf("%.6f%s", LATENCY_AVG(s->locks.latency), options.sep);
	printf("%.6f%s", s->locks.latency.max, options.sep);

	printf("%d%s", s->childwrite_latency.num, options.sep);
	printf("%.6f%s", s->childwrite_latency.min, options.sep);
	printf("%.6f%s", LATENCY_AVG(s->childwrite_latency), options.sep);
	printf("%.6f%s", s->childwrite_latency.max, options.sep);
	printf("\n");
}

static void print_statistics(struct ctdb_statistics *s)
{
	int tmp, days, hours, minutes, seconds;
	size_t i;
	const char *prefix = NULL;
	int preflen = 0;

	tmp = s->statistics_current_time.tv_sec -
	      s->statistics_start_time.tv_sec;
	seconds = tmp % 60; tmp /= 60;
	minutes = tmp % 60; tmp /= 60;
	hours   = tmp % 24; tmp /= 24;
	days    = tmp;

	printf("CTDB version %u\n", CTDB_PROTOCOL);
	printf("Current time of statistics  :                %s",
	       ctime(&s->statistics_current_time.tv_sec));
	printf("Statistics collected since  : (%03d %02d:%02d:%02d) %s",
	       days, hours, minutes, seconds,
	       ctime(&s->statistics_start_time.tv_sec));

	for (i=0; i<ARRAY_SIZE(stats_fields); i++) {
		if (strchr(stats_fields[i].name, '.') != NULL) {
			preflen = strcspn(stats_fields[i].name, ".") + 1;
			if (! prefix ||
			    strncmp(prefix, stats_fields[i].name, preflen) != 0) {
				prefix = stats_fields[i].name;
				printf(" %*.*s\n", preflen-1, preflen-1,
				       stats_fields[i].name);
			}
		} else {
			preflen = 0;
		}
		printf(" %*s%-22s%*s%10u\n", preflen ? 4 : 0, "",
		       stats_fields[i].name+preflen, preflen ? 0 : 4, "",
		       *(uint32_t *)(stats_fields[i].offset+(uint8_t *)s));
	}

	printf(" hop_count_buckets:");
	for (i=0; i<MAX_COUNT_BUCKETS; i++) {
		printf(" %d", s->hop_count_bucket[i]);
	}
	printf("\n");
	printf(" lock_buckets:");
	for (i=0; i<MAX_COUNT_BUCKETS; i++) {
		printf(" %d", s->locks.buckets[i]);
	}
	printf("\n");
	printf(" %-30s     %.6f/%.6f/%.6f sec out of %d\n",
	       "locks_latency      MIN/AVG/MAX",
	       s->locks.latency.min, LATENCY_AVG(s->locks.latency),
	       s->locks.latency.max, s->locks.latency.num);

	printf(" %-30s     %.6f/%.6f/%.6f sec out of %d\n",
	       "reclock_ctdbd      MIN/AVG/MAX",
	       s->reclock.ctdbd.min, LATENCY_AVG(s->reclock.ctdbd),
	       s->reclock.ctdbd.max, s->reclock.ctdbd.num);

	printf(" %-30s     %.6f/%.6f/%.6f sec out of %d\n",
	       "reclock_recd       MIN/AVG/MAX",
	       s->reclock.recd.min, LATENCY_AVG(s->reclock.recd),
	       s->reclock.recd.max, s->reclock.recd.num);

	printf(" %-30s     %.6f/%.6f/%.6f sec out of %d\n",
	       "call_latency       MIN/AVG/MAX",
	       s->call_latency.min, LATENCY_AVG(s->call_latency),
	       s->call_latency.max, s->call_latency.num);

	printf(" %-30s     %.6f/%.6f/%.6f sec out of %d\n",
	       "childwrite_latency MIN/AVG/MAX",
	       s->childwrite_latency.min,
	       LATENCY_AVG(s->childwrite_latency),
	       s->childwrite_latency.max, s->childwrite_latency.num);
}

static int control_statistics(TALLOC_CTX *mem_ctx, struct ctdb_context *ctdb,
			      int argc, const char **argv)
{
	struct ctdb_statistics *stats;
	int ret;

	if (argc != 0) {
		usage("statistics");
	}

	ret = ctdb_ctrl_statistics(mem_ctx, ctdb->ev, ctdb->client,
				   ctdb->cmd_pnn, TIMEOUT(), &stats);
	if (ret != 0) {
		return ret;
	}

	if (options.machinereadable) {
		print_statistics_machine(stats, true);
	} else {
		print_statistics(stats);
	}

	return 0;
}

static int control_statistics_reset(TALLOC_CTX *mem_ctx,
				    struct ctdb_context *ctdb,
				    int argc, const char **argv)
{
	int ret;

	if (argc != 0) {
		usage("statisticsreset");
	}

	ret = ctdb_ctrl_statistics_reset(mem_ctx, ctdb->ev, ctdb->client,
					 ctdb->cmd_pnn, TIMEOUT());
	if (ret != 0) {
		return ret;
	}

	return 0;
}

static int control_stats(TALLOC_CTX *mem_ctx, struct ctdb_context *ctdb,
			 int argc, const char **argv)
{
	struct ctdb_statistics_list *slist;
	int ret, count = 0, i;
	bool show_header = true;

	if (argc > 1) {
		usage("stats");
	}

	if (argc == 1) {
		count = atoi(argv[0]);
	}

	ret = ctdb_ctrl_get_stat_history(mem_ctx, ctdb->ev, ctdb->client,
					 ctdb->cmd_pnn, TIMEOUT(), &slist);
	if (ret != 0) {
		return ret;
	}

	for (i=0; i<slist->num; i++) {
		if (slist->stats[i].statistics_start_time.tv_sec == 0) {
			continue;
		}
		if (options.machinereadable == 1) {
			print_statistics_machine(&slist->stats[i],
						 show_header);
			show_header = false;
		} else {
			print_statistics(&slist->stats[i]);
		}
		if (count > 0 && i == count) {
			break;
		}
	}

	return 0;
}

static int ctdb_public_ip_cmp(const void *a, const void *b)
{
	const struct ctdb_public_ip *ip_a = a;
	const struct ctdb_public_ip *ip_b = b;

	return ctdb_sock_addr_cmp(&ip_a->addr, &ip_b->addr);
}

static void print_ip(TALLOC_CTX *mem_ctx, struct ctdb_context *ctdb,
		     struct ctdb_public_ip_list *ips,
		     struct ctdb_public_ip_info **ipinfo,
		     bool all_nodes)
{
	unsigned int i, j;
	char *conf, *avail, *active;

	if (options.machinereadable == 1) {
		printf("%s%s%s%s%s", options.sep,
		       "Public IP", options.sep,
		       "Node", options.sep);
		if (options.verbose == 1) {
			printf("%s%s%s%s%s%s\n",
			       "ActiveInterfaces", options.sep,
			       "AvailableInterfaces", options.sep,
			       "ConfiguredInterfaces", options.sep);
		} else {
			printf("\n");
		}
	} else {
		if (all_nodes) {
			printf("Public IPs on ALL nodes\n");
		} else {
			printf("Public IPs on node %u\n", ctdb->cmd_pnn);
		}
	}

	for (i = 0; i < ips->num; i++) {

		if (options.machinereadable == 1) {
			printf("%s%s%s%d%s", options.sep,
			       ctdb_sock_addr_to_string(
				       mem_ctx, &ips->ip[i].addr, false),
			       options.sep,
			       (int)ips->ip[i].pnn, options.sep);
		} else {
			printf("%s", ctdb_sock_addr_to_string(
				       mem_ctx, &ips->ip[i].addr, false));
		}

		if (options.verbose == 0) {
			if (options.machinereadable == 1) {
				printf("\n");
			} else {
				printf(" %d\n", (int)ips->ip[i].pnn);
			}
			continue;
		}

		conf = NULL;
		avail = NULL;
		active = NULL;

		if (ipinfo[i] == NULL) {
			goto skip_ipinfo;
		}

		for (j=0; j<ipinfo[i]->ifaces->num; j++) {
			struct ctdb_iface *iface;

			iface = &ipinfo[i]->ifaces->iface[j];
			if (conf == NULL) {
				conf = talloc_strdup(mem_ctx, iface->name);
			} else {
				conf = talloc_asprintf_append(
						conf, ",%s", iface->name);
			}

			if (ipinfo[i]->active_idx == j) {
				active = iface->name;
			}

			if (iface->link_state == 0) {
				continue;
			}

			if (avail == NULL) {
				avail = talloc_strdup(mem_ctx, iface->name);
			} else {
				avail = talloc_asprintf_append(
						avail, ",%s", iface->name);
			}
		}

	skip_ipinfo:

		if (options.machinereadable == 1) {
			printf("%s%s%s%s%s%s\n",
			       active ? active : "", options.sep,
			       avail ? avail : "", options.sep,
			       conf ? conf : "", options.sep);
		} else {
			printf(" node[%d] active[%s] available[%s]"
			       " configured[%s]\n",
			       (int)ips->ip[i].pnn, active ? active : "",
			       avail ? avail : "", conf ? conf : "");
		}
	}
}

static int collect_ips(uint8_t *keybuf, size_t keylen, uint8_t *databuf,
		       size_t datalen, void *private_data)
{
	struct ctdb_public_ip_list *ips = talloc_get_type_abort(
		private_data, struct ctdb_public_ip_list);
	struct ctdb_public_ip *ip;

	ip = (struct ctdb_public_ip *)databuf;
	ips->ip[ips->num] = *ip;
	ips->num += 1;

	return 0;
}

static int get_all_public_ips(struct ctdb_context *ctdb, TALLOC_CTX *mem_ctx,
			      struct ctdb_public_ip_list **out)
{
	struct ctdb_node_map *nodemap;
	struct ctdb_public_ip_list *ips;
	struct db_hash_context *ipdb;
	uint32_t *pnn_list;
	unsigned int j;
	int ret, count, i;

	nodemap = get_nodemap(ctdb, false);
	if (nodemap == NULL) {
		return 1;
	}

	ret = db_hash_init(mem_ctx, "ips", 101, DB_HASH_COMPLEX, &ipdb);
	if (ret != 0) {
		goto failed;
	}

	count = list_of_active_nodes(nodemap, CTDB_UNKNOWN_PNN, mem_ctx,
				     &pnn_list);
	if (count <= 0) {
		goto failed;
	}

	for (i=0; i<count; i++) {
		ret = ctdb_ctrl_get_public_ips(mem_ctx, ctdb->ev, ctdb->client,
					       pnn_list[i], TIMEOUT(),
					       false, &ips);
		if (ret != 0) {
			goto failed;
		}

		for (j=0; j<ips->num; j++) {
			struct ctdb_public_ip ip;

			ip.pnn = ips->ip[j].pnn;
			ip.addr = ips->ip[j].addr;

			if (pnn_list[i] == ip.pnn) {
				/* Node claims IP is hosted on it, so
				 * save that information
				 */
				ret = db_hash_add(ipdb, (uint8_t *)&ip.addr,
						  sizeof(ip.addr),
						  (uint8_t *)&ip, sizeof(ip));
				if (ret != 0) {
					goto failed;
				}
			} else {
				/* Node thinks IP is hosted elsewhere,
				 * so overwrite with CTDB_UNKNOWN_PNN
				 * if there's no existing entry
				 */
				ret = db_hash_exists(ipdb, (uint8_t *)&ip.addr,
						     sizeof(ip.addr));
				if (ret == ENOENT) {
					ip.pnn = CTDB_UNKNOWN_PNN;
					ret = db_hash_add(ipdb,
							  (uint8_t *)&ip.addr,
							  sizeof(ip.addr),
							  (uint8_t *)&ip,
							  sizeof(ip));
					if (ret != 0) {
						goto failed;
					}
				}
			}
		}

		TALLOC_FREE(ips);
	}

	talloc_free(pnn_list);

	ret = db_hash_traverse(ipdb, NULL, NULL, &count);
	if (ret != 0) {
		goto failed;
	}

	ips = talloc_zero(mem_ctx, struct ctdb_public_ip_list);
	if (ips == NULL) {
		goto failed;
	}

	ips->ip = talloc_array(ips, struct ctdb_public_ip, count);
	if (ips->ip == NULL) {
		goto failed;
	}

	ret = db_hash_traverse(ipdb, collect_ips, ips, &count);
	if (ret != 0) {
		goto failed;
	}

	if ((unsigned int)count != ips->num) {
		goto failed;
	}

	talloc_free(ipdb);

	*out = ips;
	return 0;

failed:
	talloc_free(ipdb);
	return 1;
}

static int control_ip(TALLOC_CTX *mem_ctx, struct ctdb_context *ctdb,
		      int argc, const char **argv)
{
	struct ctdb_public_ip_list *ips;
	struct ctdb_public_ip_info **ipinfo;
	unsigned int i;
	int ret;
	bool do_all = false;

	if (argc > 1) {
		usage("ip");
	}

	if (argc == 1) {
		if (strcmp(argv[0], "all") == 0) {
			do_all = true;
		} else {
			usage("ip");
		}
	}

	if (do_all) {
		ret = get_all_public_ips(ctdb, mem_ctx, &ips);
	} else {
		ret = ctdb_ctrl_get_public_ips(mem_ctx, ctdb->ev, ctdb->client,
					       ctdb->cmd_pnn, TIMEOUT(),
					       false, &ips);
	}
	if (ret != 0) {
		return ret;
	}

	qsort(ips->ip, ips->num, sizeof(struct ctdb_public_ip),
	      ctdb_public_ip_cmp);

	ipinfo = talloc_array(mem_ctx, struct ctdb_public_ip_info *, ips->num);
	if (ipinfo == NULL) {
		return 1;
	}

	for (i=0; i<ips->num; i++) {
		uint32_t pnn;
		if (do_all) {
			pnn = ips->ip[i].pnn;
		} else {
			pnn = ctdb->cmd_pnn;
		}
		if (pnn == CTDB_UNKNOWN_PNN) {
			ipinfo[i] = NULL;
			continue;
		}
		ret = ctdb_ctrl_get_public_ip_info(mem_ctx, ctdb->ev,
						   ctdb->client, pnn,
						   TIMEOUT(), &ips->ip[i].addr,
						   &ipinfo[i]);
		if (ret != 0) {
			return ret;
		}
	}

	print_ip(mem_ctx, ctdb, ips, ipinfo, do_all);
	return 0;
}

static int control_ipinfo(TALLOC_CTX *mem_ctx, struct ctdb_context *ctdb,
			  int argc, const char **argv)
{
	struct ctdb_public_ip_info *ipinfo;
	ctdb_sock_addr addr;
	unsigned int i;
	int ret;

	if (argc != 1) {
		usage("ipinfo");
	}

	ret = ctdb_sock_addr_from_string(argv[0], &addr, false);
	if (ret != 0) {
		fprintf(stderr, "Invalid IP address %s\n", argv[0]);
		return 1;
	}

	ret = ctdb_ctrl_get_public_ip_info(mem_ctx, ctdb->ev, ctdb->client,
					   ctdb->cmd_pnn, TIMEOUT(), &addr,
					   &ipinfo);
	if (ret != 0) {
		if (ret == -1) {
			printf("Node %u does not know about IP %s\n",
			       ctdb->cmd_pnn, argv[0]);
		}
		return ret;
	}

	printf("Public IP[%s] info on node %u\n",
	       ctdb_sock_addr_to_string(mem_ctx, &ipinfo->ip.addr, false),
					ctdb->cmd_pnn);

	printf("IP:%s\nCurrentNode:%u\nNumInterfaces:%u\n",
	       ctdb_sock_addr_to_string(mem_ctx, &ipinfo->ip.addr, false),
	       ipinfo->ip.pnn, ipinfo->ifaces->num);

	for (i=0; i<ipinfo->ifaces->num; i++) {
		struct ctdb_iface *iface;

		iface = &ipinfo->ifaces->iface[i];
		iface->name[CTDB_IFACE_SIZE] = '\0';
		printf("Interface[%u]: Name:%s Link:%s References:%u%s\n",
		       i+1, iface->name,
		       iface->link_state == 0 ? "down" : "up",
		       iface->references,
		       (i == ipinfo->active_idx) ? " (active)" : "");
	}

	return 0;
}

static int control_ifaces(TALLOC_CTX *mem_ctx, struct ctdb_context *ctdb,
			  int argc, const char **argv)
{
	struct ctdb_iface_list *ifaces;
	unsigned int i;
	int ret;

	if (argc != 0) {
		usage("ifaces");
	}

	ret = ctdb_ctrl_get_ifaces(mem_ctx, ctdb->ev, ctdb->client,
				   ctdb->cmd_pnn, TIMEOUT(), &ifaces);
	if (ret != 0) {
		return ret;
	}

	if (ifaces->num == 0) {
		printf("No interfaces configured on node %u\n",
		       ctdb->cmd_pnn);
		return 0;
	}

	if (options.machinereadable) {
		printf("%s%s%s%s%s%s%s\n", options.sep,
		       "Name", options.sep,
		       "LinkStatus", options.sep,
		       "References", options.sep);
	} else {
		printf("Interfaces on node %u\n", ctdb->cmd_pnn);
	}

	for (i=0; i<ifaces->num; i++) {
		if (options.machinereadable) {
			printf("%s%s%s%u%s%u%s\n", options.sep,
			       ifaces->iface[i].name, options.sep,
			       ifaces->iface[i].link_state, options.sep,
			       ifaces->iface[i].references, options.sep);
		} else {
			printf("name:%s link:%s references:%u\n",
			       ifaces->iface[i].name,
			       ifaces->iface[i].link_state ? "up" : "down",
			       ifaces->iface[i].references);
		}
	}

	return 0;
}

static int control_setifacelink(TALLOC_CTX *mem_ctx, struct ctdb_context *ctdb,
				int argc, const char **argv)
{
	struct ctdb_iface_list *ifaces;
	struct ctdb_iface *iface;
	unsigned int i;
	int ret;

	if (argc != 2) {
		usage("setifacelink");
	}

	if (strlen(argv[0]) > CTDB_IFACE_SIZE) {
		fprintf(stderr, "Interface name '%s' too long\n", argv[0]);
		return 1;
	}

	ret = ctdb_ctrl_get_ifaces(mem_ctx, ctdb->ev, ctdb->client,
				   ctdb->cmd_pnn, TIMEOUT(), &ifaces);
	if (ret != 0) {
		fprintf(stderr,
			"Failed to get interface information from node %u\n",
			ctdb->cmd_pnn);
		return ret;
	}

	iface = NULL;
	for (i=0; i<ifaces->num; i++) {
		if (strcmp(ifaces->iface[i].name, argv[0]) == 0) {
			iface = &ifaces->iface[i];
			break;
		}
	}

	if (iface == NULL) {
		printf("Interface %s not configured on node %u\n",
		       argv[0], ctdb->cmd_pnn);
		return 1;
	}

	if (strcmp(argv[1], "up") == 0) {
		iface->link_state = 1;
	} else if (strcmp(argv[1], "down") == 0) {
		iface->link_state = 0;
	} else {
		usage("setifacelink");
		return 1;
	}

	iface->references = 0;

	ret = ctdb_ctrl_set_iface_link_state(mem_ctx, ctdb->ev, ctdb->client,
					     ctdb->cmd_pnn, TIMEOUT(), iface);
	if (ret != 0) {
		return ret;
	}

	return 0;
}

static int control_process_exists(TALLOC_CTX *mem_ctx,
				  struct ctdb_context *ctdb,
				  int argc, const char **argv)
{
	pid_t pid;
	uint64_t srvid = 0;
	int status;
	int ret = 0;

	if (argc != 1 && argc != 2) {
		usage("process-exists");
	}

	pid = atoi(argv[0]);
	if (argc == 2) {
		srvid = smb_strtoull(argv[1], NULL, 0, &ret, SMB_STR_STANDARD);
		if (ret != 0) {
			return ret;
		}
	}

	if (srvid == 0) {
		ret = ctdb_ctrl_process_exists(mem_ctx, ctdb->ev, ctdb->client,
				       ctdb->cmd_pnn, TIMEOUT(), pid, &status);
	} else {
		struct ctdb_pid_srvid pid_srvid;

		pid_srvid.pid = pid;
		pid_srvid.srvid = srvid;

		ret = ctdb_ctrl_check_pid_srvid(mem_ctx, ctdb->ev,
						ctdb->client, ctdb->cmd_pnn,
						TIMEOUT(), &pid_srvid,
						&status);
	}

	if (ret != 0) {
		return ret;
	}

	if (srvid == 0) {
		printf("PID %d %s\n", pid,
		       (status == 0 ? "exists" : "does not exist"));
	} else {
		printf("PID %d with SRVID 0x%"PRIx64" %s\n", pid, srvid,
		       (status == 0 ? "exists" : "does not exist"));
	}
	return status;
}

static int control_getdbmap(TALLOC_CTX *mem_ctx, struct ctdb_context *ctdb,
			    int argc, const char **argv)
{
	struct ctdb_dbid_map *dbmap;
	unsigned int i;
	int ret;

	if (argc != 0) {
		usage("getdbmap");
	}

	ret = ctdb_ctrl_get_dbmap(mem_ctx, ctdb->ev, ctdb->client,
				  ctdb->cmd_pnn, TIMEOUT(), &dbmap);
	if (ret != 0) {
		return ret;
	}

	if (options.machinereadable == 1) {
		printf("%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s\n",
		       options.sep,
		       "ID", options.sep,
		       "Name", options.sep,
		       "Path", options.sep,
		       "Persistent", options.sep,
		       "Sticky", options.sep,
		       "Unhealthy", options.sep,
		       "Readonly", options.sep,
		       "Replicated", options.sep);
	} else {
		printf("Number of databases:%d\n", dbmap->num);
	}

	for (i=0; i<dbmap->num; i++) {
		const char *name;
		const char *path;
		const char *health;
		bool persistent;
		bool readonly;
		bool sticky;
		bool replicated;
		uint32_t db_id;

		db_id = dbmap->dbs[i].db_id;

		ret = ctdb_ctrl_get_dbname(mem_ctx, ctdb->ev, ctdb->client,
					   ctdb->cmd_pnn, TIMEOUT(), db_id,
					   &name);
		if (ret != 0) {
			return ret;
		}

		ret = ctdb_ctrl_getdbpath(mem_ctx, ctdb->ev, ctdb->client,
					  ctdb->cmd_pnn, TIMEOUT(), db_id,
					  &path);
		if (ret != 0) {
			return ret;
		}

		ret = ctdb_ctrl_db_get_health(mem_ctx, ctdb->ev, ctdb->client,
					      ctdb->cmd_pnn, TIMEOUT(), db_id,
					      &health);
		if (ret != 0) {
			return ret;
		}

		persistent = dbmap->dbs[i].flags & CTDB_DB_FLAGS_PERSISTENT;
		readonly = dbmap->dbs[i].flags & CTDB_DB_FLAGS_READONLY;
		sticky = dbmap->dbs[i].flags & CTDB_DB_FLAGS_STICKY;
		replicated = dbmap->dbs[i].flags & CTDB_DB_FLAGS_REPLICATED;

		if (options.machinereadable == 1) {
			printf("%s0x%08X%s%s%s%s%s%d%s%d%s%d%s%d%s%d%s\n",
			       options.sep,
			       db_id, options.sep,
			       name, options.sep,
			       path, options.sep,
			       !! (persistent), options.sep,
			       !! (sticky), options.sep,
			       !! (health), options.sep,
			       !! (readonly), options.sep,
			       !! (replicated), options.sep);
		} else {
			printf("dbid:0x%08x name:%s path:%s%s%s%s%s%s\n",
			       db_id, name, path,
			       persistent ? " PERSISTENT" : "",
			       sticky ? " STICKY" : "",
			       readonly ? " READONLY" : "",
			       replicated ? " REPLICATED" : "",
			       health ? " UNHEALTHY" : "");
		}

		talloc_free(discard_const(name));
		talloc_free(discard_const(path));
		talloc_free(discard_const(health));
	}

	return 0;
}

static int control_getdbstatus(TALLOC_CTX *mem_ctx, struct ctdb_context *ctdb,
			       int argc, const char **argv)
{
	uint32_t db_id;
	const char *db_name, *db_path, *db_health;
	uint8_t db_flags;
	int ret;

	if (argc != 1) {
		usage("getdbstatus");
	}

	if (! db_exists(mem_ctx, ctdb, argv[0], &db_id, &db_name, &db_flags)) {
		return 1;
	}

	ret = ctdb_ctrl_getdbpath(mem_ctx, ctdb->ev, ctdb->client,
				  ctdb->cmd_pnn, TIMEOUT(), db_id,
				  &db_path);
	if (ret != 0) {
		return ret;
	}

	ret = ctdb_ctrl_db_get_health(mem_ctx, ctdb->ev, ctdb->client,
				      ctdb->cmd_pnn, TIMEOUT(), db_id,
				      &db_health);
	if (ret != 0) {
		return ret;
	}

	printf("dbid: 0x%08x\nname: %s\npath: %s\n", db_id, db_name, db_path);
	printf("PERSISTENT: %s\nREPLICATED: %s\nSTICKY: %s\nREADONLY: %s\n",
	       (db_flags & CTDB_DB_FLAGS_PERSISTENT ? "yes" : "no"),
	       (db_flags & CTDB_DB_FLAGS_REPLICATED ? "yes" : "no"),
	       (db_flags & CTDB_DB_FLAGS_STICKY ? "yes" : "no"),
	       (db_flags & CTDB_DB_FLAGS_READONLY ? "yes" : "no"));
	printf("HEALTH: %s\n", (db_health ? db_health : "OK"));
	return 0;
}

struct dump_record_state {
	uint32_t count;
};

#define ISASCII(x) (isprint(x) && ! strchr("\"\\", (x)))

static void dump_tdb_data(const char *name, TDB_DATA val)
{
	size_t i;

	fprintf(stdout, "%s(%zu) = \"", name, val.dsize);
	for (i=0; i<val.dsize; i++) {
		if (ISASCII(val.dptr[i])) {
			fprintf(stdout, "%c", val.dptr[i]);
		} else {
			fprintf(stdout, "\\%02X", val.dptr[i]);
		}
	}
	fprintf(stdout, "\"\n");
}

static void dump_ltdb_header(struct ctdb_ltdb_header *header)
{
	fprintf(stdout, "dmaster: %u\n", header->dmaster);
	fprintf(stdout, "rsn: %" PRIu64 "\n", header->rsn);
	fprintf(stdout, "flags: 0x%08x", header->flags);
	if (header->flags & CTDB_REC_FLAG_MIGRATED_WITH_DATA) {
		fprintf(stdout, " MIGRATED_WITH_DATA");
	}
	if (header->flags & CTDB_REC_FLAG_VACUUM_MIGRATED) {
		fprintf(stdout, " VACUUM_MIGRATED");
	}
	if (header->flags & CTDB_REC_FLAG_AUTOMATIC) {
		fprintf(stdout, " AUTOMATIC");
	}
	if (header->flags & CTDB_REC_RO_HAVE_DELEGATIONS) {
		fprintf(stdout, " RO_HAVE_DELEGATIONS");
	}
	if (header->flags & CTDB_REC_RO_HAVE_READONLY) {
		fprintf(stdout, " RO_HAVE_READONLY");
	}
	if (header->flags & CTDB_REC_RO_REVOKING_READONLY) {
		fprintf(stdout, " RO_REVOKING_READONLY");
	}
	if (header->flags & CTDB_REC_RO_REVOKE_COMPLETE) {
		fprintf(stdout, " RO_REVOKE_COMPLETE");
	}
	fprintf(stdout, "\n");

}

static int dump_record(uint32_t reqid, struct ctdb_ltdb_header *header,
		       TDB_DATA key, TDB_DATA data, void *private_data)
{
	struct dump_record_state *state =
		(struct dump_record_state *)private_data;

	state->count += 1;

	dump_tdb_data("key", key);
	dump_ltdb_header(header);
	dump_tdb_data("data", data);
	fprintf(stdout, "\n");

	return 0;
}

static int control_catdb(TALLOC_CTX *mem_ctx, struct ctdb_context *ctdb,
			 int argc, const char **argv)
{
	struct ctdb_db_context *db;
	const char *db_name;
	uint32_t db_id;
	uint8_t db_flags;
	struct dump_record_state state;
	int ret;

	if (argc != 1) {
		usage("catdb");
	}

	if (! db_exists(mem_ctx, ctdb, argv[0], &db_id, &db_name, &db_flags)) {
		return 1;
	}

	ret = ctdb_attach(ctdb->ev, ctdb->client, TIMEOUT(), db_name,
			  db_flags, &db);
	if (ret != 0) {
		fprintf(stderr, "Failed to attach to DB %s\n", db_name);
		return ret;
	}

	state.count = 0;

	ret = ctdb_db_traverse(mem_ctx, ctdb->ev, ctdb->client, db,
			       ctdb->cmd_pnn, TIMEOUT(),
			       dump_record, &state);

	printf("Dumped %u records\n", state.count);

	return ret;
}

static int control_cattdb(TALLOC_CTX *mem_ctx, struct ctdb_context *ctdb,
			  int argc, const char **argv)
{
	struct ctdb_db_context *db;
	const char *db_name;
	uint32_t db_id;
	uint8_t db_flags;
	struct dump_record_state state;
	int ret;

	if (argc != 1) {
		usage("cattdb");
	}

	if (! db_exists(mem_ctx, ctdb, argv[0], &db_id, &db_name, &db_flags)) {
		return 1;
	}

	ret = ctdb_attach(ctdb->ev, ctdb->client, TIMEOUT(), db_name,
			  db_flags, &db);
	if (ret != 0) {
		fprintf(stderr, "Failed to attach to DB %s\n", db_name);
		return ret;
	}

	state.count = 0;
	ret = ctdb_db_traverse_local(db, true, true, dump_record, &state);

	printf("Dumped %u record(s)\n", state.count);

	return ret;
}

static int control_getcapabilities(TALLOC_CTX *mem_ctx,
				   struct ctdb_context *ctdb,
				   int argc, const char **argv)
{
	uint32_t caps;
	int ret;

	if (argc != 0) {
		usage("getcapabilities");
	}

	ret = ctdb_ctrl_get_capabilities(mem_ctx, ctdb->ev, ctdb->client,
					 ctdb->cmd_pnn, TIMEOUT(), &caps);
	if (ret != 0) {
		return ret;
	}

	if (options.machinereadable == 1) {
		printf("%s%s%s%s%s\n",
		       options.sep,
		       "RECMASTER", options.sep,
		       "LMASTER", options.sep);
		printf("%s%d%s%d%s\n", options.sep,
		       !! (caps & CTDB_CAP_RECMASTER), options.sep,
		       !! (caps & CTDB_CAP_LMASTER), options.sep);
	} else {
		printf("RECMASTER: %s\n",
		       (caps & CTDB_CAP_RECMASTER) ? "YES" : "NO");
		printf("LMASTER: %s\n",
		       (caps & CTDB_CAP_LMASTER) ? "YES" : "NO");
	}

	return 0;
}

static int control_pnn(TALLOC_CTX *mem_ctx, struct ctdb_context *ctdb,
		       int argc, const char **argv)
{
	printf("%u\n", ctdb_client_pnn(ctdb->client));
	return 0;
}

static int control_lvs(TALLOC_CTX *mem_ctx, struct ctdb_context *ctdb,
		       int argc, const char **argv)
{
	char *t, *lvs_helper = NULL;

	if (argc != 1) {
		usage("lvs");
	}

	t = getenv("CTDB_LVS_HELPER");
	if (t != NULL) {
		lvs_helper = talloc_strdup(mem_ctx, t);
	} else {
		lvs_helper = talloc_asprintf(mem_ctx, "%s/ctdb_lvs",
					     CTDB_HELPER_BINDIR);
	}

	if (lvs_helper == NULL) {
		fprintf(stderr, "Unable to set LVS helper\n");
		return 1;
	}

	return run_helper(mem_ctx, "LVS helper", lvs_helper, argc, argv);
}

static int control_setdebug(TALLOC_CTX *mem_ctx, struct ctdb_context *ctdb,
			    int argc, const char **argv)
{
	int log_level;
	int ret;
	bool found;

	if (argc != 1) {
		usage("setdebug");
	}

	found = debug_level_parse(argv[0], &log_level);
	if (! found) {
		fprintf(stderr,
			"Invalid debug level '%s'. Valid levels are:\n",
			argv[0]);
		fprintf(stderr, "\tERROR | WARNING | NOTICE | INFO | DEBUG\n");
		return 1;
	}

	ret = ctdb_ctrl_setdebug(mem_ctx, ctdb->ev, ctdb->client,
				 ctdb->cmd_pnn, TIMEOUT(), log_level);
	if (ret != 0) {
		return ret;
	}

	return 0;
}

static int control_getdebug(TALLOC_CTX *mem_ctx, struct ctdb_context *ctdb,
			    int argc, const char **argv)
{
	int loglevel;
	const char *log_str;
	int ret;

	if (argc != 0) {
		usage("getdebug");
	}

	ret = ctdb_ctrl_getdebug(mem_ctx, ctdb->ev, ctdb->client,
				 ctdb->cmd_pnn, TIMEOUT(), &loglevel);
	if (ret != 0) {
		return ret;
	}

	log_str = debug_level_to_string(loglevel);
	printf("%s\n", log_str);

	return 0;
}

static int control_attach(TALLOC_CTX *mem_ctx, struct ctdb_context *ctdb,
			  int argc, const char **argv)
{
	const char *db_name;
	uint8_t db_flags = 0;
	int ret;

	if (argc < 1 || argc > 2) {
		usage("attach");
	}

	db_name = argv[0];
	if (argc == 2) {
		if (strcmp(argv[1], "persistent") == 0) {
			db_flags = CTDB_DB_FLAGS_PERSISTENT;
		} else if (strcmp(argv[1], "readonly") == 0) {
			db_flags = CTDB_DB_FLAGS_READONLY;
		} else if (strcmp(argv[1], "sticky") == 0) {
			db_flags = CTDB_DB_FLAGS_STICKY;
		} else if (strcmp(argv[1], "replicated") == 0) {
			db_flags = CTDB_DB_FLAGS_REPLICATED;
		} else {
			usage("attach");
		}
	}

	ret = ctdb_attach(ctdb->ev, ctdb->client, TIMEOUT(), db_name,
			  db_flags, NULL);
	if (ret != 0) {
		return ret;
	}

	return 0;
}

static int control_detach(TALLOC_CTX *mem_ctx, struct ctdb_context *ctdb,
			  int argc, const char **argv)
{
	const char *db_name;
	uint32_t db_id;
	uint8_t db_flags;
	struct ctdb_node_map *nodemap;
	int recmode;
	unsigned int j;
	int ret, ret2, i;

	if (argc < 1) {
		usage("detach");
	}

	ret = ctdb_ctrl_get_recmode(mem_ctx, ctdb->ev, ctdb->client,
				    ctdb->cmd_pnn, TIMEOUT(), &recmode);
	if (ret != 0) {
		return ret;
	}

	if (recmode == CTDB_RECOVERY_ACTIVE) {
		fprintf(stderr, "Database cannot be detached"
				" when recovery is active\n");
		return 1;
	}

	nodemap = get_nodemap(ctdb, false);
	if (nodemap == NULL) {
		return 1;
	}

	for (j=0; j<nodemap->num; j++) {
		uint32_t value;

		if (nodemap->node[j].flags & NODE_FLAGS_DISCONNECTED) {
			continue;
		}
		if (nodemap->node[j].flags & NODE_FLAGS_DELETED) {
			continue;
		}
		if (nodemap->node[j].flags & NODE_FLAGS_INACTIVE) {
			fprintf(stderr, "Database cannot be detached on"
				" inactive (stopped or banned) node %u\n",
				nodemap->node[j].pnn);
			return 1;
		}

		ret = ctdb_ctrl_get_tunable(mem_ctx, ctdb->ev, ctdb->client,
					    nodemap->node[j].pnn, TIMEOUT(),
					    "AllowClientDBAttach", &value);
		if (ret != 0) {
			fprintf(stderr,
				"Unable to get tunable AllowClientDBAttach"
			        " from node %u\n", nodemap->node[j].pnn);
			return ret;
		}

		if (value == 1) {
			fprintf(stderr,
				"Database access is still active on node %u."
			        " Set AllowclientDBAttach=0 on all nodes.\n",
				nodemap->node[j].pnn);
			return 1;
		}
	}

	ret2 = 0;
	for (i=0; i<argc; i++) {
		if (! db_exists(mem_ctx, ctdb, argv[i], &db_id, &db_name,
				&db_flags)) {
			continue;
		}

		if (db_flags &
		    (CTDB_DB_FLAGS_PERSISTENT | CTDB_DB_FLAGS_REPLICATED)) {
			fprintf(stderr,
			        "Only volatile databases can be detached\n");
			return 1;
		}

		ret = ctdb_detach(ctdb->ev, ctdb->client, TIMEOUT(), db_id);
		if (ret != 0) {
			fprintf(stderr, "Database %s detach failed\n", db_name);
			ret2 = ret;
		}
	}

	return ret2;
}

static int control_dumpmemory(TALLOC_CTX *mem_ctx, struct ctdb_context *ctdb,
			      int argc, const char **argv)
{
	const char *mem_str;
	ssize_t n;
	int ret;

	ret = ctdb_ctrl_dump_memory(mem_ctx, ctdb->ev, ctdb->client,
				    ctdb->cmd_pnn, TIMEOUT(), &mem_str);
	if (ret != 0) {
		return ret;
	}

	n = write(1, mem_str, strlen(mem_str));
	if (n < 0 || (size_t)n != strlen(mem_str)) {
		fprintf(stderr, "Failed to write talloc summary\n");
		return 1;
	}

	return 0;
}

static void dump_memory(uint64_t srvid, TDB_DATA data, void *private_data)
{
	bool *done = (bool *)private_data;
	size_t len;
	ssize_t n;

	len = strnlen((const char *)data.dptr, data.dsize);
	n = write(1, data.dptr, len);
	if (n < 0 || (size_t)n != len) {
		fprintf(stderr, "Failed to write talloc summary\n");
	}

	*done = true;
}

static int control_rddumpmemory(TALLOC_CTX *mem_ctx, struct ctdb_context *ctdb,
				int argc, const char **argv)
{
	struct ctdb_srvid_message msg = { 0 };
	int ret;
	bool done = false;

	msg.pnn = ctdb->pnn;
	msg.srvid = next_srvid(ctdb);

	ret = ctdb_client_set_message_handler(ctdb->ev, ctdb->client,
					      msg.srvid, dump_memory, &done);
	if (ret != 0) {
		return ret;
	}

	ret = ctdb_message_mem_dump(mem_ctx, ctdb->ev, ctdb->client,
				    ctdb->cmd_pnn, &msg);
	if (ret != 0) {
		return ret;
	}

	ctdb_client_wait(ctdb->ev, &done);
	return 0;
}

static int control_getpid(TALLOC_CTX *mem_ctx, struct ctdb_context *ctdb,
			  int argc, const char **argv)
{
	pid_t pid;
	int ret;

	ret = ctdb_ctrl_get_pid(mem_ctx, ctdb->ev, ctdb->client,
				ctdb->cmd_pnn, TIMEOUT(), &pid);
	if (ret != 0) {
		return ret;
	}

	printf("%u\n", pid);
	return 0;
}

static int check_flags(TALLOC_CTX *mem_ctx, struct ctdb_context *ctdb,
		       const char *desc, uint32_t flag, bool set_flag)
{
	struct ctdb_node_map *nodemap;
	bool flag_is_set;

	nodemap = get_nodemap(ctdb, false);
	if (nodemap == NULL) {
		return 1;
	}

	flag_is_set = nodemap->node[ctdb->cmd_pnn].flags & flag;
	if (set_flag == flag_is_set) {
		if (set_flag) {
			fprintf(stderr, "Node %u is already %s\n",
				ctdb->cmd_pnn, desc);
		} else {
			fprintf(stderr, "Node %u is not %s\n",
				ctdb->cmd_pnn, desc);
		}
		return 0;
	}

	return 1;
}

static void wait_for_flags(TALLOC_CTX *mem_ctx, struct ctdb_context *ctdb,
			   uint32_t flag, bool set_flag)
{
	struct ctdb_node_map *nodemap;
	bool flag_is_set;

	while (1) {
		nodemap = get_nodemap(ctdb, true);
		if (nodemap == NULL) {
			fprintf(stderr,
				"Failed to get nodemap, trying again\n");
			sleep(1);
			continue;
		}

		flag_is_set = nodemap->node[ctdb->cmd_pnn].flags & flag;
		if (flag_is_set == set_flag) {
			break;
		}

		sleep(1);
	}
}

struct ipreallocate_state {
	int status;
	bool done;
};

static void ipreallocate_handler(uint64_t srvid, TDB_DATA data,
				 void *private_data)
{
	struct ipreallocate_state *state =
		(struct ipreallocate_state *)private_data;

	if (data.dsize != sizeof(int)) {
		/* Ignore packet */
		return;
	}

	state->status = *(int *)data.dptr;
	state->done = true;
}

static int ipreallocate(TALLOC_CTX *mem_ctx, struct ctdb_context *ctdb)
{
	struct ctdb_srvid_message msg = { 0 };
	struct ipreallocate_state state;
	int ret;

	msg.pnn = ctdb->pnn;
	msg.srvid = next_srvid(ctdb);

	state.done = false;
	ret = ctdb_client_set_message_handler(ctdb->ev, ctdb->client,
					      msg.srvid,
					      ipreallocate_handler, &state);
	if (ret != 0) {
		return ret;
	}

	while (true) {
		ret = ctdb_message_takeover_run(mem_ctx, ctdb->ev,
						ctdb->client,
						CTDB_BROADCAST_CONNECTED,
						&msg);
		if (ret != 0) {
			goto fail;
		}

		ret = ctdb_client_wait_timeout(ctdb->ev, &state.done,
					       TIMEOUT());
		if (ret != 0) {
			continue;
		}

		if (state.status >= 0) {
			ret = 0;
		} else {
			ret = state.status;
		}
		break;
	}

fail:
	ctdb_client_remove_message_handler(ctdb->ev, ctdb->client,
					   msg.srvid, &state);
	return ret;
}

static int control_disable(TALLOC_CTX *mem_ctx, struct ctdb_context *ctdb,
			   int argc, const char **argv)
{
	int ret;

	if (argc != 0) {
		usage("disable");
	}

	ret = check_flags(mem_ctx, ctdb, "disabled",
			  NODE_FLAGS_PERMANENTLY_DISABLED, true);
	if (ret == 0) {
		return 0;
	}

	ret = ctdb_ctrl_disable_node(mem_ctx,
				     ctdb->ev,
				     ctdb->client,
				     ctdb->cmd_pnn,
				     TIMEOUT());
	if (ret != 0) {
		fprintf(stderr, "Failed to disable node %u\n", ctdb->cmd_pnn);
		return ret;
	}

	wait_for_flags(mem_ctx, ctdb, NODE_FLAGS_PERMANENTLY_DISABLED, true);
	return ipreallocate(mem_ctx, ctdb);
}

static int control_enable(TALLOC_CTX *mem_ctx, struct ctdb_context *ctdb,
			  int argc, const char **argv)
{
	int ret;

	if (argc != 0) {
		usage("enable");
	}

	ret = check_flags(mem_ctx, ctdb, "disabled",
			  NODE_FLAGS_PERMANENTLY_DISABLED, false);
	if (ret == 0) {
		return 0;
	}

	ret = ctdb_ctrl_enable_node(mem_ctx,
				    ctdb->ev,
				    ctdb->client,
				    ctdb->cmd_pnn,
				    TIMEOUT());
	if (ret != 0) {
		fprintf(stderr, "Failed to enable node %u\n", ctdb->cmd_pnn);
		return ret;
	}

	wait_for_flags(mem_ctx, ctdb, NODE_FLAGS_PERMANENTLY_DISABLED, false);
	return ipreallocate(mem_ctx, ctdb);
}

static int control_stop(TALLOC_CTX *mem_ctx, struct ctdb_context *ctdb,
			int argc, const char **argv)
{
	int ret;

	if (argc != 0) {
		usage("stop");
	}

	ret = check_flags(mem_ctx, ctdb, "stopped",
			  NODE_FLAGS_STOPPED, true);
	if (ret == 0) {
		return 0;
	}

	ret = ctdb_ctrl_stop_node(mem_ctx, ctdb->ev, ctdb->client,
				  ctdb->cmd_pnn, TIMEOUT());
	if (ret != 0) {
		fprintf(stderr, "Failed to stop node %u\n", ctdb->cmd_pnn);
		return ret;
	}

	wait_for_flags(mem_ctx, ctdb, NODE_FLAGS_STOPPED, true);
	return ipreallocate(mem_ctx, ctdb);
}

static int control_continue(TALLOC_CTX *mem_ctx, struct ctdb_context *ctdb,
			    int argc, const char **argv)
{
	int ret;

	if (argc != 0) {
		usage("continue");
	}

	ret = check_flags(mem_ctx, ctdb, "stopped",
			  NODE_FLAGS_STOPPED, false);
	if (ret == 0) {
		return 0;
	}

	ret = ctdb_ctrl_continue_node(mem_ctx, ctdb->ev, ctdb->client,
				      ctdb->cmd_pnn, TIMEOUT());
	if (ret != 0) {
		fprintf(stderr, "Failed to continue stopped node %u\n",
			ctdb->cmd_pnn);
		return ret;
	}

	wait_for_flags(mem_ctx, ctdb, NODE_FLAGS_STOPPED, false);
	return ipreallocate(mem_ctx, ctdb);
}

static int control_ban(TALLOC_CTX *mem_ctx, struct ctdb_context *ctdb,
		       int argc, const char **argv)
{
	struct ctdb_ban_state ban_state;
	int ret = 0;

	if (argc != 1) {
		usage("ban");
	}

	ret = check_flags(mem_ctx, ctdb, "banned",
			  NODE_FLAGS_BANNED, true);
	if (ret == 0) {
		return 0;
	}

	ban_state.pnn = ctdb->cmd_pnn;
	ban_state.time = smb_strtoul(argv[0], NULL, 0, &ret, SMB_STR_STANDARD);
	if (ret != 0) {
		return ret;
	}

	if (ban_state.time == 0) {
		fprintf(stderr, "Ban time cannot be zero\n");
		return EINVAL;
	}

	ret = ctdb_ctrl_set_ban_state(mem_ctx, ctdb->ev, ctdb->client,
				      ctdb->cmd_pnn, TIMEOUT(), &ban_state);
	if (ret != 0) {
		fprintf(stderr, "Failed to ban node %u\n", ctdb->cmd_pnn);
		return ret;
	}

	wait_for_flags(mem_ctx, ctdb, NODE_FLAGS_BANNED, true);
	return ipreallocate(mem_ctx, ctdb);

}

static int control_unban(TALLOC_CTX *mem_ctx, struct ctdb_context *ctdb,
			 int argc, const char **argv)
{
	struct ctdb_ban_state ban_state;
	int ret;

	if (argc != 0) {
		usage("unban");
	}

	ret = check_flags(mem_ctx, ctdb, "banned",
			  NODE_FLAGS_BANNED, false);
	if (ret == 0) {
		return 0;
	}

	ban_state.pnn = ctdb->cmd_pnn;
	ban_state.time = 0;

	ret = ctdb_ctrl_set_ban_state(mem_ctx, ctdb->ev, ctdb->client,
				      ctdb->cmd_pnn, TIMEOUT(), &ban_state);
	if (ret != 0) {
		fprintf(stderr, "Failed to unban node %u\n", ctdb->cmd_pnn);
		return ret;
	}

	wait_for_flags(mem_ctx, ctdb, NODE_FLAGS_BANNED, false);
	return ipreallocate(mem_ctx, ctdb);

}

static void wait_for_shutdown(void *private_data)
{
	bool *done = (bool *)private_data;

	*done = true;
}

static int control_shutdown(TALLOC_CTX *mem_ctx, struct ctdb_context *ctdb,
			    int argc, const char **argv)
{
	int ret;
	bool done = false;

	if (argc != 0) {
		usage("shutdown");
	}

	if (ctdb->pnn == ctdb->cmd_pnn) {
		ctdb_client_set_disconnect_callback(ctdb->client,
						    wait_for_shutdown,
						    &done);
	}

	ret = ctdb_ctrl_shutdown(mem_ctx, ctdb->ev, ctdb->client,
				 ctdb->cmd_pnn, TIMEOUT());
	if (ret != 0) {
		fprintf(stderr, "Unable to shutdown node %u\n", ctdb->cmd_pnn);
		return ret;
	}

	if (ctdb->pnn == ctdb->cmd_pnn) {
		ctdb_client_wait(ctdb->ev, &done);
	}

	return 0;
}

static int get_generation(TALLOC_CTX *mem_ctx, struct ctdb_context *ctdb,
			  uint32_t *generation)
{
	uint32_t recmaster;
	int recmode;
	struct ctdb_vnn_map *vnnmap;
	int ret;

again:
	ret = ctdb_ctrl_get_recmaster(mem_ctx, ctdb->ev, ctdb->client,
				      ctdb->cmd_pnn, TIMEOUT(), &recmaster);
	if (ret != 0) {
		fprintf(stderr, "Failed to find recovery master\n");
		return ret;
	}

	ret = ctdb_ctrl_get_recmode(mem_ctx, ctdb->ev, ctdb->client,
				    recmaster, TIMEOUT(), &recmode);
	if (ret != 0) {
		fprintf(stderr, "Failed to get recovery mode from node %u\n",
			recmaster);
		return ret;
	}

	if (recmode == CTDB_RECOVERY_ACTIVE) {
		sleep(1);
		goto again;
	}

	ret = ctdb_ctrl_getvnnmap(mem_ctx, ctdb->ev, ctdb->client,
				  recmaster, TIMEOUT(), &vnnmap);
	if (ret != 0) {
		fprintf(stderr, "Failed to get generation from node %u\n",
			recmaster);
		return ret;
	}

	if (vnnmap->generation == INVALID_GENERATION) {
		talloc_free(vnnmap);
		sleep(1);
		goto again;
	}

	*generation = vnnmap->generation;
	talloc_free(vnnmap);
	return 0;
}


static int control_recover(TALLOC_CTX *mem_ctx, struct ctdb_context *ctdb,
			   int argc, const char **argv)
{
	uint32_t generation, next_generation;
	int ret;

	if (argc != 0) {
		usage("recover");
	}

	ret = get_generation(mem_ctx, ctdb, &generation);
	if (ret != 0) {
		return ret;
	}

	ret = ctdb_ctrl_set_recmode(mem_ctx, ctdb->ev, ctdb->client,
				    ctdb->cmd_pnn, TIMEOUT(),
				    CTDB_RECOVERY_ACTIVE);
	if (ret != 0) {
		fprintf(stderr, "Failed to set recovery mode active\n");
		return ret;
	}

	while (1) {
		ret = get_generation(mem_ctx, ctdb, &next_generation);
		if (ret != 0) {
			fprintf(stderr,
				"Failed to confirm end of recovery\n");
			return ret;
		}

		if (next_generation != generation) {
			break;
		}

		sleep (1);
	}

	return 0;
}

static int control_ipreallocate(TALLOC_CTX *mem_ctx, struct ctdb_context *ctdb,
				int argc, const char **argv)
{
	if (argc != 0) {
		usage("ipreallocate");
	}

	return ipreallocate(mem_ctx, ctdb);
}

static int control_isnotrecmaster(TALLOC_CTX *mem_ctx,
				  struct ctdb_context *ctdb,
				  int argc, const char **argv)
{
	uint32_t recmaster;
	int ret;

	if (argc != 0) {
		usage("isnotrecmaster");
	}

	ret = ctdb_ctrl_get_recmaster(mem_ctx, ctdb->ev, ctdb->client,
				      ctdb->pnn, TIMEOUT(), &recmaster);
	if (ret != 0) {
		fprintf(stderr, "Failed to get recmaster\n");
		return ret;
	}

	if (recmaster != ctdb->pnn) {
		printf("this node is not the recmaster\n");
		return 1;
	}

	printf("this node is the recmaster\n");
	return 0;
}

static int control_gratarp(TALLOC_CTX *mem_ctx, struct ctdb_context *ctdb,
			   int argc, const char **argv)
{
	struct ctdb_addr_info addr_info;
	int ret;

	if (argc != 2) {
		usage("gratarp");
	}

	ret = ctdb_sock_addr_from_string(argv[0], &addr_info.addr, false);
	if (ret != 0) {
		fprintf(stderr, "Invalid IP address %s\n", argv[0]);
		return 1;
	}
	addr_info.iface = argv[1];

	ret = ctdb_ctrl_send_gratuitous_arp(mem_ctx, ctdb->ev, ctdb->client,
					    ctdb->cmd_pnn, TIMEOUT(),
					    &addr_info);
	if (ret != 0) {
		fprintf(stderr, "Unable to send gratuitous arp from node %u\n",
			ctdb->cmd_pnn);
		return ret;
	}

	return 0;
}

static int control_tickle(TALLOC_CTX *mem_ctx, struct ctdb_context *ctdb,
			   int argc, const char **argv)
{
	ctdb_sock_addr src, dst;
	int ret;

	if (argc != 0 && argc != 2) {
		usage("tickle");
	}

	if (argc == 0) {
		struct ctdb_connection_list *clist;
		unsigned int i;
		unsigned int num_failed;

		/* Client first but the src/dst logic is confused */
		ret = ctdb_connection_list_read(mem_ctx, 0, false, &clist);
		if (ret != 0) {
			return ret;
		}

		num_failed = 0;
		for (i = 0; i < clist->num; i++) {
			ret = ctdb_sys_send_tcp(&clist->conn[i].src,
						&clist->conn[i].dst,
						0, 0, 0);
			if (ret != 0) {
				num_failed += 1;
			}
		}

		TALLOC_FREE(clist);

		if (num_failed > 0) {
			fprintf(stderr, "Failed to send %d tickles\n",
				num_failed);
			return 1;
		}

		return 0;
	}


	ret = ctdb_sock_addr_from_string(argv[0], &src, true);
	if (ret != 0) {
		fprintf(stderr, "Invalid IP address %s\n", argv[0]);
		return 1;
	}

	ret = ctdb_sock_addr_from_string(argv[1], &dst, true);
	if (ret != 0) {
		fprintf(stderr, "Invalid IP address %s\n", argv[1]);
		return 1;
	}

	ret = ctdb_sys_send_tcp(&src, &dst, 0, 0, 0);
	if (ret != 0) {
		fprintf(stderr, "Failed to send tickle ack\n");
		return ret;
	}

	return 0;
}

static int control_gettickles(TALLOC_CTX *mem_ctx, struct ctdb_context *ctdb,
			      int argc, const char **argv)
{
	ctdb_sock_addr addr;
	struct ctdb_tickle_list *tickles;
	unsigned port = 0;
	unsigned int i;
	int ret = 0;

	if (argc < 1 || argc > 2) {
		usage("gettickles");
	}

	if (argc == 2) {
		port = smb_strtoul(argv[1], NULL, 10, &ret, SMB_STR_STANDARD);
		if (ret != 0) {
			return ret;
		}
	}

	ret = ctdb_sock_addr_from_string(argv[0], &addr, false);
	if (ret != 0) {
		fprintf(stderr, "Invalid IP address %s\n", argv[0]);
		return 1;
	}
	ctdb_sock_addr_set_port(&addr, port);

	ret = ctdb_ctrl_get_tcp_tickle_list(mem_ctx, ctdb->ev, ctdb->client,
					    ctdb->cmd_pnn, TIMEOUT(), &addr,
					    &tickles);
	if (ret != 0) {
		fprintf(stderr, "Failed to get list of connections\n");
		return ret;
	}

	if (options.machinereadable) {
		printf("%s%s%s%s%s%s%s%s%s\n",
		       options.sep,
		       "Source IP", options.sep,
		       "Port", options.sep,
		       "Destiation IP", options.sep,
		       "Port", options.sep);
		for (i=0; i<tickles->num; i++) {
			printf("%s%s%s%u%s%s%s%u%s\n", options.sep,
			       ctdb_sock_addr_to_string(
				       mem_ctx, &tickles->conn[i].src, false),
			       options.sep,
			       ntohs(tickles->conn[i].src.ip.sin_port),
			       options.sep,
			       ctdb_sock_addr_to_string(
				       mem_ctx, &tickles->conn[i].dst, false),
			       options.sep,
			       ntohs(tickles->conn[i].dst.ip.sin_port),
			       options.sep);
		}
	} else {
		printf("Connections for IP: %s\n",
		       ctdb_sock_addr_to_string(mem_ctx,
						&tickles->addr, false));
		printf("Num connections: %u\n", tickles->num);
		for (i=0; i<tickles->num; i++) {
			printf("SRC: %s   DST: %s\n",
			       ctdb_sock_addr_to_string(
				       mem_ctx, &tickles->conn[i].src, true),
			       ctdb_sock_addr_to_string(
				       mem_ctx, &tickles->conn[i].dst, true));
		}
	}

	talloc_free(tickles);
	return 0;
}

typedef void (*clist_request_func)(struct ctdb_req_control *request,
				   struct ctdb_connection *conn);

typedef int (*clist_reply_func)(struct ctdb_reply_control *reply);

struct process_clist_state {
	struct ctdb_connection_list *clist;
	int count;
	unsigned int num_failed, num_total;
	clist_reply_func reply_func;
};

static void process_clist_done(struct tevent_req *subreq);

static struct tevent_req *process_clist_send(
					TALLOC_CTX *mem_ctx,
					struct ctdb_context *ctdb,
					struct ctdb_connection_list *clist,
					clist_request_func request_func,
					clist_reply_func reply_func)
{
	struct tevent_req *req, *subreq;
	struct process_clist_state *state;
	struct ctdb_req_control request;
	unsigned int i;

	req = tevent_req_create(mem_ctx, &state, struct process_clist_state);
	if (req == NULL) {
		return NULL;
	}

	state->clist = clist;
	state->reply_func = reply_func;

	for (i = 0; i < clist->num; i++) {
		request_func(&request, &clist->conn[i]);
		subreq = ctdb_client_control_send(state, ctdb->ev,
						  ctdb->client, ctdb->cmd_pnn,
						  TIMEOUT(), &request);
		if (tevent_req_nomem(subreq, req)) {
			return tevent_req_post(req, ctdb->ev);
		}
		tevent_req_set_callback(subreq, process_clist_done, req);
	}

	return req;
}

static void process_clist_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct process_clist_state *state = tevent_req_data(
		req, struct process_clist_state);
	struct ctdb_reply_control *reply;
	int ret;
	bool status;

	status = ctdb_client_control_recv(subreq, NULL, state, &reply);
	TALLOC_FREE(subreq);
	if (! status) {
		state->num_failed += 1;
		goto done;
	}

	ret = state->reply_func(reply);
	if (ret != 0) {
		state->num_failed += 1;
		goto done;
	}

done:
	state->num_total += 1;
	if (state->num_total == state->clist->num) {
		tevent_req_done(req);
	}
}

static int process_clist_recv(struct tevent_req *req)
{
	struct process_clist_state *state = tevent_req_data(
		req, struct process_clist_state);

	return state->num_failed;
}

static int control_addtickle(TALLOC_CTX *mem_ctx, struct ctdb_context *ctdb,
			     int argc, const char **argv)
{
	struct ctdb_connection conn;
	int ret;

	if (argc != 0 && argc != 2) {
		usage("addtickle");
	}

	if (argc == 0) {
		struct ctdb_connection_list *clist;
		struct tevent_req *req;

		/* Client first but the src/dst logic is confused */
		ret = ctdb_connection_list_read(mem_ctx, 0, false, &clist);
		if (ret != 0) {
			return ret;
		}
		if (clist->num == 0) {
			return 0;
		}

		req = process_clist_send(mem_ctx, ctdb, clist,
				 ctdb_req_control_tcp_add_delayed_update,
				 ctdb_reply_control_tcp_add_delayed_update);
		if (req == NULL) {
			talloc_free(clist);
			return ENOMEM;
		}

		tevent_req_poll(req, ctdb->ev);
		talloc_free(clist);

		ret = process_clist_recv(req);
		if (ret != 0) {
			fprintf(stderr, "Failed to add %d tickles\n", ret);
			return 1;
		}

		return 0;
	}

	ret = ctdb_sock_addr_from_string(argv[0], &conn.src, true);
	if (ret != 0) {
		fprintf(stderr, "Invalid IP address %s\n", argv[0]);
		return 1;
	}
	ret = ctdb_sock_addr_from_string(argv[1], &conn.dst, true);
	if (ret != 0) {
		fprintf(stderr, "Invalid IP address %s\n", argv[1]);
		return 1;
	}

	ret = ctdb_ctrl_tcp_add_delayed_update(mem_ctx, ctdb->ev,
					       ctdb->client, ctdb->cmd_pnn,
					       TIMEOUT(), &conn);
	if (ret != 0) {
		fprintf(stderr, "Failed to register connection\n");
		return ret;
	}

	return 0;
}

static int control_deltickle(TALLOC_CTX *mem_ctx, struct ctdb_context *ctdb,
			     int argc, const char **argv)
{
	struct ctdb_connection conn;
	int ret;

	if (argc != 0 && argc != 2) {
		usage("deltickle");
	}

	if (argc == 0) {
		struct ctdb_connection_list *clist;
		struct tevent_req *req;

		/* Client first but the src/dst logic is confused */
		ret = ctdb_connection_list_read(mem_ctx, 0, false, &clist);
		if (ret != 0) {
			return ret;
		}
		if (clist->num == 0) {
			return 0;
		}

		req = process_clist_send(mem_ctx, ctdb, clist,
					 ctdb_req_control_tcp_remove,
					 ctdb_reply_control_tcp_remove);
		if (req == NULL) {
			talloc_free(clist);
			return ENOMEM;
		}

		tevent_req_poll(req, ctdb->ev);
		talloc_free(clist);

		ret = process_clist_recv(req);
		if (ret != 0) {
			fprintf(stderr, "Failed to remove %d tickles\n", ret);
			return 1;
		}

		return 0;
	}

	ret = ctdb_sock_addr_from_string(argv[0], &conn.src, true);
	if (ret != 0) {
		fprintf(stderr, "Invalid IP address %s\n", argv[0]);
		return 1;
	}
	ret = ctdb_sock_addr_from_string(argv[1], &conn.dst, true);
	if (ret != 0) {
		fprintf(stderr, "Invalid IP address %s\n", argv[1]);
		return 1;
	}

	ret = ctdb_ctrl_tcp_remove(mem_ctx, ctdb->ev, ctdb->client,
				   ctdb->cmd_pnn, TIMEOUT(), &conn);
	if (ret != 0) {
		fprintf(stderr, "Failed to unregister connection\n");
		return ret;
	}

	return 0;
}

static int control_listnodes(TALLOC_CTX *mem_ctx, struct ctdb_context *ctdb,
			     int argc, const char **argv)
{
	struct ctdb_node_map *nodemap;
	unsigned int i;

	if (argc != 0) {
		usage("listnodes");
	}

	nodemap = read_nodes_file(mem_ctx, CTDB_UNKNOWN_PNN);
	if (nodemap == NULL) {
		return 1;
	}

	for (i=0; i<nodemap->num; i++) {
		if (nodemap->node[i].flags & NODE_FLAGS_DELETED) {
			continue;
		}

		if (options.machinereadable) {
			printf("%s%u%s%s%s\n", options.sep,
			       nodemap->node[i].pnn, options.sep,
			       ctdb_sock_addr_to_string(
				       mem_ctx, &nodemap->node[i].addr, false),
			       options.sep);
		} else {
			printf("%s\n",
			       ctdb_sock_addr_to_string(
				       mem_ctx, &nodemap->node[i].addr, false));
		}
	}

	return 0;
}

static bool nodemap_identical(struct ctdb_node_map *nodemap1,
			      struct ctdb_node_map *nodemap2)
{
	unsigned int i;

	if (nodemap1->num != nodemap2->num) {
		return false;
	}

	for (i=0; i<nodemap1->num; i++) {
		struct ctdb_node_and_flags *n1, *n2;

		n1 = &nodemap1->node[i];
		n2 = &nodemap2->node[i];

		if ((n1->pnn != n2->pnn) ||
		    (n1->flags != n2->flags) ||
		    ! ctdb_sock_addr_same_ip(&n1->addr, &n2->addr)) {
			return false;
		}
	}

	return true;
}

static int check_node_file_changes(TALLOC_CTX *mem_ctx,
				   struct ctdb_node_map *nm,
				   struct ctdb_node_map *fnm,
				   bool *reload)
{
	unsigned int i;
	bool check_failed = false;

	*reload = false;

	for (i=0; i<nm->num; i++) {
		if (i >= fnm->num) {
			fprintf(stderr,
				"Node %u (%s) missing from nodes file\n",
				nm->node[i].pnn,
				ctdb_sock_addr_to_string(
					mem_ctx, &nm->node[i].addr, false));
			check_failed = true;
			continue;
		}
		if (nm->node[i].flags & NODE_FLAGS_DELETED &&
		    fnm->node[i].flags & NODE_FLAGS_DELETED) {
			/* Node remains deleted */
			continue;
		}

		if (! (nm->node[i].flags & NODE_FLAGS_DELETED) &&
		    ! (fnm->node[i].flags & NODE_FLAGS_DELETED)) {
			/* Node not newly nor previously deleted */
			if (! ctdb_same_ip(&nm->node[i].addr,
					   &fnm->node[i].addr)) {
				fprintf(stderr,
					"Node %u has changed IP address"
					" (was %s, now %s)\n",
					nm->node[i].pnn,
					ctdb_sock_addr_to_string(
						mem_ctx,
						&nm->node[i].addr, false),
					ctdb_sock_addr_to_string(
						mem_ctx,
						&fnm->node[i].addr, false));
				check_failed = true;
			} else {
				if (nm->node[i].flags & NODE_FLAGS_DISCONNECTED) {
					fprintf(stderr,
						"WARNING: Node %u is disconnected."
						" You MUST fix this node manually!\n",
						nm->node[i].pnn);
				}
			}
			continue;
		}

		if (fnm->node[i].flags & NODE_FLAGS_DELETED) {
			/* Node is being deleted */
			printf("Node %u is DELETED\n", nm->node[i].pnn);
			*reload = true;
			if (! (nm->node[i].flags & NODE_FLAGS_DISCONNECTED)) {
				fprintf(stderr,
					"ERROR: Node %u is still connected\n",
					nm->node[i].pnn);
				check_failed = true;
			}
			continue;
		}

		if (nm->node[i].flags & NODE_FLAGS_DELETED) {
			/* Node was previously deleted */
			printf("Node %u is UNDELETED\n", nm->node[i].pnn);
			*reload = true;
		}
	}

	if (check_failed) {
		fprintf(stderr,
			"ERROR: Nodes will not be reloaded due to previous error\n");
		return 1;
	}

	/* Leftover nodes in file are NEW */
	for (; i < fnm->num; i++) {
		printf("Node %u is NEW\n", fnm->node[i].pnn);
		*reload = true;
	}

	return 0;
}

struct disable_recoveries_state {
	uint32_t *pnn_list;
	unsigned int node_count;
	bool *reply;
	int status;
	bool done;
};

static void disable_recoveries_handler(uint64_t srvid, TDB_DATA data,
				       void *private_data)
{
	struct disable_recoveries_state *state =
		(struct disable_recoveries_state *)private_data;
	unsigned int i;
	int ret;

	if (data.dsize != sizeof(int)) {
		/* Ignore packet */
		return;
	}

	/* ret will be a PNN (i.e. >=0) on success, or negative on error */
	ret = *(int *)data.dptr;
	if (ret < 0) {
		state->status = ret;
		state->done = true;
		return;
	}
	for (i=0; i<state->node_count; i++) {
		if (state->pnn_list[i] == (uint32_t)ret) {
			state->reply[i] = true;
			break;
		}
	}

	state->done = true;
	for (i=0; i<state->node_count; i++) {
		if (! state->reply[i]) {
			state->done = false;
			break;
		}
	}
}

static int disable_recoveries(TALLOC_CTX *mem_ctx, struct ctdb_context *ctdb,
			      uint32_t timeout, uint32_t *pnn_list, int count)
{
	struct ctdb_disable_message disable = { 0 };
	struct disable_recoveries_state state;
	int ret, i;

	disable.pnn = ctdb->pnn;
	disable.srvid = next_srvid(ctdb);
	disable.timeout = timeout;

	state.pnn_list = pnn_list;
	state.node_count = count;
	state.done = false;
	state.status = 0;
	state.reply = talloc_zero_array(mem_ctx, bool, count);
	if (state.reply == NULL) {
		return ENOMEM;
	}

	ret = ctdb_client_set_message_handler(ctdb->ev, ctdb->client,
					      disable.srvid,
					      disable_recoveries_handler,
					      &state);
	if (ret != 0) {
		return ret;
	}

	for (i=0; i<count; i++) {
		ret = ctdb_message_disable_recoveries(mem_ctx, ctdb->ev,
						      ctdb->client,
						      pnn_list[i],
						      &disable);
		if (ret != 0) {
			goto fail;
		}
	}

	ret = ctdb_client_wait_timeout(ctdb->ev, &state.done, TIMEOUT());
	if (ret == ETIME) {
		fprintf(stderr, "Timed out waiting to disable recoveries\n");
	} else {
		ret = (state.status >= 0 ? 0 : 1);
	}

fail:
	ctdb_client_remove_message_handler(ctdb->ev, ctdb->client,
					   disable.srvid, &state);
	return ret;
}

static int control_reloadnodes(TALLOC_CTX *mem_ctx, struct ctdb_context *ctdb,
			       int argc, const char **argv)
{
	struct ctdb_node_map *nodemap = NULL;
	struct ctdb_node_map *file_nodemap;
	struct ctdb_node_map *remote_nodemap;
	struct ctdb_req_control request;
	struct ctdb_reply_control **reply;
	bool reload;
	unsigned int i;
	int count;
	int ret;
	uint32_t *pnn_list;

	nodemap = get_nodemap(ctdb, false);
	if (nodemap == NULL) {
		return 1;
	}

	file_nodemap = read_nodes_file(mem_ctx, ctdb->pnn);
	if (file_nodemap == NULL) {
		return 1;
	}

	for (i=0; i<nodemap->num; i++) {
		if (nodemap->node[i].flags & NODE_FLAGS_DISCONNECTED) {
			continue;
		}

		ret = ctdb_ctrl_get_nodes_file(mem_ctx, ctdb->ev, ctdb->client,
					       nodemap->node[i].pnn, TIMEOUT(),
					       &remote_nodemap);
		if (ret != 0) {
			fprintf(stderr,
				"ERROR: Failed to get nodes file from node %u\n",
				nodemap->node[i].pnn);
			return ret;
		}

		if (! nodemap_identical(file_nodemap, remote_nodemap)) {
			fprintf(stderr,
				"ERROR: Nodes file on node %u differs"
				 " from current node (%u)\n",
				 nodemap->node[i].pnn, ctdb->pnn);
			return 1;
		}
	}

	ret = check_node_file_changes(mem_ctx, nodemap, file_nodemap, &reload);
	if (ret != 0) {
		return ret;
	}

	if (! reload) {
		fprintf(stderr, "No change in nodes file,"
				" skipping unnecessary reload\n");
		return 0;
	}

	count = list_of_connected_nodes(nodemap, CTDB_UNKNOWN_PNN,
					mem_ctx, &pnn_list);
	if (count <= 0) {
		fprintf(stderr, "Memory allocation error\n");
		return 1;
	}

	ret = disable_recoveries(mem_ctx, ctdb, 2*options.timelimit,
				 pnn_list, count);
	if (ret != 0) {
		fprintf(stderr, "Failed to disable recoveries\n");
		return ret;
	}

	ctdb_req_control_reload_nodes_file(&request);
	ret = ctdb_client_control_multi(mem_ctx, ctdb->ev, ctdb->client,
					pnn_list, count, TIMEOUT(),
					&request, NULL, &reply);
	if (ret != 0) {
		bool failed = false;
		int j;

		for (j=0; j<count; j++) {
			ret = ctdb_reply_control_reload_nodes_file(reply[j]);
			if (ret != 0) {
				fprintf(stderr,
					"Node %u failed to reload nodes\n",
					pnn_list[j]);
				failed = true;
			}
		}
		if (failed) {
			fprintf(stderr,
				"You MUST fix failed nodes manually!\n");
		}
	}

	ret = disable_recoveries(mem_ctx, ctdb, 0, pnn_list, count);
	if (ret != 0) {
		fprintf(stderr, "Failed to enable recoveries\n");
		return ret;
	}

	return 0;
}

static int moveip(TALLOC_CTX *mem_ctx, struct ctdb_context *ctdb,
		  ctdb_sock_addr *addr, uint32_t pnn)
{
	struct ctdb_public_ip_list *pubip_list;
	struct ctdb_public_ip pubip;
	struct ctdb_node_map *nodemap;
	struct ctdb_req_control request;
	uint32_t *pnn_list;
	unsigned int i;
	int ret, count;

	ret = ctdb_message_disable_ip_check(mem_ctx, ctdb->ev, ctdb->client,
					    CTDB_BROADCAST_CONNECTED,
					    2*options.timelimit);
	if (ret != 0) {
		fprintf(stderr, "Failed to disable IP check\n");
		return ret;
	}

	ret = ctdb_ctrl_get_public_ips(mem_ctx, ctdb->ev, ctdb->client,
				       pnn, TIMEOUT(), false, &pubip_list);
	if (ret != 0) {
		fprintf(stderr, "Failed to get Public IPs from node %u\n",
			pnn);
		return ret;
	}

	for (i=0; i<pubip_list->num; i++) {
		if (ctdb_same_ip(addr, &pubip_list->ip[i].addr)) {
			break;
		}
	}

	if (i == pubip_list->num) {
		fprintf(stderr, "Node %u CANNOT host IP address %s\n",
			pnn, ctdb_sock_addr_to_string(mem_ctx, addr, false));
		return 1;
	}

	nodemap = get_nodemap(ctdb, false);
	if (nodemap == NULL) {
		return 1;
	}

	count = list_of_active_nodes(nodemap, pnn, mem_ctx, &pnn_list);
	if (count <= 0) {
		fprintf(stderr, "Memory allocation error\n");
		return 1;
	}

	pubip.pnn = pnn;
	pubip.addr = *addr;
	ctdb_req_control_release_ip(&request, &pubip);

	ret = ctdb_client_control_multi(mem_ctx, ctdb->ev, ctdb->client,
					pnn_list, count, TIMEOUT(),
					&request, NULL, NULL);
	if (ret != 0) {
		fprintf(stderr, "Failed to release IP on nodes\n");
		return ret;
	}

	ret = ctdb_ctrl_takeover_ip(mem_ctx, ctdb->ev, ctdb->client,
				    pnn, TIMEOUT(), &pubip);
	if (ret != 0) {
		fprintf(stderr, "Failed to takeover IP on node %u\n", pnn);
		return ret;
	}

	return 0;
}

static int control_moveip(TALLOC_CTX *mem_ctx, struct ctdb_context *ctdb,
			  int argc, const char **argv)
{
	ctdb_sock_addr addr;
	uint32_t pnn;
	int retries = 0;
	int ret = 0;

	if (argc != 2) {
		usage("moveip");
	}

	ret = ctdb_sock_addr_from_string(argv[0], &addr, false);
	if (ret != 0) {
		fprintf(stderr, "Invalid IP address %s\n", argv[0]);
		return 1;
	}

	pnn = smb_strtoul(argv[1], NULL, 10, &ret, SMB_STR_STANDARD);
	if (pnn == CTDB_UNKNOWN_PNN || ret != 0) {
		fprintf(stderr, "Invalid PNN %s\n", argv[1]);
		return 1;
	}

	while (retries < 5) {
		ret = moveip(mem_ctx, ctdb, &addr, pnn);
		if (ret == 0) {
			break;
		}

		sleep(3);
		retries++;
	}

	if (ret != 0) {
		fprintf(stderr, "Failed to move IP %s to node %u\n",
			argv[0], pnn);
		return ret;
	}

	return 0;
}

static int rebalancenode(TALLOC_CTX *mem_ctx, struct ctdb_context *ctdb,
			 uint32_t pnn)
{
	int ret;

	ret = ctdb_message_rebalance_node(mem_ctx, ctdb->ev, ctdb->client,
					  CTDB_BROADCAST_CONNECTED, pnn);
	if (ret != 0) {
		fprintf(stderr,
			"Failed to ask recovery master to distribute IPs\n");
		return ret;
	}

	return 0;
}

static int control_addip(TALLOC_CTX *mem_ctx, struct ctdb_context *ctdb,
			 int argc, const char **argv)
{
	ctdb_sock_addr addr;
	struct ctdb_public_ip_list *pubip_list;
	struct ctdb_addr_info addr_info;
	unsigned int mask, i;
	int ret, retries = 0;

	if (argc != 2) {
		usage("addip");
	}

	ret = ctdb_sock_addr_mask_from_string(argv[0], &addr, &mask);
	if (ret != 0) {
		fprintf(stderr, "Invalid IP/Mask %s\n", argv[0]);
		return 1;
	}

	ret = ctdb_ctrl_get_public_ips(mem_ctx, ctdb->ev, ctdb->client,
				       ctdb->cmd_pnn, TIMEOUT(),
				       false, &pubip_list);
	if (ret != 0) {
		fprintf(stderr, "Failed to get Public IPs from node %u\n",
			ctdb->cmd_pnn);
		return 1;
	}

	for (i=0; i<pubip_list->num; i++) {
		if (ctdb_same_ip(&addr, &pubip_list->ip[i].addr)) {
			fprintf(stderr, "Node already knows about IP %s\n",
				ctdb_sock_addr_to_string(mem_ctx,
							 &addr, false));
			return 0;
		}
	}

	addr_info.addr = addr;
	addr_info.mask = mask;
	addr_info.iface = argv[1];

	while (retries < 5) {
		ret = ctdb_ctrl_add_public_ip(mem_ctx, ctdb->ev, ctdb->client,
					      ctdb->cmd_pnn, TIMEOUT(),
					      &addr_info);
		if (ret == 0) {
			break;
		}

		sleep(3);
		retries++;
	}

	if (ret != 0) {
		fprintf(stderr, "Failed to add public IP to node %u."
				" Giving up\n", ctdb->cmd_pnn);
		return ret;
	}

	ret = rebalancenode(mem_ctx, ctdb, ctdb->cmd_pnn);
	if (ret != 0) {
		return ret;
	}

	return 0;
}

static int control_delip(TALLOC_CTX *mem_ctx, struct ctdb_context *ctdb,
			 int argc, const char **argv)
{
	ctdb_sock_addr addr;
	struct ctdb_public_ip_list *pubip_list;
	struct ctdb_addr_info addr_info;
	unsigned int i;
	int ret;

	if (argc != 1) {
		usage("delip");
	}

	ret = ctdb_sock_addr_from_string(argv[0], &addr, false);
	if (ret != 0) {
		fprintf(stderr, "Invalid IP address %s\n", argv[0]);
		return 1;
	}

	ret = ctdb_ctrl_get_public_ips(mem_ctx, ctdb->ev, ctdb->client,
				       ctdb->cmd_pnn, TIMEOUT(),
				       false, &pubip_list);
	if (ret != 0) {
		fprintf(stderr, "Failed to get Public IPs from node %u\n",
			ctdb->cmd_pnn);
		return 1;
	}

	for (i=0; i<pubip_list->num; i++) {
		if (ctdb_same_ip(&addr, &pubip_list->ip[i].addr)) {
			break;
		}
	}

	if (i == pubip_list->num) {
		fprintf(stderr, "Node does not know about IP address %s\n",
			ctdb_sock_addr_to_string(mem_ctx, &addr, false));
		return 0;
	}

	addr_info.addr = addr;
	addr_info.mask = 0;
	addr_info.iface = NULL;

	ret = ctdb_ctrl_del_public_ip(mem_ctx, ctdb->ev, ctdb->client,
				      ctdb->cmd_pnn, TIMEOUT(), &addr_info);
	if (ret != 0) {
		fprintf(stderr, "Failed to delete public IP from node %u\n",
			ctdb->cmd_pnn);
		return ret;
	}

	return 0;
}

#define DB_VERSION	3
#define MAX_DB_NAME	64
#define MAX_REC_BUFFER_SIZE	(100*1000)

struct db_header {
	unsigned long version;
	time_t timestamp;
	unsigned long flags;
	unsigned long nbuf;
	unsigned long nrec;
	char name[MAX_DB_NAME];
};

struct backup_state {
	TALLOC_CTX *mem_ctx;
	struct ctdb_rec_buffer *recbuf;
	uint32_t db_id;
	int fd;
	unsigned int nbuf, nrec;
};

static int backup_handler(uint32_t reqid, struct ctdb_ltdb_header *header,
			  TDB_DATA key, TDB_DATA data, void *private_data)
{
	struct backup_state *state = (struct backup_state *)private_data;
	size_t len;
	int ret;

	if (state->recbuf == NULL) {
		state->recbuf = ctdb_rec_buffer_init(state->mem_ctx,
						     state->db_id);
		if (state->recbuf == NULL) {
			return ENOMEM;
		}
	}

	ret = ctdb_rec_buffer_add(state->recbuf, state->recbuf, reqid,
				  header, key, data);
	if (ret != 0) {
		return ret;
	}

	len = ctdb_rec_buffer_len(state->recbuf);
	if (len < MAX_REC_BUFFER_SIZE) {
		return 0;
	}

	ret = ctdb_rec_buffer_write(state->recbuf, state->fd);
	if (ret != 0) {
		fprintf(stderr, "Failed to write records to backup file\n");
		return ret;
	}

	state->nbuf += 1;
	state->nrec += state->recbuf->count;
	TALLOC_FREE(state->recbuf);

	return 0;
}

static int control_backupdb(TALLOC_CTX *mem_ctx, struct ctdb_context *ctdb,
			    int argc, const char **argv)
{
	const char *db_name;
	struct ctdb_db_context *db;
	uint32_t db_id;
	uint8_t db_flags;
	struct backup_state state;
	struct db_header db_hdr;
	int fd, ret;

	if (argc != 2) {
		usage("backupdb");
	}

	if (! db_exists(mem_ctx, ctdb, argv[0], &db_id, &db_name, &db_flags)) {
		return 1;
	}

	ret = ctdb_attach(ctdb->ev, ctdb->client, TIMEOUT(), db_name,
			  db_flags, &db);
	if (ret != 0) {
		fprintf(stderr, "Failed to attach to DB %s\n", db_name);
		return ret;
	}

	fd = open(argv[1], O_RDWR|O_CREAT, 0600);
	if (fd == -1) {
		ret = errno;
		fprintf(stderr, "Failed to open file %s for writing\n",
			argv[1]);
		return ret;
	}

	/* Write empty header first */
	ZERO_STRUCT(db_hdr);
	ret = write(fd, &db_hdr, sizeof(struct db_header));
	if (ret == -1) {
		ret = errno;
		close(fd);
		fprintf(stderr, "Failed to write header to file %s\n", argv[1]);
		return ret;
	}

	state.mem_ctx = mem_ctx;
	state.recbuf = NULL;
	state.fd = fd;
	state.nbuf = 0;
	state.nrec = 0;

	ret = ctdb_db_traverse_local(db, true, false, backup_handler, &state);
	if (ret != 0) {
		fprintf(stderr, "Failed to collect records from DB %s\n",
			db_name);
		close(fd);
		return ret;
	}

	if (state.recbuf != NULL) {
		ret = ctdb_rec_buffer_write(state.recbuf, state.fd);
		if (ret != 0) {
			fprintf(stderr,
				"Failed to write records to backup file\n");
			close(fd);
			return ret;
		}

		state.nbuf += 1;
		state.nrec += state.recbuf->count;
		TALLOC_FREE(state.recbuf);
	}

	db_hdr.version = DB_VERSION;
	db_hdr.timestamp = time(NULL);
	db_hdr.flags = db_flags;
	db_hdr.nbuf = state.nbuf;
	db_hdr.nrec = state.nrec;
	strncpy(db_hdr.name, db_name, MAX_DB_NAME-1);

	lseek(fd, 0, SEEK_SET);
	ret = write(fd, &db_hdr, sizeof(struct db_header));
	if (ret == -1) {
		ret = errno;
		close(fd);
		fprintf(stderr, "Failed to write header to file %s\n", argv[1]);
		return ret;
	}

	close(fd);
	printf("Database backed up to %s\n", argv[1]);
	return 0;
}

static int control_restoredb(TALLOC_CTX *mem_ctx, struct ctdb_context *ctdb,
			     int argc, const char **argv)
{
	const char *db_name = NULL;
	struct ctdb_db_context *db;
	struct db_header db_hdr;
	struct ctdb_node_map *nodemap;
	struct ctdb_req_control request;
	struct ctdb_reply_control **reply;
	struct ctdb_transdb wipedb;
	struct ctdb_pulldb_ext pulldb;
	struct ctdb_rec_buffer *recbuf;
	uint32_t generation;
	uint32_t *pnn_list;
	char timebuf[128];
	ssize_t n;
	int fd;
	unsigned long i, count;
	int ret;
	uint8_t db_flags;

	if (argc < 1 || argc > 2) {
		usage("restoredb");
	}

	fd = open(argv[0], O_RDONLY, 0600);
	if (fd == -1) {
		ret = errno;
		fprintf(stderr, "Failed to open file %s for reading\n",
			argv[0]);
		return ret;
	}

	if (argc == 2) {
		db_name = argv[1];
	}

	n = read(fd, &db_hdr, sizeof(struct db_header));
	if (n == -1) {
		ret = errno;
		close(fd);
		fprintf(stderr, "Failed to read db header from file %s\n",
			argv[0]);
		return ret;
	}
	db_hdr.name[sizeof(db_hdr.name)-1] = '\0';

	if (db_hdr.version != DB_VERSION) {
		fprintf(stderr,
			"Wrong version of backup file, expected %u, got %lu\n",
			DB_VERSION, db_hdr.version);
		close(fd);
		return EINVAL;
	}

	if (db_name == NULL) {
		db_name = db_hdr.name;
	}

	strftime(timebuf, sizeof(timebuf)-1, "%Y/%m/%d %H:%M:%S",
		 localtime(&db_hdr.timestamp));
	printf("Restoring database %s from backup @ %s\n", db_name, timebuf);

	db_flags = db_hdr.flags & 0xff;
	ret = ctdb_attach(ctdb->ev, ctdb->client, TIMEOUT(), db_name,
			  db_flags, &db);
	if (ret != 0) {
		fprintf(stderr, "Failed to attach to DB %s\n", db_name);
		close(fd);
		return ret;
	}

	nodemap = get_nodemap(ctdb, false);
	if (nodemap == NULL) {
		fprintf(stderr, "Failed to get nodemap\n");
		close(fd);
		return ENOMEM;
	}

	ret = get_generation(mem_ctx, ctdb, &generation);
	if (ret != 0) {
		fprintf(stderr, "Failed to get current generation\n");
		close(fd);
		return ret;
	}

	count = list_of_active_nodes(nodemap, CTDB_UNKNOWN_PNN, mem_ctx,
				     &pnn_list);
	if (count <= 0) {
		close(fd);
		return ENOMEM;
	}

	wipedb.db_id = ctdb_db_id(db);
	wipedb.tid = generation;

	ctdb_req_control_db_freeze(&request, wipedb.db_id);
	ret = ctdb_client_control_multi(mem_ctx, ctdb->ev,
					ctdb->client, pnn_list, count,
					TIMEOUT(), &request, NULL, NULL);
	if (ret != 0) {
		goto failed;
	}


	ctdb_req_control_db_transaction_start(&request, &wipedb);
	ret = ctdb_client_control_multi(mem_ctx, ctdb->ev, ctdb->client,
					pnn_list, count, TIMEOUT(),
					&request, NULL, NULL);
	if (ret != 0) {
		goto failed;
	}

	ctdb_req_control_wipe_database(&request, &wipedb);
	ret = ctdb_client_control_multi(mem_ctx, ctdb->ev, ctdb->client,
					pnn_list, count, TIMEOUT(),
					&request, NULL, NULL);
	if (ret != 0) {
		goto failed;
	}

	pulldb.db_id = ctdb_db_id(db);
	pulldb.lmaster = 0;
	pulldb.srvid = SRVID_CTDB_PUSHDB;

	ctdb_req_control_db_push_start(&request, &pulldb);
	ret = ctdb_client_control_multi(mem_ctx, ctdb->ev, ctdb->client,
					pnn_list, count, TIMEOUT(),
					&request, NULL, NULL);
	if (ret != 0) {
		goto failed;
	}

	for (i=0; i<db_hdr.nbuf; i++) {
		struct ctdb_req_message message;
		TDB_DATA data;
		size_t np;

		ret = ctdb_rec_buffer_read(fd, mem_ctx, &recbuf);
		if (ret != 0) {
			goto failed;
		}

		data.dsize = ctdb_rec_buffer_len(recbuf);
		data.dptr = talloc_size(mem_ctx, data.dsize);
		if (data.dptr == NULL) {
			goto failed;
		}

		ctdb_rec_buffer_push(recbuf, data.dptr, &np);

		message.srvid = pulldb.srvid;
		message.data.data = data;

		ret = ctdb_client_message_multi(mem_ctx, ctdb->ev,
						ctdb->client,
						pnn_list, count,
						&message, NULL);
		if (ret != 0) {
			goto failed;
		}

		talloc_free(recbuf);
		talloc_free(data.dptr);
	}

	ctdb_req_control_db_push_confirm(&request, pulldb.db_id);
	ret = ctdb_client_control_multi(mem_ctx, ctdb->ev, ctdb->client,
					pnn_list, count, TIMEOUT(),
					&request, NULL, &reply);
	if (ret != 0) {
		goto failed;
	}

	for (i=0; i<count; i++) {
		uint32_t num_records;

		ret = ctdb_reply_control_db_push_confirm(reply[i],
							 &num_records);
		if (ret != 0) {
			fprintf(stderr, "Invalid response from node %u\n",
				pnn_list[i]);
			goto failed;
		}

		if (num_records != db_hdr.nrec) {
			fprintf(stderr, "Node %u received %u of %lu records\n",
				pnn_list[i], num_records, db_hdr.nrec);
			goto failed;
		}
	}

	ctdb_req_control_db_set_healthy(&request, wipedb.db_id);
	ret = ctdb_client_control_multi(mem_ctx, ctdb->ev, ctdb->client,
					pnn_list, count, TIMEOUT(),
					&request, NULL, NULL);
	if (ret != 0) {
		goto failed;
	}

	ctdb_req_control_db_transaction_commit(&request, &wipedb);
	ret = ctdb_client_control_multi(mem_ctx, ctdb->ev, ctdb->client,
					pnn_list, count, TIMEOUT(),
					&request, NULL, NULL);
	if (ret != 0) {
		goto failed;
	}

	ctdb_req_control_db_thaw(&request, wipedb.db_id);
	ret = ctdb_client_control_multi(mem_ctx, ctdb->ev,
					ctdb->client, pnn_list, count,
					TIMEOUT(), &request, NULL, NULL);
	if (ret != 0) {
		goto failed;
	}

	printf("Database %s restored\n", db_name);
	close(fd);
	return 0;


failed:
	close(fd);
	ctdb_ctrl_set_recmode(mem_ctx, ctdb->ev, ctdb->client,
			      ctdb->pnn, TIMEOUT(), CTDB_RECOVERY_ACTIVE);
	return ret;
}

struct dumpdbbackup_state {
	ctdb_rec_parser_func_t parser;
	struct dump_record_state sub_state;
};

static int dumpdbbackup_handler(uint32_t reqid,
				struct ctdb_ltdb_header *header,
				TDB_DATA key, TDB_DATA data,
				void *private_data)
{
	struct dumpdbbackup_state *state =
		(struct dumpdbbackup_state *)private_data;
	struct ctdb_ltdb_header hdr;
	int ret;

	ret = ctdb_ltdb_header_extract(&data, &hdr);
	if (ret != 0) {
		return ret;
	}

	return state->parser(reqid, &hdr, key, data, &state->sub_state);
}

static int control_dumpdbbackup(TALLOC_CTX *mem_ctx, struct ctdb_context *ctdb,
				int argc, const char **argv)
{
	struct db_header db_hdr;
	char timebuf[128];
	struct dumpdbbackup_state state;
	ssize_t n;
	unsigned long i;
	int fd, ret;

	if (argc != 1) {
		usage("dumpbackup");
	}

	fd = open(argv[0], O_RDONLY, 0600);
	if (fd == -1) {
		ret = errno;
		fprintf(stderr, "Failed to open file %s for reading\n",
			argv[0]);
		return ret;
	}

	n = read(fd, &db_hdr, sizeof(struct db_header));
	if (n == -1) {
		ret = errno;
		close(fd);
		fprintf(stderr, "Failed to read db header from file %s\n",
			argv[0]);
		return ret;
	}
	db_hdr.name[sizeof(db_hdr.name)-1] = '\0';

	if (db_hdr.version != DB_VERSION) {
		fprintf(stderr,
			"Wrong version of backup file, expected %u, got %lu\n",
			DB_VERSION, db_hdr.version);
		close(fd);
		return EINVAL;
	}

	strftime(timebuf, sizeof(timebuf)-1, "%Y/%m/%d %H:%M:%S",
		 localtime(&db_hdr.timestamp));
	printf("Dumping database %s from backup @ %s\n",
	       db_hdr.name, timebuf);

	state.parser = dump_record;
	state.sub_state.count = 0;

	for (i=0; i<db_hdr.nbuf; i++) {
		struct ctdb_rec_buffer *recbuf;

		ret = ctdb_rec_buffer_read(fd, mem_ctx, &recbuf);
		if (ret != 0) {
			fprintf(stderr, "Failed to read records\n");
			close(fd);
			return ret;
		}

		ret = ctdb_rec_buffer_traverse(recbuf, dumpdbbackup_handler,
					       &state);
		if (ret != 0) {
			fprintf(stderr, "Failed to dump records\n");
			close(fd);
			return ret;
		}
	}

	close(fd);
	printf("Dumped %u record(s)\n", state.sub_state.count);
	return 0;
}

static int control_wipedb(TALLOC_CTX *mem_ctx, struct ctdb_context *ctdb,
			  int argc, const char **argv)
{
	const char *db_name;
	struct ctdb_db_context *db;
	uint32_t db_id;
	uint8_t db_flags;
	struct ctdb_node_map *nodemap;
	struct ctdb_req_control request;
	struct ctdb_transdb wipedb;
	uint32_t generation;
	uint32_t *pnn_list;
	int count, ret;

	if (argc != 1) {
		usage("wipedb");
	}

	if (! db_exists(mem_ctx, ctdb, argv[0], &db_id, &db_name, &db_flags)) {
		return 1;
	}

	ret = ctdb_attach(ctdb->ev, ctdb->client, TIMEOUT(), db_name,
			  db_flags, &db);
	if (ret != 0) {
		fprintf(stderr, "Failed to attach to DB %s\n", db_name);
		return ret;
	}

	nodemap = get_nodemap(ctdb, false);
	if (nodemap == NULL) {
		fprintf(stderr, "Failed to get nodemap\n");
		return ENOMEM;
	}

	ret = get_generation(mem_ctx, ctdb, &generation);
	if (ret != 0) {
		fprintf(stderr, "Failed to get current generation\n");
		return ret;
	}

	count = list_of_active_nodes(nodemap, CTDB_UNKNOWN_PNN, mem_ctx,
				     &pnn_list);
	if (count <= 0) {
		return ENOMEM;
	}

	ctdb_req_control_db_freeze(&request, db_id);
	ret = ctdb_client_control_multi(mem_ctx, ctdb->ev,
					ctdb->client, pnn_list, count,
					TIMEOUT(), &request, NULL, NULL);
	if (ret != 0) {
		goto failed;
	}

	wipedb.db_id = db_id;
	wipedb.tid = generation;

	ctdb_req_control_db_transaction_start(&request, &wipedb);
	ret = ctdb_client_control_multi(mem_ctx, ctdb->ev, ctdb->client,
					pnn_list, count, TIMEOUT(),
					&request, NULL, NULL);
	if (ret != 0) {
		goto failed;
	}

	ctdb_req_control_wipe_database(&request, &wipedb);
	ret = ctdb_client_control_multi(mem_ctx, ctdb->ev, ctdb->client,
					pnn_list, count, TIMEOUT(),
					&request, NULL, NULL);
	if (ret != 0) {
		goto failed;
	}

	ctdb_req_control_db_set_healthy(&request, db_id);
	ret = ctdb_client_control_multi(mem_ctx, ctdb->ev, ctdb->client,
					pnn_list, count, TIMEOUT(),
					&request, NULL, NULL);
	if (ret != 0) {
		goto failed;
	}

	ctdb_req_control_db_transaction_commit(&request, &wipedb);
	ret = ctdb_client_control_multi(mem_ctx, ctdb->ev, ctdb->client,
					pnn_list, count, TIMEOUT(),
					&request, NULL, NULL);
	if (ret != 0) {
		goto failed;
	}

	ctdb_req_control_db_thaw(&request, db_id);
	ret = ctdb_client_control_multi(mem_ctx, ctdb->ev,
					ctdb->client, pnn_list, count,
					TIMEOUT(), &request, NULL, NULL);
	if (ret != 0) {
		goto failed;
	}

	printf("Database %s wiped\n", db_name);
	return 0;


failed:
	ctdb_ctrl_set_recmode(mem_ctx, ctdb->ev, ctdb->client,
			      ctdb->pnn, TIMEOUT(), CTDB_RECOVERY_ACTIVE);
	return ret;
}

static int control_recmaster(TALLOC_CTX *mem_ctx, struct ctdb_context *ctdb,
			     int argc, const char **argv)
{
	uint32_t recmaster;
	int ret;

	ret = ctdb_ctrl_get_recmaster(mem_ctx, ctdb->ev, ctdb->client,
				      ctdb->cmd_pnn, TIMEOUT(), &recmaster);
	if (ret != 0) {
		return ret;
	}

	printf("%u\n", recmaster);
	return 0;
}

static int control_event(TALLOC_CTX *mem_ctx, struct ctdb_context *ctdb,
			 int argc, const char **argv)
{
	char *t, *event_helper = NULL;

	t = getenv("CTDB_EVENT_HELPER");
	if (t != NULL) {
		event_helper = talloc_strdup(mem_ctx, t);
	} else {
		event_helper = talloc_asprintf(mem_ctx, "%s/ctdb-event",
					       CTDB_HELPER_BINDIR);
	}

	if (event_helper == NULL) {
		fprintf(stderr, "Unable to set event daemon helper\n");
		return 1;
	}

	return run_helper(mem_ctx, "event daemon helper", event_helper,
			  argc, argv);
}

static int control_scriptstatus(TALLOC_CTX *mem_ctx, struct ctdb_context *ctdb,
				int argc, const char **argv)
{
	const char *new_argv[4];

	if (argc > 1) {
		usage("scriptstatus");
	}

	new_argv[0] = "status";
	new_argv[1] = "legacy";
	new_argv[2] = (argc == 0) ? "monitor" : argv[0];
	new_argv[3] = NULL;

	(void) control_event(mem_ctx, ctdb, 3, new_argv);
	return 0;
}

static int control_natgw(TALLOC_CTX *mem_ctx, struct ctdb_context *ctdb,
			 int argc, const char **argv)
{
	char *t, *natgw_helper = NULL;

	if (argc != 1) {
		usage("natgw");
	}

	t = getenv("CTDB_NATGW_HELPER");
	if (t != NULL) {
		natgw_helper = talloc_strdup(mem_ctx, t);
	} else {
		natgw_helper = talloc_asprintf(mem_ctx, "%s/ctdb_natgw",
					       CTDB_HELPER_BINDIR);
	}

	if (natgw_helper == NULL) {
		fprintf(stderr, "Unable to set NAT gateway helper\n");
		return 1;
	}

	return run_helper(mem_ctx, "NAT gateway helper", natgw_helper,
			  argc, argv);
}

/*
 * Find the PNN of the current node
 * discover the pnn by loading the nodes file and try to bind
 * to all addresses one at a time until the ip address is found.
 */
static bool find_node_xpnn(TALLOC_CTX *mem_ctx, uint32_t *pnn)
{
	struct ctdb_node_map *nodemap;
	unsigned int i;

	nodemap = read_nodes_file(mem_ctx, CTDB_UNKNOWN_PNN);
	if (nodemap == NULL) {
		return false;
	}

	for (i=0; i<nodemap->num; i++) {
		if (nodemap->node[i].flags & NODE_FLAGS_DELETED) {
			continue;
		}
		if (ctdb_sys_have_ip(&nodemap->node[i].addr)) {
			if (pnn != NULL) {
				*pnn = nodemap->node[i].pnn;
			}
			talloc_free(nodemap);
			return true;
		}
	}

	fprintf(stderr, "Failed to detect PNN of the current node.\n");
	talloc_free(nodemap);
	return false;
}

static int control_getreclock(TALLOC_CTX *mem_ctx, struct ctdb_context *ctdb,
			      int argc, const char **argv)
{
	const char *reclock;
	int ret;

	if (argc != 0) {
		usage("getreclock");
	}

	ret = ctdb_ctrl_get_reclock_file(mem_ctx, ctdb->ev, ctdb->client,
					 ctdb->cmd_pnn, TIMEOUT(), &reclock);
	if (ret != 0) {
		return ret;
	}

	if (reclock != NULL) {
		printf("%s\n", reclock);
	}

	return 0;
}

static int control_setlmasterrole(TALLOC_CTX *mem_ctx,
				  struct ctdb_context *ctdb,
				  int argc, const char **argv)
{
	uint32_t lmasterrole = 0;
	int ret;

	if (argc != 1) {
		usage("setlmasterrole");
	}

	if (strcmp(argv[0], "on") == 0) {
		lmasterrole = 1;
	} else if (strcmp(argv[0], "off") == 0) {
		lmasterrole = 0;
	} else {
		usage("setlmasterrole");
	}

	ret = ctdb_ctrl_set_lmasterrole(mem_ctx, ctdb->ev, ctdb->client,
					ctdb->cmd_pnn, TIMEOUT(), lmasterrole);
	if (ret != 0) {
		return ret;
	}

	return 0;
}

static int control_setrecmasterrole(TALLOC_CTX *mem_ctx,
				    struct ctdb_context *ctdb,
				    int argc, const char **argv)
{
	uint32_t recmasterrole = 0;
	int ret;

	if (argc != 1) {
		usage("setrecmasterrole");
	}

	if (strcmp(argv[0], "on") == 0) {
		recmasterrole = 1;
	} else if (strcmp(argv[0], "off") == 0) {
		recmasterrole = 0;
	} else {
		usage("setrecmasterrole");
	}

	ret = ctdb_ctrl_set_recmasterrole(mem_ctx, ctdb->ev, ctdb->client,
					  ctdb->cmd_pnn, TIMEOUT(),
					  recmasterrole);
	if (ret != 0) {
		return ret;
	}

	return 0;
}

static int control_setdbreadonly(TALLOC_CTX *mem_ctx,
				 struct ctdb_context *ctdb,
				 int argc, const char **argv)
{
	uint32_t db_id;
	uint8_t db_flags;
	int ret;

	if (argc != 1) {
		usage("setdbreadonly");
	}

	if (! db_exists(mem_ctx, ctdb, argv[0], &db_id, NULL, &db_flags)) {
		return 1;
	}

	if (db_flags & (CTDB_DB_FLAGS_PERSISTENT | CTDB_DB_FLAGS_REPLICATED)) {
		fprintf(stderr, "READONLY can be set only on volatile DB\n");
		return 1;
	}

	ret = ctdb_ctrl_set_db_readonly(mem_ctx, ctdb->ev, ctdb->client,
					ctdb->cmd_pnn, TIMEOUT(), db_id);
	if (ret != 0) {
		return ret;
	}

	return 0;
}

static int control_setdbsticky(TALLOC_CTX *mem_ctx, struct ctdb_context *ctdb,
			       int argc, const char **argv)
{
	uint32_t db_id;
	uint8_t db_flags;
	int ret;

	if (argc != 1) {
		usage("setdbsticky");
	}

	if (! db_exists(mem_ctx, ctdb, argv[0], &db_id, NULL, &db_flags)) {
		return 1;
	}

	if (db_flags & (CTDB_DB_FLAGS_PERSISTENT | CTDB_DB_FLAGS_REPLICATED)) {
		fprintf(stderr, "STICKY can be set only on volatile DB\n");
		return 1;
	}

	ret = ctdb_ctrl_set_db_sticky(mem_ctx, ctdb->ev, ctdb->client,
				      ctdb->cmd_pnn, TIMEOUT(), db_id);
	if (ret != 0) {
		return ret;
	}

	return 0;
}

static int control_pfetch(TALLOC_CTX *mem_ctx, struct ctdb_context *ctdb,
			  int argc, const char **argv)
{
	const char *db_name;
	struct ctdb_db_context *db;
	struct ctdb_transaction_handle *h;
	uint8_t db_flags;
	TDB_DATA key, data;
	int ret;

	if (argc != 2) {
		usage("pfetch");
	}

	if (! db_exists(mem_ctx, ctdb, argv[0], NULL, &db_name, &db_flags)) {
		return 1;
	}

	if (! (db_flags &
	       (CTDB_DB_FLAGS_PERSISTENT | CTDB_DB_FLAGS_REPLICATED))) {
		fprintf(stderr, "Transactions not supported on DB %s\n",
			db_name);
		return 1;
	}

	ret = ctdb_attach(ctdb->ev, ctdb->client, TIMEOUT(), db_name,
			  db_flags, &db);
	if (ret != 0) {
		fprintf(stderr, "Failed to attach to DB %s\n", db_name);
		return ret;
	}

	ret = str_to_data(argv[1], strlen(argv[1]), mem_ctx, &key);
	if (ret != 0) {
		fprintf(stderr, "Failed to parse key %s\n", argv[1]);
		return ret;
	}

	ret = ctdb_transaction_start(mem_ctx, ctdb->ev, ctdb->client,
				     TIMEOUT(), db, true, &h);
	if (ret != 0) {
		fprintf(stderr, "Failed to start transaction on db %s\n",
			db_name);
		return ret;
	}

	ret = ctdb_transaction_fetch_record(h, key, mem_ctx, &data);
	if (ret != 0) {
		fprintf(stderr, "Failed to read record for key %s\n",
			argv[1]);
		ctdb_transaction_cancel(h);
		return ret;
	}

	printf("%.*s\n", (int)data.dsize, data.dptr);

	ctdb_transaction_cancel(h);
	return 0;
}

static int control_pstore(TALLOC_CTX *mem_ctx, struct ctdb_context *ctdb,
			  int argc, const char **argv)
{
	const char *db_name;
	struct ctdb_db_context *db;
	struct ctdb_transaction_handle *h;
	uint8_t db_flags;
	TDB_DATA key, data;
	int ret;

	if (argc != 3) {
		usage("pstore");
	}

	if (! db_exists(mem_ctx, ctdb, argv[0], NULL, &db_name, &db_flags)) {
		return 1;
	}

	if (! (db_flags &
	       (CTDB_DB_FLAGS_PERSISTENT | CTDB_DB_FLAGS_REPLICATED))) {
		fprintf(stderr, "Transactions not supported on DB %s\n",
			db_name);
		return 1;
	}

	ret = ctdb_attach(ctdb->ev, ctdb->client, TIMEOUT(), db_name,
			  db_flags, &db);
	if (ret != 0) {
		fprintf(stderr, "Failed to attach to DB %s\n", db_name);
		return ret;
	}

	ret = str_to_data(argv[1], strlen(argv[1]), mem_ctx, &key);
	if (ret != 0) {
		fprintf(stderr, "Failed to parse key %s\n", argv[1]);
		return ret;
	}

	ret = str_to_data(argv[2], strlen(argv[2]), mem_ctx, &data);
	if (ret != 0) {
		fprintf(stderr, "Failed to parse value %s\n", argv[2]);
		return ret;
	}

	ret = ctdb_transaction_start(mem_ctx, ctdb->ev, ctdb->client,
				     TIMEOUT(), db, false, &h);
	if (ret != 0) {
		fprintf(stderr, "Failed to start transaction on db %s\n",
			db_name);
		return ret;
	}

	ret = ctdb_transaction_store_record(h, key, data);
	if (ret != 0) {
		fprintf(stderr, "Failed to store record for key %s\n",
			argv[1]);
		ctdb_transaction_cancel(h);
		return ret;
	}

	ret = ctdb_transaction_commit(h);
	if (ret != 0) {
		fprintf(stderr, "Failed to commit transaction on db %s\n",
			db_name);
		ctdb_transaction_cancel(h);
		return ret;
	}

	return 0;
}

static int control_pdelete(TALLOC_CTX *mem_ctx, struct ctdb_context *ctdb,
			   int argc, const char **argv)
{
	const char *db_name;
	struct ctdb_db_context *db;
	struct ctdb_transaction_handle *h;
	uint8_t db_flags;
	TDB_DATA key;
	int ret;

	if (argc != 2) {
		usage("pdelete");
	}

	if (! db_exists(mem_ctx, ctdb, argv[0], NULL, &db_name, &db_flags)) {
		return 1;
	}

	if (! (db_flags &
	       (CTDB_DB_FLAGS_PERSISTENT | CTDB_DB_FLAGS_REPLICATED))) {
		fprintf(stderr, "Transactions not supported on DB %s\n",
			db_name);
		return 1;
	}

	ret = ctdb_attach(ctdb->ev, ctdb->client, TIMEOUT(), db_name,
			  db_flags, &db);
	if (ret != 0) {
		fprintf(stderr, "Failed to attach to DB %s\n", db_name);
		return ret;
	}

	ret = str_to_data(argv[1], strlen(argv[1]), mem_ctx, &key);
	if (ret != 0) {
		fprintf(stderr, "Failed to parse key %s\n", argv[1]);
		return ret;
	}

	ret = ctdb_transaction_start(mem_ctx, ctdb->ev, ctdb->client,
				     TIMEOUT(), db, false, &h);
	if (ret != 0) {
		fprintf(stderr, "Failed to start transaction on db %s\n",
			db_name);
		return ret;
	}

	ret = ctdb_transaction_delete_record(h, key);
	if (ret != 0) {
		fprintf(stderr, "Failed to delete record for key %s\n",
			argv[1]);
		ctdb_transaction_cancel(h);
		return ret;
	}

	ret = ctdb_transaction_commit(h);
	if (ret != 0) {
		fprintf(stderr, "Failed to commit transaction on db %s\n",
			db_name);
		ctdb_transaction_cancel(h);
		return ret;
	}

	return 0;
}

static int ptrans_parse_string(TALLOC_CTX *mem_ctx, const char **ptr, TDB_DATA *data)
{
	const char *t;
	size_t n;
	int ret;

	*data = tdb_null;

	/* Skip whitespace */
	n = strspn(*ptr, " \t");
	t = *ptr + n;

	if (t[0] == '"') {
		/* Quoted ASCII string - no wide characters! */
		t++;
		n = strcspn(t, "\"");
		if (t[n] == '"') {
			if (n > 0) {
				ret = str_to_data(t, n, mem_ctx, data);
				if (ret != 0) {
					return ret;
				}
			}
			*ptr = t + n + 1;
		} else {
			fprintf(stderr, "Unmatched \" in input %s\n", *ptr);
			return 1;
		}
	} else {
		fprintf(stderr, "Unsupported input format in %s\n", *ptr);
		return 1;
	}

	return 0;
}

#define MAX_LINE_SIZE	1024

static bool ptrans_get_key_value(TALLOC_CTX *mem_ctx, FILE *file,
				 TDB_DATA *key, TDB_DATA *value)
{
	char line [MAX_LINE_SIZE]; /* FIXME: make this more flexible? */
	const char *ptr;
	int ret;

	ptr = fgets(line, MAX_LINE_SIZE, file);
	if (ptr == NULL) {
		return false;
	}

	/* Get key */
	ret = ptrans_parse_string(mem_ctx, &ptr, key);
	if (ret != 0 || ptr == NULL || key->dptr == NULL) {
		/* Line Ignored but not EOF */
		*key = tdb_null;
		return true;
	}

	/* Get value */
	ret = ptrans_parse_string(mem_ctx, &ptr, value);
	if (ret != 0) {
		/* Line Ignored but not EOF */
		talloc_free(key->dptr);
		*key = tdb_null;
		return true;
	}

	return true;
}

static int control_ptrans(TALLOC_CTX *mem_ctx, struct ctdb_context *ctdb,
			  int argc, const char **argv)
{
	const char *db_name;
	struct ctdb_db_context *db;
	struct ctdb_transaction_handle *h;
	uint8_t db_flags;
	FILE *file;
	TDB_DATA key = tdb_null, value = tdb_null;
	int ret;

	if (argc < 1 || argc > 2) {
		usage("ptrans");
	}

	if (! db_exists(mem_ctx, ctdb, argv[0], NULL, &db_name, &db_flags)) {
		return 1;
	}

	if (! (db_flags &
	       (CTDB_DB_FLAGS_PERSISTENT | CTDB_DB_FLAGS_REPLICATED))) {
		fprintf(stderr, "Transactions not supported on DB %s\n",
			db_name);
		return 1;
	}

	if (argc == 2) {
		file = fopen(argv[1], "r");
		if (file == NULL) {
			fprintf(stderr, "Failed to open file %s\n", argv[1]);
			return 1;
		}
	} else {
		file = stdin;
	}

	ret = ctdb_attach(ctdb->ev, ctdb->client, TIMEOUT(), db_name,
			  db_flags, &db);
	if (ret != 0) {
		fprintf(stderr, "Failed to attach to DB %s\n", db_name);
		goto done;
	}

	ret = ctdb_transaction_start(mem_ctx, ctdb->ev, ctdb->client,
				     TIMEOUT(), db, false, &h);
	if (ret != 0) {
		fprintf(stderr, "Failed to start transaction on db %s\n",
			db_name);
		goto done;
	}

	while (ptrans_get_key_value(mem_ctx, file, &key, &value)) {
		if (key.dsize != 0) {
			ret = ctdb_transaction_store_record(h, key, value);
			if (ret != 0) {
				fprintf(stderr, "Failed to store record\n");
				ctdb_transaction_cancel(h);
				goto done;
			}
			talloc_free(key.dptr);
			talloc_free(value.dptr);
		}
	}

	ret = ctdb_transaction_commit(h);
	if (ret != 0) {
		fprintf(stderr, "Failed to commit transaction on db %s\n",
			db_name);
		ctdb_transaction_cancel(h);
	}

done:
	if (file != stdin) {
		fclose(file);
	}
	return ret;
}

static int control_tfetch(TALLOC_CTX *mem_ctx, struct ctdb_context *ctdb,
			  int argc, const char **argv)
{
	struct tdb_context *tdb;
	TDB_DATA key, data;
	struct ctdb_ltdb_header header;
	int ret;

	if (argc < 2 || argc > 3) {
		usage("tfetch");
	}

	tdb = tdb_open(argv[0], 0, 0, O_RDWR, 0);
	if (tdb == NULL) {
		fprintf(stderr, "Failed to open TDB file %s\n", argv[0]);
		return 1;
	}

	ret = str_to_data(argv[1], strlen(argv[1]), mem_ctx, &key);
	if (ret != 0) {
		fprintf(stderr, "Failed to parse key %s\n", argv[1]);
		tdb_close(tdb);
		return ret;
	}

	data = tdb_fetch(tdb, key);
	if (data.dptr == NULL) {
		fprintf(stderr, "No record for key %s\n", argv[1]);
		tdb_close(tdb);
		return 1;
	}

	if (data.dsize < sizeof(struct ctdb_ltdb_header)) {
		fprintf(stderr, "Invalid record for key %s\n", argv[1]);
		tdb_close(tdb);
		return 1;
	}

	tdb_close(tdb);

	if (argc == 3) {
		int fd;
		ssize_t nwritten;

		fd = open(argv[2], O_WRONLY|O_CREAT|O_TRUNC, 0600);
		if (fd == -1) {
			fprintf(stderr, "Failed to open output file %s\n",
				argv[2]);
			goto fail;
		}

		nwritten = sys_write(fd, data.dptr, data.dsize);
		if (nwritten == -1 ||
		    (size_t)nwritten != data.dsize) {
			fprintf(stderr, "Failed to write record to file\n");
			close(fd);
			goto fail;
		}

		close(fd);
	}

fail:
	ret = ctdb_ltdb_header_extract(&data, &header);
	if (ret != 0) {
		fprintf(stderr, "Failed to parse header from data\n");
		return 1;
	}

	dump_ltdb_header(&header);
	dump_tdb_data("data", data);

	return 0;
}

static int control_tstore(TALLOC_CTX *mem_ctx, struct ctdb_context *ctdb,
			  int argc, const char **argv)
{
	struct tdb_context *tdb;
	TDB_DATA key, data[2], value;
	struct ctdb_ltdb_header header;
	uint8_t header_buf[sizeof(struct ctdb_ltdb_header)];
	size_t np;
	int ret = 0;

	if (argc < 3 || argc > 5) {
		usage("tstore");
	}

	tdb = tdb_open(argv[0], 0, 0, O_RDWR, 0);
	if (tdb == NULL) {
		fprintf(stderr, "Failed to open TDB file %s\n", argv[0]);
		return 1;
	}

	ret = str_to_data(argv[1], strlen(argv[1]), mem_ctx, &key);
	if (ret != 0) {
		fprintf(stderr, "Failed to parse key %s\n", argv[1]);
		tdb_close(tdb);
		return ret;
	}

	ret = str_to_data(argv[2], strlen(argv[2]), mem_ctx, &value);
	if (ret != 0) {
		fprintf(stderr, "Failed to parse value %s\n", argv[2]);
		tdb_close(tdb);
		return ret;
	}

	ZERO_STRUCT(header);

	if (argc > 3) {
		header.rsn = (uint64_t)smb_strtoull(argv[3],
						    NULL,
						    0,
						    &ret,
						    SMB_STR_STANDARD);
		if (ret != 0) {
			return ret;
		}
	}
	if (argc > 4) {
		header.dmaster = (uint32_t)atol(argv[4]);
	}
	if (argc > 5) {
		header.flags = (uint32_t)atol(argv[5]);
	}

	ctdb_ltdb_header_push(&header, header_buf, &np);

	data[0].dsize = np;
	data[0].dptr = header_buf;

	data[1].dsize = value.dsize;
	data[1].dptr = value.dptr;

	ret = tdb_storev(tdb, key, data, 2, TDB_REPLACE);
	if (ret != 0) {
		fprintf(stderr, "Failed to write record %s to file %s\n",
			argv[1], argv[0]);
	}

	tdb_close(tdb);

	return ret;
}

static int control_readkey(TALLOC_CTX *mem_ctx, struct ctdb_context *ctdb,
			   int argc, const char **argv)
{
	const char *db_name;
	struct ctdb_db_context *db;
	struct ctdb_record_handle *h;
	uint8_t db_flags;
	TDB_DATA key, data;
	bool readonly = false;
	int ret;

	if (argc < 2 || argc > 3) {
		usage("readkey");
	}

	if (argc == 3) {
		if (strcmp(argv[2], "readonly") == 0) {
			readonly = true;
		} else {
			usage("readkey");
		}
	}

	if (! db_exists(mem_ctx, ctdb, argv[0], NULL, &db_name, &db_flags)) {
		return 1;
	}

	if (db_flags & (CTDB_DB_FLAGS_PERSISTENT | CTDB_DB_FLAGS_REPLICATED)) {
		fprintf(stderr, "DB %s is not a volatile database\n",
			db_name);
		return 1;
	}

	ret = ctdb_attach(ctdb->ev, ctdb->client, TIMEOUT(), db_name,
			  db_flags, &db);
	if (ret != 0) {
		fprintf(stderr, "Failed to attach to DB %s\n", db_name);
		return ret;
	}

	ret = str_to_data(argv[1], strlen(argv[1]), mem_ctx, &key);
	if (ret != 0) {
		fprintf(stderr, "Failed to parse key %s\n", argv[1]);
		return ret;
	}

	ret = ctdb_fetch_lock(mem_ctx, ctdb->ev, ctdb->client,
			      db, key, readonly, &h, NULL, &data);
	if (ret != 0) {
		fprintf(stderr, "Failed to read record for key %s\n",
			argv[1]);
	} else {
		printf("Data: size:%zu ptr:[%.*s]\n", data.dsize,
		       (int)data.dsize, data.dptr);
	}

	talloc_free(h);
	return ret;
}

static int control_writekey(TALLOC_CTX *mem_ctx, struct ctdb_context *ctdb,
			    int argc, const char **argv)
{
	const char *db_name;
	struct ctdb_db_context *db;
	struct ctdb_record_handle *h;
	uint8_t db_flags;
	TDB_DATA key, data;
	int ret;

	if (argc != 3) {
		usage("writekey");
	}

	if (! db_exists(mem_ctx, ctdb, argv[0], NULL, &db_name, &db_flags)) {
		return 1;
	}

	if (db_flags & (CTDB_DB_FLAGS_PERSISTENT | CTDB_DB_FLAGS_REPLICATED)) {
		fprintf(stderr, "DB %s is not a volatile database\n",
			db_name);
		return 1;
	}

	ret = ctdb_attach(ctdb->ev, ctdb->client, TIMEOUT(), db_name,
			  db_flags, &db);
	if (ret != 0) {
		fprintf(stderr, "Failed to attach to DB %s\n", db_name);
		return ret;
	}

	ret = str_to_data(argv[1], strlen(argv[1]), mem_ctx, &key);
	if (ret != 0) {
		fprintf(stderr, "Failed to parse key %s\n", argv[1]);
		return ret;
	}

	ret = str_to_data(argv[2], strlen(argv[2]), mem_ctx, &data);
	if (ret != 0) {
		fprintf(stderr, "Failed to parse value %s\n", argv[2]);
		return ret;
	}

	ret = ctdb_fetch_lock(mem_ctx, ctdb->ev, ctdb->client,
			      db, key, false, &h, NULL, NULL);
	if (ret != 0) {
		fprintf(stderr, "Failed to lock record for key %s\n", argv[0]);
		return ret;
	}

	ret = ctdb_store_record(h, data);
	if (ret != 0) {
		fprintf(stderr, "Failed to store record for key %s\n",
			argv[1]);
	}

	talloc_free(h);
	return ret;
}

static int control_deletekey(TALLOC_CTX *mem_ctx, struct ctdb_context *ctdb,
			     int argc, const char **argv)
{
	const char *db_name;
	struct ctdb_db_context *db;
	struct ctdb_record_handle *h;
	uint8_t db_flags;
	TDB_DATA key, data;
	int ret;

	if (argc != 2) {
		usage("deletekey");
	}

	if (! db_exists(mem_ctx, ctdb, argv[0], NULL, &db_name, &db_flags)) {
		return 1;
	}

	if (db_flags & (CTDB_DB_FLAGS_PERSISTENT | CTDB_DB_FLAGS_REPLICATED)) {
		fprintf(stderr, "DB %s is not a volatile database\n",
			db_name);
		return 1;
	}

	ret = ctdb_attach(ctdb->ev, ctdb->client, TIMEOUT(), db_name,
			  db_flags, &db);
	if (ret != 0) {
		fprintf(stderr, "Failed to attach to DB %s\n", db_name);
		return ret;
	}

	ret = str_to_data(argv[1], strlen(argv[1]), mem_ctx, &key);
	if (ret != 0) {
		fprintf(stderr, "Failed to parse key %s\n", argv[1]);
		return ret;
	}

	ret = ctdb_fetch_lock(mem_ctx, ctdb->ev, ctdb->client,
			      db, key, false, &h, NULL, &data);
	if (ret != 0) {
		fprintf(stderr, "Failed to fetch record for key %s\n",
			argv[1]);
		return ret;
	}

	ret = ctdb_delete_record(h);
	if (ret != 0) {
		fprintf(stderr, "Failed to delete record for key %s\n",
			argv[1]);
	}

	talloc_free(h);
	return ret;
}

static int control_checktcpport(TALLOC_CTX *mem_ctx, struct ctdb_context *ctdb,
				int argc, const char **argv)
{
	struct sockaddr_in sin;
	unsigned int port;
	int s, v;
	int ret;

	if (argc != 1) {
		usage("chktcpport");
	}

	port = atoi(argv[0]);

	s = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (s == -1) {
		fprintf(stderr, "Failed to open local socket\n");
		return errno;
	}

	v = fcntl(s, F_GETFL, 0);
	if (v == -1 || fcntl(s, F_SETFL, v | O_NONBLOCK)) {
		fprintf(stderr, "Unable to set socket non-blocking\n");
		close(s);
		return errno;
	}

	bzero(&sin, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_port = htons(port);
	ret = bind(s, (struct sockaddr *)&sin, sizeof(sin));
	close(s);
	if (ret == -1) {
		fprintf(stderr, "Failed to bind to TCP port %u\n", port);
		return errno;
	}

	return 0;
}

static int control_getdbseqnum(TALLOC_CTX *mem_ctx, struct ctdb_context *ctdb,
			       int argc, const char **argv)
{
	uint32_t db_id;
	const char *db_name;
	uint64_t seqnum;
	int ret;

	if (argc != 1) {
		usage("getdbseqnum");
	}

	if (! db_exists(mem_ctx, ctdb, argv[0], &db_id, &db_name, NULL)) {
		return 1;
	}

	ret = ctdb_ctrl_get_db_seqnum(mem_ctx, ctdb->ev, ctdb->client,
				      ctdb->cmd_pnn, TIMEOUT(), db_id,
				      &seqnum);
	if (ret != 0) {
		fprintf(stderr, "Failed to get sequence number for DB %s\n",
			db_name);
		return ret;
	}

	printf("0x%"PRIx64"\n", seqnum);
	return 0;
}

static int control_nodestatus(TALLOC_CTX *mem_ctx, struct ctdb_context *ctdb,
			      int argc, const char **argv)
{
	const char *nodestring = NULL;
	struct ctdb_node_map *nodemap;
	unsigned int i;
	int ret;
	bool print_hdr = false;

	if (argc > 1) {
		usage("nodestatus");
	}

	if (argc == 1) {
		nodestring = argv[0];
		if (strcmp(nodestring, "all") == 0) {
			print_hdr = true;
		}
	}

	if (! parse_nodestring(mem_ctx, ctdb, nodestring, &nodemap)) {
		return 1;
	}

	if (options.machinereadable) {
		print_nodemap_machine(mem_ctx, ctdb, nodemap, ctdb->cmd_pnn);
	} else {
		print_nodemap(mem_ctx, ctdb, nodemap, ctdb->cmd_pnn, print_hdr);
	}

	ret = 0;
	for (i=0; i<nodemap->num; i++) {
		uint32_t flags = nodemap->node[i].flags;

		if ((flags & NODE_FLAGS_DELETED) != 0) {
			continue;
		}

		ret |= flags;
	}

	return ret;
}

const struct {
	const char *name;
	uint32_t offset;
} db_stats_fields[] = {
#define DBSTATISTICS_FIELD(n) { #n, offsetof(struct ctdb_db_statistics, n) }
	DBSTATISTICS_FIELD(db_ro_delegations),
	DBSTATISTICS_FIELD(db_ro_revokes),
	DBSTATISTICS_FIELD(locks.num_calls),
	DBSTATISTICS_FIELD(locks.num_current),
	DBSTATISTICS_FIELD(locks.num_pending),
	DBSTATISTICS_FIELD(locks.num_failed),
};

static void print_dbstatistics(const char *db_name,
			       struct ctdb_db_statistics *s)
{
	size_t i;
	const char *prefix = NULL;
	int preflen = 0;

	printf("DB Statistics %s\n", db_name);

	for (i=0; i<ARRAY_SIZE(db_stats_fields); i++) {
		if (strchr(db_stats_fields[i].name, '.') != NULL) {
			preflen = strcspn(db_stats_fields[i].name, ".") + 1;
			if (! prefix ||
			    strncmp(prefix, db_stats_fields[i].name, preflen) != 0) {
				prefix = db_stats_fields[i].name;
				printf(" %*.*s\n", preflen-1, preflen-1,
				       db_stats_fields[i].name);
			}
		} else {
			preflen = 0;
		}
		printf(" %*s%-22s%*s%10u\n", preflen ? 4 : 0, "",
		       db_stats_fields[i].name+preflen, preflen ? 0 : 4, "",
		       *(uint32_t *)(db_stats_fields[i].offset+(uint8_t *)s));
	}

	printf(" hop_count_buckets:");
	for (i=0; i<MAX_COUNT_BUCKETS; i++) {
		printf(" %d", s->hop_count_bucket[i]);
	}
	printf("\n");

	printf(" lock_buckets:");
	for (i=0; i<MAX_COUNT_BUCKETS; i++) {
		printf(" %d", s->locks.buckets[i]);
	}
	printf("\n");

	printf(" %-30s     %.6f/%.6f/%.6f sec out of %d\n",
	       "locks_latency      MIN/AVG/MAX",
	       s->locks.latency.min, LATENCY_AVG(s->locks.latency),
	       s->locks.latency.max, s->locks.latency.num);

	printf(" %-30s     %.6f/%.6f/%.6f sec out of %d\n",
	       "vacuum_latency     MIN/AVG/MAX",
	       s->vacuum.latency.min, LATENCY_AVG(s->vacuum.latency),
	       s->vacuum.latency.max, s->vacuum.latency.num);

	printf(" Num Hot Keys:     %d\n", s->num_hot_keys);
	for (i=0; i<s->num_hot_keys; i++) {
		size_t j;
		printf("     Count:%d Key:", s->hot_keys[i].count);
		for (j=0; j<s->hot_keys[i].key.dsize; j++) {
			printf("%02x", s->hot_keys[i].key.dptr[j] & 0xff);
		}
		printf("\n");
	}
}

static int control_dbstatistics(TALLOC_CTX *mem_ctx, struct ctdb_context *ctdb,
			        int argc, const char **argv)
{
	uint32_t db_id;
	const char *db_name;
	struct ctdb_db_statistics *dbstats;
	int ret;

	if (argc != 1) {
		usage("dbstatistics");
	}

	if (! db_exists(mem_ctx, ctdb, argv[0], &db_id, &db_name, NULL)) {
		return 1;
	}

	ret = ctdb_ctrl_get_db_statistics(mem_ctx, ctdb->ev, ctdb->client,
					  ctdb->cmd_pnn, TIMEOUT(), db_id,
					  &dbstats);
	if (ret != 0) {
		fprintf(stderr, "Failed to get statistics for DB %s\n",
			db_name);
		return ret;
	}

	print_dbstatistics(db_name, dbstats);
	return 0;
}

struct disable_takeover_runs_state {
	uint32_t *pnn_list;
	unsigned int node_count;
	bool *reply;
	int status;
	bool done;
};

static void disable_takeover_run_handler(uint64_t srvid, TDB_DATA data,
					 void *private_data)
{
	struct disable_takeover_runs_state *state =
		(struct disable_takeover_runs_state *)private_data;
	unsigned int i;
	int ret;

	if (data.dsize != sizeof(int)) {
		/* Ignore packet */
		return;
	}

	/* ret will be a PNN (i.e. >=0) on success, or negative on error */
	ret = *(int *)data.dptr;
	if (ret < 0) {
		state->status = ret;
		state->done = true;
		return;
	}
	for (i=0; i<state->node_count; i++) {
		if (state->pnn_list[i] == (uint32_t)ret) {
			state->reply[i] = true;
			break;
		}
	}

	state->done = true;
	for (i=0; i<state->node_count; i++) {
		if (! state->reply[i]) {
			state->done = false;
			break;
		}
	}
}

static int disable_takeover_runs(TALLOC_CTX *mem_ctx,
				 struct ctdb_context *ctdb, uint32_t timeout,
				 uint32_t *pnn_list, int count)
{
	struct ctdb_disable_message disable = { 0 };
	struct disable_takeover_runs_state state;
	int ret, i;

	disable.pnn = ctdb->pnn;
	disable.srvid = next_srvid(ctdb);
	disable.timeout = timeout;

	state.pnn_list = pnn_list;
	state.node_count = count;
	state.done = false;
	state.status = 0;
	state.reply = talloc_zero_array(mem_ctx, bool, count);
	if (state.reply == NULL) {
		return ENOMEM;
	}

	ret = ctdb_client_set_message_handler(ctdb->ev, ctdb->client,
					      disable.srvid,
					      disable_takeover_run_handler,
					      &state);
	if (ret != 0) {
		return ret;
	}

	for (i=0; i<count; i++) {
		ret = ctdb_message_disable_takeover_runs(mem_ctx, ctdb->ev,
							 ctdb->client,
							 pnn_list[i],
							 &disable);
		if (ret != 0) {
			goto fail;
		}
	}

	ret = ctdb_client_wait_timeout(ctdb->ev, &state.done, TIMEOUT());
	if (ret == ETIME) {
		fprintf(stderr, "Timed out waiting to disable takeover runs\n");
	} else {
		ret = (state.status >= 0 ? 0 : 1);
	}

fail:
	ctdb_client_remove_message_handler(ctdb->ev, ctdb->client,
					   disable.srvid, &state);
	return ret;
}

static int control_reloadips(TALLOC_CTX *mem_ctx, struct ctdb_context *ctdb,
			     int argc, const char **argv)
{
	const char *nodestring = NULL;
	struct ctdb_node_map *nodemap, *nodemap2;
	struct ctdb_req_control request;
	uint32_t *pnn_list, *pnn_list2;
	int ret, count, count2;

	if (argc > 1) {
		usage("reloadips");
	}

	if (argc == 1) {
		nodestring = argv[0];
	}

	nodemap = get_nodemap(ctdb, false);
	if (nodemap == NULL) {
		return 1;
	}

	if (! parse_nodestring(mem_ctx, ctdb, nodestring, &nodemap2)) {
		return 1;
	}

	count = list_of_connected_nodes(nodemap, CTDB_UNKNOWN_PNN,
					mem_ctx, &pnn_list);
	if (count <= 0) {
		fprintf(stderr, "Memory allocation error\n");
		return 1;
	}

	count2 = list_of_active_nodes(nodemap2, CTDB_UNKNOWN_PNN,
				      mem_ctx, &pnn_list2);
	if (count2 <= 0) {
		fprintf(stderr, "Memory allocation error\n");
		return 1;
	}

	/* Disable takeover runs on all connected nodes.  A reply
	 * indicating success is needed from each node so all nodes
	 * will need to be active.
	 *
	 * A check could be added to not allow reloading of IPs when
	 * there are disconnected nodes.  However, this should
	 * probably be left up to the administrator.
	 */
	ret = disable_takeover_runs(mem_ctx, ctdb, 2*options.timelimit,
				    pnn_list, count);
	if (ret != 0) {
		fprintf(stderr, "Failed to disable takeover runs\n");
		return ret;
	}

	/* Now tell all the desired nodes to reload their public IPs.
	 * Keep trying this until it succeeds.  This assumes all
	 * failures are transient, which might not be true...
	 */
	ctdb_req_control_reload_public_ips(&request);
	ret = ctdb_client_control_multi(mem_ctx, ctdb->ev, ctdb->client,
					pnn_list2, count2, TIMEOUT(),
					&request, NULL, NULL);
	if (ret != 0) {
		fprintf(stderr, "Failed to reload IPs on some nodes.\n");
	}

	/* It isn't strictly necessary to wait until takeover runs are
	 * re-enabled but doing so can't hurt.
	 */
	ret = disable_takeover_runs(mem_ctx, ctdb, 0, pnn_list, count);
	if (ret != 0) {
		fprintf(stderr, "Failed to enable takeover runs\n");
		return ret;
	}

	return ipreallocate(mem_ctx, ctdb);
}


static const struct ctdb_cmd {
	const char *name;
	int (*fn)(TALLOC_CTX *, struct ctdb_context *, int, const char **);
	bool without_daemon; /* can be run without daemon running ? */
	bool remote; /* can be run on remote nodes */
	const char *msg;
	const char *args;
} ctdb_commands[] = {
	{ "version", control_version, true, false,
		"show version of ctdb", NULL },
	{ "status", control_status, false, true,
		"show node status", NULL },
	{ "uptime", control_uptime, false, true,
		"show node uptime", NULL },
	{ "ping", control_ping, false, true,
		"ping a node", NULL },
	{ "runstate", control_runstate, false, true,
		"get/check runstate of a node",
		"[setup|first_recovery|startup|running]" },
	{ "getvar", control_getvar, false, true,
		"get a tunable variable", "<name>" },
	{ "setvar", control_setvar, false, true,
		"set a tunable variable", "<name> <value>" },
	{ "listvars", control_listvars, false, true,
		"list tunable variables", NULL },
	{ "statistics", control_statistics, false, true,
		"show ctdb statistics", NULL },
	{ "statisticsreset", control_statistics_reset, false, true,
		"reset ctdb statistics", NULL },
	{ "stats", control_stats, false, true,
		"show rolling statistics", "[count]" },
	{ "ip", control_ip, false, true,
		"show public ips", "[all]" },
	{ "ipinfo", control_ipinfo, false, true,
		"show public ip details", "<ip>" },
	{ "ifaces", control_ifaces, false, true,
		"show interfaces", NULL },
	{ "setifacelink", control_setifacelink, false, true,
		"set interface link status", "<iface> up|down" },
	{ "process-exists", control_process_exists, false, true,
		"check if a process exists on a node",  "<pid> [<srvid>]" },
	{ "getdbmap", control_getdbmap, false, true,
		"show attached databases", NULL },
	{ "getdbstatus", control_getdbstatus, false, true,
		"show database status", "<dbname|dbid>" },
	{ "catdb", control_catdb, false, false,
		"dump cluster-wide ctdb database", "<dbname|dbid>" },
	{ "cattdb", control_cattdb, false, false,
		"dump local ctdb database", "<dbname|dbid>" },
	{ "getcapabilities", control_getcapabilities, false, true,
		"show node capabilities", NULL },
	{ "pnn", control_pnn, false, false,
		"show the pnn of the currnet node", NULL },
	{ "lvs", control_lvs, false, false,
		"show lvs configuration", "master|list|status" },
	{ "setdebug", control_setdebug, false, true,
		"set debug level", "ERROR|WARNING|NOTICE|INFO|DEBUG" },
	{ "getdebug", control_getdebug, false, true,
		"get debug level", NULL },
	{ "attach", control_attach, false, false,
		"attach a database", "<dbname> [persistent|replicated]" },
	{ "detach", control_detach, false, false,
		"detach database(s)", "<dbname|dbid> ..." },
	{ "dumpmemory", control_dumpmemory, false, true,
		"dump ctdbd memory map", NULL },
	{ "rddumpmemory", control_rddumpmemory, false, true,
		"dump recoverd memory map", NULL },
	{ "getpid", control_getpid, false, true,
		"get ctdbd process ID", NULL },
	{ "disable", control_disable, false, true,
		"disable a node", NULL },
	{ "enable", control_enable, false, true,
		"enable a node", NULL },
	{ "stop", control_stop, false, true,
		"stop a node", NULL },
	{ "continue", control_continue, false, true,
		"continue a stopped node", NULL },
	{ "ban", control_ban, false, true,
		"ban a node", "<bantime>"},
	{ "unban", control_unban, false, true,
		"unban a node", NULL },
	{ "shutdown", control_shutdown, false, true,
		"shutdown ctdb daemon", NULL },
	{ "recover", control_recover, false, true,
		"force recovery", NULL },
	{ "sync", control_ipreallocate, false, true,
		"run ip reallocation (deprecated)", NULL },
	{ "ipreallocate", control_ipreallocate, false, true,
		"run ip reallocation", NULL },
	{ "isnotrecmaster", control_isnotrecmaster, false, false,
		"check if local node is the recmaster", NULL },
	{ "gratarp", control_gratarp, false, true,
		"send a gratuitous arp", "<ip> <interface>" },
	{ "tickle", control_tickle, true, false,
		"send a tcp tickle ack", "<srcip:port> <dstip:port>" },
	{ "gettickles", control_gettickles, false, true,
		"get the list of tickles", "<ip> [<port>]" },
	{ "addtickle", control_addtickle, false, true,
		"add a tickle", "<ip>:<port> <ip>:<port>" },
	{ "deltickle", control_deltickle, false, true,
		"delete a tickle", "<ip>:<port> <ip>:<port>" },
	{ "listnodes", control_listnodes, true, true,
		"list nodes in the cluster", NULL },
	{ "reloadnodes", control_reloadnodes, false, false,
		"reload the nodes file all nodes", NULL },
	{ "moveip", control_moveip, false, false,
		"move an ip address to another node", "<ip> <node>" },
	{ "addip", control_addip, false, true,
		"add an ip address to a node", "<ip/mask> <iface>" },
	{ "delip", control_delip, false, true,
		"delete an ip address from a node", "<ip>" },
	{ "backupdb", control_backupdb, false, false,
		"backup a database into a file", "<dbname|dbid> <file>" },
	{ "restoredb", control_restoredb, false, false,
		"restore a database from a file", "<file> [dbname]" },
	{ "dumpdbbackup", control_dumpdbbackup, true, false,
		"dump database from a backup file", "<file>" },
	{ "wipedb", control_wipedb, false, false,
		"wipe the contents of a database.", "<dbname|dbid>"},
	{ "recmaster", control_recmaster, false, true,
		"show the pnn for the recovery master", NULL },
	{ "event", control_event, true, false,
		"event and event script commands", NULL },
	{ "scriptstatus", control_scriptstatus, true, false,
		"show event script status",
		"[init|setup|startup|monitor|takeip|releaseip|ipreallocated]" },
	{ "natgw", control_natgw, false, false,
		"show natgw configuration", "master|list|status" },
	{ "getreclock", control_getreclock, false, true,
		"get recovery lock file", NULL },
	{ "setlmasterrole", control_setlmasterrole, false, true,
		"set LMASTER role", "on|off" },
	{ "setrecmasterrole", control_setrecmasterrole, false, true,
		"set RECMASTER role", "on|off"},
	{ "setdbreadonly", control_setdbreadonly, false, true,
		"enable readonly records", "<dbname|dbid>" },
	{ "setdbsticky", control_setdbsticky, false, true,
		"enable sticky records", "<dbname|dbid>"},
	{ "pfetch", control_pfetch, false, false,
		"fetch record from persistent database", "<dbname|dbid> <key>" },
	{ "pstore", control_pstore, false, false,
		"write record to persistent database", "<dbname|dbid> <key> <value>" },
	{ "pdelete", control_pdelete, false, false,
		"delete record from persistent database", "<dbname|dbid> <key>" },
	{ "ptrans", control_ptrans, false, false,
		"update a persistent database (from file or stdin)", "<dbname|dbid> [<file>]" },
	{ "tfetch", control_tfetch, false, true,
		"fetch a record", "<tdb-file> <key> [<file>]" },
	{ "tstore", control_tstore, false, true,
		"store a record", "<tdb-file> <key> <data> [<rsn> <dmaster> <flags>]" },
	{ "readkey", control_readkey, false, false,
		"read value of a database key", "<dbname|dbid> <key> [readonly]" },
	{ "writekey", control_writekey, false, false,
		"write value for a database key", "<dbname|dbid> <key> <value>" },
	{ "deletekey", control_deletekey, false, false,
		"delete a database key", "<dbname|dbid> <key>" },
	{ "checktcpport", control_checktcpport, true, false,
		"check if a service is bound to a specific tcp port or not", "<port>" },
	{ "getdbseqnum", control_getdbseqnum, false, false,
		"get database sequence number", "<dbname|dbid>" },
	{ "nodestatus", control_nodestatus, false, true,
		"show and return node status", "[all|<pnn-list>]" },
	{ "dbstatistics", control_dbstatistics, false, true,
		"show database statistics", "<dbname|dbid>" },
	{ "reloadips", control_reloadips, false, false,
		"reload the public addresses file", "[all|<pnn-list>]" },
};

static const struct ctdb_cmd *match_command(const char *command)
{
	const struct ctdb_cmd *cmd;
	size_t i;

	for (i=0; i<ARRAY_SIZE(ctdb_commands); i++) {
		cmd = &ctdb_commands[i];
		if (strlen(command) == strlen(cmd->name) &&
		    strncmp(command, cmd->name, strlen(command)) == 0) {
			return cmd;
		}
	}

	return NULL;
}


/**
 * Show usage message
 */
static void usage_full(void)
{
	size_t i;

	poptPrintHelp(pc, stdout, 0);
	printf("\nCommands:\n");
	for (i=0; i<ARRAY_SIZE(ctdb_commands); i++) {
		printf("  %-15s %-27s  %s\n",
		       ctdb_commands[i].name,
		       ctdb_commands[i].args ? ctdb_commands[i].args : "",
		       ctdb_commands[i].msg);
	}
}

static void usage(const char *command)
{
	const struct ctdb_cmd *cmd;

	if (command == NULL) {
		usage_full();
		exit(1);
	}

	cmd = match_command(command);
	if (cmd == NULL) {
		usage_full();
	} else {
		poptPrintUsage(pc, stdout, 0);
		printf("\nCommands:\n");
		printf("  %-15s %-27s  %s\n",
		       cmd->name, cmd->args ? cmd->args : "", cmd->msg);
	}

	exit(1);
}

struct poptOption cmdline_options[] = {
	POPT_AUTOHELP
	{
		.longName   = "debug",
		.shortName  = 'd',
		.argInfo    = POPT_ARG_STRING,
		.arg        = &options.debuglevelstr,
		.val        = 0,
		.descrip    = "debug level",
	},
	{
		.longName   = "timelimit",
		.shortName  = 't',
		.argInfo    = POPT_ARG_INT,
		.arg        = &options.timelimit,
		.val        = 0,
		.descrip    = "timelimit (in seconds)",
	},
	{
		.longName   = "node",
		.shortName  = 'n',
		.argInfo    = POPT_ARG_INT,
		.arg        = &options.pnn,
		.val        = 0,
		.descrip    = "node specification - integer",
	},
	{
		.longName   = NULL,
		.shortName  = 'Y',
		.argInfo    = POPT_ARG_NONE,
		.arg        = &options.machinereadable,
		.val        = 0,
		.descrip    = "enable machine readable output",
	},
	{
		.longName   = "separator",
		.shortName  = 'x',
		.argInfo    = POPT_ARG_STRING,
		.arg        = &options.sep,
		.val        = 0,
		.descrip    = "specify separator for machine readable output",
		.argDescrip = "CHAR",
	},
	{
		.shortName  = 'X',
		.argInfo    = POPT_ARG_NONE,
		.arg        = &options.machineparsable,
		.val        = 0,
		.descrip    = "enable machine parsable output with separator |",
	},
	{
		.longName   = "verbose",
		.shortName  = 'v',
		.argInfo    = POPT_ARG_NONE,
		.arg        = &options.verbose,
		.val        = 0,
		.descrip    = "enable verbose output",
	},
	{
		.longName   = "maxruntime",
		.shortName  = 'T',
		.argInfo    = POPT_ARG_INT,
		.arg        = &options.maxruntime,
		.val        = 0,
		.descrip    = "die if runtime exceeds this limit (in seconds)",
	},
	POPT_TABLEEND
};

static int process_command(const struct ctdb_cmd *cmd, int argc,
			   const char **argv)
{
	TALLOC_CTX *tmp_ctx;
	struct ctdb_context *ctdb;
	const char *ctdb_socket;
	int ret;
	bool status;
	uint64_t srvid_offset;

	tmp_ctx = talloc_new(NULL);
	if (tmp_ctx == NULL) {
		fprintf(stderr, "Memory allocation error\n");
		goto fail;
	}

	if (cmd->without_daemon) {
		if (options.pnn != -1) {
			fprintf(stderr,
				"Cannot specify node for command %s\n",
				cmd->name);
			goto fail;
		}

		ret = cmd->fn(tmp_ctx, NULL, argc-1, argv+1);
		talloc_free(tmp_ctx);
		return ret;
	}

	ctdb = talloc_zero(tmp_ctx, struct ctdb_context);
	if (ctdb == NULL) {
		fprintf(stderr, "Memory allocation error\n");
		goto fail;
	}

	ctdb->ev = tevent_context_init(ctdb);
	if (ctdb->ev == NULL) {
		fprintf(stderr, "Failed to initialize tevent\n");
		goto fail;
	}

	ctdb_socket = path_socket(ctdb, "ctdbd");
	if (ctdb_socket == NULL) {
		fprintf(stderr, "Memory allocation error\n");
		goto fail;
	}

	ret = ctdb_client_init(ctdb, ctdb->ev, ctdb_socket, &ctdb->client);
	if (ret != 0) {
		fprintf(stderr, "Failed to connect to CTDB daemon (%s)\n",
			ctdb_socket);

		if (!find_node_xpnn(ctdb, NULL)) {
			fprintf(stderr, "Is this node part of CTDB cluster?\n");
		}
		goto fail;
	}

	ctdb->pnn = ctdb_client_pnn(ctdb->client);
	srvid_offset = getpid() & 0xFFFF;
	ctdb->srvid = SRVID_CTDB_TOOL | (srvid_offset << 16);

	if (options.pnn != -1) {
		status = verify_pnn(ctdb, options.pnn);
		if (! status) {
			goto fail;
		}

		ctdb->cmd_pnn = options.pnn;
	} else {
		ctdb->cmd_pnn = ctdb->pnn;
	}

	if (! cmd->remote && ctdb->pnn != ctdb->cmd_pnn) {
		fprintf(stderr, "Node cannot be specified for command %s\n",
			cmd->name);
		goto fail;
	}

	ret = cmd->fn(tmp_ctx, ctdb, argc-1, argv+1);
	talloc_free(tmp_ctx);
	return ret;

fail:
	talloc_free(tmp_ctx);
	return 1;
}

static void signal_handler(int sig)
{
	fprintf(stderr, "Maximum runtime exceeded - exiting\n");
}

static void alarm_handler(int sig)
{
	/* Kill any child processes */
	signal(SIGTERM, signal_handler);
	kill(0, SIGTERM);

	_exit(1);
}

int main(int argc, const char *argv[])
{
	int opt;
	const char **extra_argv;
	int extra_argc;
	const struct ctdb_cmd *cmd;
	const char *test_mode;
	int loglevel;
	bool ok;
	int ret = 0;

	setlinebuf(stdout);

	/* Set default options */
	options.debuglevelstr = NULL;
	options.timelimit = 10;
	options.sep = "|";
	options.maxruntime = 0;
	options.pnn = -1;

	pc = poptGetContext(argv[0], argc, argv, cmdline_options,
			    POPT_CONTEXT_KEEP_FIRST);
	while ((opt = poptGetNextOpt(pc)) != -1) {
		fprintf(stderr, "Invalid option %s: %s\n",
			poptBadOption(pc, 0), poptStrerror(opt));
		exit(1);
	}

	if (options.maxruntime == 0) {
		const char *ctdb_timeout;

		ctdb_timeout = getenv("CTDB_TIMEOUT");
		if (ctdb_timeout != NULL) {
			options.maxruntime = smb_strtoul(ctdb_timeout,
							 NULL,
							 0,
							 &ret,
							 SMB_STR_STANDARD);
			if (ret != 0) {
				fprintf(stderr, "Invalid value CTDB_TIMEOUT\n");
				exit(1);
			}
		} else {
			options.maxruntime = 120;
		}
	}

	if (options.machineparsable) {
		options.machinereadable = 1;
	}

	/* setup the remaining options for the commands */
	extra_argc = 0;
	extra_argv = poptGetArgs(pc);
	if (extra_argv) {
		extra_argv++;
		while (extra_argv[extra_argc]) extra_argc++;
	}

	if (extra_argc < 1) {
		usage(NULL);
	}

	cmd = match_command(extra_argv[0]);
	if (cmd == NULL) {
		fprintf(stderr, "Unknown command '%s'\n", extra_argv[0]);
		exit(1);
	}

	/* Enable logging */
	setup_logging("ctdb", DEBUG_STDERR);
	ok = debug_level_parse(options.debuglevelstr, &loglevel);
	if (!ok) {
		loglevel = DEBUG_ERR;
	}
	debuglevel_set(loglevel);

	/* Stop process group kill in alarm_handler() from killing tests */
	test_mode = getenv("CTDB_TEST_MODE");
	if (test_mode != NULL) {
		const char *have_setpgid = getenv("CTDB_TOOL_SETPGID");
		if (have_setpgid == NULL) {
			setpgid(0, 0);
			setenv("CTDB_TOOL_SETPGID", "1", 1);
		}
	}

	signal(SIGALRM, alarm_handler);
	alarm(options.maxruntime);

	ret = process_command(cmd, extra_argc, extra_argv);
	if (ret == -1) {
		ret = 1;
	}

	(void)poptFreeContext(pc);

	return ret;
}
