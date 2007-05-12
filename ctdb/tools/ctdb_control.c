/* 
   ctdb control tool

   Copyright (C) Andrew Tridgell  2007

   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with this library; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#include "includes.h"
#include "lib/events/events.h"
#include "system/filesys.h"
#include "popt.h"
#include "cmdline.h"
#include "../include/ctdb.h"
#include "../include/ctdb_private.h"


/*
  show usage message
 */
static void usage(void)
{
	printf(
		"Usage: ctdb_control [options] <control>\n"
		"\nControls:\n"
		"  ping\n"
		"  process-exists <vnn:pid>           see if a process exists\n"
		"  status <vnn|all>                   show ctdb status on a node\n"
		"  statusreset <vnn|all>              reset status on a node\n"
		"  debug <vnn|all> <level>            set ctdb debug level on a node\n"
		"  debuglevel                         display ctdb debug levels\n"
		"  getvnnmap <vnn>                    display ctdb vnnmap\n"
		"  setvnnmap <vnn> <generation> <numslots> <lmaster>*\n"
		"  getdbmap <vnn>                     lists databases on a node\n"
		"  getnodemap <vnn>                   lists nodes known to a ctdb daemon\n"
		"  createdb <vnn> <dbname>            create a database\n"
		"  catdb <dbname> [vnn]               lists all keys/data in a db\n"
		"  cpdb <fromvnn> <tovnn> <dbid>      lists all keys in a remote tdb\n"
		"  setdmaster <vnn> <dbid> <dmaster>  sets new dmaster for all records in the database\n"
		"  cleardb <vnn> <dbid>               deletes all records in a db\n"
		"  getrecmode <vnn>                   get recovery mode\n"
		"  setrecmode <vnn> <mode>            set recovery mode\n"
		"  getrecmaster <vnn>                 get recovery master\n"
		"  setrecmaster <vnn> <master_vnn>    set recovery master\n"
		"  attach <dbname>                    attach a database\n"
		"  getpid <vnn>                       get the pid of a ctdb daemon\n"
		"  freeze <vnn|all>                   freeze a node\n"
		"  thaw <vnn|all>                     thaw a node\n"
	);
	exit(1);
}

/*
  see if a process exists
 */
static int control_process_exists(struct ctdb_context *ctdb, int argc, const char **argv)
{
	uint32_t vnn, pid;
	int ret;
	if (argc < 1) {
		usage();
	}

	if (sscanf(argv[0], "%u:%u", &vnn, &pid) != 2) {
		printf("Badly formed vnn:pid\n");
		return -1;
	}

	ret = ctdb_ctrl_process_exists(ctdb, vnn, pid);
	if (ret == 0) {
		printf("%u:%u exists\n", vnn, pid);
	} else {
		printf("%u:%u does not exist\n", vnn, pid);
	}
	return ret;
}

/*
  display status structure
 */
static void show_status(struct ctdb_status *s)
{
	TALLOC_CTX *tmp_ctx = talloc_new(NULL);
	int i;
	const char *prefix=NULL;
	size_t preflen=0;
	const struct {
		const char *name;
		uint32_t offset;
	} fields[] = {
#define STATUS_FIELD(n) { #n, offsetof(struct ctdb_status, n) }
		STATUS_FIELD(num_clients),
		STATUS_FIELD(frozen),
		STATUS_FIELD(recovering),
		STATUS_FIELD(client_packets_sent),
		STATUS_FIELD(client_packets_recv),
		STATUS_FIELD(node_packets_sent),
		STATUS_FIELD(node_packets_recv),
		STATUS_FIELD(node.req_call),
		STATUS_FIELD(node.reply_call),
		STATUS_FIELD(node.req_dmaster),
		STATUS_FIELD(node.reply_dmaster),
		STATUS_FIELD(node.reply_error),
		STATUS_FIELD(node.req_message),
		STATUS_FIELD(node.req_finished),
		STATUS_FIELD(node.req_control),
		STATUS_FIELD(node.reply_control),
		STATUS_FIELD(client.req_call),
		STATUS_FIELD(client.req_message),
		STATUS_FIELD(client.req_finished),
		STATUS_FIELD(client.req_connect_wait),
		STATUS_FIELD(client.req_shutdown),
		STATUS_FIELD(client.req_control),
		STATUS_FIELD(controls.status),
		STATUS_FIELD(controls.get_config),
		STATUS_FIELD(controls.ping),
		STATUS_FIELD(controls.attach),
		STATUS_FIELD(controls.set_call),
		STATUS_FIELD(controls.process_exists),
		STATUS_FIELD(controls.traverse_start),
		STATUS_FIELD(controls.traverse_all),
		STATUS_FIELD(controls.traverse_data),
		STATUS_FIELD(controls.update_seqnum),
		STATUS_FIELD(controls.enable_seqnum),
		STATUS_FIELD(controls.set_seqnum_frequency),
		STATUS_FIELD(controls.register_srvid),
		STATUS_FIELD(controls.deregister_srvid),
		STATUS_FIELD(timeouts.call),
		STATUS_FIELD(timeouts.control),
		STATUS_FIELD(timeouts.traverse),
		STATUS_FIELD(total_calls),
		STATUS_FIELD(pending_calls),
		STATUS_FIELD(lockwait_calls),
		STATUS_FIELD(pending_lockwait_calls),
		STATUS_FIELD(memory_used),
		STATUS_FIELD(max_hop_count),
	};
	printf("CTDB version %u\n", CTDB_VERSION);
	for (i=0;i<ARRAY_SIZE(fields);i++) {
		if (strchr(fields[i].name, '.')) {
			preflen = strcspn(fields[i].name, ".")+1;
			if (!prefix || strncmp(prefix, fields[i].name, preflen) != 0) {
				prefix = fields[i].name;
				printf(" %*.*s\n", preflen-1, preflen-1, fields[i].name);
			}
		} else {
			preflen = 0;
		}
		printf(" %*s%-22s%*s%10u\n", 
		       preflen?4:0, "",
		       fields[i].name+preflen, 
		       preflen?0:4, "",
		       *(uint32_t *)(fields[i].offset+(uint8_t *)s));
	}
	printf(" %-30s     %.6f sec\n", "max_call_latency", s->max_call_latency);
	printf(" %-30s     %.6f sec\n", "max_lockwait_latency", s->max_lockwait_latency);
	talloc_free(tmp_ctx);
}

/*
  display remote ctdb status combined from all nodes
 */
static int control_status_all(struct ctdb_context *ctdb)
{
	int ret, i;
	struct ctdb_status status;
	uint32_t *nodes;
	uint32_t num_nodes;

	nodes = ctdb_get_connected_nodes(ctdb, timeval_current_ofs(1, 0), ctdb, &num_nodes);
	CTDB_NO_MEMORY(ctdb, nodes);
	
	ZERO_STRUCT(status);

	for (i=0;i<num_nodes;i++) {
		struct ctdb_status s1;
		int j;
		uint32_t *v1 = (uint32_t *)&s1;
		uint32_t *v2 = (uint32_t *)&status;
		uint32_t num_ints = 
			offsetof(struct ctdb_status, __last_counter) / sizeof(uint32_t);
		ret = ctdb_ctrl_status(ctdb, nodes[i], &s1);
		if (ret != 0) {
			printf("Unable to get status from node %u\n", nodes[i]);
			return ret;
		}
		for (j=0;j<num_ints;j++) {
			v2[j] += v1[j];
		}
		status.max_hop_count = 
			MAX(status.max_hop_count, s1.max_hop_count);
		status.max_call_latency = 
			MAX(status.max_call_latency, s1.max_call_latency);
		status.max_lockwait_latency = 
			MAX(status.max_lockwait_latency, s1.max_lockwait_latency);
	}
	talloc_free(nodes);
	printf("Gathered status for %u nodes\n", num_nodes);
	show_status(&status);
	return 0;
}

/*
  display remote ctdb status
 */
static int control_status(struct ctdb_context *ctdb, int argc, const char **argv)
{
	uint32_t vnn;
	int ret;
	struct ctdb_status status;
	if (argc < 1) {
		usage();
	}

	if (strcmp(argv[0], "all") == 0) {
		return control_status_all(ctdb);
	}

	vnn = strtoul(argv[0], NULL, 0);

	ret = ctdb_ctrl_status(ctdb, vnn, &status);
	if (ret != 0) {
		printf("Unable to get status from node %u\n", vnn);
		return ret;
	}
	show_status(&status);
	return 0;
}


/*
  reset status on all nodes
 */
static int control_status_reset_all(struct ctdb_context *ctdb)
{
	int ret, i;
	uint32_t *nodes;
	uint32_t num_nodes;

	nodes = ctdb_get_connected_nodes(ctdb, timeval_current_ofs(1, 0), ctdb, &num_nodes);
	CTDB_NO_MEMORY(ctdb, nodes);
	
	for (i=0;i<num_nodes;i++) {
		ret = ctdb_status_reset(ctdb, nodes[i]);
		if (ret != 0) {
			printf("Unable to reset status on node %u\n", nodes[i]);
			return ret;
		}
	}
	talloc_free(nodes);
	return 0;
}


/*
  reset remote ctdb status
 */
static int control_status_reset(struct ctdb_context *ctdb, int argc, const char **argv)
{
	uint32_t vnn;
	int ret;
	if (argc < 1) {
		usage();
	}

	if (strcmp(argv[0], "all") == 0) {
		return control_status_reset_all(ctdb);
	}

	vnn = strtoul(argv[0], NULL, 0);

	ret = ctdb_status_reset(ctdb, vnn);
	if (ret != 0) {
		printf("Unable to reset status on node %u\n", vnn);
		return ret;
	}
	return 0;
}


/*
  display remote ctdb vnn map
 */
static int control_getvnnmap(struct ctdb_context *ctdb, int argc, const char **argv)
{
	uint32_t vnn;
	int i, ret;
	struct ctdb_vnn_map *vnnmap=NULL;
	if (argc < 1) {
		usage();
	}

	vnn = strtoul(argv[0], NULL, 0);

	ret = ctdb_ctrl_getvnnmap(ctdb, timeval_current_ofs(1, 0), vnn, ctdb, &vnnmap);
	if (ret != 0) {
		printf("Unable to get vnnmap from node %u\n", vnn);
		return ret;
	}
	printf("Generation:%d\n",vnnmap->generation);
	printf("Size:%d\n",vnnmap->size);
	for(i=0;i<vnnmap->size;i++){
		printf("hash:%d lmaster:%d\n",i,vnnmap->map[i]);
	}
	return 0;
}

/*
  display pid of a ctdb daemon
 */
static int control_getpid(struct ctdb_context *ctdb, int argc, const char **argv)
{
	uint32_t vnn, pid;
	int ret;


	if (argc < 1) {
		usage();
	}

	vnn     = strtoul(argv[0], NULL, 0);

	ret = ctdb_ctrl_getpid(ctdb, timeval_current_ofs(1, 0), vnn, &pid);
	if (ret != 0) {
		printf("Unable to get daemon pid from node %u\n", vnn);
		return ret;
	}
	printf("Pid:%d\n",pid);

	return 0;
}

/*
  display recovery mode of a remote node
 */
static int control_getrecmode(struct ctdb_context *ctdb, int argc, const char **argv)
{
	uint32_t vnn, recmode;
	int ret;


	if (argc < 1) {
		usage();
	}

	vnn     = strtoul(argv[0], NULL, 0);

	ret = ctdb_ctrl_getrecmode(ctdb, timeval_current_ofs(1, 0), vnn, &recmode);
	if (ret != 0) {
		printf("Unable to get recmode from node %u\n", vnn);
		return ret;
	}
	printf("Recovery mode:%s (%d)\n",recmode==CTDB_RECOVERY_NORMAL?"NORMAL":"RECOVERY",recmode);

	return 0;
}

/*
  set recovery mode of a remote node
 */
static int control_setrecmode(struct ctdb_context *ctdb, int argc, const char **argv)
{
	uint32_t vnn, recmode;
	int ret;


	if (argc < 2) {
		usage();
	}

	vnn     = strtoul(argv[0], NULL, 0);
	recmode = strtoul(argv[1], NULL, 0);

	ret = ctdb_ctrl_setrecmode(ctdb, timeval_current_ofs(1, 0), vnn, recmode);
	if (ret != 0) {
		printf("Unable to set recmode on node %u\n", vnn);
		return ret;
	}

	return 0;
}

/*
  display recovery master of a remote node
 */
static int control_getrecmaster(struct ctdb_context *ctdb, int argc, const char **argv)
{
	uint32_t vnn, recmaster;
	int ret;


	if (argc < 1) {
		usage();
	}

	vnn     = strtoul(argv[0], NULL, 0);

	ret = ctdb_ctrl_getrecmaster(ctdb, timeval_current_ofs(1, 0), vnn, &recmaster);
	if (ret != 0) {
		printf("Unable to get recmaster from node %u\n", vnn);
		return ret;
	}
	printf("Recovery master:%d\n",recmaster);

	return 0;
}

/*
  set recovery master of a remote node
 */
static int control_setrecmaster(struct ctdb_context *ctdb, int argc, const char **argv)
{
	uint32_t vnn, recmaster;
	int ret;


	if (argc < 2) {
		usage();
	}

	vnn       = strtoul(argv[0], NULL, 0);
	recmaster = strtoul(argv[1], NULL, 0);

	ret = ctdb_ctrl_setrecmaster(ctdb, timeval_current_ofs(1, 0), vnn, recmaster);
	if (ret != 0) {
		printf("Unable to set recmaster on node %u\n", vnn);
		return ret;
	}

	return 0;
}

/*
  display remote list of keys/data for a db
 */
static int control_catdb(struct ctdb_context *ctdb, int argc, const char **argv)
{
	const char *db_name;
	struct ctdb_db_context *ctdb_db;
	uint32_t vnn;
	int ret;

	if (argc < 1) {
		usage();
	}

	db_name = argv[0];
	ctdb_db = ctdb_attach(ctdb, db_name);
	if (ctdb_db == NULL) {
		DEBUG(0,("Unable to attach to database '%s'\n", db_name));
		return -1;
	}

	if (argc==1) {
		/* traverse and dump the cluster tdb */
		ret = ctdb_dump_db(ctdb_db, stdout);
		if (ret == -1) {
			printf("Unable to dump database\n");
			return -1;
		}
	} else {
		struct ctdb_key_list keys;
		int i;

		/* dump only the local tdb of a specific node */
		vnn     = strtoul(argv[1], NULL, 0);
		ret = ctdb_ctrl_pulldb(ctdb, vnn, ctdb_db->db_id, CTDB_LMASTER_ANY, ctdb, &keys);
		if (ret == -1) {
			printf("Unable to pull remote database\n");
			return -1;
		}
		for(i=0;i<keys.num;i++){
			char *keystr, *datastr;

			keystr  = hex_encode(ctdb, keys.keys[i].dptr, keys.keys[i].dsize);
			datastr = hex_encode(ctdb, keys.data[i].dptr, keys.data[i].dsize);

			printf("rsn:%llu lmaster:%d dmaster:%d key:%s data:%s\n", keys.headers[i].rsn, keys.lmasters[i], keys.headers[i].dmaster, keystr, datastr); 
			ret++;
		}
	}
	
	talloc_free(ctdb_db);

	printf("Dumped %d records\n", ret);
	return 0;
}

/*
  copy a db from one node to another
 */
static int control_cpdb(struct ctdb_context *ctdb, int argc, const char **argv)
{
	uint32_t fromvnn, tovnn, dbid;
	int ret;
	TALLOC_CTX *mem_ctx;

	if (argc < 3) {
		usage();
	}

	fromvnn  = strtoul(argv[0], NULL, 0);
	tovnn    = strtoul(argv[1], NULL, 0);
	dbid     = strtoul(argv[2], NULL, 0);

	mem_ctx = talloc_new(ctdb);
	ret = ctdb_ctrl_copydb(ctdb, timeval_current_ofs(1, 0), fromvnn, tovnn, dbid, CTDB_LMASTER_ANY, mem_ctx);
	if (ret != 0) {
		printf("Unable to copy db from node %u to node %u\n", fromvnn, tovnn);
		return ret;
	}

	talloc_free(mem_ctx);
	return 0;
}

/*
  display a list of the databases on a remote ctdb
 */
static int control_getdbmap(struct ctdb_context *ctdb, int argc, const char **argv)
{
	uint32_t vnn;
	int i, ret;
	struct ctdb_dbid_map *dbmap=NULL;

	if (argc < 1) {
		usage();
	}

	vnn = strtoul(argv[0], NULL, 0);

	ret = ctdb_ctrl_getdbmap(ctdb, timeval_current_ofs(1, 0), vnn, ctdb, &dbmap);
	if (ret != 0) {
		printf("Unable to get dbids from node %u\n", vnn);
		return ret;
	}

	printf("Number of databases:%d\n", dbmap->num);
	for(i=0;i<dbmap->num;i++){
		const char *path;
		const char *name;

		ctdb_ctrl_getdbpath(ctdb, timeval_current_ofs(1, 0), CTDB_CURRENT_NODE, dbmap->dbids[i], ctdb, &path);
		ctdb_ctrl_getdbname(ctdb, timeval_current_ofs(1, 0), CTDB_CURRENT_NODE, dbmap->dbids[i], ctdb, &name);
		printf("dbid:0x%08x name:%s path:%s\n", dbmap->dbids[i], name, path);
	}

	return 0;
}

/*
  display a list nodes known to a remote ctdb
 */
static int control_getnodemap(struct ctdb_context *ctdb, int argc, const char **argv)
{
	uint32_t vnn;
	int i, ret;
	struct ctdb_node_map *nodemap=NULL;

	if (argc < 1) {
		usage();
	}

	vnn = strtoul(argv[0], NULL, 0);

	ret = ctdb_ctrl_getnodemap(ctdb, timeval_current_ofs(1, 0), vnn, ctdb, &nodemap);
	if (ret != 0) {
		printf("Unable to get nodemap from node %u\n", vnn);
		return ret;
	}

	printf("Number of nodes:%d\n", nodemap->num);
	for(i=0;i<nodemap->num;i++){
		printf("vnn:%d %s%s\n", nodemap->nodes[i].vnn,
			nodemap->nodes[i].flags&NODE_FLAGS_CONNECTED?
				"CONNECTED":"UNAVAILABLE",
			nodemap->nodes[i].vnn==vnn?" (THIS NODE)":"");
	}

	return 0;
}

/*
  set remote ctdb vnn map
 */
static int control_setvnnmap(struct ctdb_context *ctdb, int argc, const char **argv)
{
	uint32_t vnn, num_nodes, generation;
	struct ctdb_vnn_map *vnnmap;
	int i, ret;
	if (argc < 3) {
		usage();
	}

	vnn        = strtoul(argv[0], NULL, 0);
	generation = strtoul(argv[1], NULL, 0);
	num_nodes  = strtoul(argv[2], NULL, 0);

	vnnmap = talloc(ctdb, struct ctdb_vnn_map);
	CTDB_NO_MEMORY(ctdb, vnnmap);

	vnnmap->generation = generation;
	vnnmap->size       = num_nodes;
	vnnmap->map        = talloc_array(vnnmap, uint32_t, vnnmap->size);
	CTDB_NO_MEMORY(ctdb, vnnmap->map);

	for (i=0;i<vnnmap->size;i++) {
		vnnmap->map[i] = strtoul(argv[3+i], NULL, 0);
	}

	ret = ctdb_ctrl_setvnnmap(ctdb, timeval_current_ofs(1, 0), vnn, ctdb, vnnmap);
	if (ret != 0) {
		printf("Unable to set vnnmap for node %u\n", vnn);
		return ret;
	}
	return 0;
}


/*
  set the dmaster for all records in a database
 */
static int control_setdmaster(struct ctdb_context *ctdb, int argc, const char **argv)
{
	uint32_t vnn, dbid, dmaster;
	int ret;

	if (argc < 3) {
		usage();
	}

	vnn     = strtoul(argv[0], NULL, 0);
	dbid    = strtoul(argv[1], NULL, 0);
	dmaster = strtoul(argv[2], NULL, 0);

	ret = ctdb_ctrl_setdmaster(ctdb, timeval_current_ofs(1, 0), vnn, ctdb, dbid, dmaster);
	if (ret != 0) {
		printf("Unable to set dmaster for node %u db:0x%08x\n", vnn, dbid);
		return ret;
	}
	return 0;
}

/*
  clears a database
 */
static int control_cleardb(struct ctdb_context *ctdb, int argc, const char **argv)
{
	uint32_t vnn, dbid;
	int ret;

	if (argc < 2) {
		usage();
	}

	vnn     = strtoul(argv[0], NULL, 0);
	dbid    = strtoul(argv[1], NULL, 0);

	ret = ctdb_ctrl_cleardb(ctdb, vnn, ctdb, dbid);
	if (ret != 0) {
		printf("Unable to clear db for node %u db:0x%08x\n", vnn, dbid);
		return ret;
	}
	return 0;
}

/*
  create a database
 */
static int control_createdb(struct ctdb_context *ctdb, int argc, const char **argv)
{
	uint32_t vnn;
	const char *dbname;
	int ret;
	int32_t res;
	TDB_DATA data;
	struct timeval timeout;

	if (argc < 2) {
		usage();
	}

	vnn     = strtoul(argv[0], NULL, 0);
	dbname  = argv[1];

	/* tell ctdb daemon to attach */
	data.dptr = discard_const(dbname);
	data.dsize = strlen(dbname)+1;
	timeout = timeval_current_ofs(1, 0);
	ret = ctdb_control(ctdb, vnn, 0, CTDB_CONTROL_DB_ATTACH,
			   0, data, ctdb, &data, &res, 
			   &timeout);
	if (ret != 0 || res != 0 || data.dsize != sizeof(uint32_t)) {
		DEBUG(0,("Failed to attach to database '%s'\n", dbname));
		return -1;
	}

	return 0;
}

/*
  ping all node
 */
static int control_ping(struct ctdb_context *ctdb, int argc, const char **argv)
{
	int ret, i;
	uint32_t *nodes;
	uint32_t num_nodes;

	nodes = ctdb_get_connected_nodes(ctdb, timeval_current_ofs(1, 0), ctdb, &num_nodes);
	CTDB_NO_MEMORY(ctdb, nodes);

	for (i=0;i<num_nodes;i++) {
		struct timeval tv = timeval_current();
		ret = ctdb_ctrl_ping(ctdb, nodes[i]);
		if (ret == -1) {
			printf("Unable to get ping response from node %u\n", nodes[i]);
		} else {
			printf("response from %u time=%.6f sec  (%d clients)\n", 
			       nodes[i], timeval_elapsed(&tv), ret);
		}
	}
	talloc_free(nodes);
	return 0;
}


/*
  display debug level on all node
 */
static int control_debuglevel(struct ctdb_context *ctdb, int argc, const char **argv)
{
	int ret, i;
	uint32_t *nodes;
	uint32_t num_nodes;

	nodes = ctdb_get_connected_nodes(ctdb, timeval_current_ofs(1, 0), ctdb, &num_nodes);
	CTDB_NO_MEMORY(ctdb, nodes);

	for (i=0;i<num_nodes;i++) {
		uint32_t level;
		ret = ctdb_ctrl_get_debuglevel(ctdb, nodes[i], &level);
		if (ret != 0) {
			printf("Unable to get debuglevel response from node %u\n", 
				nodes[i]);
		} else {
			printf("Node %u is at debug level %u\n", nodes[i], level);
		}
	}
	talloc_free(nodes);
	return 0;
}

/*
  set debug level on a node
 */
static int control_debug(struct ctdb_context *ctdb, int argc, const char **argv)
{
	int ret;
	uint32_t vnn, level, i;
	uint32_t *nodes;
	uint32_t num_nodes;

	if (argc < 2) {
		usage();
	}

	level = strtoul(argv[1], NULL, 0);

	if (strcmp(argv[0], "all") != 0) {
		vnn = strtoul(argv[0], NULL, 0);
		ret = ctdb_ctrl_set_debuglevel(ctdb, vnn, level);
		if (ret != 0) {
			printf("Unable to set debug level on node %u\n", vnn);
		}
		
		return 0;
	}

	nodes = ctdb_get_connected_nodes(ctdb, timeval_current_ofs(1, 0), ctdb, &num_nodes);
	CTDB_NO_MEMORY(ctdb, nodes);
	for (i=0;i<num_nodes;i++) {
		ret = ctdb_ctrl_set_debuglevel(ctdb, nodes[i], level);
		if (ret != 0) {
			printf("Unable to set debug level on node %u\n", nodes[i]);
			break;
		}
	}
	talloc_free(nodes);
	return 0;
}


/*
  freeze a node
 */
static int control_freeze(struct ctdb_context *ctdb, int argc, const char **argv)
{
	int ret=0, count=0;
	uint32_t vnn, i;
	uint32_t *nodes;
	uint32_t num_nodes;

	if (argc < 1) {
		usage();
	}

	if (strcmp(argv[0], "all") != 0) {
		vnn = strtoul(argv[0], NULL, 0);
		ret = ctdb_ctrl_freeze(ctdb, timeval_current_ofs(5, 0), vnn);
		if (ret != 0) {
			printf("Unable to freeze node %u\n", vnn);
		}		
		return 0;
	}

	nodes = ctdb_get_connected_nodes(ctdb, timeval_current_ofs(1, 0), ctdb, &num_nodes);
	CTDB_NO_MEMORY(ctdb, nodes);
	for (i=0;i<num_nodes;i++) {
		int res = ctdb_ctrl_freeze(ctdb, timeval_current_ofs(5, 0), nodes[i]);
		if (res != 0) {
			printf("Warning: Unable to freeze node %u\n", nodes[i]);
		} else {
			count++;
		}
		ret |= res;
	}
	printf("Froze %u nodes\n", count);
	talloc_free(nodes);
	return 0;
}

/*
  thaw a node
 */
static int control_thaw(struct ctdb_context *ctdb, int argc, const char **argv)
{
	int ret=0, count=0;
	uint32_t vnn, i;
	uint32_t *nodes;
	uint32_t num_nodes;

	if (argc < 1) {
		usage();
	}

	if (strcmp(argv[0], "all") != 0) {
		vnn = strtoul(argv[0], NULL, 0);
		ret = ctdb_ctrl_thaw(ctdb, timeval_current_ofs(5, 0), vnn);
		if (ret != 0) {
			printf("Unable to thaw node %u\n", vnn);
		}		
		return 0;
	}

	nodes = ctdb_get_connected_nodes(ctdb, timeval_current_ofs(1, 0), ctdb, &num_nodes);
	CTDB_NO_MEMORY(ctdb, nodes);
	for (i=0;i<num_nodes;i++) {
		int res = ctdb_ctrl_thaw(ctdb, timeval_current_ofs(5, 0), nodes[i]);
		if (res != 0) {
			printf("Warning: Unable to thaw node %u\n", nodes[i]);
		} else {
			count++;
		}
		ret |= res;
	}
	printf("Thawed %u nodes\n", count);
	talloc_free(nodes);
	return 0;
}


/*
  attach to a database
 */
static int control_attach(struct ctdb_context *ctdb, int argc, const char **argv)
{
	const char *db_name;
	struct ctdb_db_context *ctdb_db;
	if (argc < 1) {
		usage();
	}
	db_name = argv[0];

	ctdb_db = ctdb_attach(ctdb, db_name);
	if (ctdb_db == NULL) {
		DEBUG(0,("Unable to attach to database '%s'\n", db_name));
		return -1;
	}

	return 0;
}

/*
  dump memory usage
 */
static int control_dumpmemory(struct ctdb_context *ctdb, int argc, const char **argv)
{

	uint32_t vnn;
	if (argc < 1) {
		usage();
	}
	if (strcmp(argv[0], "all") == 0) {
		vnn = CTDB_BROADCAST_ALL;
	} else {
		vnn = strtoul(argv[0], NULL, 0);
	}

	ctdb_control(ctdb, vnn, 0, CTDB_CONTROL_DUMP_MEMORY,
		     CTDB_CTRL_FLAG_NOREPLY, tdb_null, NULL, NULL, NULL, NULL);

	return 0;
}

/*
  main program
*/
int main(int argc, const char *argv[])
{
	struct ctdb_context *ctdb;
	struct poptOption popt_options[] = {
		POPT_AUTOHELP
		POPT_CTDB_CMDLINE
		POPT_TABLEEND
	};
	int opt;
	const char **extra_argv;
	int extra_argc = 0;
	int ret, i;
	poptContext pc;
	struct event_context *ev;
	const char *control;
	static struct {
		const char *name;
		int (*fn)(struct ctdb_context *, int, const char **);
	} commands[] = {
		{ "process-exists", control_process_exists },
		{ "status", control_status },
		{ "statusreset", control_status_reset },
		{ "getvnnmap", control_getvnnmap },
		{ "getdbmap", control_getdbmap },
		{ "getnodemap", control_getnodemap },
		{ "catdb", control_catdb },
		{ "cpdb", control_cpdb },
		{ "setvnnmap", control_setvnnmap },
		{ "setdmaster", control_setdmaster },
		{ "createdb", control_createdb },
		{ "cleardb", control_cleardb },
		{ "getrecmode", control_getrecmode },
		{ "setrecmode", control_setrecmode },
		{ "getrecmaster", control_getrecmaster },
		{ "setrecmaster", control_setrecmaster },
		{ "ping", control_ping },
		{ "debug", control_debug },
		{ "debuglevel", control_debuglevel },
		{ "attach", control_attach },
		{ "dumpmemory", control_dumpmemory },
		{ "getpid", control_getpid },
		{ "freeze", control_freeze },
		{ "thaw", control_thaw },
	};

	pc = poptGetContext(argv[0], argc, argv, popt_options, POPT_CONTEXT_KEEP_FIRST);

	while ((opt = poptGetNextOpt(pc)) != -1) {
		switch (opt) {
		default:
			fprintf(stderr, "Invalid option %s: %s\n", 
				poptBadOption(pc, 0), poptStrerror(opt));
			exit(1);
		}
	}

	/* setup the remaining options for the main program to use */
	extra_argv = poptGetArgs(pc);
	if (extra_argv) {
		extra_argv++;
		while (extra_argv[extra_argc]) extra_argc++;
	}

	if (extra_argc < 1) {
		usage();
	}

	control = extra_argv[0];

	ev = event_context_init(NULL);

	/* initialise ctdb */
	ctdb = ctdb_cmdline_client(ev);
	if (ctdb == NULL) {
		printf("Failed to init ctdb\n");
		exit(1);
	}

	for (i=0;i<ARRAY_SIZE(commands);i++) {
		if (strcmp(control, commands[i].name) == 0) {
			ret = commands[i].fn(ctdb, extra_argc-1, extra_argv+1);
			break;
		}
	}

	if (i == ARRAY_SIZE(commands)) {
		printf("Unknown control '%s'\n", control);
		exit(1);
	}

	return ret;
}
