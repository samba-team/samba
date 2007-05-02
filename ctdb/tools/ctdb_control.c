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
	printf("Usage: ctdb_control [options] <control>\n");
	printf("\nControls:\n");
	printf("  ping\n");
	printf("  process-exists <vnn:pid>           see if a process exists\n");
	printf("  status <vnn|all>                   show ctdb status on a node\n");
	printf("  statusreset <vnn|all>              reset status on a node\n");
	printf("  debug <vnn|all> <level>            set ctdb debug level on a node\n");
	printf("  debuglevel                         display ctdb debug levels\n");
	printf("  getvnnmap <vnn>                    display ctdb vnnmap\n");
	printf("  setvnnmap <vnn> <generation> <numslots> <lmaster>*\n");
	printf("  getdbmap <vnn>                     lists databases on a node\n");
	printf("  getnodemap <vnn>                   lists nodes known to a ctdb daemon\n");
	printf("  createdb <vnn> <dbname>            create a database\n");
	printf("  catdb <vnn> <dbid>                 lists all keys in a remote tdb\n");
	printf("  cpdb <fromvnn> <tovnn> <dbid>      lists all keys in a remote tdb\n");
	printf("  setdmaster <vnn> <dbid> <dmaster>  sets new dmaster for all records in the database\n");
	printf("  cleardb <vnn> <dbid>               deletes all records in a db\n");
	printf("  getrecmode <vnn>                   get recovery mode\n");
	printf("  setrecmode <vnn> <mode>            set recovery mode\n");
	printf("  recover <vnn>                      recover the cluster\n");
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
	printf("CTDB version %u\n", CTDB_VERSION);
	printf(" client_packets_sent     %u\n", s->client_packets_sent);
	printf(" client_packets_recv     %u\n", s->client_packets_recv);
	printf("   req_call              %u\n", s->client.req_call);
	printf("   req_message           %u\n", s->client.req_message);
	printf("   req_finished          %u\n", s->client.req_finished);
	printf("   req_register          %u\n", s->client.req_register);
	printf("   req_connect_wait      %u\n", s->client.req_connect_wait);
	printf("   req_shutdown          %u\n", s->client.req_shutdown);
	printf("   req_control           %u\n", s->client.req_control);
	printf(" node_packets_sent       %u\n", s->node_packets_sent);
	printf(" node_packets_recv       %u\n", s->node_packets_recv);
	printf("   req_call              %u\n", s->count.req_call);
	printf("   reply_call            %u\n", s->count.reply_call);
	printf("   req_dmaster           %u\n", s->count.req_dmaster);
	printf("   reply_dmaster         %u\n", s->count.reply_dmaster);
	printf("   reply_error           %u\n", s->count.reply_error);
	printf("   req_message           %u\n", s->count.req_message);
	printf("   req_finished          %u\n", s->count.req_finished);
	printf(" total_calls             %u\n", s->total_calls);
	printf(" pending_calls           %u\n", s->pending_calls);
	printf(" lockwait_calls          %u\n", s->lockwait_calls);
	printf(" pending_lockwait_calls  %u\n", s->pending_lockwait_calls);
	printf(" max_hop_count           %u\n", s->max_hop_count);
	printf(" max_call_latency        %.6f sec\n", s->max_call_latency);
	printf(" max_lockwait_latency    %.6f sec\n", s->max_lockwait_latency);
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

	nodes = ctdb_get_connected_nodes(ctdb, ctdb, &num_nodes);
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

	nodes = ctdb_get_connected_nodes(ctdb, ctdb, &num_nodes);
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
  perform a samba3 style recovery
 */
static int control_recover(struct ctdb_context *ctdb, int argc, const char **argv)
{
	uint32_t vnn, num_nodes, generation, dmaster;
	struct ctdb_vnn_map vnnmap;
	struct ctdb_node_map nodemap;
	int i, j, ret;
	struct ctdb_dbid_map dbmap;

	if (argc < 1) {
		usage();
	}


	vnn = strtoul(argv[0], NULL, 0);

	printf("recover ctdb from node %d\n", vnn);

	/* 1: find a list of all nodes */
	printf("\n1: fetching list of nodes\n");
	ret = ctdb_ctrl_getnodemap(ctdb, vnn, ctdb, &nodemap);
	if (ret != 0) {
		printf("Unable to get nodemap from node %u\n", vnn);
		return ret;
	}

	/* 2: count the active nodes */
	printf("\n2: count number of active nodes\n");
	num_nodes = 0;
	for (i=0; i<nodemap.num; i++) {
		if (nodemap.nodes[i].flags&NODE_FLAGS_CONNECTED) {
			num_nodes++;
		}
	}
	printf("number of active nodes:%d\n",num_nodes);

	/* 3: go to all active nodes and activate recovery mode */
	printf("\n3: set recovery mode for all active nodes\n");
	for (j=0; j<nodemap.num; j++) {
		/* dont change it for nodes that are unavailable */
		if (!(nodemap.nodes[j].flags&NODE_FLAGS_CONNECTED)) {
			continue;
		}

		printf("setting node %d to recovery mode\n",nodemap.nodes[j].vnn);
		ret = ctdb_ctrl_setrecmode(ctdb, nodemap.nodes[j].vnn, CTDB_RECOVERY_ACTIVE);
		if (ret != 0) {
			printf("Unable to set recmode on node %u\n", nodemap.nodes[j].vnn);
			return ret;
		}
	}
	
	/* 4: get a list of all databases */
	printf("\n4: getting list of databases to recover\n");
	ret = ctdb_ctrl_getdbmap(ctdb, vnn, ctdb, &dbmap);
	if (ret != 0) {
		printf("Unable to get dbids from node %u\n", vnn);
		return ret;
	}
	for (i=0;i<dbmap.num;i++) {
		const char *path;

		ctdb_ctrl_getdbpath(ctdb, dbmap.dbids[i], ctdb, &path);
		printf("dbid:0x%08x path:%s\n", dbmap.dbids[i], path);
	}

	/* 5: pull all records from all other nodes across to this node
	      (this merges based on rsn internally)
	*/
	printf("\n5: merge all records from remote nodes\n");
	for (i=0;i<dbmap.num;i++) {
		printf("recovering database 0x%08x\n",dbmap.dbids[i]);
		for (j=0; j<nodemap.num; j++) {
			/* we dont need to merge with ourselves */
			if (nodemap.nodes[j].vnn == vnn) {
				continue;
			}
			/* dont merge from nodes that are unavailable */
			if (!(nodemap.nodes[j].flags&NODE_FLAGS_CONNECTED)) {
				continue;
			}

			printf("merging all records from node %d for database 0x%08x\n", nodemap.nodes[j].vnn, dbmap.dbids[i]);
			ret = ctdb_ctrl_copydb(ctdb, nodemap.nodes[j].vnn, vnn, dbmap.dbids[i], CTDB_LMASTER_ANY, ctdb);
			if (ret != 0) {
				printf("Unable to copy db from node %u to node %u\n", nodemap.nodes[j].vnn, vnn);
				return ret;
			}
		}
	}

	/* 6: update dmaster to point to this node for all databases/nodes */
	printf("\n6: repoint dmaster to the recovery node\n");
	dmaster = vnn;
	printf("new dmaster is %d\n", dmaster);
	for (i=0;i<dbmap.num;i++) {
		for (j=0; j<nodemap.num; j++) {
			/* dont repoint nodes that are unavailable */
			if (!(nodemap.nodes[j].flags&NODE_FLAGS_CONNECTED)) {
				continue;
			}

			printf("setting dmaster to %d for node %d db 0x%08x\n",dmaster,nodemap.nodes[j].vnn,dbmap.dbids[i]);
			ret = ctdb_ctrl_setdmaster(ctdb, nodemap.nodes[j].vnn, ctdb, dbmap.dbids[i], dmaster);
			if (ret != 0) {
				printf("Unable to set dmaster for node %u db:0x%08x\n", nodemap.nodes[j].vnn, dbmap.dbids[i]);
				return ret;
			}
		}
	}

	/* 7: push all records out to the nodes again */
	printf("\n7: push all records to remote nodes\n");
	for (i=0;i<dbmap.num;i++) {
		printf("distributing new database 0x%08x\n",dbmap.dbids[i]);
		for (j=0; j<nodemap.num; j++) {
			/* we dont need to push to ourselves */
			if (nodemap.nodes[j].vnn == vnn) {
				continue;
			}
			/* dont push to nodes that are unavailable */
			if (!(nodemap.nodes[j].flags&NODE_FLAGS_CONNECTED)) {
				continue;
			}

			printf("pushing all records to node %d for database 0x%08x\n", nodemap.nodes[j].vnn, dbmap.dbids[i]);
			ret = ctdb_ctrl_copydb(ctdb, vnn, nodemap.nodes[j].vnn, dbmap.dbids[i], CTDB_LMASTER_ANY, ctdb);
			if (ret != 0) {
				printf("Unable to copy db from node %u to node %u\n", vnn, nodemap.nodes[j].vnn);
				return ret;
			}
		}
	}
				
	/* 8: build a new vnn map */
	printf("\n8: build a new vnn map with a new generation id\n");
	generation = random();
	vnnmap.generation = generation;
	vnnmap.size = num_nodes;
	vnnmap.map = talloc_array(ctdb, uint32_t, num_nodes);
	for (i=j=0;i<nodemap.num;i++) {
		if (nodemap.nodes[i].flags&NODE_FLAGS_CONNECTED) {
			vnnmap.map[j++]=nodemap.nodes[i].vnn;
		}
	}
	printf("Generation:%d\n",vnnmap.generation);
	printf("Size:%d\n",vnnmap.size);
	for(i=0;i<vnnmap.size;i++){
		printf("hash:%d lmaster:%d\n",i,vnnmap.map[i]);
	}

	/* 9: push the new vnn map out to all the nodes */
	printf("\n9: distribute the new vnn map\n");
	for (j=0; j<nodemap.num; j++) {
		/* dont push to nodes that are unavailable */
		if (!(nodemap.nodes[j].flags&NODE_FLAGS_CONNECTED)) {
			continue;
		}

		printf("setting new vnn map on node %d\n",nodemap.nodes[j].vnn);
		ret = ctdb_ctrl_setvnnmap(ctdb, nodemap.nodes[j].vnn, ctdb, &vnnmap);
		if (ret != 0) {
			printf("Unable to set vnnmap for node %u\n", vnn);
			return ret;
		}
	}

	/* 10: disable recovery mode */
	printf("\n10: restore recovery mode back to normal\n");
	for (j=0; j<nodemap.num; j++) {
		/* dont push to nodes that are unavailable */
		if (!(nodemap.nodes[j].flags&NODE_FLAGS_CONNECTED)) {
			continue;
		}

		printf("changing recovery mode back to normal for node %d\n",nodemap.nodes[j].vnn);
		ret = ctdb_ctrl_setrecmode(ctdb, nodemap.nodes[j].vnn, CTDB_RECOVERY_NORMAL);
		if (ret != 0) {
			printf("Unable to set recmode on node %u\n", nodemap.nodes[j].vnn);
			return ret;
		}
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
	struct ctdb_vnn_map *vnnmap;
	if (argc < 1) {
		usage();
	}

	vnn = strtoul(argv[0], NULL, 0);

	vnnmap = talloc_zero(ctdb, struct ctdb_vnn_map);
	ret = ctdb_ctrl_getvnnmap(ctdb, vnn, vnnmap);
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

	ret = ctdb_ctrl_getrecmode(ctdb, vnn, &recmode);
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
	recmode = strtoul(argv[0], NULL, 0);

	ret = ctdb_ctrl_setrecmode(ctdb, vnn, recmode);
	if (ret != 0) {
		printf("Unable to set recmode on node %u\n", vnn);
		return ret;
	}

	return 0;
}

/*
  display remote list of keys for a tdb
 */
static int control_catdb(struct ctdb_context *ctdb, int argc, const char **argv)
{
	uint32_t vnn, dbid;
	int i, j, ret;
	struct ctdb_key_list keys;
	TALLOC_CTX *mem_ctx;

	if (argc < 2) {
		usage();
	}

	vnn  = strtoul(argv[0], NULL, 0);
	dbid = strtoul(argv[1], NULL, 0);

	mem_ctx = talloc_new(ctdb);
	ret = ctdb_ctrl_pulldb(ctdb, vnn, dbid, CTDB_LMASTER_ANY, mem_ctx, &keys);
	if (ret != 0) {
		printf("Unable to get keys from node %u\n", vnn);
		return ret;
	}
	printf("Number of keys:%d in dbid:0x%08x\n",keys.num,keys.dbid);
	for(i=0;i<keys.num;i++){
		printf("key:");
		for(j=0;j<keys.keys[i].dsize;j++){
			printf("%02x",keys.keys[i].dptr[j]);
		}
		printf(" lmaster:%d rsn:%llu dmaster:%d laccessor:%d lacount:%d",keys.lmasters[i],keys.headers[i].rsn,keys.headers[i].dmaster,keys.headers[i].laccessor,keys.headers[i].lacount);
		printf(" data:");	
		for(j=0;j<keys.data[i].dsize;j++){
			printf("%02x",keys.data[i].dptr[j]);
		}
		printf("\n");
	}

	talloc_free(mem_ctx);
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
	ret = ctdb_ctrl_copydb(ctdb, fromvnn, tovnn, dbid, CTDB_LMASTER_ANY, mem_ctx);
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
	struct ctdb_dbid_map dbmap;

	if (argc < 1) {
		usage();
	}

	vnn = strtoul(argv[0], NULL, 0);

	ret = ctdb_ctrl_getdbmap(ctdb, vnn, ctdb, &dbmap);
	if (ret != 0) {
		printf("Unable to get dbids from node %u\n", vnn);
		return ret;
	}

	printf("Number of databases:%d\n", dbmap.num);
	for(i=0;i<dbmap.num;i++){
		const char *path;

		ctdb_ctrl_getdbpath(ctdb, dbmap.dbids[i], ctdb, &path);
		printf("dbid:0x%08x path:%s\n", dbmap.dbids[i], path);
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
	struct ctdb_node_map *nodemap;

	if (argc < 1) {
		usage();
	}

	vnn = strtoul(argv[0], NULL, 0);

	nodemap = talloc_zero(ctdb, struct ctdb_node_map);
	ret = ctdb_ctrl_getnodemap(ctdb, vnn, nodemap, nodemap);
	if (ret != 0) {
		printf("Unable to get nodemap from node %u\n", vnn);
		talloc_free(nodemap);
		return ret;
	}

	printf("Number of nodes:%d\n", nodemap->num);
	for(i=0;i<nodemap->num;i++){
		printf("vnn:%d %s%s\n", nodemap->nodes[i].vnn,
			nodemap->nodes[i].flags&NODE_FLAGS_CONNECTED?
				"CONNECTED":"UNAVAILABLE",
			nodemap->nodes[i].vnn==vnn?" (THIS NODE)":"");
	}
	talloc_free(nodemap);
	return 0;
}

/*
  set remote ctdb vnn map
 */
static int control_setvnnmap(struct ctdb_context *ctdb, int argc, const char **argv)
{
	uint32_t vnn;
	struct ctdb_vnn_map *vnnmap;
	int i, ret;
	if (argc < 3) {
		usage();
	}

	vnn = strtoul(argv[0], NULL, 0);

	vnnmap = talloc_zero(ctdb, struct ctdb_vnn_map);
	vnnmap->generation = strtoul(argv[1], NULL, 0);
	vnnmap->size = strtoul(argv[2], NULL, 0);
	vnnmap->map = talloc_array(vnnmap, uint32_t, vnnmap->size);
	for (i=0;i<vnnmap->size;i++) {
		vnnmap->map[i] = strtoul(argv[3+i], NULL, 0);
	}

	ret = ctdb_ctrl_setvnnmap(ctdb, vnn, ctdb, vnnmap);
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

	ret = ctdb_ctrl_setdmaster(ctdb, vnn, ctdb, dbid, dmaster);
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

	if (argc < 2) {
		usage();
	}

	vnn     = strtoul(argv[0], NULL, 0);
	dbname  = argv[1];

	/* tell ctdb daemon to attach */
	data.dptr = discard_const(dbname);
	data.dsize = strlen(dbname)+1;
	ret = ctdb_control(ctdb, vnn, 0, CTDB_CONTROL_DB_ATTACH,
			   0, data, ctdb, &data, &res);
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

	nodes = ctdb_get_connected_nodes(ctdb, ctdb, &num_nodes);
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

	nodes = ctdb_get_connected_nodes(ctdb, ctdb, &num_nodes);
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

	nodes = ctdb_get_connected_nodes(ctdb, ctdb, &num_nodes);
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
	int ret;
	poptContext pc;
	struct event_context *ev;
	const char *control;

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

	if (strcmp(control, "process-exists") == 0) {
		ret = control_process_exists(ctdb, extra_argc-1, extra_argv+1);
	} else if (strcmp(control, "status") == 0) {
		ret = control_status(ctdb, extra_argc-1, extra_argv+1);
	} else if (strcmp(control, "statusreset") == 0) {
		ret = control_status_reset(ctdb, extra_argc-1, extra_argv+1);
	} else if (strcmp(control, "getvnnmap") == 0) {
		ret = control_getvnnmap(ctdb, extra_argc-1, extra_argv+1);
	} else if (strcmp(control, "getdbmap") == 0) {
		ret = control_getdbmap(ctdb, extra_argc-1, extra_argv+1);
	} else if (strcmp(control, "getnodemap") == 0) {
		ret = control_getnodemap(ctdb, extra_argc-1, extra_argv+1);
	} else if (strcmp(control, "catdb") == 0) {
		ret = control_catdb(ctdb, extra_argc-1, extra_argv+1);
	} else if (strcmp(control, "cpdb") == 0) {
		ret = control_cpdb(ctdb, extra_argc-1, extra_argv+1);
	} else if (strcmp(control, "setvnnmap") == 0) {
		ret = control_setvnnmap(ctdb, extra_argc-1, extra_argv+1);
	} else if (strcmp(control, "setdmaster") == 0) {
		ret = control_setdmaster(ctdb, extra_argc-1, extra_argv+1);
	} else if (strcmp(control, "cleardb") == 0) {
		ret = control_cleardb(ctdb, extra_argc-1, extra_argv+1);
	} else if (strcmp(control, "createdb") == 0) {
		ret = control_createdb(ctdb, extra_argc-1, extra_argv+1);
	} else if (strcmp(control, "getrecmode") == 0) {
		ret = control_getrecmode(ctdb, extra_argc-1, extra_argv+1);
	} else if (strcmp(control, "setrecmode") == 0) {
		ret = control_setrecmode(ctdb, extra_argc-1, extra_argv+1);
	} else if (strcmp(control, "ping") == 0) {
		ret = control_ping(ctdb, extra_argc-1, extra_argv+1);
	} else if (strcmp(control, "debug") == 0) {
		ret = control_debug(ctdb, extra_argc-1, extra_argv+1);
	} else if (strcmp(control, "debuglevel") == 0) {
		ret = control_debuglevel(ctdb, extra_argc-1, extra_argv+1);
	} else if (strcmp(control, "recover") == 0) {
		ret = control_recover(ctdb, extra_argc-1, extra_argv+1);
	} else if (strcmp(control, "attach") == 0) {
		ret = control_attach(ctdb, extra_argc-1, extra_argv+1);
	} else {
		printf("Unknown control '%s'\n", control);
		exit(1);
	}

	return ret;
}
