/* 
   ctdb control tool

   Copyright (C) Andrew Tridgell  2007

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

#include "includes.h"
#include "lib/events/events.h"
#include "system/filesys.h"
#include "system/network.h"
#include "popt.h"
#include "cmdline.h"
#include "../include/ctdb.h"
#include "../include/ctdb_private.h"

static void usage(void);

static struct {
	int timelimit;
	uint32_t vnn;
	int machinereadable;
} options;

#define TIMELIMIT() timeval_current_ofs(options.timelimit, 0)

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
		DEBUG(0, ("Badly formed vnn:pid\n"));
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
  display statistics structure
 */
static void show_statistics(struct ctdb_statistics *s)
{
	TALLOC_CTX *tmp_ctx = talloc_new(NULL);
	int i;
	const char *prefix=NULL;
	int preflen=0;
	const struct {
		const char *name;
		uint32_t offset;
	} fields[] = {
#define STATISTICS_FIELD(n) { #n, offsetof(struct ctdb_statistics, n) }
		STATISTICS_FIELD(num_clients),
		STATISTICS_FIELD(frozen),
		STATISTICS_FIELD(recovering),
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
		STATISTICS_FIELD(client.req_call),
		STATISTICS_FIELD(client.req_message),
		STATISTICS_FIELD(client.req_control),
		STATISTICS_FIELD(timeouts.call),
		STATISTICS_FIELD(timeouts.control),
		STATISTICS_FIELD(timeouts.traverse),
		STATISTICS_FIELD(total_calls),
		STATISTICS_FIELD(pending_calls),
		STATISTICS_FIELD(lockwait_calls),
		STATISTICS_FIELD(pending_lockwait_calls),
		STATISTICS_FIELD(memory_used),
		STATISTICS_FIELD(max_hop_count),
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
  display remote ctdb statistics combined from all nodes
 */
static int control_statistics_all(struct ctdb_context *ctdb)
{
	int ret, i;
	struct ctdb_statistics statistics;
	uint32_t *nodes;
	uint32_t num_nodes;

	nodes = ctdb_get_connected_nodes(ctdb, TIMELIMIT(), ctdb, &num_nodes);
	CTDB_NO_MEMORY(ctdb, nodes);
	
	ZERO_STRUCT(statistics);

	for (i=0;i<num_nodes;i++) {
		struct ctdb_statistics s1;
		int j;
		uint32_t *v1 = (uint32_t *)&s1;
		uint32_t *v2 = (uint32_t *)&statistics;
		uint32_t num_ints = 
			offsetof(struct ctdb_statistics, __last_counter) / sizeof(uint32_t);
		ret = ctdb_ctrl_statistics(ctdb, nodes[i], &s1);
		if (ret != 0) {
			DEBUG(0, ("Unable to get statistics from node %u\n", nodes[i]));
			return ret;
		}
		for (j=0;j<num_ints;j++) {
			v2[j] += v1[j];
		}
		statistics.max_hop_count = 
			MAX(statistics.max_hop_count, s1.max_hop_count);
		statistics.max_call_latency = 
			MAX(statistics.max_call_latency, s1.max_call_latency);
		statistics.max_lockwait_latency = 
			MAX(statistics.max_lockwait_latency, s1.max_lockwait_latency);
	}
	talloc_free(nodes);
	printf("Gathered statistics for %u nodes\n", num_nodes);
	show_statistics(&statistics);
	return 0;
}

/*
  display remote ctdb statistics
 */
static int control_statistics(struct ctdb_context *ctdb, int argc, const char **argv)
{
	int ret;
	struct ctdb_statistics statistics;

	if (options.vnn == CTDB_BROADCAST_ALL) {
		return control_statistics_all(ctdb);
	}

	ret = ctdb_ctrl_statistics(ctdb, options.vnn, &statistics);
	if (ret != 0) {
		DEBUG(0, ("Unable to get statistics from node %u\n", options.vnn));
		return ret;
	}
	show_statistics(&statistics);
	return 0;
}


/*
  reset remote ctdb statistics
 */
static int control_statistics_reset(struct ctdb_context *ctdb, int argc, const char **argv)
{
	int ret;

	ret = ctdb_statistics_reset(ctdb, options.vnn);
	if (ret != 0) {
		DEBUG(0, ("Unable to reset statistics on node %u\n", options.vnn));
		return ret;
	}
	return 0;
}


/*
  display remote ctdb status
 */
static int control_status(struct ctdb_context *ctdb, int argc, const char **argv)
{
	int i, ret;
	struct ctdb_vnn_map *vnnmap=NULL;
	struct ctdb_node_map *nodemap=NULL;
	uint32_t recmode, recmaster;
	int myvnn;

	myvnn = ctdb_ctrl_getvnn(ctdb, TIMELIMIT(), options.vnn);
	if (myvnn == -1) {
		return -1;
	}

	ret = ctdb_ctrl_getnodemap(ctdb, TIMELIMIT(), options.vnn, ctdb, &nodemap);
	if (ret != 0) {
		DEBUG(0, ("Unable to get nodemap from node %u\n", options.vnn));
		return ret;
	}

	if(options.machinereadable){
		printf(":Node:IP:Disonnected:Disabled:Permanently Disabled:\n");
		for(i=0;i<nodemap->num;i++){
			printf(":%d:%s:%d:%d:%d:\n", nodemap->nodes[i].vnn,
				inet_ntoa(nodemap->nodes[i].sin.sin_addr),
			       !!(nodemap->nodes[i].flags&NODE_FLAGS_DISCONNECTED),
			       !!(nodemap->nodes[i].flags&NODE_FLAGS_UNHEALTHY),
			       !!(nodemap->nodes[i].flags&NODE_FLAGS_PERMANENTLY_DISABLED));
		}
		return 0;
	}

	printf("Number of nodes:%d\n", nodemap->num);
	for(i=0;i<nodemap->num;i++){
		static const struct {
			uint32_t flag;
			const char *name;
		} flag_names[] = {
			{ NODE_FLAGS_DISCONNECTED,          "DISCONNECTED" },
			{ NODE_FLAGS_PERMANENTLY_DISABLED,  "DISABLED" },
			{ NODE_FLAGS_BANNED,                "BANNED" },
			{ NODE_FLAGS_UNHEALTHY,             "UNHEALTHY" },
		};
		char *flags_str = NULL;
		int j;
		for (j=0;j<ARRAY_SIZE(flag_names);j++) {
			if (nodemap->nodes[i].flags & flag_names[j].flag) {
				if (flags_str == NULL) {
					flags_str = talloc_strdup(ctdb, flag_names[j].name);
				} else {
					flags_str = talloc_asprintf_append(flags_str, "|%s",
									   flag_names[j].name);
				}
				CTDB_NO_MEMORY_FATAL(ctdb, flags_str);
			}
		}
		if (flags_str == NULL) {
			flags_str = talloc_strdup(ctdb, "OK");
			CTDB_NO_MEMORY_FATAL(ctdb, flags_str);
		}
		printf("vnn:%d %-16s %s%s\n", nodemap->nodes[i].vnn,
		       inet_ntoa(nodemap->nodes[i].sin.sin_addr),
		       flags_str,
		       nodemap->nodes[i].vnn == myvnn?" (THIS NODE)":"");
		talloc_free(flags_str);
	}

	ret = ctdb_ctrl_getvnnmap(ctdb, TIMELIMIT(), options.vnn, ctdb, &vnnmap);
	if (ret != 0) {
		DEBUG(0, ("Unable to get vnnmap from node %u\n", options.vnn));
		return ret;
	}
	if (vnnmap->generation == INVALID_GENERATION) {
		printf("Generation:INVALID\n");
	} else {
		printf("Generation:%d\n",vnnmap->generation);
	}
	printf("Size:%d\n",vnnmap->size);
	for(i=0;i<vnnmap->size;i++){
		printf("hash:%d lmaster:%d\n", i, vnnmap->map[i]);
	}

	ret = ctdb_ctrl_getrecmode(ctdb, ctdb, TIMELIMIT(), options.vnn, &recmode);
	if (ret != 0) {
		DEBUG(0, ("Unable to get recmode from node %u\n", options.vnn));
		return ret;
	}
	printf("Recovery mode:%s (%d)\n",recmode==CTDB_RECOVERY_NORMAL?"NORMAL":"RECOVERY",recmode);

	ret = ctdb_ctrl_getrecmaster(ctdb, ctdb, TIMELIMIT(), options.vnn, &recmaster);
	if (ret != 0) {
		DEBUG(0, ("Unable to get recmaster from node %u\n", options.vnn));
		return ret;
	}
	printf("Recovery master:%d\n",recmaster);

	return 0;
}

/*
  get a list of all tickles for this vnn
 */
static int control_get_tickles(struct ctdb_context *ctdb, int argc, const char **argv)
{
	struct ctdb_control_tcp_tickle_list *list;
	uint32_t vnn;
	int i, ret;

	if (argc < 1) {
		usage();
	}

	vnn = strtoul(argv[0], NULL, 0);

	ret = ctdb_ctrl_get_tcp_tickles(ctdb, TIMELIMIT(), options.vnn, ctdb, vnn, &list);
	if (ret == -1) {
		DEBUG(0, ("Unable to list tickles\n"));
		return -1;
	}

	printf("Tickles for vnn:%u\n", list->vnn);
	printf("Num tickles:%u\n", list->tickles.num);
	for (i=0;i<list->tickles.num;i++) {
		printf("SRC: %s:%u   ", inet_ntoa(list->tickles.connections[i].saddr.sin_addr), ntohs(list->tickles.connections[i].saddr.sin_port));
		printf("DST: %s:%u\n", inet_ntoa(list->tickles.connections[i].daddr.sin_addr), ntohs(list->tickles.connections[i].daddr.sin_port));
	}

	talloc_free(list);
	
	return 0;
}

/*
  kill a tcp connection
 */
static int kill_tcp(struct ctdb_context *ctdb, int argc, const char **argv)
{
	int ret;
	struct ctdb_control_killtcp killtcp;

	if (argc < 2) {
		usage();
	}

	if (!parse_ip_port(argv[0], &killtcp.src)) {
		DEBUG(0, ("Bad IP:port '%s'\n", argv[0]));
		return -1;
	}

	if (!parse_ip_port(argv[1], &killtcp.dst)) {
		DEBUG(0, ("Bad IP:port '%s'\n", argv[1]));
		return -1;
	}

	ret = ctdb_ctrl_killtcp(ctdb, TIMELIMIT(), options.vnn, &killtcp);
	if (ret != 0) {
		DEBUG(0, ("Unable to killtcp from node %u\n", options.vnn));
		return ret;
	}

	return -1;
}

/*
  send a tcp tickle ack
 */
static int tickle_tcp(struct ctdb_context *ctdb, int argc, const char **argv)
{
	int s, ret;
	struct sockaddr_in src, dst;

	if (argc < 2) {
		usage();
	}

	if (!parse_ip_port(argv[0], &src)) {
		DEBUG(0, ("Bad IP:port '%s'\n", argv[0]));
		return -1;
	}

	if (!parse_ip_port(argv[1], &dst)) {
		DEBUG(0, ("Bad IP:port '%s'\n", argv[1]));
		return -1;
	}

	s = ctdb_sys_open_sending_socket();
	if (s == -1) {
		DEBUG(0, ("Failed to open socket for sending tickle\n"));
		return 0;
	}

	ret = ctdb_sys_send_tcp(s, &src, &dst, 0, 0, 0);
	close(s);
	if (ret==0) {
		return 0;
	}
	DEBUG(0, ("Error while sending tickle ack\n"));

	return -1;
}

/*
  display public ip status
 */
static int control_ip(struct ctdb_context *ctdb, int argc, const char **argv)
{
	int i, ret;
	struct ctdb_all_public_ips *ips;
	int myvnn;

	myvnn = ctdb_ctrl_getvnn(ctdb, TIMELIMIT(), options.vnn);
	if (myvnn == -1) {
		return -1;
	}

	ret = ctdb_ctrl_get_public_ips(ctdb, TIMELIMIT(), options.vnn, ctdb, &ips);
	if (ret != 0) {
		DEBUG(0, ("Unable to get public ips from node %u\n", options.vnn));
		return ret;
	}

	if(options.machinereadable){
		printf(":Public IP:Node:\n");
		for(i=0;i<ips->num;i++){
			printf(":%s:%d:\n",
			inet_ntoa(ips->ips[i].sin.sin_addr),
			ips->ips[i].takeover_vnn);
		}
		return 0;
	}


	printf("Number of nodes:%d\n", ips->num);
	for(i=0;i<ips->num;i++){
		printf("%-16s %d\n",
			inet_ntoa(ips->ips[i].sin.sin_addr),
			ips->ips[i].takeover_vnn);
	}

	return 0;
}

/*
  display public ip address of this node
 */
static int control_publicip(struct ctdb_context *ctdb, int argc, const char **argv)
{
	int ret;
	struct ctdb_all_public_ips *ips;
	int myvnn;

	myvnn = ctdb_ctrl_getvnn(ctdb, TIMELIMIT(), options.vnn);
	if (myvnn == -1) {
		return -1;
	}

	ret = ctdb_ctrl_get_public_ips(ctdb, TIMELIMIT(), options.vnn, ctdb, &ips);
	if (ret != 0) {
		DEBUG(0, ("Unable to get public ips from node %u\n", options.vnn));
		return ret;
	}

	printf("%-16s\n", inet_ntoa(ips->ips[myvnn].sin.sin_addr));

	return 0;
}

/*
  display pid of a ctdb daemon
 */
static int control_getpid(struct ctdb_context *ctdb, int argc, const char **argv)
{
	uint32_t pid;
	int ret;

	ret = ctdb_ctrl_getpid(ctdb, TIMELIMIT(), options.vnn, &pid);
	if (ret != 0) {
		DEBUG(0, ("Unable to get daemon pid from node %u\n", options.vnn));
		return ret;
	}
	printf("Pid:%d\n", pid);

	return 0;
}

/*
  disable a remote node
 */
static int control_disable(struct ctdb_context *ctdb, int argc, const char **argv)
{
	int ret;

	ret = ctdb_ctrl_modflags(ctdb, TIMELIMIT(), options.vnn, NODE_FLAGS_PERMANENTLY_DISABLED, 0);
	if (ret != 0) {
		DEBUG(0, ("Unable to disable node %u\n", options.vnn));
		return ret;
	}

	return 0;
}

/*
  enable a disabled remote node
 */
static int control_enable(struct ctdb_context *ctdb, int argc, const char **argv)
{
	int ret;

	ret = ctdb_ctrl_modflags(ctdb, TIMELIMIT(), options.vnn, 0, NODE_FLAGS_PERMANENTLY_DISABLED);
	if (ret != 0) {
		DEBUG(0, ("Unable to enable node %u\n", options.vnn));
		return ret;
	}

	return 0;
}

/*
  ban a node from the cluster
 */
static int control_ban(struct ctdb_context *ctdb, int argc, const char **argv)
{
	int ret;
	uint32_t recmaster;
	struct ctdb_ban_info b;
	TDB_DATA data;
	uint32_t ban_time;

	if (argc < 1) {
		usage();
	}

	ban_time = strtoul(argv[0], NULL, 0);

	ret = ctdb_ctrl_getrecmaster(ctdb, ctdb, TIMELIMIT(), options.vnn, &recmaster);
	if (ret != 0) {
		DEBUG(0,("Failed to find the recmaster\n"));
		return -1;
	}

	b.vnn = options.vnn;
	b.ban_time = ban_time;

	data.dptr = (uint8_t *)&b;
	data.dsize = sizeof(b);

	ret = ctdb_send_message(ctdb, recmaster, CTDB_SRVID_BAN_NODE, data);
	if (ret != 0) {
		DEBUG(0,("Failed to tell the recmaster to ban node %u\n", options.vnn));
		return -1;
	}
	
	return 0;
}


/*
  unban a node from the cluster
 */
static int control_unban(struct ctdb_context *ctdb, int argc, const char **argv)
{
	int ret;
	uint32_t recmaster;
	TDB_DATA data;

	ret = ctdb_ctrl_getrecmaster(ctdb, ctdb, TIMELIMIT(), options.vnn, &recmaster);
	if (ret != 0) {
		DEBUG(0,("Failed to find the recmaster\n"));
		return -1;
	}

	data.dptr = (uint8_t *)&options.vnn;
	data.dsize = sizeof(uint32_t);

	ret = ctdb_send_message(ctdb, recmaster, CTDB_SRVID_UNBAN_NODE, data);
	if (ret != 0) {
		DEBUG(0,("Failed to tell the recmaster to unban node %u\n", options.vnn));
		return -1;
	}
	
	return 0;
}


/*
  shutdown a daemon
 */
static int control_shutdown(struct ctdb_context *ctdb, int argc, const char **argv)
{
	int ret;

	ret = ctdb_ctrl_shutdown(ctdb, TIMELIMIT(), options.vnn);
	if (ret != 0) {
		DEBUG(0, ("Unable to shutdown node %u\n", options.vnn));
		return ret;
	}

	return 0;
}

/*
  trigger a recovery
 */
static int control_recover(struct ctdb_context *ctdb, int argc, const char **argv)
{
	int ret;

	ret = ctdb_ctrl_freeze(ctdb, TIMELIMIT(), options.vnn);
	if (ret != 0) {
		DEBUG(0, ("Unable to freeze node\n"));
		return ret;
	}

	ret = ctdb_ctrl_setrecmode(ctdb, TIMELIMIT(), options.vnn, CTDB_RECOVERY_ACTIVE);
	if (ret != 0) {
		DEBUG(0, ("Unable to set recovery mode\n"));
		return ret;
	}

	return 0;
}


/*
  display monitoring mode of a remote node
 */
static int control_getmonmode(struct ctdb_context *ctdb, int argc, const char **argv)
{
	uint32_t monmode;
	int ret;

	ret = ctdb_ctrl_getmonmode(ctdb, TIMELIMIT(), options.vnn, &monmode);
	if (ret != 0) {
		DEBUG(0, ("Unable to get monmode from node %u\n", options.vnn));
		return ret;
	}
	printf("Monitoring mode:%s (%d)\n",monmode==CTDB_MONITORING_ACTIVE?"ACTIVE":"DISABLED",monmode);

	return 0;
}

/*
  set the monitoring mode of a remote node
 */
static int control_setmonmode(struct ctdb_context *ctdb, int argc, const char **argv)
{
	uint32_t monmode;
	int ret;

	if (argc < 1) {
		usage();
	}

	monmode = strtoul(argv[0], NULL, 0);

	ret = ctdb_ctrl_setmonmode(ctdb, TIMELIMIT(), options.vnn, monmode);
	if (ret != 0) {
		DEBUG(0, ("Unable to set monmode on node %u\n", options.vnn));
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

	/* traverse and dump the cluster tdb */
	ret = ctdb_dump_db(ctdb_db, stdout);
	if (ret == -1) {
		DEBUG(0, ("Unable to dump database\n"));
		return -1;
	}
	talloc_free(ctdb_db);

	printf("Dumped %d records\n", ret);
	return 0;
}


/*
  display a list of the databases on a remote ctdb
 */
static int control_getdbmap(struct ctdb_context *ctdb, int argc, const char **argv)
{
	int i, ret;
	struct ctdb_dbid_map *dbmap=NULL;

	ret = ctdb_ctrl_getdbmap(ctdb, TIMELIMIT(), options.vnn, ctdb, &dbmap);
	if (ret != 0) {
		DEBUG(0, ("Unable to get dbids from node %u\n", options.vnn));
		return ret;
	}

	printf("Number of databases:%d\n", dbmap->num);
	for(i=0;i<dbmap->num;i++){
		const char *path;
		const char *name;

		ctdb_ctrl_getdbpath(ctdb, TIMELIMIT(), options.vnn, dbmap->dbids[i], ctdb, &path);
		ctdb_ctrl_getdbname(ctdb, TIMELIMIT(), options.vnn, dbmap->dbids[i], ctdb, &name);
		printf("dbid:0x%08x name:%s path:%s\n", dbmap->dbids[i], name, path);
	}

	return 0;
}

/*
  ping a node
 */
static int control_ping(struct ctdb_context *ctdb, int argc, const char **argv)
{
	int ret;
	struct timeval tv = timeval_current();
	ret = ctdb_ctrl_ping(ctdb, options.vnn);
	if (ret == -1) {
		printf("Unable to get ping response from node %u\n", options.vnn);
	} else {
		printf("response from %u time=%.6f sec  (%d clients)\n", 
		       options.vnn, timeval_elapsed(&tv), ret);
	}
	return 0;
}


/*
  get a tunable
 */
static int control_getvar(struct ctdb_context *ctdb, int argc, const char **argv)
{
	const char *name;
	uint32_t value;
	int ret;

	if (argc < 1) {
		usage();
	}

	name = argv[0];
	ret = ctdb_ctrl_get_tunable(ctdb, TIMELIMIT(), options.vnn, name, &value);
	if (ret == -1) {
		DEBUG(0, ("Unable to get tunable variable '%s'\n", name));
		return -1;
	}

	printf("%-19s = %u\n", name, value);
	return 0;
}

/*
  set a tunable
 */
static int control_setvar(struct ctdb_context *ctdb, int argc, const char **argv)
{
	const char *name;
	uint32_t value;
	int ret;

	if (argc < 2) {
		usage();
	}

	name = argv[0];
	value = strtoul(argv[1], NULL, 0);

	ret = ctdb_ctrl_set_tunable(ctdb, TIMELIMIT(), options.vnn, name, value);
	if (ret == -1) {
		DEBUG(0, ("Unable to set tunable variable '%s'\n", name));
		return -1;
	}
	return 0;
}

/*
  list all tunables
 */
static int control_listvars(struct ctdb_context *ctdb, int argc, const char **argv)
{
	uint32_t count;
	const char **list;
	int ret, i;

	ret = ctdb_ctrl_list_tunables(ctdb, TIMELIMIT(), options.vnn, ctdb, &list, &count);
	if (ret == -1) {
		DEBUG(0, ("Unable to list tunable variables\n"));
		return -1;
	}

	for (i=0;i<count;i++) {
		control_getvar(ctdb, 1, &list[i]);
	}

	talloc_free(list);
	
	return 0;
}

/*
  display debug level on a node
 */
static int control_getdebug(struct ctdb_context *ctdb, int argc, const char **argv)
{
	int ret;
	uint32_t level;

	ret = ctdb_ctrl_get_debuglevel(ctdb, options.vnn, &level);
	if (ret != 0) {
	  DEBUG(0, ("Unable to get debuglevel response from node %u\n", 
		       options.vnn));
	} else {
		printf("Node %u is at debug level %u\n", options.vnn, level);
	}
	return 0;
}


/*
  set debug level on a node or all nodes
 */
static int control_setdebug(struct ctdb_context *ctdb, int argc, const char **argv)
{
	int ret;
	uint32_t level;

	if (argc < 1) {
		usage();
	}

	level = strtoul(argv[0], NULL, 0);

	ret = ctdb_ctrl_set_debuglevel(ctdb, options.vnn, level);
	if (ret != 0) {
		DEBUG(0, ("Unable to set debug level on node %u\n", options.vnn));
	}
	return 0;
}


/*
  freeze a node
 */
static int control_freeze(struct ctdb_context *ctdb, int argc, const char **argv)
{
	int ret;

	ret = ctdb_ctrl_freeze(ctdb, TIMELIMIT(), options.vnn);
	if (ret != 0) {
		DEBUG(0, ("Unable to freeze node %u\n", options.vnn));
	}		
	return 0;
}

/*
  thaw a node
 */
static int control_thaw(struct ctdb_context *ctdb, int argc, const char **argv)
{
	int ret;

	ret = ctdb_ctrl_thaw(ctdb, TIMELIMIT(), options.vnn);
	if (ret != 0) {
		DEBUG(0, ("Unable to thaw node %u\n", options.vnn));
	}		
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
	return ctdb_control(ctdb, options.vnn, 0, CTDB_CONTROL_DUMP_MEMORY,
			    CTDB_CTRL_FLAG_NOREPLY, tdb_null, NULL, NULL, NULL, NULL, NULL);
}


static const struct {
	const char *name;
	int (*fn)(struct ctdb_context *, int, const char **);
	bool auto_all;
	const char *msg;
	const char *args;
} ctdb_commands[] = {
	{ "status",          control_status,            true,  "show node status" },
	{ "ping",            control_ping,              true,  "ping all nodes" },
	{ "getvar",          control_getvar,            true,  "get a tunable variable",               "<name>"},
	{ "setvar",          control_setvar,            true,  "set a tunable variable",               "<name> <value>"},
	{ "listvars",        control_listvars,          true,  "list tunable variables"},
	{ "statistics",      control_statistics,        false, "show statistics" },
	{ "statisticsreset", control_statistics_reset,  true,  "reset statistics"},
	{ "ip",              control_ip,                true,  "show which public ip's that ctdb manages" },
	{ "publicip",        control_publicip,          false, "show the default public ip address for this node" },
	{ "process-exists",  control_process_exists,    true,  "check if a process exists on a node",  "<pid>"},
	{ "getdbmap",        control_getdbmap,          true,  "show the database map" },
	{ "catdb",           control_catdb,             true,  "dump a database" ,                     "<dbname>"},
	{ "getmonmode",      control_getmonmode,        true,  "show monitoring mode" },
	{ "setmonmode",      control_setmonmode,        true,  "set monitoring mode", "<0|1>" },
	{ "setdebug",        control_setdebug,          true,  "set debug level",                      "<debuglevel>" },
	{ "getdebug",        control_getdebug,          true,  "get debug level" },
	{ "attach",          control_attach,            true,  "attach to a database",                 "<dbname>" },
	{ "dumpmemory",      control_dumpmemory,        true,  "dump memory map to logs" },
	{ "getpid",          control_getpid,            true,  "get ctdbd process ID" },
	{ "disable",         control_disable,           true,  "disable a nodes public IP" },
	{ "enable",          control_enable,            true,  "enable a nodes public IP" },
	{ "ban",             control_ban,               true,  "ban a node from the cluster",          "<bantime|0>"},
	{ "unban",           control_unban,             true,  "unban a node from the cluster" },
	{ "shutdown",        control_shutdown,          true,  "shutdown ctdbd" },
	{ "recover",         control_recover,           true,  "force recovery" },
	{ "freeze",          control_freeze,            true,  "freeze all databases" },
	{ "thaw",            control_thaw,              true,  "thaw all databases" },
	{ "killtcp",         kill_tcp,                  false, "kill a tcp connection.", "<srcip:port> <dstip:port>" },
	{ "tickle",          tickle_tcp,                false, "send a tcp tickle ack", "<srcip:port> <dstip:port>" },
	{ "gettickles",      control_get_tickles,       false, "get the list of tickles registered for this vnn", "<vnn>" },
};

/*
  show usage message
 */
static void usage(void)
{
	int i;
	printf(
"Usage: ctdb [options] <control>\n" \
"Options:\n" \
"   -n <node>          choose node number, or 'all' (defaults to local node)\n"
"   -Y                 generate machinereadable output\n"
"   -t <timelimit>     set timelimit for control in seconds (default %u)\n", options.timelimit);
	printf("Controls:\n");
	for (i=0;i<ARRAY_SIZE(ctdb_commands);i++) {
		printf("  %-15s %-27s  %s\n", 
		       ctdb_commands[i].name, 
		       ctdb_commands[i].args?ctdb_commands[i].args:"",
		       ctdb_commands[i].msg);
	}
	exit(1);
}


/*
  main program
*/
int main(int argc, const char *argv[])
{
	struct ctdb_context *ctdb;
	char *nodestring = NULL;
	struct poptOption popt_options[] = {
		POPT_AUTOHELP
		POPT_CTDB_CMDLINE
		{ "timelimit", 't', POPT_ARG_INT, &options.timelimit, 0, "timelimit", "integer" },
		{ "node",      'n', POPT_ARG_STRING, &nodestring, 0, "node", "integer|all" },
		{ "machinereadable", 'Y', POPT_ARG_NONE, &options.machinereadable, 0, "enable machinereadable output", NULL },
		POPT_TABLEEND
	};
	int opt;
	const char **extra_argv;
	int extra_argc = 0;
	int ret=-1, i;
	poptContext pc;
	struct event_context *ev;
	const char *control;

	/* set some defaults */
	options.timelimit = 3;
	options.vnn = CTDB_CURRENT_NODE;

	pc = poptGetContext(argv[0], argc, argv, popt_options, POPT_CONTEXT_KEEP_FIRST);

	while ((opt = poptGetNextOpt(pc)) != -1) {
		switch (opt) {
		default:
			DEBUG(0, ("Invalid option %s: %s\n", 
				poptBadOption(pc, 0), poptStrerror(opt)));
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

	/* setup the node number to contact */
	if (nodestring != NULL) {
		if (strcmp(nodestring, "all") == 0) {
			options.vnn = CTDB_BROADCAST_ALL;
		} else {
			options.vnn = strtoul(nodestring, NULL, 0);
		}
	}

	control = extra_argv[0];

	ev = event_context_init(NULL);

	/* initialise ctdb */
	ctdb = ctdb_cmdline_client(ev);
	if (ctdb == NULL) {
		DEBUG(0, ("Failed to init ctdb\n"));
		exit(1);
	}

	for (i=0;i<ARRAY_SIZE(ctdb_commands);i++) {
		if (strcmp(control, ctdb_commands[i].name) == 0) {
			int j;

			if (options.vnn == CTDB_CURRENT_NODE) {
				int vnn;
				vnn = ctdb_ctrl_getvnn(ctdb, TIMELIMIT(), options.vnn);		
				if (vnn == -1) {
					return -1;
				}
				options.vnn = vnn;
			}

			if (ctdb_commands[i].auto_all && 
			    options.vnn == CTDB_BROADCAST_ALL) {
				uint32_t *nodes;
				uint32_t num_nodes;
				ret = 0;

				nodes = ctdb_get_connected_nodes(ctdb, TIMELIMIT(), ctdb, &num_nodes);
				CTDB_NO_MEMORY(ctdb, nodes);
	
				for (j=0;j<num_nodes;j++) {
					options.vnn = nodes[j];
					ret |= ctdb_commands[i].fn(ctdb, extra_argc-1, extra_argv+1);
				}
				talloc_free(nodes);
			} else {
				ret = ctdb_commands[i].fn(ctdb, extra_argc-1, extra_argv+1);
			}
			break;
		}
	}

	if (i == ARRAY_SIZE(ctdb_commands)) {
		DEBUG(0, ("Unknown control '%s'\n", control));
		exit(1);
	}

	return ret;
}
