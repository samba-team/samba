/* 
   ctdb control tool

   Copyright (C) Andrew Tridgell  2007
   Copyright (C) Ronnie Sahlberg  2007

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
#include "system/time.h"
#include "system/filesys.h"
#include "system/network.h"
#include "system/locale.h"
#include "popt.h"
#include "cmdline.h"
#include "../include/ctdb.h"
#include "../include/ctdb_client.h"
#include "../include/ctdb_private.h"
#include "../common/rb_tree.h"
#include "db_wrap.h"

#define ERR_TIMEOUT	20	/* timed out trying to reach node */
#define ERR_NONODE	21	/* node does not exist */
#define ERR_DISNODE	22	/* node is disconnected */

struct ctdb_connection *ctdb_connection;

static void usage(void);

static struct {
	int timelimit;
	uint32_t pnn;
	uint32_t *nodes;
	int machinereadable;
	int verbose;
	int maxruntime;
	int printemptyrecords;
	int printdatasize;
	int printlmaster;
	int printhash;
	int printrecordflags;
} options;

#define TIMELIMIT() timeval_current_ofs(options.timelimit, 0)
#define LONGTIMELIMIT() timeval_current_ofs(options.timelimit*10, 0)

#ifdef CTDB_VERS
static int control_version(struct ctdb_context *ctdb, int argc, const char **argv)
{
#define STR(x) #x
#define XSTR(x) STR(x)
	printf("CTDB version: %s\n", XSTR(CTDB_VERS));
	return 0;
}
#endif

#define CTDB_NOMEM_ABORT(p) do { if (!(p)) {				\
		DEBUG(DEBUG_ALERT,("ctdb fatal error: %s\n",		\
				   "Out of memory in " __location__ ));	\
		abort();						\
	}} while (0)

/* Pretty print the flags to a static buffer in human-readable format.
 * This never returns NULL!
 */
static const char *pretty_print_flags(uint32_t flags)
{
	int j;
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
	static char flags_str[512]; /* Big enough to contain all flag names */

	flags_str[0] = '\0';
	for (j=0;j<ARRAY_SIZE(flag_names);j++) {
		if (flags & flag_names[j].flag) {
			if (flags_str[0] == '\0') {
				(void) strcpy(flags_str, flag_names[j].name);
			} else {
				(void) strcat(flags_str, "|");
				(void) strcat(flags_str, flag_names[j].name);
			}
		}
	}
	if (flags_str[0] == '\0') {
		(void) strcpy(flags_str, "OK");
	}

	return flags_str;
}

static int h2i(char h)
{
	if (h >= 'a' && h <= 'f') return h - 'a' + 10;
	if (h >= 'A' && h <= 'F') return h - 'f' + 10;
	return h - '0';
}

static TDB_DATA hextodata(TALLOC_CTX *mem_ctx, const char *str)
{
	int i, len;
	TDB_DATA key = {NULL, 0};

	len = strlen(str);
	if (len & 0x01) {
		DEBUG(DEBUG_ERR,("Key specified with odd number of hexadecimal digits\n"));
		return key;
	}

	key.dsize = len>>1;
	key.dptr  = talloc_size(mem_ctx, key.dsize);

	for (i=0; i < len/2; i++) {
		key.dptr[i] = h2i(str[i*2]) << 4 | h2i(str[i*2+1]);
	}
	return key;
}

/* Parse a nodestring.  Parameter dd_ok controls what happens to nodes
 * that are disconnected or deleted.  If dd_ok is true those nodes are
 * included in the output list of nodes.  If dd_ok is false, those
 * nodes are filtered from the "all" case and cause an error if
 * explicitly specified.
 */
static bool parse_nodestring(struct ctdb_context *ctdb,
			     const char * nodestring,
			     uint32_t current_pnn,
			     bool dd_ok,
			     uint32_t **nodes,
			     uint32_t *pnn_mode)
{
	int n;
	uint32_t i;
	struct ctdb_node_map *nodemap;
       
	*nodes = NULL;

	if (!ctdb_getnodemap(ctdb_connection, CTDB_CURRENT_NODE, &nodemap)) {
		DEBUG(DEBUG_ERR, ("Unable to get nodemap from local node\n"));
		exit(10);
	}

	if (nodestring != NULL) {
		*nodes = talloc_array(ctdb, uint32_t, 0);
		CTDB_NOMEM_ABORT(*nodes);
               
		n = 0;

		if (strcmp(nodestring, "all") == 0) {
			*pnn_mode = CTDB_BROADCAST_ALL;

			/* all */
			for (i = 0; i < nodemap->num; i++) {
				if ((nodemap->nodes[i].flags & 
				     (NODE_FLAGS_DISCONNECTED |
				      NODE_FLAGS_DELETED)) && !dd_ok) {
					continue;
				}
				*nodes = talloc_realloc(ctdb, *nodes,
							uint32_t, n+1);
				CTDB_NOMEM_ABORT(*nodes);
				(*nodes)[n] = i;
				n++;
			}
		} else {
			/* x{,y...} */
			char *ns, *tok;
                       
			ns = talloc_strdup(ctdb, nodestring);
			tok = strtok(ns, ",");
			while (tok != NULL) {
				uint32_t pnn;
				i = (uint32_t)strtoul(tok, NULL, 0);
				if (i >= nodemap->num) {
					DEBUG(DEBUG_ERR, ("Node %u does not exist\n", i));
					exit(ERR_NONODE);
				}
				if ((nodemap->nodes[i].flags & 
				     (NODE_FLAGS_DISCONNECTED |
				      NODE_FLAGS_DELETED)) && !dd_ok) {
					DEBUG(DEBUG_ERR, ("Node %u has status %s\n", i, pretty_print_flags(nodemap->nodes[i].flags)));
					exit(ERR_DISNODE);
				}
				if (!ctdb_getpnn(ctdb_connection, i, &pnn)) {
					DEBUG(DEBUG_ERR, ("Can not access node %u. Node is not operational.\n", i));
					exit(10);
				}

				*nodes = talloc_realloc(ctdb, *nodes,
							uint32_t, n+1);
				CTDB_NOMEM_ABORT(*nodes);

				(*nodes)[n] = i;
				n++;

				tok = strtok(NULL, ",");
			}
			talloc_free(ns);

			if (n == 1) {
				*pnn_mode = (*nodes)[0];
			} else {
				*pnn_mode = CTDB_MULTICAST;
			}
		}
	} else {
		/* default - no nodes specified */
		*nodes = talloc_array(ctdb, uint32_t, 1);
		CTDB_NOMEM_ABORT(*nodes);
		*pnn_mode = CTDB_CURRENT_NODE;

		if (!ctdb_getpnn(ctdb_connection, current_pnn,
				 &((*nodes)[0]))) {
			return false;
		}
	}

	ctdb_free_nodemap(nodemap);

	return true;
}

/*
 check if a database exists
*/
static int db_exists(struct ctdb_context *ctdb, const char *db_name, bool *persistent)
{
	int i, ret;
	struct ctdb_dbid_map *dbmap=NULL;

	ret = ctdb_ctrl_getdbmap(ctdb, TIMELIMIT(), options.pnn, ctdb, &dbmap);
	if (ret != 0) {
		DEBUG(DEBUG_ERR, ("Unable to get dbids from node %u\n", options.pnn));
		return -1;
	}

	for(i=0;i<dbmap->num;i++){
		const char *name;

		ctdb_ctrl_getdbname(ctdb, TIMELIMIT(), options.pnn, dbmap->dbs[i].dbid, ctdb, &name);
		if (!strcmp(name, db_name)) {
			if (persistent) {
				*persistent = dbmap->dbs[i].flags & CTDB_DB_FLAGS_PERSISTENT;
			}
			return 0;
		}
	}

	return -1;
}

/*
  see if a process exists
 */
static int control_process_exists(struct ctdb_context *ctdb, int argc, const char **argv)
{
	uint32_t pnn, pid;
	int ret;
	if (argc < 1) {
		usage();
	}

	if (sscanf(argv[0], "%u:%u", &pnn, &pid) != 2) {
		DEBUG(DEBUG_ERR, ("Badly formed pnn:pid\n"));
		return -1;
	}

	ret = ctdb_ctrl_process_exists(ctdb, pnn, pid);
	if (ret == 0) {
		printf("%u:%u exists\n", pnn, pid);
	} else {
		printf("%u:%u does not exist\n", pnn, pid);
	}
	return ret;
}

/*
  display statistics structure
 */
static void show_statistics(struct ctdb_statistics *s, int show_header)
{
	TALLOC_CTX *tmp_ctx = talloc_new(NULL);
	int i;
	const char *prefix=NULL;
	int preflen=0;
	int tmp, days, hours, minutes, seconds;
	const struct {
		const char *name;
		uint32_t offset;
	} fields[] = {
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
		STATISTICS_FIELD(childwrite_calls),
		STATISTICS_FIELD(pending_childwrite_calls),
		STATISTICS_FIELD(memory_used),
		STATISTICS_FIELD(max_hop_count),
		STATISTICS_FIELD(total_ro_delegations),
		STATISTICS_FIELD(total_ro_revokes),
	};
	
	tmp = s->statistics_current_time.tv_sec - s->statistics_start_time.tv_sec;
	seconds = tmp%60;
	tmp    /= 60;
	minutes = tmp%60;
	tmp    /= 60;
	hours   = tmp%24;
	tmp    /= 24;
	days    = tmp;

	if (options.machinereadable){
		if (show_header) {
			printf("CTDB version:");
			printf("Current time of statistics:");
			printf("Statistics collected since:");
			for (i=0;i<ARRAY_SIZE(fields);i++) {
				printf("%s:", fields[i].name);
			}
			printf("num_reclock_ctdbd_latency:");
			printf("min_reclock_ctdbd_latency:");
			printf("avg_reclock_ctdbd_latency:");
			printf("max_reclock_ctdbd_latency:");

			printf("num_reclock_recd_latency:");
			printf("min_reclock_recd_latency:");
			printf("avg_reclock_recd_latency:");
			printf("max_reclock_recd_latency:");

			printf("num_call_latency:");
			printf("min_call_latency:");
			printf("avg_call_latency:");
			printf("max_call_latency:");

			printf("num_lockwait_latency:");
			printf("min_lockwait_latency:");
			printf("avg_lockwait_latency:");
			printf("max_lockwait_latency:");

			printf("num_childwrite_latency:");
			printf("min_childwrite_latency:");
			printf("avg_childwrite_latency:");
			printf("max_childwrite_latency:");
			printf("\n");
		}
		printf("%d:", CTDB_VERSION);
		printf("%d:", (int)s->statistics_current_time.tv_sec);
		printf("%d:", (int)s->statistics_start_time.tv_sec);
		for (i=0;i<ARRAY_SIZE(fields);i++) {
			printf("%d:", *(uint32_t *)(fields[i].offset+(uint8_t *)s));
		}
		printf("%d:", s->reclock.ctdbd.num);
		printf("%.6f:", s->reclock.ctdbd.min);
		printf("%.6f:", s->reclock.ctdbd.num?s->reclock.ctdbd.total/s->reclock.ctdbd.num:0.0);
		printf("%.6f:", s->reclock.ctdbd.max);

		printf("%d:", s->reclock.recd.num);
		printf("%.6f:", s->reclock.recd.min);
		printf("%.6f:", s->reclock.recd.num?s->reclock.recd.total/s->reclock.recd.num:0.0);
		printf("%.6f:", s->reclock.recd.max);

		printf("%d:", s->call_latency.num);
		printf("%.6f:", s->call_latency.min);
		printf("%.6f:", s->call_latency.num?s->call_latency.total/s->call_latency.num:0.0);
		printf("%.6f:", s->call_latency.max);

		printf("%d:", s->lockwait_latency.num);
		printf("%.6f:", s->lockwait_latency.min);
		printf("%.6f:", s->lockwait_latency.num?s->lockwait_latency.total/s->lockwait_latency.num:0.0);
		printf("%.6f:", s->lockwait_latency.max);

		printf("%d:", s->childwrite_latency.num);
		printf("%.6f:", s->childwrite_latency.min);
		printf("%.6f:", s->childwrite_latency.num?s->childwrite_latency.total/s->childwrite_latency.num:0.0);
		printf("%.6f:", s->childwrite_latency.max);
		printf("\n");
	} else {
		printf("CTDB version %u\n", CTDB_VERSION);
		printf("Current time of statistics  :                %s", ctime(&s->statistics_current_time.tv_sec));
		printf("Statistics collected since  : (%03d %02d:%02d:%02d) %s", days, hours, minutes, seconds, ctime(&s->statistics_start_time.tv_sec));

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
		printf(" hop_count_buckets:");
		for (i=0;i<MAX_COUNT_BUCKETS;i++) {
			printf(" %d", s->hop_count_bucket[i]);
		}
		printf("\n");
		printf(" %-30s     %.6f/%.6f/%.6f sec out of %d\n", "reclock_ctdbd       MIN/AVG/MAX", s->reclock.ctdbd.min, s->reclock.ctdbd.num?s->reclock.ctdbd.total/s->reclock.ctdbd.num:0.0, s->reclock.ctdbd.max, s->reclock.ctdbd.num);

		printf(" %-30s     %.6f/%.6f/%.6f sec out of %d\n", "reclock_recd       MIN/AVG/MAX", s->reclock.recd.min, s->reclock.recd.num?s->reclock.recd.total/s->reclock.recd.num:0.0, s->reclock.recd.max, s->reclock.recd.num);

		printf(" %-30s     %.6f/%.6f/%.6f sec out of %d\n", "call_latency       MIN/AVG/MAX", s->call_latency.min, s->call_latency.num?s->call_latency.total/s->call_latency.num:0.0, s->call_latency.max, s->call_latency.num);
		printf(" %-30s     %.6f/%.6f/%.6f sec out of %d\n", "lockwait_latency   MIN/AVG/MAX", s->lockwait_latency.min, s->lockwait_latency.num?s->lockwait_latency.total/s->lockwait_latency.num:0.0, s->lockwait_latency.max, s->lockwait_latency.num);
		printf(" %-30s     %.6f/%.6f/%.6f sec out of %d\n", "childwrite_latency MIN/AVG/MAX", s->childwrite_latency.min, s->childwrite_latency.num?s->childwrite_latency.total/s->childwrite_latency.num:0.0, s->childwrite_latency.max, s->childwrite_latency.num);
	}

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
			DEBUG(DEBUG_ERR, ("Unable to get statistics from node %u\n", nodes[i]));
			return ret;
		}
		for (j=0;j<num_ints;j++) {
			v2[j] += v1[j];
		}
		statistics.max_hop_count = 
			MAX(statistics.max_hop_count, s1.max_hop_count);
		statistics.call_latency.max = 
			MAX(statistics.call_latency.max, s1.call_latency.max);
		statistics.lockwait_latency.max = 
			MAX(statistics.lockwait_latency.max, s1.lockwait_latency.max);
	}
	talloc_free(nodes);
	printf("Gathered statistics for %u nodes\n", num_nodes);
	show_statistics(&statistics, 1);
	return 0;
}

/*
  display remote ctdb statistics
 */
static int control_statistics(struct ctdb_context *ctdb, int argc, const char **argv)
{
	int ret;
	struct ctdb_statistics statistics;

	if (options.pnn == CTDB_BROADCAST_ALL) {
		return control_statistics_all(ctdb);
	}

	ret = ctdb_ctrl_statistics(ctdb, options.pnn, &statistics);
	if (ret != 0) {
		DEBUG(DEBUG_ERR, ("Unable to get statistics from node %u\n", options.pnn));
		return ret;
	}
	show_statistics(&statistics, 1);
	return 0;
}


/*
  reset remote ctdb statistics
 */
static int control_statistics_reset(struct ctdb_context *ctdb, int argc, const char **argv)
{
	int ret;

	ret = ctdb_statistics_reset(ctdb, options.pnn);
	if (ret != 0) {
		DEBUG(DEBUG_ERR, ("Unable to reset statistics on node %u\n", options.pnn));
		return ret;
	}
	return 0;
}


/*
  display remote ctdb rolling statistics
 */
static int control_stats(struct ctdb_context *ctdb, int argc, const char **argv)
{
	int ret;
	struct ctdb_statistics_wire *stats;
	int i, num_records = -1;

	if (argc ==1) {
		num_records = atoi(argv[0]) - 1;
	}

	ret = ctdb_ctrl_getstathistory(ctdb, TIMELIMIT(), options.pnn, ctdb, &stats);
	if (ret != 0) {
		DEBUG(DEBUG_ERR, ("Unable to get rolling statistics from node %u\n", options.pnn));
		return ret;
	}
	for (i=0;i<stats->num;i++) {
		if (stats->stats[i].statistics_start_time.tv_sec == 0) {
			continue;
		}
		show_statistics(&stats->stats[i], i==0);
		if (i == num_records) {
			break;
		}
	}
	return 0;
}


/*
  display remote ctdb db statistics
 */
static int control_dbstatistics(struct ctdb_context *ctdb, int argc, const char **argv)
{
	TALLOC_CTX *tmp_ctx = talloc_new(ctdb);
	struct ctdb_db_statistics *dbstatistics;
	struct ctdb_dbid_map *dbmap=NULL;
	int i, ret;

	if (argc < 1) {
		usage();
	}

	ret = ctdb_ctrl_getdbmap(ctdb, TIMELIMIT(), options.pnn, tmp_ctx, &dbmap);
	if (ret != 0) {
		DEBUG(DEBUG_ERR, ("Unable to get dbids from node %u\n", options.pnn));
		return ret;
	}
	for(i=0;i<dbmap->num;i++){
		const char *name;

		ctdb_ctrl_getdbname(ctdb, TIMELIMIT(), options.pnn, dbmap->dbs[i].dbid, tmp_ctx, &name);
		if(!strcmp(argv[0], name)){
			talloc_free(discard_const(name));
			break;
		}
		talloc_free(discard_const(name));
	}
	if (i == dbmap->num) {
		DEBUG(DEBUG_ERR,("No database with name '%s' found\n", argv[0]));
		talloc_free(tmp_ctx);
		return -1;
	}

	if (!ctdb_getdbstat(ctdb_connection, options.pnn, dbmap->dbs[i].dbid, &dbstatistics)) {
		DEBUG(DEBUG_ERR,("Failed to read db statistics from node\n"));
		talloc_free(tmp_ctx);
		return -1;
	}

	printf("DB Statistics:\n");
	printf("RO Delegations: %d\n", dbstatistics->db_ro_delegations);
	printf("RO Revokes:     %d\n", dbstatistics->db_ro_revokes);
	printf(" hop_count_buckets:");
	for (i=0;i<MAX_COUNT_BUCKETS;i++) {
		printf(" %d", dbstatistics->hop_count_bucket[i]);
	}
	printf("\n");
	printf("Num Hot Keys:     %d\n", dbstatistics->num_hot_keys);
	for (i = 0; i < dbstatistics->num_hot_keys; i++) {
		int j;
		printf("Count:%d Key:", dbstatistics->hot_keys[i].count);
		for (j = 0; j < dbstatistics->hot_keys[i].key.dsize; j++) {
			printf("%02x", dbstatistics->hot_keys[i].key.dptr[j]&0xff);
		}
		printf("\n");
	}

	ctdb_free_dbstat(dbstatistics);
	return 0;
}

/*
  display uptime of remote node
 */
static int control_uptime(struct ctdb_context *ctdb, int argc, const char **argv)
{
	int ret;
	struct ctdb_uptime *uptime = NULL;
	int tmp, days, hours, minutes, seconds;

	ret = ctdb_ctrl_uptime(ctdb, ctdb, TIMELIMIT(), options.pnn, &uptime);
	if (ret != 0) {
		DEBUG(DEBUG_ERR, ("Unable to get uptime from node %u\n", options.pnn));
		return ret;
	}

	if (options.machinereadable){
		printf(":Current Node Time:Ctdb Start Time:Last Recovery/Failover Time:Last Recovery/IPFailover Duration:\n");
		printf(":%u:%u:%u:%lf\n",
			(unsigned int)uptime->current_time.tv_sec,
			(unsigned int)uptime->ctdbd_start_time.tv_sec,
			(unsigned int)uptime->last_recovery_finished.tv_sec,
			timeval_delta(&uptime->last_recovery_finished,
				      &uptime->last_recovery_started)
		);
		return 0;
	}

	printf("Current time of node          :                %s", ctime(&uptime->current_time.tv_sec));

	tmp = uptime->current_time.tv_sec - uptime->ctdbd_start_time.tv_sec;
	seconds = tmp%60;
	tmp    /= 60;
	minutes = tmp%60;
	tmp    /= 60;
	hours   = tmp%24;
	tmp    /= 24;
	days    = tmp;
	printf("Ctdbd start time              : (%03d %02d:%02d:%02d) %s", days, hours, minutes, seconds, ctime(&uptime->ctdbd_start_time.tv_sec));

	tmp = uptime->current_time.tv_sec - uptime->last_recovery_finished.tv_sec;
	seconds = tmp%60;
	tmp    /= 60;
	minutes = tmp%60;
	tmp    /= 60;
	hours   = tmp%24;
	tmp    /= 24;
	days    = tmp;
	printf("Time of last recovery/failover: (%03d %02d:%02d:%02d) %s", days, hours, minutes, seconds, ctime(&uptime->last_recovery_finished.tv_sec));
	
	printf("Duration of last recovery/failover: %lf seconds\n",
		timeval_delta(&uptime->last_recovery_finished,
			      &uptime->last_recovery_started));

	return 0;
}

/*
  show the PNN of the current node
 */
static int control_pnn(struct ctdb_context *ctdb, int argc, const char **argv)
{
	uint32_t mypnn;
	bool ret;

	ret = ctdb_getpnn(ctdb_connection, options.pnn, &mypnn);
	if (!ret) {
		DEBUG(DEBUG_ERR, ("Unable to get pnn from node."));
		return -1;
	}

	printf("PNN:%d\n", mypnn);
	return 0;
}


struct pnn_node {
	struct pnn_node *next;
	const char *addr;
	int pnn;
};

static struct pnn_node *read_nodes_file(TALLOC_CTX *mem_ctx)
{
	const char *nodes_list;
	int nlines;
	char **lines;
	int i, pnn;
	struct pnn_node *pnn_nodes = NULL;
	struct pnn_node *pnn_node;
	struct pnn_node *tmp_node;

	/* read the nodes file */
	nodes_list = getenv("CTDB_NODES");
	if (nodes_list == NULL) {
		nodes_list = "/etc/ctdb/nodes";
	}
	lines = file_lines_load(nodes_list, &nlines, mem_ctx);
	if (lines == NULL) {
		return NULL;
	}
	while (nlines > 0 && strcmp(lines[nlines-1], "") == 0) {
		nlines--;
	}
	for (i=0, pnn=0; i<nlines; i++) {
		char *node;

		node = lines[i];
		/* strip leading spaces */
		while((*node == ' ') || (*node == '\t')) {
			node++;
		}
		if (*node == '#') {
			pnn++;
			continue;
		}
		if (strcmp(node, "") == 0) {
			continue;
		}
		pnn_node = talloc(mem_ctx, struct pnn_node);
		pnn_node->pnn = pnn++;
		pnn_node->addr = talloc_strdup(pnn_node, node);
		pnn_node->next = pnn_nodes;
		pnn_nodes = pnn_node;
	}

	/* swap them around so we return them in incrementing order */
	pnn_node = pnn_nodes;
	pnn_nodes = NULL;
	while (pnn_node) {
		tmp_node = pnn_node;
		pnn_node = pnn_node->next;

		tmp_node->next = pnn_nodes;
		pnn_nodes = tmp_node;
	}

	return pnn_nodes;
}

/*
  show the PNN of the current node
  discover the pnn by loading the nodes file and try to bind to all
  addresses one at a time until the ip address is found.
 */
static int control_xpnn(struct ctdb_context *ctdb, int argc, const char **argv)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct pnn_node *pnn_nodes;
	struct pnn_node *pnn_node;

	pnn_nodes = read_nodes_file(mem_ctx);
	if (pnn_nodes == NULL) {
		DEBUG(DEBUG_ERR,("Failed to read nodes file\n"));
		talloc_free(mem_ctx);
		return -1;
	}

	for(pnn_node=pnn_nodes;pnn_node;pnn_node=pnn_node->next) {
		ctdb_sock_addr addr;

		if (parse_ip(pnn_node->addr, NULL, 63999, &addr) == 0) {
			DEBUG(DEBUG_ERR,("Wrongly formed ip address '%s' in nodes file\n", pnn_node->addr));
			talloc_free(mem_ctx);
			return -1;
		}

		if (ctdb_sys_have_ip(&addr)) {
			printf("PNN:%d\n", pnn_node->pnn);
			talloc_free(mem_ctx);
			return 0;
		}
	}

	printf("Failed to detect which PNN this node is\n");
	talloc_free(mem_ctx);
	return -1;
}

/* Helpers for ctdb status
 */
static bool is_partially_online(struct ctdb_node_and_flags *node)
{
	int j;
	bool ret = false;

	if (node->flags == 0) {
		struct ctdb_ifaces_list *ifaces;

		if (ctdb_getifaces(ctdb_connection, node->pnn, &ifaces)) {
			for (j=0; j < ifaces->num; j++) {
				if (ifaces->ifaces[j].link_state != 0) {
					continue;
				}
				ret = true;
				break;
			}
			ctdb_free_ifaces(ifaces);
		}
	}

	return ret;
}

static void control_status_header_machine(void)
{
	printf(":Node:IP:Disconnected:Banned:Disabled:Unhealthy:Stopped"
	       ":Inactive:PartiallyOnline:ThisNode:\n");
}

static int control_status_1_machine(int mypnn, struct ctdb_node_and_flags *node)
{
	printf(":%d:%s:%d:%d:%d:%d:%d:%d:%d:%c:\n", node->pnn,
	       ctdb_addr_to_str(&node->addr),
	       !!(node->flags&NODE_FLAGS_DISCONNECTED),
	       !!(node->flags&NODE_FLAGS_BANNED),
	       !!(node->flags&NODE_FLAGS_PERMANENTLY_DISABLED),
	       !!(node->flags&NODE_FLAGS_UNHEALTHY),
	       !!(node->flags&NODE_FLAGS_STOPPED),
	       !!(node->flags&NODE_FLAGS_INACTIVE),
	       is_partially_online(node) ? 1 : 0,
	       (node->pnn == mypnn)?'Y':'N');

	return node->flags;
}

static int control_status_1_human(int mypnn, struct ctdb_node_and_flags *node)
{
       printf("pnn:%d %-16s %s%s\n", node->pnn,
              ctdb_addr_to_str(&node->addr),
              is_partially_online(node) ? "PARTIALLYONLINE" : pretty_print_flags(node->flags),
              node->pnn == mypnn?" (THIS NODE)":"");

       return node->flags;
}

/*
  display remote ctdb status
 */
static int control_status(struct ctdb_context *ctdb, int argc, const char **argv)
{
	int i;
	struct ctdb_vnn_map *vnnmap=NULL;
	struct ctdb_node_map *nodemap=NULL;
	uint32_t recmode, recmaster, mypnn;

	if (!ctdb_getpnn(ctdb_connection, options.pnn, &mypnn)) {
		return -1;
	}

	if (!ctdb_getnodemap(ctdb_connection, options.pnn, &nodemap)) {
		DEBUG(DEBUG_ERR, ("Unable to get nodemap from node %u\n", options.pnn));
		return -1;
	}

	if (options.machinereadable) {
		control_status_header_machine();
		for (i=0;i<nodemap->num;i++) {
			if (nodemap->nodes[i].flags & NODE_FLAGS_DELETED) {
				continue;
			}
			(void) control_status_1_machine(mypnn,
							&nodemap->nodes[i]);
		}
		return 0;
	}

	printf("Number of nodes:%d\n", nodemap->num);
	for(i=0;i<nodemap->num;i++){
		if (nodemap->nodes[i].flags & NODE_FLAGS_DELETED) {
			continue;
		}
		(void) control_status_1_human(mypnn, &nodemap->nodes[i]);
	}

	if (!ctdb_getvnnmap(ctdb_connection, options.pnn, &vnnmap)) {
		DEBUG(DEBUG_ERR, ("Unable to get vnnmap from node %u\n", options.pnn));
		return -1;
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
	ctdb_free_vnnmap(vnnmap);

	if (!ctdb_getrecmode(ctdb_connection, options.pnn, &recmode)) {
		DEBUG(DEBUG_ERR, ("Unable to get recmode from node %u\n", options.pnn));
		return -1;
	}
	printf("Recovery mode:%s (%d)\n",recmode==CTDB_RECOVERY_NORMAL?"NORMAL":"RECOVERY",recmode);

	if (!ctdb_getrecmaster(ctdb_connection, options.pnn, &recmaster)) {
		DEBUG(DEBUG_ERR, ("Unable to get recmaster from node %u\n", options.pnn));
		return -1;
	}
	printf("Recovery master:%d\n",recmaster);

	return 0;
}

static int control_nodestatus(struct ctdb_context *ctdb, int argc, const char **argv)
{
	int i, ret;
	struct ctdb_node_map *nodemap=NULL;
	uint32_t * nodes;
	uint32_t pnn_mode, mypnn;

	if (argc > 1) {
		usage();
	}

	if (!parse_nodestring(ctdb, argc == 1 ? argv[0] : NULL,
			      options.pnn, true, &nodes, &pnn_mode)) {
		return -1;
	}

	if (options.machinereadable) {
		control_status_header_machine();
	} else if (pnn_mode == CTDB_BROADCAST_ALL) {
		printf("Number of nodes:%d\n", (int) talloc_array_length(nodes));
	}

	if (!ctdb_getpnn(ctdb_connection, options.pnn, &mypnn)) {
		DEBUG(DEBUG_ERR, ("Unable to get PNN from local node\n"));
		return -1;
	}

	if (!ctdb_getnodemap(ctdb_connection, options.pnn, &nodemap)) {
		DEBUG(DEBUG_ERR, ("Unable to get nodemap from node %u\n", options.pnn));
		return -1;
	}

	ret = 0;

	for (i = 0; i < talloc_array_length(nodes); i++) {
		if (options.machinereadable) {
			ret |= control_status_1_machine(mypnn,
							&nodemap->nodes[nodes[i]]);
		} else {
			ret |= control_status_1_human(mypnn,
						      &nodemap->nodes[nodes[i]]);
		}
	}
	return ret;
}

struct natgw_node {
	struct natgw_node *next;
	const char *addr;
};

/*
  display the list of nodes belonging to this natgw configuration
 */
static int control_natgwlist(struct ctdb_context *ctdb, int argc, const char **argv)
{
	int i, ret;
	uint32_t capabilities;
	const char *natgw_list;
	int nlines;
	char **lines;
	struct natgw_node *natgw_nodes = NULL;
	struct natgw_node *natgw_node;
	struct ctdb_node_map *nodemap=NULL;
	uint32_t mypnn;
	const char *fmt;


	/* read the natgw nodes file into a linked list */
	natgw_list = getenv("CTDB_NATGW_NODES");
	if (natgw_list == NULL) {
		natgw_list = "/etc/ctdb/natgw_nodes";
	}
	lines = file_lines_load(natgw_list, &nlines, ctdb);
	if (lines == NULL) {
		ctdb_set_error(ctdb, "Failed to load natgw node list '%s'\n", natgw_list);
		return -1;
	}
	for (i=0;i<nlines;i++) {
		char *node;

		node = lines[i];
		/* strip leading spaces */
		while((*node == ' ') || (*node == '\t')) {
			node++;
		}
		if (*node == '#') {
			continue;
		}
		if (strcmp(node, "") == 0) {
			continue;
		}
		natgw_node = talloc(ctdb, struct natgw_node);
		natgw_node->addr = talloc_strdup(natgw_node, node);
		CTDB_NO_MEMORY(ctdb, natgw_node->addr);
		natgw_node->next = natgw_nodes;
		natgw_nodes = natgw_node;
	}

	ret = ctdb_ctrl_getnodemap(ctdb, TIMELIMIT(), CTDB_CURRENT_NODE, ctdb, &nodemap);
	if (ret != 0) {
		DEBUG(DEBUG_ERR, ("Unable to get nodemap from local node.\n"));
		return ret;
	}

	i=0;
	while(i<nodemap->num) {
		for(natgw_node=natgw_nodes;natgw_node;natgw_node=natgw_node->next) {
			if (!strcmp(natgw_node->addr, ctdb_addr_to_str(&nodemap->nodes[i].addr))) {
				break;
			}
		}

		/* this node was not in the natgw so we just remove it from
		 * the list
		 */
		if ((natgw_node == NULL) 
		||  (nodemap->nodes[i].flags & NODE_FLAGS_DISCONNECTED) ) {
			int j;

			for (j=i+1; j<nodemap->num; j++) {
				nodemap->nodes[j-1] = nodemap->nodes[j];
			}
			nodemap->num--;
			continue;
		}

		i++;
	}

	if (options.machinereadable) {
		printf(":Node:IP:\n");
		fmt = ":%d:%s:\n";
	} else {
		fmt = "%d %s\n";
	}

	/* pick a node to be natgwmaster
	 * we dont allow STOPPED, DELETED, BANNED or UNHEALTHY nodes to become the natgwmaster
	 */
	for(i=0;i<nodemap->num;i++){
		if (!(nodemap->nodes[i].flags & (NODE_FLAGS_DISCONNECTED|NODE_FLAGS_STOPPED|NODE_FLAGS_DELETED|NODE_FLAGS_BANNED|NODE_FLAGS_UNHEALTHY))) {
			ret = ctdb_ctrl_getcapabilities(ctdb, TIMELIMIT(), nodemap->nodes[i].pnn, &capabilities);
			if (ret != 0) {
				DEBUG(DEBUG_ERR, ("Unable to get capabilities from node %u\n", nodemap->nodes[i].pnn));
				return ret;
			}
			if (!(capabilities&CTDB_CAP_NATGW)) {
				continue;
			}
			printf(fmt, nodemap->nodes[i].pnn,ctdb_addr_to_str(&nodemap->nodes[i].addr));
			break;
		}
	}
	/* we couldnt find any healthy node, try unhealthy ones */
	if (i == nodemap->num) {
		for(i=0;i<nodemap->num;i++){
			if (!(nodemap->nodes[i].flags & (NODE_FLAGS_DISCONNECTED|NODE_FLAGS_STOPPED|NODE_FLAGS_DELETED))) {
				ret = ctdb_ctrl_getcapabilities(ctdb, TIMELIMIT(), nodemap->nodes[i].pnn, &capabilities);
				if (ret != 0) {
					DEBUG(DEBUG_ERR, ("Unable to get capabilities from node %u\n", nodemap->nodes[i].pnn));
					return ret;
				}
				if (!(capabilities&CTDB_CAP_NATGW)) {
					continue;
				}
				printf(fmt, nodemap->nodes[i].pnn,ctdb_addr_to_str(&nodemap->nodes[i].addr));
				break;
			}
		}
	}
	/* unless all nodes are STOPPED, when we pick one anyway */
	if (i == nodemap->num) {
		for(i=0;i<nodemap->num;i++){
			if (!(nodemap->nodes[i].flags & (NODE_FLAGS_DISCONNECTED|NODE_FLAGS_DELETED))) {
				ret = ctdb_ctrl_getcapabilities(ctdb, TIMELIMIT(), nodemap->nodes[i].pnn, &capabilities);
				if (ret != 0) {
					DEBUG(DEBUG_ERR, ("Unable to get capabilities from node %u\n", nodemap->nodes[i].pnn));
					return ret;
				}
				if (!(capabilities&CTDB_CAP_NATGW)) {
					continue;
				}
				printf(fmt, nodemap->nodes[i].pnn, ctdb_addr_to_str(&nodemap->nodes[i].addr));
				break;
			}
		}
		/* or if we still can not find any */
		if (i == nodemap->num) {
			printf(fmt, -1, "0.0.0.0");
			ret = 2; /* matches ENOENT */
		}
	}

	/* print the pruned list of nodes belonging to this natgw list */
	if (!ctdb_getpnn(ctdb_connection, options.pnn, &mypnn)) {
		DEBUG(DEBUG_ERR, ("Unable to get PNN from node %u\n", options.pnn));
		return -1;
	}
	if (options.machinereadable) {
		control_status_header_machine();
	} else {
		printf("Number of nodes:%d\n", nodemap->num);
	}
	for(i=0;i<nodemap->num;i++){
		if (nodemap->nodes[i].flags & NODE_FLAGS_DELETED) {
			continue;
		}
		if (options.machinereadable) {
			control_status_1_machine(mypnn, &(nodemap->nodes[i]));
		} else {
			control_status_1_human(mypnn, &(nodemap->nodes[i]));
		}
	}

	return ret;
}

/*
  display the status of the scripts for monitoring (or other events)
 */
static int control_one_scriptstatus(struct ctdb_context *ctdb,
				    enum ctdb_eventscript_call type)
{
	struct ctdb_scripts_wire *script_status;
	int ret, i;

	ret = ctdb_ctrl_getscriptstatus(ctdb, TIMELIMIT(), options.pnn, ctdb, type, &script_status);
	if (ret != 0) {
		DEBUG(DEBUG_ERR, ("Unable to get script status from node %u\n", options.pnn));
		return ret;
	}

	if (script_status == NULL) {
		if (!options.machinereadable) {
			printf("%s cycle never run\n",
			       ctdb_eventscript_call_names[type]);
		}
		return 0;
	}

	if (!options.machinereadable) {
		printf("%d scripts were executed last %s cycle\n",
		       script_status->num_scripts,
		       ctdb_eventscript_call_names[type]);
	}
	for (i=0; i<script_status->num_scripts; i++) {
		const char *status = NULL;

		switch (script_status->scripts[i].status) {
		case -ETIME:
			status = "TIMEDOUT";
			break;
		case -ENOEXEC:
			status = "DISABLED";
			break;
		case 0:
			status = "OK";
			break;
		default:
			if (script_status->scripts[i].status > 0)
				status = "ERROR";
			break;
		}
		if (options.machinereadable) {
			printf(":%s:%s:%i:%s:%lu.%06lu:%lu.%06lu:%s:\n",
			       ctdb_eventscript_call_names[type],
			       script_status->scripts[i].name,
			       script_status->scripts[i].status,
			       status,
			       (long)script_status->scripts[i].start.tv_sec,
			       (long)script_status->scripts[i].start.tv_usec,
			       (long)script_status->scripts[i].finished.tv_sec,
			       (long)script_status->scripts[i].finished.tv_usec,
			       script_status->scripts[i].output);
			continue;
		}
		if (status)
			printf("%-20s Status:%s    ",
			       script_status->scripts[i].name, status);
		else
			/* Some other error, eg from stat. */
			printf("%-20s Status:CANNOT RUN (%s)",
			       script_status->scripts[i].name,
			       strerror(-script_status->scripts[i].status));

		if (script_status->scripts[i].status >= 0) {
			printf("Duration:%.3lf ",
			timeval_delta(&script_status->scripts[i].finished,
			      &script_status->scripts[i].start));
		}
		if (script_status->scripts[i].status != -ENOEXEC) {
			printf("%s",
			       ctime(&script_status->scripts[i].start.tv_sec));
			if (script_status->scripts[i].status != 0) {
				printf("   OUTPUT:%s\n",
				       script_status->scripts[i].output);
			}
		} else {
			printf("\n");
		}
	}
	return 0;
}


static int control_scriptstatus(struct ctdb_context *ctdb,
				int argc, const char **argv)
{
	int ret;
	enum ctdb_eventscript_call type, min, max;
	const char *arg;

	if (argc > 1) {
		DEBUG(DEBUG_ERR, ("Unknown arguments to scriptstatus\n"));
		return -1;
	}

	if (argc == 0)
		arg = ctdb_eventscript_call_names[CTDB_EVENT_MONITOR];
	else
		arg = argv[0];

	for (type = 0; type < CTDB_EVENT_MAX; type++) {
		if (strcmp(arg, ctdb_eventscript_call_names[type]) == 0) {
			min = type;
			max = type+1;
			break;
		}
	}
	if (type == CTDB_EVENT_MAX) {
		if (strcmp(arg, "all") == 0) {
			min = 0;
			max = CTDB_EVENT_MAX;
		} else {
			DEBUG(DEBUG_ERR, ("Unknown event type %s\n", argv[0]));
			return -1;
		}
	}

	if (options.machinereadable) {
		printf(":Type:Name:Code:Status:Start:End:Error Output...:\n");
	}

	for (type = min; type < max; type++) {
		ret = control_one_scriptstatus(ctdb, type);
		if (ret != 0) {
			return ret;
		}
	}

	return 0;
}

/*
  enable an eventscript
 */
static int control_enablescript(struct ctdb_context *ctdb, int argc, const char **argv)
{
	int ret;

	if (argc < 1) {
		usage();
	}

	ret = ctdb_ctrl_enablescript(ctdb, TIMELIMIT(), options.pnn, argv[0]);
	if (ret != 0) {
	  DEBUG(DEBUG_ERR, ("Unable to enable script %s on node %u\n", argv[0], options.pnn));
		return ret;
	}

	return 0;
}

/*
  disable an eventscript
 */
static int control_disablescript(struct ctdb_context *ctdb, int argc, const char **argv)
{
	int ret;

	if (argc < 1) {
		usage();
	}

	ret = ctdb_ctrl_disablescript(ctdb, TIMELIMIT(), options.pnn, argv[0]);
	if (ret != 0) {
	  DEBUG(DEBUG_ERR, ("Unable to disable script %s on node %u\n", argv[0], options.pnn));
		return ret;
	}

	return 0;
}

/*
  display the pnn of the recovery master
 */
static int control_recmaster(struct ctdb_context *ctdb, int argc, const char **argv)
{
	uint32_t recmaster;

	if (!ctdb_getrecmaster(ctdb_connection, options.pnn, &recmaster)) {
		DEBUG(DEBUG_ERR, ("Unable to get recmaster from node %u\n", options.pnn));
		return -1;
	}
	printf("%d\n",recmaster);

	return 0;
}

/*
  add a tickle to a public address
 */
static int control_add_tickle(struct ctdb_context *ctdb, int argc, const char **argv)
{
	struct ctdb_tcp_connection t;
	TDB_DATA data;
	int ret;

	if (argc < 2) {
		usage();
	}

	if (parse_ip_port(argv[0], &t.src_addr) == 0) {
		DEBUG(DEBUG_ERR,("Wrongly formed ip address '%s'\n", argv[0]));
		return -1;
	}
	if (parse_ip_port(argv[1], &t.dst_addr) == 0) {
		DEBUG(DEBUG_ERR,("Wrongly formed ip address '%s'\n", argv[1]));
		return -1;
	}

	data.dptr = (uint8_t *)&t;
	data.dsize = sizeof(t);

	/* tell all nodes about this tcp connection */
	ret = ctdb_control(ctdb, options.pnn, 0, CTDB_CONTROL_TCP_ADD_DELAYED_UPDATE,
			   0, data, ctdb, NULL, NULL, NULL, NULL);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,("Failed to add tickle\n"));
		return -1;
	}
	
	return 0;
}


/*
  delete a tickle from a node
 */
static int control_del_tickle(struct ctdb_context *ctdb, int argc, const char **argv)
{
	struct ctdb_tcp_connection t;
	TDB_DATA data;
	int ret;

	if (argc < 2) {
		usage();
	}

	if (parse_ip_port(argv[0], &t.src_addr) == 0) {
		DEBUG(DEBUG_ERR,("Wrongly formed ip address '%s'\n", argv[0]));
		return -1;
	}
	if (parse_ip_port(argv[1], &t.dst_addr) == 0) {
		DEBUG(DEBUG_ERR,("Wrongly formed ip address '%s'\n", argv[1]));
		return -1;
	}

	data.dptr = (uint8_t *)&t;
	data.dsize = sizeof(t);

	/* tell all nodes about this tcp connection */
	ret = ctdb_control(ctdb, options.pnn, 0, CTDB_CONTROL_TCP_REMOVE,
			   0, data, ctdb, NULL, NULL, NULL, NULL);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,("Failed to remove tickle\n"));
		return -1;
	}
	
	return 0;
}


/*
  get a list of all tickles for this pnn
 */
static int control_get_tickles(struct ctdb_context *ctdb, int argc, const char **argv)
{
	struct ctdb_control_tcp_tickle_list *list;
	ctdb_sock_addr addr;
	int i, ret;
	unsigned port = 0;

	if (argc < 1) {
		usage();
	}

	if (argc == 2) {
		port = atoi(argv[1]);
	}

	if (parse_ip(argv[0], NULL, 0, &addr) == 0) {
		DEBUG(DEBUG_ERR,("Wrongly formed ip address '%s'\n", argv[0]));
		return -1;
	}

	ret = ctdb_ctrl_get_tcp_tickles(ctdb, TIMELIMIT(), options.pnn, ctdb, &addr, &list);
	if (ret == -1) {
		DEBUG(DEBUG_ERR, ("Unable to list tickles\n"));
		return -1;
	}

	if (options.machinereadable){
		printf(":source ip:port:destination ip:port:\n");
		for (i=0;i<list->tickles.num;i++) {
			if (port && port != ntohs(list->tickles.connections[i].dst_addr.ip.sin_port)) {
				continue;
			}
			printf(":%s:%u", ctdb_addr_to_str(&list->tickles.connections[i].src_addr), ntohs(list->tickles.connections[i].src_addr.ip.sin_port));
			printf(":%s:%u:\n", ctdb_addr_to_str(&list->tickles.connections[i].dst_addr), ntohs(list->tickles.connections[i].dst_addr.ip.sin_port));
		}
	} else {
		printf("Tickles for ip:%s\n", ctdb_addr_to_str(&list->addr));
		printf("Num tickles:%u\n", list->tickles.num);
		for (i=0;i<list->tickles.num;i++) {
			if (port && port != ntohs(list->tickles.connections[i].dst_addr.ip.sin_port)) {
				continue;
			}
			printf("SRC: %s:%u   ", ctdb_addr_to_str(&list->tickles.connections[i].src_addr), ntohs(list->tickles.connections[i].src_addr.ip.sin_port));
			printf("DST: %s:%u\n", ctdb_addr_to_str(&list->tickles.connections[i].dst_addr), ntohs(list->tickles.connections[i].dst_addr.ip.sin_port));
		}
	}

	talloc_free(list);
	
	return 0;
}


static int move_ip(struct ctdb_context *ctdb, ctdb_sock_addr *addr, uint32_t pnn)
{
	struct ctdb_all_public_ips *ips;
	struct ctdb_public_ip ip;
	int i, ret;
	uint32_t *nodes;
	uint32_t disable_time;
	TDB_DATA data;
	struct ctdb_node_map *nodemap=NULL;
	TALLOC_CTX *tmp_ctx = talloc_new(ctdb);

	disable_time = 30;
	data.dptr  = (uint8_t*)&disable_time;
	data.dsize = sizeof(disable_time);
	ret = ctdb_client_send_message(ctdb, CTDB_BROADCAST_CONNECTED, CTDB_SRVID_DISABLE_IP_CHECK, data);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,("Failed to send message to disable ipcheck\n"));
		return -1;
	}



	/* read the public ip list from the node */
	ret = ctdb_ctrl_get_public_ips(ctdb, TIMELIMIT(), pnn, ctdb, &ips);
	if (ret != 0) {
		DEBUG(DEBUG_ERR, ("Unable to get public ip list from node %u\n", pnn));
		talloc_free(tmp_ctx);
		return -1;
	}

	for (i=0;i<ips->num;i++) {
		if (ctdb_same_ip(addr, &ips->ips[i].addr)) {
			break;
		}
	}
	if (i==ips->num) {
		DEBUG(DEBUG_ERR, ("Node %u can not host ip address '%s'\n",
			pnn, ctdb_addr_to_str(addr)));
		talloc_free(tmp_ctx);
		return -1;
	}

	ip.pnn  = pnn;
	ip.addr = *addr;

	data.dptr  = (uint8_t *)&ip;
	data.dsize = sizeof(ip);

	ret = ctdb_ctrl_getnodemap(ctdb, TIMELIMIT(), options.pnn, tmp_ctx, &nodemap);
	if (ret != 0) {
		DEBUG(DEBUG_ERR, ("Unable to get nodemap from node %u\n", options.pnn));
		talloc_free(tmp_ctx);
		return ret;
	}

       	nodes = list_of_active_nodes_except_pnn(ctdb, nodemap, tmp_ctx, pnn);
	ret = ctdb_client_async_control(ctdb, CTDB_CONTROL_RELEASE_IP,
					nodes, 0,
					LONGTIMELIMIT(),
					false, data,
					NULL, NULL,
					NULL);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,("Failed to release IP on nodes\n"));
		talloc_free(tmp_ctx);
		return -1;
	}

	ret = ctdb_ctrl_takeover_ip(ctdb, LONGTIMELIMIT(), pnn, &ip);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,("Failed to take over IP on node %d\n", pnn));
		talloc_free(tmp_ctx);
		return -1;
	}

	/* update the recovery daemon so it now knows to expect the new
	   node assignment for this ip.
	*/
	ret = ctdb_client_send_message(ctdb, CTDB_BROADCAST_CONNECTED, CTDB_SRVID_RECD_UPDATE_IP, data);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,("Failed to send message to update the ip on the recovery master.\n"));
		return -1;
	}

	talloc_free(tmp_ctx);
	return 0;
}

/*
  move/failover an ip address to a specific node
 */
static int control_moveip(struct ctdb_context *ctdb, int argc, const char **argv)
{
	uint32_t pnn;
	int ret, retries = 0;
	ctdb_sock_addr addr;

	if (argc < 2) {
		usage();
		return -1;
	}

	if (parse_ip(argv[0], NULL, 0, &addr) == 0) {
		DEBUG(DEBUG_ERR,("Wrongly formed ip address '%s'\n", argv[0]));
		return -1;
	}


	if (sscanf(argv[1], "%u", &pnn) != 1) {
		DEBUG(DEBUG_ERR, ("Badly formed pnn\n"));
		return -1;
	}

	do {
		ret = move_ip(ctdb, &addr, pnn);
		if (ret != 0) {
			DEBUG(DEBUG_ERR,("Failed to move ip to node %d. Wait 3 second and try again.\n", pnn));
			sleep(3);
			retries++;
		}
	} while (retries < 5 && ret != 0);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,("Failed to move ip to node %d. Giving up.\n", pnn));
		return -1;
	}

	return 0;
}

static int rebalance_node(struct ctdb_context *ctdb, uint32_t pnn)
{
	uint32_t recmaster;
	TDB_DATA data;

	if (ctdb_ctrl_getrecmaster(ctdb, ctdb, TIMELIMIT(), pnn, &recmaster) != 0) {
		DEBUG(DEBUG_ERR, ("Unable to get recmaster from node %u\n", pnn));
		return -1;
	}

	data.dptr  = (uint8_t *)&pnn;
	data.dsize = sizeof(uint32_t);
	if (ctdb_client_send_message(ctdb, recmaster, CTDB_SRVID_REBALANCE_NODE, data) != 0) {
		DEBUG(DEBUG_ERR,("Failed to send message to force node reallocation\n"));
		return -1;
	}

	return 0;
}


/*
  rebalance a node by setting it to allow failback and triggering a
  takeover run
 */
static int control_rebalancenode(struct ctdb_context *ctdb, int argc, const char **argv)
{
	switch (options.pnn) {
	case CTDB_BROADCAST_ALL:
	case CTDB_CURRENT_NODE:
		DEBUG(DEBUG_ERR,("You must specify a node number with -n <pnn> for the node to rebalance\n"));
		return -1;
	}

	return rebalance_node(ctdb, options.pnn);
}


static int rebalance_ip(struct ctdb_context *ctdb, ctdb_sock_addr *addr)
{
	struct ctdb_public_ip ip;
	int ret;
	uint32_t *nodes;
	uint32_t disable_time;
	TDB_DATA data;
	struct ctdb_node_map *nodemap=NULL;
	TALLOC_CTX *tmp_ctx = talloc_new(ctdb);

	disable_time = 30;
	data.dptr  = (uint8_t*)&disable_time;
	data.dsize = sizeof(disable_time);
	ret = ctdb_client_send_message(ctdb, CTDB_BROADCAST_CONNECTED, CTDB_SRVID_DISABLE_IP_CHECK, data);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,("Failed to send message to disable ipcheck\n"));
		return -1;
	}

	ip.pnn  = -1;
	ip.addr = *addr;

	data.dptr  = (uint8_t *)&ip;
	data.dsize = sizeof(ip);

	ret = ctdb_ctrl_getnodemap(ctdb, TIMELIMIT(), options.pnn, tmp_ctx, &nodemap);
	if (ret != 0) {
		DEBUG(DEBUG_ERR, ("Unable to get nodemap from node %u\n", options.pnn));
		talloc_free(tmp_ctx);
		return ret;
	}

       	nodes = list_of_active_nodes(ctdb, nodemap, tmp_ctx, true);
	ret = ctdb_client_async_control(ctdb, CTDB_CONTROL_RELEASE_IP,
					nodes, 0,
					LONGTIMELIMIT(),
					false, data,
					NULL, NULL,
					NULL);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,("Failed to release IP on nodes\n"));
		talloc_free(tmp_ctx);
		return -1;
	}

	talloc_free(tmp_ctx);
	return 0;
}

/*
  release an ip form all nodes and have it re-assigned by recd
 */
static int control_rebalanceip(struct ctdb_context *ctdb, int argc, const char **argv)
{
	ctdb_sock_addr addr;

	if (argc < 1) {
		usage();
		return -1;
	}

	if (parse_ip(argv[0], NULL, 0, &addr) == 0) {
		DEBUG(DEBUG_ERR,("Wrongly formed ip address '%s'\n", argv[0]));
		return -1;
	}

	if (rebalance_ip(ctdb, &addr) != 0) {
		DEBUG(DEBUG_ERR,("Error when trying to reassign ip\n"));
		return -1;
	}

	return 0;
}

static int getips_store_callback(void *param, void *data)
{
	struct ctdb_public_ip *node_ip = (struct ctdb_public_ip *)data;
	struct ctdb_all_public_ips *ips = param;
	int i;

	i = ips->num++;
	ips->ips[i].pnn  = node_ip->pnn;
	ips->ips[i].addr = node_ip->addr;
	return 0;
}

static int getips_count_callback(void *param, void *data)
{
	uint32_t *count = param;

	(*count)++;
	return 0;
}

#define IP_KEYLEN	4
static uint32_t *ip_key(ctdb_sock_addr *ip)
{
	static uint32_t key[IP_KEYLEN];

	bzero(key, sizeof(key));

	switch (ip->sa.sa_family) {
	case AF_INET:
		key[0]	= ip->ip.sin_addr.s_addr;
		break;
	case AF_INET6: {
		uint32_t *s6_a32 = (uint32_t *)&(ip->ip6.sin6_addr.s6_addr);
		key[0]	= s6_a32[3];
		key[1]	= s6_a32[2];
		key[2]	= s6_a32[1];
		key[3]	= s6_a32[0];
		break;
	}
	default:
		DEBUG(DEBUG_ERR, (__location__ " ERROR, unknown family passed :%u\n", ip->sa.sa_family));
		return key;
	}

	return key;
}

static void *add_ip_callback(void *parm, void *data)
{
	return parm;
}

static int
control_get_all_public_ips(struct ctdb_context *ctdb, TALLOC_CTX *tmp_ctx, struct ctdb_all_public_ips **ips)
{
	struct ctdb_all_public_ips *tmp_ips;
	struct ctdb_node_map *nodemap=NULL;
	trbt_tree_t *ip_tree;
	int i, j, len, ret;
	uint32_t count;

	ret = ctdb_ctrl_getnodemap(ctdb, TIMELIMIT(), CTDB_CURRENT_NODE, tmp_ctx, &nodemap);
	if (ret != 0) {
		DEBUG(DEBUG_ERR, ("Unable to get nodemap from node %u\n", options.pnn));
		return ret;
	}

	ip_tree = trbt_create(tmp_ctx, 0);

	for(i=0;i<nodemap->num;i++){
		if (nodemap->nodes[i].flags & NODE_FLAGS_DELETED) {
			continue;
		}
		if (nodemap->nodes[i].flags & NODE_FLAGS_DISCONNECTED) {
			continue;
		}

		/* read the public ip list from this node */
		ret = ctdb_ctrl_get_public_ips(ctdb, TIMELIMIT(), nodemap->nodes[i].pnn, tmp_ctx, &tmp_ips);
		if (ret != 0) {
			DEBUG(DEBUG_ERR, ("Unable to get public ip list from node %u\n", nodemap->nodes[i].pnn));
			return -1;
		}
	
		for (j=0; j<tmp_ips->num;j++) {
			struct ctdb_public_ip *node_ip;

			node_ip = talloc(tmp_ctx, struct ctdb_public_ip);
			node_ip->pnn  = tmp_ips->ips[j].pnn;
			node_ip->addr = tmp_ips->ips[j].addr;

			trbt_insertarray32_callback(ip_tree,
				IP_KEYLEN, ip_key(&tmp_ips->ips[j].addr),
				add_ip_callback,
				node_ip);
		}
		talloc_free(tmp_ips);
	}

	/* traverse */
	count = 0;
	trbt_traversearray32(ip_tree, IP_KEYLEN, getips_count_callback, &count);

	len = offsetof(struct ctdb_all_public_ips, ips) + 
		count*sizeof(struct ctdb_public_ip);
	tmp_ips = talloc_zero_size(tmp_ctx, len);
	trbt_traversearray32(ip_tree, IP_KEYLEN, getips_store_callback, tmp_ips);

	*ips = tmp_ips;

	return 0;
}


/* 
 * scans all other nodes and returns a pnn for another node that can host this 
 * ip address or -1
 */
static int
find_other_host_for_public_ip(struct ctdb_context *ctdb, ctdb_sock_addr *addr)
{
	TALLOC_CTX *tmp_ctx = talloc_new(ctdb);
	struct ctdb_all_public_ips *ips;
	struct ctdb_node_map *nodemap=NULL;
	int i, j, ret;

	ret = ctdb_ctrl_getnodemap(ctdb, TIMELIMIT(), CTDB_CURRENT_NODE, tmp_ctx, &nodemap);
	if (ret != 0) {
		DEBUG(DEBUG_ERR, ("Unable to get nodemap from node %u\n", options.pnn));
		talloc_free(tmp_ctx);
		return ret;
	}

	for(i=0;i<nodemap->num;i++){
		if (nodemap->nodes[i].flags & NODE_FLAGS_INACTIVE) {
			continue;
		}
		if (nodemap->nodes[i].pnn == options.pnn) {
			continue;
		}

		/* read the public ip list from this node */
		ret = ctdb_ctrl_get_public_ips(ctdb, TIMELIMIT(), nodemap->nodes[i].pnn, tmp_ctx, &ips);
		if (ret != 0) {
			DEBUG(DEBUG_ERR, ("Unable to get public ip list from node %u\n", nodemap->nodes[i].pnn));
			return -1;
		}

		for (j=0;j<ips->num;j++) {
			if (ctdb_same_ip(addr, &ips->ips[j].addr)) {
				talloc_free(tmp_ctx);
				return nodemap->nodes[i].pnn;
			}
		}
		talloc_free(ips);
	}

	talloc_free(tmp_ctx);
	return -1;
}

static uint32_t ipreallocate_finished;

/*
  handler for receiving the response to ipreallocate
*/
static void ip_reallocate_handler(struct ctdb_context *ctdb, uint64_t srvid, 
			     TDB_DATA data, void *private_data)
{
	ipreallocate_finished = 1;
}

static void ctdb_every_second(struct event_context *ev, struct timed_event *te, struct timeval t, void *p)
{
	struct ctdb_context *ctdb = talloc_get_type(p, struct ctdb_context);

	event_add_timed(ctdb->ev, ctdb, 
				timeval_current_ofs(1, 0),
				ctdb_every_second, ctdb);
}

/*
  ask the recovery daemon on the recovery master to perform a ip reallocation
 */
static int control_ipreallocate(struct ctdb_context *ctdb, int argc, const char **argv)
{
	int i, ret;
	TDB_DATA data;
	struct takeover_run_reply rd;
	uint32_t recmaster;
	struct ctdb_node_map *nodemap=NULL;
	int retries=0;
	struct timeval tv = timeval_current();

	/* we need some events to trigger so we can timeout and restart
	   the loop
	*/
	event_add_timed(ctdb->ev, ctdb, 
				timeval_current_ofs(1, 0),
				ctdb_every_second, ctdb);

	rd.pnn = ctdb_ctrl_getpnn(ctdb, TIMELIMIT(), CTDB_CURRENT_NODE);
	if (rd.pnn == -1) {
		DEBUG(DEBUG_ERR, ("Failed to get pnn of local node\n"));
		return -1;
	}
	rd.srvid = getpid();

	/* register a message port for receiveing the reply so that we
	   can receive the reply
	*/
	ctdb_client_set_message_handler(ctdb, rd.srvid, ip_reallocate_handler, NULL);

	data.dptr = (uint8_t *)&rd;
	data.dsize = sizeof(rd);

again:
	/* check that there are valid nodes available */
	if (ctdb_ctrl_getnodemap(ctdb, TIMELIMIT(), options.pnn, ctdb, &nodemap) != 0) {
		DEBUG(DEBUG_ERR, ("Unable to get nodemap from local node\n"));
		return -1;
	}
	for (i=0; i<nodemap->num;i++) {
		if ((nodemap->nodes[i].flags & (NODE_FLAGS_DELETED|NODE_FLAGS_BANNED|NODE_FLAGS_STOPPED)) == 0) {
			break;
		}
	}
	if (i==nodemap->num) {
		DEBUG(DEBUG_ERR,("No recmaster available, no need to wait for cluster convergence\n"));
		return 0;
	}


	if (!ctdb_getrecmaster(ctdb_connection, options.pnn, &recmaster)) {
		DEBUG(DEBUG_ERR, ("Unable to get recmaster from node %u\n", options.pnn));
		return -1;
	}

	/* verify the node exists */
	if (ctdb_ctrl_getnodemap(ctdb, TIMELIMIT(), recmaster, ctdb, &nodemap) != 0) {
		DEBUG(DEBUG_ERR, ("Unable to get nodemap from local node\n"));
		return -1;
	}


	/* check tha there are nodes available that can act as a recmaster */
	for (i=0; i<nodemap->num; i++) {
		if (nodemap->nodes[i].flags & (NODE_FLAGS_DELETED|NODE_FLAGS_BANNED|NODE_FLAGS_STOPPED)) {
			continue;
		}
		break;
	}
	if (i == nodemap->num) {
		DEBUG(DEBUG_ERR,("No possible nodes to host addresses.\n"));
		return 0;
	}

	/* verify the recovery master is not STOPPED, nor BANNED */
	if (nodemap->nodes[recmaster].flags & (NODE_FLAGS_DELETED|NODE_FLAGS_BANNED|NODE_FLAGS_STOPPED)) {
		DEBUG(DEBUG_ERR,("No suitable recmaster found. Try again\n"));
		retries++;
		sleep(1);
		goto again;
	} 
	
	/* verify the recovery master is not STOPPED, nor BANNED */
	if (nodemap->nodes[recmaster].flags & (NODE_FLAGS_DELETED|NODE_FLAGS_BANNED|NODE_FLAGS_STOPPED)) {
		DEBUG(DEBUG_ERR,("No suitable recmaster found. Try again\n"));
		retries++;
		sleep(1);
		goto again;
	} 

	ipreallocate_finished = 0;
	ret = ctdb_client_send_message(ctdb, recmaster, CTDB_SRVID_TAKEOVER_RUN, data);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,("Failed to send ip takeover run request message to %u\n", options.pnn));
		return -1;
	}

	tv = timeval_current();
	/* this loop will terminate when we have received the reply */
	while (timeval_elapsed(&tv) < 5.0 && ipreallocate_finished == 0) {
		event_loop_once(ctdb->ev);
	}
	if (ipreallocate_finished == 1) {
		return 0;
	}

	retries++;
	sleep(1);
	goto again;

	return 0;
}


/*
  add a public ip address to a node
 */
static int control_addip(struct ctdb_context *ctdb, int argc, const char **argv)
{
	int i, ret;
	int len, retries = 0;
	unsigned mask;
	ctdb_sock_addr addr;
	struct ctdb_control_ip_iface *pub;
	TALLOC_CTX *tmp_ctx = talloc_new(ctdb);
	struct ctdb_all_public_ips *ips;


	if (argc != 2) {
		talloc_free(tmp_ctx);
		usage();
	}

	if (!parse_ip_mask(argv[0], argv[1], &addr, &mask)) {
		DEBUG(DEBUG_ERR, ("Badly formed ip/mask : %s\n", argv[0]));
		talloc_free(tmp_ctx);
		return -1;
	}

	/* read the public ip list from the node */
	ret = ctdb_ctrl_get_public_ips(ctdb, TIMELIMIT(), options.pnn, tmp_ctx, &ips);
	if (ret != 0) {
		DEBUG(DEBUG_ERR, ("Unable to get public ip list from node %u\n", options.pnn));
		talloc_free(tmp_ctx);
		return -1;
	}
	for (i=0;i<ips->num;i++) {
		if (ctdb_same_ip(&addr, &ips->ips[i].addr)) {
			DEBUG(DEBUG_ERR,("Can not add ip to node. Node already hosts this ip\n"));
			return 0;
		}
	}



	/* Dont timeout. This command waits for an ip reallocation
	   which sometimes can take wuite a while if there has
	   been a recent recovery
	*/
	alarm(0);

	len = offsetof(struct ctdb_control_ip_iface, iface) + strlen(argv[1]) + 1;
	pub = talloc_size(tmp_ctx, len); 
	CTDB_NO_MEMORY(ctdb, pub);

	pub->addr  = addr;
	pub->mask  = mask;
	pub->len   = strlen(argv[1])+1;
	memcpy(&pub->iface[0], argv[1], strlen(argv[1])+1);

	do {
		ret = ctdb_ctrl_add_public_ip(ctdb, TIMELIMIT(), options.pnn, pub);
		if (ret != 0) {
			DEBUG(DEBUG_ERR, ("Unable to add public ip to node %u. Wait 3 seconds and try again.\n", options.pnn));
			sleep(3);
			retries++;
		}
	} while (retries < 5 && ret != 0);
	if (ret != 0) {
		DEBUG(DEBUG_ERR, ("Unable to add public ip to node %u. Giving up.\n", options.pnn));
		talloc_free(tmp_ctx);
		return ret;
	}

	if (rebalance_node(ctdb, options.pnn) != 0) {
		DEBUG(DEBUG_ERR,("Error when trying to rebalance node\n"));
		return ret;
	}

	talloc_free(tmp_ctx);
	return 0;
}

/*
  add a public ip address to a node
 */
static int control_ipiface(struct ctdb_context *ctdb, int argc, const char **argv)
{
	ctdb_sock_addr addr;

	if (argc != 1) {
		usage();
	}

	if (!parse_ip(argv[0], NULL, 0, &addr)) {
		printf("Badly formed ip : %s\n", argv[0]);
		return -1;
	}

	printf("IP on interface %s\n", ctdb_sys_find_ifname(&addr));

	return 0;
}

static int control_delip(struct ctdb_context *ctdb, int argc, const char **argv);

static int control_delip_all(struct ctdb_context *ctdb, int argc, const char **argv, ctdb_sock_addr *addr)
{
	TALLOC_CTX *tmp_ctx = talloc_new(ctdb);
	struct ctdb_node_map *nodemap=NULL;
	struct ctdb_all_public_ips *ips;
	int ret, i, j;

	ret = ctdb_ctrl_getnodemap(ctdb, TIMELIMIT(), CTDB_CURRENT_NODE, tmp_ctx, &nodemap);
	if (ret != 0) {
		DEBUG(DEBUG_ERR, ("Unable to get nodemap from current node\n"));
		return ret;
	}

	/* remove it from the nodes that are not hosting the ip currently */
	for(i=0;i<nodemap->num;i++){
		if (nodemap->nodes[i].flags & NODE_FLAGS_INACTIVE) {
			continue;
		}
		if (ctdb_ctrl_get_public_ips(ctdb, TIMELIMIT(), nodemap->nodes[i].pnn, tmp_ctx, &ips) != 0) {
			DEBUG(DEBUG_ERR, ("Unable to get public ip list from node %d\n", nodemap->nodes[i].pnn));
			continue;
		}

		for (j=0;j<ips->num;j++) {
			if (ctdb_same_ip(addr, &ips->ips[j].addr)) {
				break;
			}
		}
		if (j==ips->num) {
			continue;
		}

		if (ips->ips[j].pnn == nodemap->nodes[i].pnn) {
			continue;
		}

		options.pnn = nodemap->nodes[i].pnn;
		control_delip(ctdb, argc, argv);
	}


	/* remove it from every node (also the one hosting it) */
	for(i=0;i<nodemap->num;i++){
		if (nodemap->nodes[i].flags & NODE_FLAGS_INACTIVE) {
			continue;
		}
		if (ctdb_ctrl_get_public_ips(ctdb, TIMELIMIT(), nodemap->nodes[i].pnn, tmp_ctx, &ips) != 0) {
			DEBUG(DEBUG_ERR, ("Unable to get public ip list from node %d\n", nodemap->nodes[i].pnn));
			continue;
		}

		for (j=0;j<ips->num;j++) {
			if (ctdb_same_ip(addr, &ips->ips[j].addr)) {
				break;
			}
		}
		if (j==ips->num) {
			continue;
		}

		options.pnn = nodemap->nodes[i].pnn;
		control_delip(ctdb, argc, argv);
	}

	talloc_free(tmp_ctx);
	return 0;
}
	
/*
  delete a public ip address from a node
 */
static int control_delip(struct ctdb_context *ctdb, int argc, const char **argv)
{
	int i, ret;
	int retries = 0;
	ctdb_sock_addr addr;
	struct ctdb_control_ip_iface pub;
	TALLOC_CTX *tmp_ctx = talloc_new(ctdb);
	struct ctdb_all_public_ips *ips;

	if (argc != 1) {
		talloc_free(tmp_ctx);
		usage();
	}

	if (parse_ip(argv[0], NULL, 0, &addr) == 0) {
		DEBUG(DEBUG_ERR,("Wrongly formed ip address '%s'\n", argv[0]));
		return -1;
	}

	if (options.pnn == CTDB_BROADCAST_ALL) {
		return control_delip_all(ctdb, argc, argv, &addr);
	}

	pub.addr  = addr;
	pub.mask  = 0;
	pub.len   = 0;

	ret = ctdb_ctrl_get_public_ips(ctdb, TIMELIMIT(), options.pnn, tmp_ctx, &ips);
	if (ret != 0) {
		DEBUG(DEBUG_ERR, ("Unable to get public ip list from cluster\n"));
		talloc_free(tmp_ctx);
		return ret;
	}
	
	for (i=0;i<ips->num;i++) {
		if (ctdb_same_ip(&addr, &ips->ips[i].addr)) {
			break;
		}
	}

	if (i==ips->num) {
		DEBUG(DEBUG_ERR, ("This node does not support this public address '%s'\n",
			ctdb_addr_to_str(&addr)));
		talloc_free(tmp_ctx);
		return -1;
	}

	if (ips->ips[i].pnn == options.pnn) {
		ret = find_other_host_for_public_ip(ctdb, &addr);
		if (ret != -1) {
			do {
				ret = move_ip(ctdb, &addr, ret);
				if (ret != 0) {
					DEBUG(DEBUG_ERR,("Failed to move ip to node %d. Wait 3 seconds and try again.\n", options.pnn));
					sleep(3);
					retries++;
				}
			} while (retries < 5 && ret != 0);
			if (ret != 0) {
				DEBUG(DEBUG_ERR,("Failed to move ip to node %d. Giving up.\n", options.pnn));
				return -1;
			}
		}
	}

	ret = ctdb_ctrl_del_public_ip(ctdb, TIMELIMIT(), options.pnn, &pub);
	if (ret != 0) {
		DEBUG(DEBUG_ERR, ("Unable to del public ip from node %u\n", options.pnn));
		talloc_free(tmp_ctx);
		return ret;
	}

	talloc_free(tmp_ctx);
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

	if (!parse_ip_port(argv[0], &killtcp.src_addr)) {
		DEBUG(DEBUG_ERR, ("Bad IP:port '%s'\n", argv[0]));
		return -1;
	}

	if (!parse_ip_port(argv[1], &killtcp.dst_addr)) {
		DEBUG(DEBUG_ERR, ("Bad IP:port '%s'\n", argv[1]));
		return -1;
	}

	ret = ctdb_ctrl_killtcp(ctdb, TIMELIMIT(), options.pnn, &killtcp);
	if (ret != 0) {
		DEBUG(DEBUG_ERR, ("Unable to killtcp from node %u\n", options.pnn));
		return ret;
	}

	return 0;
}


/*
  send a gratious arp
 */
static int control_gratious_arp(struct ctdb_context *ctdb, int argc, const char **argv)
{
	int ret;
	ctdb_sock_addr addr;

	if (argc < 2) {
		usage();
	}

	if (!parse_ip(argv[0], NULL, 0, &addr)) {
		DEBUG(DEBUG_ERR, ("Bad IP '%s'\n", argv[0]));
		return -1;
	}

	ret = ctdb_ctrl_gratious_arp(ctdb, TIMELIMIT(), options.pnn, &addr, argv[1]);
	if (ret != 0) {
		DEBUG(DEBUG_ERR, ("Unable to send gratious_arp from node %u\n", options.pnn));
		return ret;
	}

	return 0;
}

/*
  register a server id
 */
static int regsrvid(struct ctdb_context *ctdb, int argc, const char **argv)
{
	int ret;
	struct ctdb_server_id server_id;

	if (argc < 3) {
		usage();
	}

	server_id.pnn       = strtoul(argv[0], NULL, 0);
	server_id.type      = strtoul(argv[1], NULL, 0);
	server_id.server_id = strtoul(argv[2], NULL, 0);

	ret = ctdb_ctrl_register_server_id(ctdb, TIMELIMIT(), &server_id);
	if (ret != 0) {
		DEBUG(DEBUG_ERR, ("Unable to register server_id from node %u\n", options.pnn));
		return ret;
	}
	DEBUG(DEBUG_ERR,("Srvid registered. Sleeping for 999 seconds\n"));
	sleep(999);
	return -1;
}

/*
  unregister a server id
 */
static int unregsrvid(struct ctdb_context *ctdb, int argc, const char **argv)
{
	int ret;
	struct ctdb_server_id server_id;

	if (argc < 3) {
		usage();
	}

	server_id.pnn       = strtoul(argv[0], NULL, 0);
	server_id.type      = strtoul(argv[1], NULL, 0);
	server_id.server_id = strtoul(argv[2], NULL, 0);

	ret = ctdb_ctrl_unregister_server_id(ctdb, TIMELIMIT(), &server_id);
	if (ret != 0) {
		DEBUG(DEBUG_ERR, ("Unable to unregister server_id from node %u\n", options.pnn));
		return ret;
	}
	return -1;
}

/*
  check if a server id exists
 */
static int chksrvid(struct ctdb_context *ctdb, int argc, const char **argv)
{
	uint32_t status;
	int ret;
	struct ctdb_server_id server_id;

	if (argc < 3) {
		usage();
	}

	server_id.pnn       = strtoul(argv[0], NULL, 0);
	server_id.type      = strtoul(argv[1], NULL, 0);
	server_id.server_id = strtoul(argv[2], NULL, 0);

	ret = ctdb_ctrl_check_server_id(ctdb, TIMELIMIT(), options.pnn, &server_id, &status);
	if (ret != 0) {
		DEBUG(DEBUG_ERR, ("Unable to check server_id from node %u\n", options.pnn));
		return ret;
	}

	if (status) {
		printf("Server id %d:%d:%d EXISTS\n", server_id.pnn, server_id.type, server_id.server_id);
	} else {
		printf("Server id %d:%d:%d does NOT exist\n", server_id.pnn, server_id.type, server_id.server_id);
	}
	return 0;
}

/*
  get a list of all server ids that are registered on a node
 */
static int getsrvids(struct ctdb_context *ctdb, int argc, const char **argv)
{
	int i, ret;
	struct ctdb_server_id_list *server_ids;

	ret = ctdb_ctrl_get_server_id_list(ctdb, ctdb, TIMELIMIT(), options.pnn, &server_ids);
	if (ret != 0) {
		DEBUG(DEBUG_ERR, ("Unable to get server_id list from node %u\n", options.pnn));
		return ret;
	}

	for (i=0; i<server_ids->num; i++) {
		printf("Server id %d:%d:%d\n", 
			server_ids->server_ids[i].pnn, 
			server_ids->server_ids[i].type, 
			server_ids->server_ids[i].server_id); 
	}

	return -1;
}

/*
  check if a server id exists
 */
static int check_srvids(struct ctdb_context *ctdb, int argc, const char **argv)
{
	TALLOC_CTX *tmp_ctx = talloc_new(NULL);
	uint64_t *ids;
	uint8_t *result;
	int i;

	if (argc < 1) {
		talloc_free(tmp_ctx);
		usage();
	}

	ids    = talloc_array(tmp_ctx, uint64_t, argc);
	result = talloc_array(tmp_ctx, uint8_t, argc);

	for (i = 0; i < argc; i++) {
		ids[i] = strtoull(argv[i], NULL, 0);
	}

	if (!ctdb_check_message_handlers(ctdb_connection,
		options.pnn, argc, ids, result)) {
		DEBUG(DEBUG_ERR, ("Unable to check server_id from node %u\n",
				  options.pnn));
		talloc_free(tmp_ctx);
		return -1;
	}

	for (i=0; i < argc; i++) {
		printf("Server id %d:%llu %s\n", options.pnn, (long long)ids[i],
		       result[i] ? "exists" : "does not exist");
	}

	talloc_free(tmp_ctx);
	return 0;
}

/*
  send a tcp tickle ack
 */
static int tickle_tcp(struct ctdb_context *ctdb, int argc, const char **argv)
{
	int ret;
	ctdb_sock_addr	src, dst;

	if (argc < 2) {
		usage();
	}

	if (!parse_ip_port(argv[0], &src)) {
		DEBUG(DEBUG_ERR, ("Bad IP:port '%s'\n", argv[0]));
		return -1;
	}

	if (!parse_ip_port(argv[1], &dst)) {
		DEBUG(DEBUG_ERR, ("Bad IP:port '%s'\n", argv[1]));
		return -1;
	}

	ret = ctdb_sys_send_tcp(&src, &dst, 0, 0, 0);
	if (ret==0) {
		return 0;
	}
	DEBUG(DEBUG_ERR, ("Error while sending tickle ack\n"));

	return -1;
}


/*
  display public ip status
 */
static int control_ip(struct ctdb_context *ctdb, int argc, const char **argv)
{
	int i, ret;
	TALLOC_CTX *tmp_ctx = talloc_new(ctdb);
	struct ctdb_all_public_ips *ips;

	if (options.pnn == CTDB_BROADCAST_ALL) {
		/* read the list of public ips from all nodes */
		ret = control_get_all_public_ips(ctdb, tmp_ctx, &ips);
	} else {
		/* read the public ip list from this node */
		ret = ctdb_ctrl_get_public_ips(ctdb, TIMELIMIT(), options.pnn, tmp_ctx, &ips);
	}
	if (ret != 0) {
		DEBUG(DEBUG_ERR, ("Unable to get public ips from node %u\n", options.pnn));
		talloc_free(tmp_ctx);
		return ret;
	}

	if (options.machinereadable){
		printf(":Public IP:Node:");
		if (options.verbose){
			printf("ActiveInterface:AvailableInterfaces:ConfiguredInterfaces:");
		}
		printf("\n");
	} else {
		if (options.pnn == CTDB_BROADCAST_ALL) {
			printf("Public IPs on ALL nodes\n");
		} else {
			printf("Public IPs on node %u\n", options.pnn);
		}
	}

	for (i=1;i<=ips->num;i++) {
		struct ctdb_control_public_ip_info *info = NULL;
		int32_t pnn;
		char *aciface = NULL;
		char *avifaces = NULL;
		char *cifaces = NULL;

		if (options.pnn == CTDB_BROADCAST_ALL) {
			pnn = ips->ips[ips->num-i].pnn;
		} else {
			pnn = options.pnn;
		}

		if (pnn != -1) {
			ret = ctdb_ctrl_get_public_ip_info(ctdb, TIMELIMIT(), pnn, ctdb,
						   &ips->ips[ips->num-i].addr, &info);
		} else {
			ret = -1;
		}

		if (ret == 0) {
			int j;
			for (j=0; j < info->num; j++) {
				if (cifaces == NULL) {
					cifaces = talloc_strdup(info,
								info->ifaces[j].name);
				} else {
					cifaces = talloc_asprintf_append(cifaces,
									 ",%s",
									 info->ifaces[j].name);
				}

				if (info->active_idx == j) {
					aciface = info->ifaces[j].name;
				}

				if (info->ifaces[j].link_state == 0) {
					continue;
				}

				if (avifaces == NULL) {
					avifaces = talloc_strdup(info, info->ifaces[j].name);
				} else {
					avifaces = talloc_asprintf_append(avifaces,
									  ",%s",
									  info->ifaces[j].name);
				}
			}
		}

		if (options.machinereadable){
			printf(":%s:%d:",
				ctdb_addr_to_str(&ips->ips[ips->num-i].addr),
				ips->ips[ips->num-i].pnn);
			if (options.verbose){
				printf("%s:%s:%s:",
					aciface?aciface:"",
					avifaces?avifaces:"",
					cifaces?cifaces:"");
			}
			printf("\n");
		} else {
			if (options.verbose) {
				printf("%s node[%d] active[%s] available[%s] configured[%s]\n",
					ctdb_addr_to_str(&ips->ips[ips->num-i].addr),
					ips->ips[ips->num-i].pnn,
					aciface?aciface:"",
					avifaces?avifaces:"",
					cifaces?cifaces:"");
			} else {
				printf("%s %d\n",
					ctdb_addr_to_str(&ips->ips[ips->num-i].addr),
					ips->ips[ips->num-i].pnn);
			}
		}
		talloc_free(info);
	}

	talloc_free(tmp_ctx);
	return 0;
}

/*
  public ip info
 */
static int control_ipinfo(struct ctdb_context *ctdb, int argc, const char **argv)
{
	int i, ret;
	ctdb_sock_addr addr;
	TALLOC_CTX *tmp_ctx = talloc_new(ctdb);
	struct ctdb_control_public_ip_info *info;

	if (argc != 1) {
		talloc_free(tmp_ctx);
		usage();
	}

	if (parse_ip(argv[0], NULL, 0, &addr) == 0) {
		DEBUG(DEBUG_ERR,("Wrongly formed ip address '%s'\n", argv[0]));
		return -1;
	}

	/* read the public ip info from this node */
	ret = ctdb_ctrl_get_public_ip_info(ctdb, TIMELIMIT(), options.pnn,
					   tmp_ctx, &addr, &info);
	if (ret != 0) {
		DEBUG(DEBUG_ERR, ("Unable to get public ip[%s]info from node %u\n",
				  argv[0], options.pnn));
		talloc_free(tmp_ctx);
		return ret;
	}

	printf("Public IP[%s] info on node %u\n",
	       ctdb_addr_to_str(&info->ip.addr),
	       options.pnn);

	printf("IP:%s\nCurrentNode:%d\nNumInterfaces:%u\n",
	       ctdb_addr_to_str(&info->ip.addr),
	       info->ip.pnn, info->num);

	for (i=0; i<info->num; i++) {
		info->ifaces[i].name[CTDB_IFACE_SIZE] = '\0';

		printf("Interface[%u]: Name:%s Link:%s References:%u%s\n",
		       i+1, info->ifaces[i].name,
		       info->ifaces[i].link_state?"up":"down",
		       (unsigned int)info->ifaces[i].references,
		       (i==info->active_idx)?" (active)":"");
	}

	talloc_free(tmp_ctx);
	return 0;
}

/*
  display interfaces status
 */
static int control_ifaces(struct ctdb_context *ctdb, int argc, const char **argv)
{
	int i;
	struct ctdb_ifaces_list *ifaces;

	/* read the public ip list from this node */
	if (!ctdb_getifaces(ctdb_connection, options.pnn, &ifaces)) {
		DEBUG(DEBUG_ERR, ("Unable to get interfaces from node %u\n",
				  options.pnn));
		return -1;
	}

	if (options.machinereadable){
		printf(":Name:LinkStatus:References:\n");
	} else {
		printf("Interfaces on node %u\n", options.pnn);
	}

	for (i=0; i<ifaces->num; i++) {
		if (options.machinereadable){
			printf(":%s:%s:%u\n",
			       ifaces->ifaces[i].name,
			       ifaces->ifaces[i].link_state?"1":"0",
			       (unsigned int)ifaces->ifaces[i].references);
		} else {
			printf("name:%s link:%s references:%u\n",
			       ifaces->ifaces[i].name,
			       ifaces->ifaces[i].link_state?"up":"down",
			       (unsigned int)ifaces->ifaces[i].references);
		}
	}

	ctdb_free_ifaces(ifaces);
	return 0;
}


/*
  set link status of an interface
 */
static int control_setifacelink(struct ctdb_context *ctdb, int argc, const char **argv)
{
	int ret;
	TALLOC_CTX *tmp_ctx = talloc_new(ctdb);
	struct ctdb_control_iface_info info;

	ZERO_STRUCT(info);

	if (argc != 2) {
		usage();
	}

	if (strlen(argv[0]) > CTDB_IFACE_SIZE) {
		DEBUG(DEBUG_ERR, ("interfaces name '%s' too long\n",
				  argv[0]));
		talloc_free(tmp_ctx);
		return -1;
	}
	strcpy(info.name, argv[0]);

	if (strcmp(argv[1], "up") == 0) {
		info.link_state = 1;
	} else if (strcmp(argv[1], "down") == 0) {
		info.link_state = 0;
	} else {
		DEBUG(DEBUG_ERR, ("link state invalid '%s' should be 'up' or 'down'\n",
				  argv[1]));
		talloc_free(tmp_ctx);
		return -1;
	}

	/* read the public ip list from this node */
	ret = ctdb_ctrl_set_iface_link(ctdb, TIMELIMIT(), options.pnn,
				   tmp_ctx, &info);
	if (ret != 0) {
		DEBUG(DEBUG_ERR, ("Unable to set link state for interfaces %s node %u\n",
				  argv[0], options.pnn));
		talloc_free(tmp_ctx);
		return ret;
	}

	talloc_free(tmp_ctx);
	return 0;
}

/*
  display pid of a ctdb daemon
 */
static int control_getpid(struct ctdb_context *ctdb, int argc, const char **argv)
{
	uint32_t pid;
	int ret;

	ret = ctdb_ctrl_getpid(ctdb, TIMELIMIT(), options.pnn, &pid);
	if (ret != 0) {
		DEBUG(DEBUG_ERR, ("Unable to get daemon pid from node %u\n", options.pnn));
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
	struct ctdb_node_map *nodemap=NULL;

	/* check if the node is already disabled */
	if (ctdb_ctrl_getnodemap(ctdb, TIMELIMIT(), CTDB_CURRENT_NODE, ctdb, &nodemap) != 0) {
		DEBUG(DEBUG_ERR, ("Unable to get nodemap from local node\n"));
		exit(10);
	}
	if (nodemap->nodes[options.pnn].flags & NODE_FLAGS_PERMANENTLY_DISABLED) {
		DEBUG(DEBUG_ERR,("Node %d is already disabled.\n", options.pnn));
		return 0;
	}

	do {
		ret = ctdb_ctrl_modflags(ctdb, TIMELIMIT(), options.pnn, NODE_FLAGS_PERMANENTLY_DISABLED, 0);
		if (ret != 0) {
			DEBUG(DEBUG_ERR, ("Unable to disable node %u\n", options.pnn));
			return ret;
		}

		sleep(1);

		/* read the nodemap and verify the change took effect */
		if (ctdb_ctrl_getnodemap(ctdb, TIMELIMIT(), CTDB_CURRENT_NODE, ctdb, &nodemap) != 0) {
			DEBUG(DEBUG_ERR, ("Unable to get nodemap from local node\n"));
			exit(10);
		}

	} while (!(nodemap->nodes[options.pnn].flags & NODE_FLAGS_PERMANENTLY_DISABLED));
	ret = control_ipreallocate(ctdb, argc, argv);
	if (ret != 0) {
		DEBUG(DEBUG_ERR, ("IP Reallocate failed on node %u\n", options.pnn));
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

	struct ctdb_node_map *nodemap=NULL;


	/* check if the node is already enabled */
	if (ctdb_ctrl_getnodemap(ctdb, TIMELIMIT(), CTDB_CURRENT_NODE, ctdb, &nodemap) != 0) {
		DEBUG(DEBUG_ERR, ("Unable to get nodemap from local node\n"));
		exit(10);
	}
	if (!(nodemap->nodes[options.pnn].flags & NODE_FLAGS_PERMANENTLY_DISABLED)) {
		DEBUG(DEBUG_ERR,("Node %d is already enabled.\n", options.pnn));
		return 0;
	}

	do {
		ret = ctdb_ctrl_modflags(ctdb, TIMELIMIT(), options.pnn, 0, NODE_FLAGS_PERMANENTLY_DISABLED);
		if (ret != 0) {
			DEBUG(DEBUG_ERR, ("Unable to enable node %u\n", options.pnn));
			return ret;
		}

		sleep(1);

		/* read the nodemap and verify the change took effect */
		if (ctdb_ctrl_getnodemap(ctdb, TIMELIMIT(), CTDB_CURRENT_NODE, ctdb, &nodemap) != 0) {
			DEBUG(DEBUG_ERR, ("Unable to get nodemap from local node\n"));
			exit(10);
		}

	} while (nodemap->nodes[options.pnn].flags & NODE_FLAGS_PERMANENTLY_DISABLED);

	ret = control_ipreallocate(ctdb, argc, argv);
	if (ret != 0) {
		DEBUG(DEBUG_ERR, ("IP Reallocate failed on node %u\n", options.pnn));
		return ret;
	}

	return 0;
}

/*
  stop a remote node
 */
static int control_stop(struct ctdb_context *ctdb, int argc, const char **argv)
{
	int ret;
	struct ctdb_node_map *nodemap=NULL;

	do {
		ret = ctdb_ctrl_stop_node(ctdb, TIMELIMIT(), options.pnn);
		if (ret != 0) {
			DEBUG(DEBUG_ERR, ("Unable to stop node %u   try again\n", options.pnn));
		}
	
		sleep(1);

		/* read the nodemap and verify the change took effect */
		if (ctdb_ctrl_getnodemap(ctdb, TIMELIMIT(), CTDB_CURRENT_NODE, ctdb, &nodemap) != 0) {
			DEBUG(DEBUG_ERR, ("Unable to get nodemap from local node\n"));
			exit(10);
		}

	} while (!(nodemap->nodes[options.pnn].flags & NODE_FLAGS_STOPPED));
	ret = control_ipreallocate(ctdb, argc, argv);
	if (ret != 0) {
		DEBUG(DEBUG_ERR, ("IP Reallocate failed on node %u\n", options.pnn));
		return ret;
	}

	return 0;
}

/*
  restart a stopped remote node
 */
static int control_continue(struct ctdb_context *ctdb, int argc, const char **argv)
{
	int ret;

	struct ctdb_node_map *nodemap=NULL;

	do {
		ret = ctdb_ctrl_continue_node(ctdb, TIMELIMIT(), options.pnn);
		if (ret != 0) {
			DEBUG(DEBUG_ERR, ("Unable to continue node %u\n", options.pnn));
			return ret;
		}
	
		sleep(1);

		/* read the nodemap and verify the change took effect */
		if (ctdb_ctrl_getnodemap(ctdb, TIMELIMIT(), CTDB_CURRENT_NODE, ctdb, &nodemap) != 0) {
			DEBUG(DEBUG_ERR, ("Unable to get nodemap from local node\n"));
			exit(10);
		}

	} while (nodemap->nodes[options.pnn].flags & NODE_FLAGS_STOPPED);
	ret = control_ipreallocate(ctdb, argc, argv);
	if (ret != 0) {
		DEBUG(DEBUG_ERR, ("IP Reallocate failed on node %u\n", options.pnn));
		return ret;
	}

	return 0;
}

static uint32_t get_generation(struct ctdb_context *ctdb)
{
	struct ctdb_vnn_map *vnnmap=NULL;
	int ret;

	/* wait until the recmaster is not in recovery mode */
	while (1) {
		uint32_t recmode, recmaster;
		
		if (vnnmap != NULL) {
			talloc_free(vnnmap);
			vnnmap = NULL;
		}

		/* get the recmaster */
		if (!ctdb_getrecmaster(ctdb_connection, CTDB_CURRENT_NODE, &recmaster)) {
			DEBUG(DEBUG_ERR, ("Unable to get recmaster from node %u\n", options.pnn));
			exit(10);
		}

		/* get recovery mode */
		if (!ctdb_getrecmode(ctdb_connection, recmaster, &recmode)) {
			DEBUG(DEBUG_ERR, ("Unable to get recmode from node %u\n", options.pnn));
			exit(10);
		}

		/* get the current generation number */
		ret = ctdb_ctrl_getvnnmap(ctdb, TIMELIMIT(), recmaster, ctdb, &vnnmap);
		if (ret != 0) {
			DEBUG(DEBUG_ERR, ("Unable to get vnnmap from recmaster (%u)\n", recmaster));
			exit(10);
		}

		if ((recmode == CTDB_RECOVERY_NORMAL)
		&&  (vnnmap->generation != 1)){
			return vnnmap->generation;
		}
		sleep(1);
	}
}

/*
  ban a node from the cluster
 */
static int control_ban(struct ctdb_context *ctdb, int argc, const char **argv)
{
	int ret;
	struct ctdb_node_map *nodemap=NULL;
	struct ctdb_ban_time bantime;

	if (argc < 1) {
		usage();
	}
	
	/* verify the node exists */
	ret = ctdb_ctrl_getnodemap(ctdb, TIMELIMIT(), CTDB_CURRENT_NODE, ctdb, &nodemap);
	if (ret != 0) {
		DEBUG(DEBUG_ERR, ("Unable to get nodemap from local node\n"));
		return ret;
	}

	if (nodemap->nodes[options.pnn].flags & NODE_FLAGS_BANNED) {
		DEBUG(DEBUG_ERR,("Node %u is already banned.\n", options.pnn));
		return -1;
	}

	bantime.pnn  = options.pnn;
	bantime.time = strtoul(argv[0], NULL, 0);

	ret = ctdb_ctrl_set_ban(ctdb, TIMELIMIT(), options.pnn, &bantime);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,("Banning node %d for %d seconds failed.\n", bantime.pnn, bantime.time));
		return -1;
	}	

	ret = control_ipreallocate(ctdb, argc, argv);
	if (ret != 0) {
		DEBUG(DEBUG_ERR, ("IP Reallocate failed on node %u\n", options.pnn));
		return ret;
	}

	return 0;
}


/*
  unban a node from the cluster
 */
static int control_unban(struct ctdb_context *ctdb, int argc, const char **argv)
{
	int ret;
	struct ctdb_node_map *nodemap=NULL;
	struct ctdb_ban_time bantime;

	/* verify the node exists */
	ret = ctdb_ctrl_getnodemap(ctdb, TIMELIMIT(), CTDB_CURRENT_NODE, ctdb, &nodemap);
	if (ret != 0) {
		DEBUG(DEBUG_ERR, ("Unable to get nodemap from local node\n"));
		return ret;
	}

	if (!(nodemap->nodes[options.pnn].flags & NODE_FLAGS_BANNED)) {
		DEBUG(DEBUG_ERR,("Node %u is not banned.\n", options.pnn));
		return -1;
	}

	bantime.pnn  = options.pnn;
	bantime.time = 0;

	ret = ctdb_ctrl_set_ban(ctdb, TIMELIMIT(), options.pnn, &bantime);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,("Unbanning node %d failed.\n", bantime.pnn));
		return -1;
	}	

	ret = control_ipreallocate(ctdb, argc, argv);
	if (ret != 0) {
		DEBUG(DEBUG_ERR, ("IP Reallocate failed on node %u\n", options.pnn));
		return ret;
	}

	return 0;
}


/*
  show ban information for a node
 */
static int control_showban(struct ctdb_context *ctdb, int argc, const char **argv)
{
	int ret;
	struct ctdb_node_map *nodemap=NULL;
	struct ctdb_ban_time *bantime;

	/* verify the node exists */
	ret = ctdb_ctrl_getnodemap(ctdb, TIMELIMIT(), CTDB_CURRENT_NODE, ctdb, &nodemap);
	if (ret != 0) {
		DEBUG(DEBUG_ERR, ("Unable to get nodemap from local node\n"));
		return ret;
	}

	ret = ctdb_ctrl_get_ban(ctdb, TIMELIMIT(), options.pnn, ctdb, &bantime);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,("Showing ban info for node %d failed.\n", options.pnn));
		return -1;
	}	

	if (bantime->time == 0) {
		printf("Node %u is not banned\n", bantime->pnn);
	} else {
		printf("Node %u is banned banned for %d seconds\n", bantime->pnn, bantime->time);
	}

	return 0;
}

/*
  shutdown a daemon
 */
static int control_shutdown(struct ctdb_context *ctdb, int argc, const char **argv)
{
	int ret;

	ret = ctdb_ctrl_shutdown(ctdb, TIMELIMIT(), options.pnn);
	if (ret != 0) {
		DEBUG(DEBUG_ERR, ("Unable to shutdown node %u\n", options.pnn));
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
	uint32_t generation, next_generation;

	/* record the current generation number */
	generation = get_generation(ctdb);

	ret = ctdb_ctrl_freeze_priority(ctdb, TIMELIMIT(), options.pnn, 1);
	if (ret != 0) {
		DEBUG(DEBUG_ERR, ("Unable to freeze node\n"));
		return ret;
	}

	ret = ctdb_ctrl_setrecmode(ctdb, TIMELIMIT(), options.pnn, CTDB_RECOVERY_ACTIVE);
	if (ret != 0) {
		DEBUG(DEBUG_ERR, ("Unable to set recovery mode\n"));
		return ret;
	}

	/* wait until we are in a new generation */
	while (1) {
		next_generation = get_generation(ctdb);
		if (next_generation != generation) {
			return 0;
		}
		sleep(1);
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

	ret = ctdb_ctrl_getmonmode(ctdb, TIMELIMIT(), options.pnn, &monmode);
	if (ret != 0) {
		DEBUG(DEBUG_ERR, ("Unable to get monmode from node %u\n", options.pnn));
		return ret;
	}
	if (!options.machinereadable){
		printf("Monitoring mode:%s (%d)\n",monmode==CTDB_MONITORING_ACTIVE?"ACTIVE":"DISABLED",monmode);
	} else {
		printf(":mode:\n");
		printf(":%d:\n",monmode);
	}
	return 0;
}


/*
  display capabilities of a remote node
 */
static int control_getcapabilities(struct ctdb_context *ctdb, int argc, const char **argv)
{
	uint32_t capabilities;

	if (!ctdb_getcapabilities(ctdb_connection, options.pnn, &capabilities)) {
		DEBUG(DEBUG_ERR, ("Unable to get capabilities from node %u\n", options.pnn));
		return -1;
	}
	
	if (!options.machinereadable){
		printf("RECMASTER: %s\n", (capabilities&CTDB_CAP_RECMASTER)?"YES":"NO");
		printf("LMASTER: %s\n", (capabilities&CTDB_CAP_LMASTER)?"YES":"NO");
		printf("LVS: %s\n", (capabilities&CTDB_CAP_LVS)?"YES":"NO");
		printf("NATGW: %s\n", (capabilities&CTDB_CAP_NATGW)?"YES":"NO");
	} else {
		printf(":RECMASTER:LMASTER:LVS:NATGW:\n");
		printf(":%d:%d:%d:%d:\n",
			!!(capabilities&CTDB_CAP_RECMASTER),
			!!(capabilities&CTDB_CAP_LMASTER),
			!!(capabilities&CTDB_CAP_LVS),
			!!(capabilities&CTDB_CAP_NATGW));
	}
	return 0;
}

/*
  display lvs configuration
 */
static int control_lvs(struct ctdb_context *ctdb, int argc, const char **argv)
{
	uint32_t *capabilities;
	struct ctdb_node_map *nodemap=NULL;
	int i, ret;
	int healthy_count = 0;

	if (!ctdb_getnodemap(ctdb_connection, options.pnn, &nodemap)) {
		DEBUG(DEBUG_ERR, ("Unable to get nodemap from node %u\n", options.pnn));
		return -1;
	}

	capabilities = talloc_array(ctdb, uint32_t, nodemap->num);
	CTDB_NO_MEMORY(ctdb, capabilities);
	
	ret = 0;

	/* collect capabilities for all connected nodes */
	for (i=0; i<nodemap->num; i++) {
		if (nodemap->nodes[i].flags & NODE_FLAGS_INACTIVE) {
			continue;
		}
		if (nodemap->nodes[i].flags & NODE_FLAGS_PERMANENTLY_DISABLED) {
			continue;
		}
	
		if (!ctdb_getcapabilities(ctdb_connection, i, &capabilities[i])) {
			DEBUG(DEBUG_ERR, ("Unable to get capabilities from node %u\n", i));
			ret = -1;
			goto done;
		}

		if (!(capabilities[i] & CTDB_CAP_LVS)) {
			continue;
		}

		if (!(nodemap->nodes[i].flags & NODE_FLAGS_UNHEALTHY)) {
			healthy_count++;
		}
	}

	/* Print all LVS nodes */
	for (i=0; i<nodemap->num; i++) {
		if (nodemap->nodes[i].flags & NODE_FLAGS_INACTIVE) {
			continue;
		}
		if (nodemap->nodes[i].flags & NODE_FLAGS_PERMANENTLY_DISABLED) {
			continue;
		}
		if (!(capabilities[i] & CTDB_CAP_LVS)) {
			continue;
		}

		if (healthy_count != 0) {
			if (nodemap->nodes[i].flags & NODE_FLAGS_UNHEALTHY) {
				continue;
			}
		}

		printf("%d:%s\n", i, 
			ctdb_addr_to_str(&nodemap->nodes[i].addr));
	}

done:
	ctdb_free_nodemap(nodemap);
	return ret;
}

/*
  display who is the lvs master
 */
static int control_lvsmaster(struct ctdb_context *ctdb, int argc, const char **argv)
{
	uint32_t *capabilities;
	struct ctdb_node_map *nodemap=NULL;
	int i, ret;
	int healthy_count = 0;

	if (!ctdb_getnodemap(ctdb_connection, options.pnn, &nodemap)) {
		DEBUG(DEBUG_ERR, ("Unable to get nodemap from node %u\n", options.pnn));
		return -1;
	}

	capabilities = talloc_array(ctdb, uint32_t, nodemap->num);
	CTDB_NO_MEMORY(ctdb, capabilities);

	ret = -1;
	
	/* collect capabilities for all connected nodes */
	for (i=0; i<nodemap->num; i++) {
		if (nodemap->nodes[i].flags & NODE_FLAGS_INACTIVE) {
			continue;
		}
		if (nodemap->nodes[i].flags & NODE_FLAGS_PERMANENTLY_DISABLED) {
			continue;
		}
	
		if (!ctdb_getcapabilities(ctdb_connection, i, &capabilities[i])) {
			DEBUG(DEBUG_ERR, ("Unable to get capabilities from node %u\n", i));
			ret = -1;
			goto done;
		}

		if (!(capabilities[i] & CTDB_CAP_LVS)) {
			continue;
		}

		if (!(nodemap->nodes[i].flags & NODE_FLAGS_UNHEALTHY)) {
			healthy_count++;
		}
	}

	/* find and show the lvsmaster */
	for (i=0; i<nodemap->num; i++) {
		if (nodemap->nodes[i].flags & NODE_FLAGS_INACTIVE) {
			continue;
		}
		if (nodemap->nodes[i].flags & NODE_FLAGS_PERMANENTLY_DISABLED) {
			continue;
		}
		if (!(capabilities[i] & CTDB_CAP_LVS)) {
			continue;
		}

		if (healthy_count != 0) {
			if (nodemap->nodes[i].flags & NODE_FLAGS_UNHEALTHY) {
				continue;
			}
		}

		if (options.machinereadable){
			printf("%d\n", i);
		} else {
			printf("Node %d is LVS master\n", i);
		}
		ret = 0;
		goto done;
	}

	printf("There is no LVS master\n");
done:
	ctdb_free_nodemap(nodemap);
	return ret;
}

/*
  disable monitoring on a  node
 */
static int control_disable_monmode(struct ctdb_context *ctdb, int argc, const char **argv)
{
	
	int ret;

	ret = ctdb_ctrl_disable_monmode(ctdb, TIMELIMIT(), options.pnn);
	if (ret != 0) {
		DEBUG(DEBUG_ERR, ("Unable to disable monmode on node %u\n", options.pnn));
		return ret;
	}
	printf("Monitoring mode:%s\n","DISABLED");

	return 0;
}

/*
  enable monitoring on a  node
 */
static int control_enable_monmode(struct ctdb_context *ctdb, int argc, const char **argv)
{
	
	int ret;

	ret = ctdb_ctrl_enable_monmode(ctdb, TIMELIMIT(), options.pnn);
	if (ret != 0) {
		DEBUG(DEBUG_ERR, ("Unable to enable monmode on node %u\n", options.pnn));
		return ret;
	}
	printf("Monitoring mode:%s\n","ACTIVE");

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
	bool persistent;
	struct ctdb_dump_db_context c;

	if (argc < 1) {
		usage();
	}

	db_name = argv[0];


	if (db_exists(ctdb, db_name, &persistent)) {
		DEBUG(DEBUG_ERR,("Database '%s' does not exist\n", db_name));
		return -1;
	}

	ctdb_db = ctdb_attach(ctdb, TIMELIMIT(), db_name, persistent, 0);

	if (ctdb_db == NULL) {
		DEBUG(DEBUG_ERR,("Unable to attach to database '%s'\n", db_name));
		return -1;
	}

	if (options.printlmaster) {
		ret = ctdb_ctrl_getvnnmap(ctdb, TIMELIMIT(), options.pnn,
					  ctdb, &ctdb->vnn_map);
		if (ret != 0) {
			DEBUG(DEBUG_ERR, ("Unable to get vnnmap from node %u\n",
					  options.pnn));
			return ret;
		}
	}

	ZERO_STRUCT(c);
	c.f = stdout;
	c.printemptyrecords = (bool)options.printemptyrecords;
	c.printdatasize = (bool)options.printdatasize;
	c.printlmaster = (bool)options.printlmaster;
	c.printhash = (bool)options.printhash;
	c.printrecordflags = (bool)options.printrecordflags;

	/* traverse and dump the cluster tdb */
	ret = ctdb_dump_db(ctdb_db, &c);
	if (ret == -1) {
		DEBUG(DEBUG_ERR, ("Unable to dump database\n"));
		DEBUG(DEBUG_ERR, ("Maybe try 'ctdb getdbstatus %s'"
				  " and 'ctdb getvar AllowUnhealthyDBRead'\n",
				  db_name));
		return -1;
	}
	talloc_free(ctdb_db);

	printf("Dumped %d records\n", ret);
	return 0;
}

struct cattdb_data {
	struct ctdb_context *ctdb;
	uint32_t count;
};

static int cattdb_traverse(struct tdb_context *tdb, TDB_DATA key, TDB_DATA data, void *private_data)
{
	struct cattdb_data *d = private_data;
	struct ctdb_dump_db_context c;

	d->count++;

	ZERO_STRUCT(c);
	c.f = stdout;
	c.printemptyrecords = (bool)options.printemptyrecords;
	c.printdatasize = (bool)options.printdatasize;
	c.printlmaster = false;
	c.printhash = (bool)options.printhash;
	c.printrecordflags = true;

	return ctdb_dumpdb_record(d->ctdb, key, data, &c);
}

/*
  cat the local tdb database using same format as catdb
 */
static int control_cattdb(struct ctdb_context *ctdb, int argc, const char **argv)
{
	const char *db_name;
	struct ctdb_db_context *ctdb_db;
	struct cattdb_data d;
	bool persistent;

	if (argc < 1) {
		usage();
	}

	db_name = argv[0];


	if (db_exists(ctdb, db_name, &persistent)) {
		DEBUG(DEBUG_ERR,("Database '%s' does not exist\n", db_name));
		return -1;
	}

	ctdb_db = ctdb_attach(ctdb, TIMELIMIT(), db_name, persistent, 0);

	if (ctdb_db == NULL) {
		DEBUG(DEBUG_ERR,("Unable to attach to database '%s'\n", db_name));
		return -1;
	}

	/* traverse the local tdb */
	d.count = 0;
	d.ctdb  = ctdb;
	if (tdb_traverse_read(ctdb_db->ltdb->tdb, cattdb_traverse, &d) == -1) {
		printf("Failed to cattdb data\n");
		exit(10);
	}
	talloc_free(ctdb_db);

	printf("Dumped %d records\n", d.count);
	return 0;
}

/*
  display the content of a database key
 */
static int control_readkey(struct ctdb_context *ctdb, int argc, const char **argv)
{
	const char *db_name;
	struct ctdb_db_context *ctdb_db;
	struct ctdb_record_handle *h;
	TALLOC_CTX *tmp_ctx = talloc_new(ctdb);
	TDB_DATA key, data;
	bool persistent;

	if (argc < 2) {
		usage();
	}

	db_name = argv[0];

	if (db_exists(ctdb, db_name, &persistent)) {
		DEBUG(DEBUG_ERR,("Database '%s' does not exist\n", db_name));
		return -1;
	}

	ctdb_db = ctdb_attach(ctdb, TIMELIMIT(), db_name, persistent, 0);

	if (ctdb_db == NULL) {
		DEBUG(DEBUG_ERR,("Unable to attach to database '%s'\n", db_name));
		return -1;
	}

	key.dptr  = discard_const(argv[1]);
	key.dsize = strlen((char *)key.dptr);

	h = ctdb_fetch_lock(ctdb_db, tmp_ctx, key, &data);
	if (h == NULL) {
		printf("Failed to fetch record '%s' on node %d\n", 
	       		(const char *)key.dptr, ctdb_get_pnn(ctdb));
		talloc_free(tmp_ctx);
		exit(10);
	}

	printf("Data: size:%d ptr:[%s]\n", (int)data.dsize, data.dptr);

	talloc_free(ctdb_db);
	talloc_free(tmp_ctx);
	return 0;
}

/*
  display the content of a database key
 */
static int control_writekey(struct ctdb_context *ctdb, int argc, const char **argv)
{
	const char *db_name;
	struct ctdb_db_context *ctdb_db;
	struct ctdb_record_handle *h;
	TALLOC_CTX *tmp_ctx = talloc_new(ctdb);
	TDB_DATA key, data;
	bool persistent;

	if (argc < 3) {
		usage();
	}

	db_name = argv[0];

	if (db_exists(ctdb, db_name, &persistent)) {
		DEBUG(DEBUG_ERR,("Database '%s' does not exist\n", db_name));
		return -1;
	}

	ctdb_db = ctdb_attach(ctdb, TIMELIMIT(), db_name, persistent, 0);

	if (ctdb_db == NULL) {
		DEBUG(DEBUG_ERR,("Unable to attach to database '%s'\n", db_name));
		return -1;
	}

	key.dptr  = discard_const(argv[1]);
	key.dsize = strlen((char *)key.dptr);

	h = ctdb_fetch_lock(ctdb_db, tmp_ctx, key, &data);
	if (h == NULL) {
		printf("Failed to fetch record '%s' on node %d\n", 
	       		(const char *)key.dptr, ctdb_get_pnn(ctdb));
		talloc_free(tmp_ctx);
		exit(10);
	}

	data.dptr  = discard_const(argv[2]);
	data.dsize = strlen((char *)data.dptr);

	if (ctdb_record_store(h, data) != 0) {
		printf("Failed to store record\n");
	}

	talloc_free(h);
	talloc_free(ctdb_db);
	talloc_free(tmp_ctx);
	return 0;
}

/*
  fetch a record from a persistent database
 */
static int control_pfetch(struct ctdb_context *ctdb, int argc, const char **argv)
{
	const char *db_name;
	struct ctdb_db_context *ctdb_db;
	TALLOC_CTX *tmp_ctx = talloc_new(ctdb);
	struct ctdb_transaction_handle *h;
	TDB_DATA key, data;
	int fd, ret;
	bool persistent;

	if (argc < 2) {
		talloc_free(tmp_ctx);
		usage();
	}

	db_name = argv[0];


	if (db_exists(ctdb, db_name, &persistent)) {
		DEBUG(DEBUG_ERR,("Database '%s' does not exist\n", db_name));
		talloc_free(tmp_ctx);
		return -1;
	}

	if (!persistent) {
		DEBUG(DEBUG_ERR,("Database '%s' is not persistent\n", db_name));
		talloc_free(tmp_ctx);
		return -1;
	}

	ctdb_db = ctdb_attach(ctdb, TIMELIMIT(), db_name, persistent, 0);

	if (ctdb_db == NULL) {
		DEBUG(DEBUG_ERR,("Unable to attach to database '%s'\n", db_name));
		talloc_free(tmp_ctx);
		return -1;
	}

	h = ctdb_transaction_start(ctdb_db, tmp_ctx);
	if (h == NULL) {
		DEBUG(DEBUG_ERR,("Failed to start transaction on database %s\n", db_name));
		talloc_free(tmp_ctx);
		return -1;
	}

	key.dptr  = discard_const(argv[1]);
	key.dsize = strlen(argv[1]);
	ret = ctdb_transaction_fetch(h, tmp_ctx, key, &data);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,("Failed to fetch record\n"));
		talloc_free(tmp_ctx);
		return -1;
	}

	if (data.dsize == 0 || data.dptr == NULL) {
		DEBUG(DEBUG_ERR,("Record is empty\n"));
		talloc_free(tmp_ctx);
		return -1;
	}

	if (argc == 3) {
	  fd = open(argv[2], O_WRONLY|O_CREAT|O_TRUNC, 0600);
		if (fd == -1) {
			DEBUG(DEBUG_ERR,("Failed to open output file %s\n", argv[2]));
			talloc_free(tmp_ctx);
			return -1;
		}
		write(fd, data.dptr, data.dsize);
		close(fd);
	} else {
		write(1, data.dptr, data.dsize);
	}

	/* abort the transaction */
	talloc_free(h);


	talloc_free(tmp_ctx);
	return 0;
}

/*
  fetch a record from a tdb-file
 */
static int control_tfetch(struct ctdb_context *ctdb, int argc, const char **argv)
{
	const char *tdb_file;
	TDB_CONTEXT *tdb;
	TDB_DATA key, data;
	TALLOC_CTX *tmp_ctx = talloc_new(NULL);
	int fd;

	if (argc < 2) {
		usage();
	}

	tdb_file = argv[0];

	tdb = tdb_open(tdb_file, 0, 0, O_RDONLY, 0);
	if (tdb == NULL) {
		printf("Failed to open TDB file %s\n", tdb_file);
		return -1;
	}

	if (!strncmp(argv[1], "0x", 2)) {
		key = hextodata(tmp_ctx, argv[1] + 2);
		if (key.dsize == 0) {
			printf("Failed to convert \"%s\" into a TDB_DATA\n", argv[1]);
			return -1;
		}
	} else {
		key.dptr  = discard_const(argv[1]);
		key.dsize = strlen(argv[1]);
	}

	data = tdb_fetch(tdb, key);
	if (data.dptr == NULL || data.dsize < sizeof(struct ctdb_ltdb_header)) {
		printf("Failed to read record %s from tdb %s\n", argv[1], tdb_file);
		tdb_close(tdb);
		return -1;
	}

	tdb_close(tdb);

	if (argc == 3) {
	  fd = open(argv[2], O_WRONLY|O_CREAT|O_TRUNC, 0600);
		if (fd == -1) {
			printf("Failed to open output file %s\n", argv[2]);
			return -1;
		}
		if (options.verbose){
			write(fd, data.dptr, data.dsize);
		} else {
			write(fd, data.dptr+sizeof(struct ctdb_ltdb_header), data.dsize-sizeof(struct ctdb_ltdb_header));
		}
		close(fd);
	} else {
		if (options.verbose){
			write(1, data.dptr, data.dsize);
		} else {
			write(1, data.dptr+sizeof(struct ctdb_ltdb_header), data.dsize-sizeof(struct ctdb_ltdb_header));
		}
	}

	talloc_free(tmp_ctx);
	return 0;
}

/*
  store a record and header to a tdb-file
 */
static int control_tstore(struct ctdb_context *ctdb, int argc, const char **argv)
{
	const char *tdb_file;
	TDB_CONTEXT *tdb;
	TDB_DATA key, data;
	TALLOC_CTX *tmp_ctx = talloc_new(NULL);

	if (argc < 3) {
		usage();
	}

	tdb_file = argv[0];

	tdb = tdb_open(tdb_file, 0, 0, O_RDWR, 0);
	if (tdb == NULL) {
		printf("Failed to open TDB file %s\n", tdb_file);
		return -1;
	}

	if (!strncmp(argv[1], "0x", 2)) {
		key = hextodata(tmp_ctx, argv[1] + 2);
		if (key.dsize == 0) {
			printf("Failed to convert \"%s\" into a TDB_DATA\n", argv[1]);
			return -1;
		}
	} else {
		key.dptr  = discard_const(argv[1]);
		key.dsize = strlen(argv[1]);
	}

	if (!strncmp(argv[2], "0x", 2)) {
		data = hextodata(tmp_ctx, argv[2] + 2);
		if (data.dsize == 0) {
			printf("Failed to convert \"%s\" into a TDB_DATA\n", argv[2]);
			return -1;
		}
	} else {
		data.dptr  = discard_const(argv[2]);
		data.dsize = strlen(argv[2]);
	}

	if (data.dsize < sizeof(struct ctdb_ltdb_header)) {
		printf("Not enough data. You must specify the full ctdb_ltdb_header too when storing\n");
		return -1;
	}
	if (tdb_store(tdb, key, data, TDB_REPLACE) != 0) {
		printf("Failed to write record %s to tdb %s\n", argv[1], tdb_file);
		tdb_close(tdb);
		return -1;
	}

	tdb_close(tdb);

	talloc_free(tmp_ctx);
	return 0;
}

/*
  write a record to a persistent database
 */
static int control_pstore(struct ctdb_context *ctdb, int argc, const char **argv)
{
	const char *db_name;
	struct ctdb_db_context *ctdb_db;
	TALLOC_CTX *tmp_ctx = talloc_new(ctdb);
	struct ctdb_transaction_handle *h;
	struct stat st;
	TDB_DATA key, data;
	int fd, ret;

	if (argc < 3) {
		talloc_free(tmp_ctx);
		usage();
	}

	fd = open(argv[2], O_RDONLY);
	if (fd == -1) {
		DEBUG(DEBUG_ERR,("Failed to open file containing record data : %s  %s\n", argv[2], strerror(errno)));
		talloc_free(tmp_ctx);
		return -1;
	}
	
	ret = fstat(fd, &st);
	if (ret == -1) {
		DEBUG(DEBUG_ERR,("fstat of file %s failed: %s\n", argv[2], strerror(errno)));
		close(fd);
		talloc_free(tmp_ctx);
		return -1;
	}

	if (!S_ISREG(st.st_mode)) {
		DEBUG(DEBUG_ERR,("Not a regular file %s\n", argv[2]));
		close(fd);
		talloc_free(tmp_ctx);
		return -1;
	}

	data.dsize = st.st_size;
	if (data.dsize == 0) {
		data.dptr  = NULL;
	} else {
		data.dptr = talloc_size(tmp_ctx, data.dsize);
		if (data.dptr == NULL) {
			DEBUG(DEBUG_ERR,("Failed to talloc %d of memory to store record data\n", (int)data.dsize));
			close(fd);
			talloc_free(tmp_ctx);
			return -1;
		}
		ret = read(fd, data.dptr, data.dsize);
		if (ret != data.dsize) {
			DEBUG(DEBUG_ERR,("Failed to read %d bytes of record data\n", (int)data.dsize));
			close(fd);
			talloc_free(tmp_ctx);
			return -1;
		}
	}
	close(fd);


	db_name = argv[0];

	ctdb_db = ctdb_attach(ctdb, TIMELIMIT(), db_name, true, 0);
	if (ctdb_db == NULL) {
		DEBUG(DEBUG_ERR,("Unable to attach to database '%s'\n", db_name));
		talloc_free(tmp_ctx);
		return -1;
	}

	h = ctdb_transaction_start(ctdb_db, tmp_ctx);
	if (h == NULL) {
		DEBUG(DEBUG_ERR,("Failed to start transaction on database %s\n", db_name));
		talloc_free(tmp_ctx);
		return -1;
	}

	key.dptr  = discard_const(argv[1]);
	key.dsize = strlen(argv[1]);
	ret = ctdb_transaction_store(h, key, data);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,("Failed to store record\n"));
		talloc_free(tmp_ctx);
		return -1;
	}

	ret = ctdb_transaction_commit(h);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,("Failed to commit transaction\n"));
		talloc_free(tmp_ctx);
		return -1;
	}


	talloc_free(tmp_ctx);
	return 0;
}

/*
  check if a service is bound to a port or not
 */
static int control_chktcpport(struct ctdb_context *ctdb, int argc, const char **argv)
{
	int s, ret;
	unsigned v;
	int port;
        struct sockaddr_in sin;

	if (argc != 1) {
		printf("Use: ctdb chktcport <port>\n");
		return EINVAL;
	}

	port = atoi(argv[0]);

	s = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (s == -1) {
		printf("Failed to open local socket\n");
		return errno;
	}

	v = fcntl(s, F_GETFL, 0);
        fcntl(s, F_SETFL, v | O_NONBLOCK);

	bzero(&sin, sizeof(sin));
	sin.sin_family = PF_INET;
	sin.sin_port   = htons(port);
	ret = bind(s, (struct sockaddr *)&sin, sizeof(sin));
	close(s);
	if (ret == -1) {
		printf("Failed to bind to local socket: %d %s\n", errno, strerror(errno));
		return errno;
	}

	return 0;
}



static void log_handler(struct ctdb_context *ctdb, uint64_t srvid, 
			     TDB_DATA data, void *private_data)
{
	DEBUG(DEBUG_ERR,("Log data received\n"));
	if (data.dsize > 0) {
		printf("%s", data.dptr);
	}

	exit(0);
}

/*
  display a list of log messages from the in memory ringbuffer
 */
static int control_getlog(struct ctdb_context *ctdb, int argc, const char **argv)
{
	int ret;
	int32_t res;
	struct ctdb_get_log_addr log_addr;
	TDB_DATA data;
	TALLOC_CTX *tmp_ctx = talloc_new(ctdb);
	char *errmsg;
	struct timeval tv;

	if (argc != 1) {
		DEBUG(DEBUG_ERR,("Invalid arguments\n"));
		talloc_free(tmp_ctx);
		return -1;
	}

	log_addr.pnn = ctdb_ctrl_getpnn(ctdb, TIMELIMIT(), CTDB_CURRENT_NODE);
	log_addr.srvid = getpid();
	if (isalpha(argv[0][0]) || argv[0][0] == '-') { 
		log_addr.level = get_debug_by_desc(argv[0]);
	} else {
		log_addr.level = strtol(argv[0], NULL, 0);
	}


	data.dptr = (unsigned char *)&log_addr;
	data.dsize = sizeof(log_addr);

	DEBUG(DEBUG_ERR, ("Pulling logs from node %u\n", options.pnn));

	ctdb_client_set_message_handler(ctdb, log_addr.srvid, log_handler, NULL);
	sleep(1);

	DEBUG(DEBUG_ERR,("Listen for response on %d\n", (int)log_addr.srvid));

	ret = ctdb_control(ctdb, options.pnn, 0, CTDB_CONTROL_GET_LOG,
			   0, data, tmp_ctx, NULL, &res, NULL, &errmsg);
	if (ret != 0 || res != 0) {
		DEBUG(DEBUG_ERR,("Failed to get logs - %s\n", errmsg));
		talloc_free(tmp_ctx);
		return -1;
	}


	tv = timeval_current();
	/* this loop will terminate when we have received the reply */
	while (timeval_elapsed(&tv) < 3.0) {	
		event_loop_once(ctdb->ev);
	}

	DEBUG(DEBUG_INFO,("Timed out waiting for log data.\n"));

	talloc_free(tmp_ctx);
	return 0;
}

/*
  clear the in memory log area
 */
static int control_clearlog(struct ctdb_context *ctdb, int argc, const char **argv)
{
	int ret;
	int32_t res;
	char *errmsg;
	TALLOC_CTX *tmp_ctx = talloc_new(ctdb);

	ret = ctdb_control(ctdb, options.pnn, 0, CTDB_CONTROL_CLEAR_LOG,
			   0, tdb_null, tmp_ctx, NULL, &res, NULL, &errmsg);
	if (ret != 0 || res != 0) {
		DEBUG(DEBUG_ERR,("Failed to clear logs\n"));
		talloc_free(tmp_ctx);
		return -1;
	}

	talloc_free(tmp_ctx);
	return 0;
}


static uint32_t reloadips_finished;

static void reloadips_handler(struct ctdb_context *ctdb, uint64_t srvid, 
			     TDB_DATA data, void *private_data)
{
	reloadips_finished = 1;
}

static int reloadips_all(struct ctdb_context *ctdb)
{
	struct reloadips_all_reply rips;
	struct ctdb_node_map *nodemap=NULL;
	TDB_DATA data;
	uint32_t recmaster;
	int ret, i;

	/* check that there are valid nodes available */
	if (ctdb_ctrl_getnodemap(ctdb, TIMELIMIT(), CTDB_CURRENT_NODE, ctdb, &nodemap) != 0) {
		DEBUG(DEBUG_ERR, ("Unable to get nodemap from local node\n"));
		return 1;
	}
	for (i=0; i<nodemap->num;i++) {
		if (nodemap->nodes[i].flags != 0) {
			DEBUG(DEBUG_ERR,("reloadips -n all  can only be used when all nodes are up and healthy. Aborting due to problem with node %d\n", i));
			return 1;
		}
	}


	rips.pnn = ctdb_ctrl_getpnn(ctdb, TIMELIMIT(), CTDB_CURRENT_NODE);
	if (rips.pnn == -1) {
		DEBUG(DEBUG_ERR, ("Failed to get pnn of local node\n"));
		return 1;
	}
	rips.srvid = getpid();


	/* register a message port for receiveing the reply so that we
	   can receive the reply
	*/
	ctdb_client_set_message_handler(ctdb, rips.srvid, reloadips_handler, NULL);

	if (!ctdb_getrecmaster(ctdb_connection, CTDB_CURRENT_NODE, &recmaster)) {
		DEBUG(DEBUG_ERR, ("Unable to get recmaster from node\n"));
		return -1;
	}


	data.dptr = (uint8_t *)&rips;
	data.dsize = sizeof(rips);

	ret = ctdb_client_send_message(ctdb, recmaster, CTDB_SRVID_RELOAD_ALL_IPS, data);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,("Failed to send reload all ips request message to %u\n", options.pnn));
		return 1;
	}

	reloadips_finished = 0;
	while (reloadips_finished == 0) {
		event_loop_once(ctdb->ev);
	}

	return 0;
}

/*
  reload public ips on a specific node
 */
static int control_reloadips(struct ctdb_context *ctdb, int argc, const char **argv)
{
	int ret;
	int32_t res;
	char *errmsg;
	TALLOC_CTX *tmp_ctx = talloc_new(ctdb);

	if (options.pnn == CTDB_BROADCAST_ALL) {
		return reloadips_all(ctdb);
	}

	ret = ctdb_control(ctdb, options.pnn, 0, CTDB_CONTROL_RELOAD_PUBLIC_IPS,
			   0, tdb_null, tmp_ctx, NULL, &res, NULL, &errmsg);
	if (ret != 0 || res != 0) {
		DEBUG(DEBUG_ERR,("Failed to reload ips\n"));
		talloc_free(tmp_ctx);
		return -1;
	}

	talloc_free(tmp_ctx);
	return 0;
}

/*
  display a list of the databases on a remote ctdb
 */
static int control_getdbmap(struct ctdb_context *ctdb, int argc, const char **argv)
{
	int i, ret;
	struct ctdb_dbid_map *dbmap=NULL;

	ret = ctdb_ctrl_getdbmap(ctdb, TIMELIMIT(), options.pnn, ctdb, &dbmap);
	if (ret != 0) {
		DEBUG(DEBUG_ERR, ("Unable to get dbids from node %u\n", options.pnn));
		return ret;
	}

	if(options.machinereadable){
		printf(":ID:Name:Path:Persistent:Sticky:Unhealthy:ReadOnly:\n");
		for(i=0;i<dbmap->num;i++){
			const char *path;
			const char *name;
			const char *health;
			bool persistent;
			bool readonly;
			bool sticky;

			ctdb_ctrl_getdbpath(ctdb, TIMELIMIT(), options.pnn,
					    dbmap->dbs[i].dbid, ctdb, &path);
			ctdb_ctrl_getdbname(ctdb, TIMELIMIT(), options.pnn,
					    dbmap->dbs[i].dbid, ctdb, &name);
			ctdb_ctrl_getdbhealth(ctdb, TIMELIMIT(), options.pnn,
					      dbmap->dbs[i].dbid, ctdb, &health);
			persistent = dbmap->dbs[i].flags & CTDB_DB_FLAGS_PERSISTENT;
			readonly   = dbmap->dbs[i].flags & CTDB_DB_FLAGS_READONLY;
			sticky     = dbmap->dbs[i].flags & CTDB_DB_FLAGS_STICKY;
			printf(":0x%08X:%s:%s:%d:%d:%d:%d:\n",
			       dbmap->dbs[i].dbid, name, path,
			       !!(persistent), !!(sticky),
			       !!(health), !!(readonly));
		}
		return 0;
	}

	printf("Number of databases:%d\n", dbmap->num);
	for(i=0;i<dbmap->num;i++){
		const char *path;
		const char *name;
		const char *health;
		bool persistent;
		bool readonly;
		bool sticky;

		ctdb_ctrl_getdbpath(ctdb, TIMELIMIT(), options.pnn, dbmap->dbs[i].dbid, ctdb, &path);
		ctdb_ctrl_getdbname(ctdb, TIMELIMIT(), options.pnn, dbmap->dbs[i].dbid, ctdb, &name);
		ctdb_ctrl_getdbhealth(ctdb, TIMELIMIT(), options.pnn, dbmap->dbs[i].dbid, ctdb, &health);
		persistent = dbmap->dbs[i].flags & CTDB_DB_FLAGS_PERSISTENT;
		readonly   = dbmap->dbs[i].flags & CTDB_DB_FLAGS_READONLY;
		sticky     = dbmap->dbs[i].flags & CTDB_DB_FLAGS_STICKY;
		printf("dbid:0x%08x name:%s path:%s%s%s%s%s\n",
		       dbmap->dbs[i].dbid, name, path,
		       persistent?" PERSISTENT":"",
		       sticky?" STICKY":"",
		       readonly?" READONLY":"",
		       health?" UNHEALTHY":"");
	}

	return 0;
}

/*
  display the status of a database on a remote ctdb
 */
static int control_getdbstatus(struct ctdb_context *ctdb, int argc, const char **argv)
{
	int i, ret;
	struct ctdb_dbid_map *dbmap=NULL;
	const char *db_name;

	if (argc < 1) {
		usage();
	}

	db_name = argv[0];

	ret = ctdb_ctrl_getdbmap(ctdb, TIMELIMIT(), options.pnn, ctdb, &dbmap);
	if (ret != 0) {
		DEBUG(DEBUG_ERR, ("Unable to get dbids from node %u\n", options.pnn));
		return ret;
	}

	for(i=0;i<dbmap->num;i++){
		const char *path;
		const char *name;
		const char *health;
		bool persistent;
		bool readonly;
		bool sticky;

		ctdb_ctrl_getdbname(ctdb, TIMELIMIT(), options.pnn, dbmap->dbs[i].dbid, ctdb, &name);
		if (strcmp(name, db_name) != 0) {
			continue;
		}

		ctdb_ctrl_getdbpath(ctdb, TIMELIMIT(), options.pnn, dbmap->dbs[i].dbid, ctdb, &path);
		ctdb_ctrl_getdbhealth(ctdb, TIMELIMIT(), options.pnn, dbmap->dbs[i].dbid, ctdb, &health);
		persistent = dbmap->dbs[i].flags & CTDB_DB_FLAGS_PERSISTENT;
		readonly   = dbmap->dbs[i].flags & CTDB_DB_FLAGS_READONLY;
		sticky     = dbmap->dbs[i].flags & CTDB_DB_FLAGS_STICKY;
		printf("dbid: 0x%08x\nname: %s\npath: %s\nPERSISTENT: %s\nSTICKY: %s\nREADONLY: %s\nHEALTH: %s\n",
		       dbmap->dbs[i].dbid, name, path,
		       persistent?"yes":"no",
		       sticky?"yes":"no",
		       readonly?"yes":"no",
		       health?health:"OK");
		return 0;
	}

	DEBUG(DEBUG_ERR, ("db %s doesn't exist on node %u\n", db_name, options.pnn));
	return 0;
}

/*
  check if the local node is recmaster or not
  it will return 1 if this node is the recmaster and 0 if it is not
  or if the local ctdb daemon could not be contacted
 */
static int control_isnotrecmaster(struct ctdb_context *ctdb, int argc, const char **argv)
{
	uint32_t mypnn, recmaster;

	mypnn = ctdb_ctrl_getpnn(ctdb, TIMELIMIT(), options.pnn);
	if (mypnn == -1) {
		printf("Failed to get pnn of node\n");
		return 1;
	}

	if (!ctdb_getrecmaster(ctdb_connection, options.pnn, &recmaster)) {
		printf("Failed to get the recmaster\n");
		return 1;
	}

	if (recmaster != mypnn) {
		printf("this node is not the recmaster\n");
		return 1;
	}

	printf("this node is the recmaster\n");
	return 0;
}

/*
  ping a node
 */
static int control_ping(struct ctdb_context *ctdb, int argc, const char **argv)
{
	int ret;
	struct timeval tv = timeval_current();
	ret = ctdb_ctrl_ping(ctdb, options.pnn);
	if (ret == -1) {
		printf("Unable to get ping response from node %u\n", options.pnn);
		return -1;
	} else {
		printf("response from %u time=%.6f sec  (%d clients)\n", 
		       options.pnn, timeval_elapsed(&tv), ret);
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
	ret = ctdb_ctrl_get_tunable(ctdb, TIMELIMIT(), options.pnn, name, &value);
	if (ret == -1) {
		DEBUG(DEBUG_ERR, ("Unable to get tunable variable '%s'\n", name));
		return -1;
	}

	printf("%-23s = %u\n", name, value);
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

	ret = ctdb_ctrl_set_tunable(ctdb, TIMELIMIT(), options.pnn, name, value);
	if (ret == -1) {
		DEBUG(DEBUG_ERR, ("Unable to set tunable variable '%s'\n", name));
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

	ret = ctdb_ctrl_list_tunables(ctdb, TIMELIMIT(), options.pnn, ctdb, &list, &count);
	if (ret == -1) {
		DEBUG(DEBUG_ERR, ("Unable to list tunable variables\n"));
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
	int32_t level;

	ret = ctdb_ctrl_get_debuglevel(ctdb, options.pnn, &level);
	if (ret != 0) {
		DEBUG(DEBUG_ERR, ("Unable to get debuglevel response from node %u\n", options.pnn));
		return ret;
	} else {
		if (options.machinereadable){
			printf(":Name:Level:\n");
			printf(":%s:%d:\n",get_debug_by_level(level),level);
		} else {
			printf("Node %u is at debug level %s (%d)\n", options.pnn, get_debug_by_level(level), level);
		}
	}
	return 0;
}

/*
  display reclock file of a node
 */
static int control_getreclock(struct ctdb_context *ctdb, int argc, const char **argv)
{
	int ret;
	const char *reclock;

	ret = ctdb_ctrl_getreclock(ctdb, TIMELIMIT(), options.pnn, ctdb, &reclock);
	if (ret != 0) {
		DEBUG(DEBUG_ERR, ("Unable to get reclock file from node %u\n", options.pnn));
		return ret;
	} else {
		if (options.machinereadable){
			if (reclock != NULL) {
				printf("%s", reclock);
			}
		} else {
			if (reclock == NULL) {
				printf("No reclock file used.\n");
			} else {
				printf("Reclock file:%s\n", reclock);
			}
		}
	}
	return 0;
}

/*
  set the reclock file of a node
 */
static int control_setreclock(struct ctdb_context *ctdb, int argc, const char **argv)
{
	int ret;
	const char *reclock;

	if (argc == 0) {
		reclock = NULL;
	} else if (argc == 1) {
		reclock = argv[0];
	} else {
		usage();
	}

	ret = ctdb_ctrl_setreclock(ctdb, TIMELIMIT(), options.pnn, reclock);
	if (ret != 0) {
		DEBUG(DEBUG_ERR, ("Unable to get reclock file from node %u\n", options.pnn));
		return ret;
	}
	return 0;
}

/*
  set the natgw state on/off
 */
static int control_setnatgwstate(struct ctdb_context *ctdb, int argc, const char **argv)
{
	int ret;
	uint32_t natgwstate;

	if (argc == 0) {
		usage();
	}

	if (!strcmp(argv[0], "on")) {
		natgwstate = 1;
	} else if (!strcmp(argv[0], "off")) {
		natgwstate = 0;
	} else {
		usage();
	}

	ret = ctdb_ctrl_setnatgwstate(ctdb, TIMELIMIT(), options.pnn, natgwstate);
	if (ret != 0) {
		DEBUG(DEBUG_ERR, ("Unable to set the natgw state for node %u\n", options.pnn));
		return ret;
	}

	return 0;
}

/*
  set the lmaster role on/off
 */
static int control_setlmasterrole(struct ctdb_context *ctdb, int argc, const char **argv)
{
	int ret;
	uint32_t lmasterrole;

	if (argc == 0) {
		usage();
	}

	if (!strcmp(argv[0], "on")) {
		lmasterrole = 1;
	} else if (!strcmp(argv[0], "off")) {
		lmasterrole = 0;
	} else {
		usage();
	}

	ret = ctdb_ctrl_setlmasterrole(ctdb, TIMELIMIT(), options.pnn, lmasterrole);
	if (ret != 0) {
		DEBUG(DEBUG_ERR, ("Unable to set the lmaster role for node %u\n", options.pnn));
		return ret;
	}

	return 0;
}

/*
  set the recmaster role on/off
 */
static int control_setrecmasterrole(struct ctdb_context *ctdb, int argc, const char **argv)
{
	int ret;
	uint32_t recmasterrole;

	if (argc == 0) {
		usage();
	}

	if (!strcmp(argv[0], "on")) {
		recmasterrole = 1;
	} else if (!strcmp(argv[0], "off")) {
		recmasterrole = 0;
	} else {
		usage();
	}

	ret = ctdb_ctrl_setrecmasterrole(ctdb, TIMELIMIT(), options.pnn, recmasterrole);
	if (ret != 0) {
		DEBUG(DEBUG_ERR, ("Unable to set the recmaster role for node %u\n", options.pnn));
		return ret;
	}

	return 0;
}

/*
  set debug level on a node or all nodes
 */
static int control_setdebug(struct ctdb_context *ctdb, int argc, const char **argv)
{
	int i, ret;
	int32_t level;

	if (argc == 0) {
		printf("You must specify the debug level. Valid levels are:\n");
		for (i=0; debug_levels[i].description != NULL; i++) {
			printf("%s (%d)\n", debug_levels[i].description, debug_levels[i].level);
		}

		return 0;
	}

	if (isalpha(argv[0][0]) || argv[0][0] == '-') { 
		level = get_debug_by_desc(argv[0]);
	} else {
		level = strtol(argv[0], NULL, 0);
	}

	for (i=0; debug_levels[i].description != NULL; i++) {
		if (level == debug_levels[i].level) {
			break;
		}
	}
	if (debug_levels[i].description == NULL) {
		printf("Invalid debug level, must be one of\n");
		for (i=0; debug_levels[i].description != NULL; i++) {
			printf("%s (%d)\n", debug_levels[i].description, debug_levels[i].level);
		}
		return -1;
	}

	ret = ctdb_ctrl_set_debuglevel(ctdb, options.pnn, level);
	if (ret != 0) {
		DEBUG(DEBUG_ERR, ("Unable to set debug level on node %u\n", options.pnn));
	}
	return 0;
}


/*
  thaw a node
 */
static int control_thaw(struct ctdb_context *ctdb, int argc, const char **argv)
{
	int ret;
	uint32_t priority;
	
	if (argc == 1) {
		priority = strtol(argv[0], NULL, 0);
	} else {
		priority = 0;
	}
	DEBUG(DEBUG_ERR,("Thaw by priority %u\n", priority));

	ret = ctdb_ctrl_thaw_priority(ctdb, TIMELIMIT(), options.pnn, priority);
	if (ret != 0) {
		DEBUG(DEBUG_ERR, ("Unable to thaw node %u\n", options.pnn));
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
	bool persistent = false;

	if (argc < 1) {
		usage();
	}
	db_name = argv[0];
	if (argc > 2) {
		usage();
	}
	if (argc == 2) {
		if (strcmp(argv[1], "persistent") != 0) {
			usage();
		}
		persistent = true;
	}

	ctdb_db = ctdb_attach(ctdb, TIMELIMIT(), db_name, persistent, 0);
	if (ctdb_db == NULL) {
		DEBUG(DEBUG_ERR,("Unable to attach to database '%s'\n", db_name));
		return -1;
	}

	return 0;
}

/*
  set db priority
 */
static int control_setdbprio(struct ctdb_context *ctdb, int argc, const char **argv)
{
	struct ctdb_db_priority db_prio;
	int ret;

	if (argc < 2) {
		usage();
	}

	db_prio.db_id    = strtoul(argv[0], NULL, 0);
	db_prio.priority = strtoul(argv[1], NULL, 0);

	ret = ctdb_ctrl_set_db_priority(ctdb, TIMELIMIT(), options.pnn, &db_prio);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,("Unable to set db prio\n"));
		return -1;
	}

	return 0;
}

/*
  get db priority
 */
static int control_getdbprio(struct ctdb_context *ctdb, int argc, const char **argv)
{
	uint32_t db_id, priority;
	int ret;

	if (argc < 1) {
		usage();
	}

	db_id = strtoul(argv[0], NULL, 0);

	ret = ctdb_ctrl_get_db_priority(ctdb, TIMELIMIT(), options.pnn, db_id, &priority);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,("Unable to get db prio\n"));
		return -1;
	}

	DEBUG(DEBUG_ERR,("Priority:%u\n", priority));

	return 0;
}

/*
  set the sticky records capability for a database
 */
static int control_setdbsticky(struct ctdb_context *ctdb, int argc, const char **argv)
{
	TALLOC_CTX *tmp_ctx = talloc_new(ctdb);
	uint32_t db_id;
	struct ctdb_dbid_map *dbmap=NULL;
	int i, ret;

	if (argc < 1) {
		usage();
	}

	if (!strncmp(argv[0], "0x", 2)) {
		db_id = strtoul(argv[0] + 2, NULL, 0);
	} else {
		ret = ctdb_ctrl_getdbmap(ctdb, TIMELIMIT(), options.pnn, tmp_ctx, &dbmap);
		if (ret != 0) {
			DEBUG(DEBUG_ERR, ("Unable to get dbids from node %u\n", options.pnn));
			talloc_free(tmp_ctx);
			return ret;
		}
		for(i=0;i<dbmap->num;i++){
			const char *name;

			ctdb_ctrl_getdbname(ctdb, TIMELIMIT(), options.pnn, dbmap->dbs[i].dbid, tmp_ctx, &name);
			if(!strcmp(argv[0], name)){
				talloc_free(discard_const(name));
				break;
			}
			talloc_free(discard_const(name));
		}
		if (i == dbmap->num) {
			DEBUG(DEBUG_ERR,("No database with name '%s' found\n", argv[0]));
			talloc_free(tmp_ctx);
			return -1;
		}
		db_id = dbmap->dbs[i].dbid;
	}

	ret = ctdb_ctrl_set_db_sticky(ctdb, options.pnn, db_id);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,("Unable to set db to support sticky records\n"));
		talloc_free(tmp_ctx);
		return -1;
	}

	talloc_free(tmp_ctx);
	return 0;
}

/*
  set the readonly capability for a database
 */
static int control_setdbreadonly(struct ctdb_context *ctdb, int argc, const char **argv)
{
	TALLOC_CTX *tmp_ctx = talloc_new(ctdb);
	uint32_t db_id;
	struct ctdb_dbid_map *dbmap=NULL;
	int i, ret;

	if (argc < 1) {
		usage();
	}

	if (!strncmp(argv[0], "0x", 2)) {
		db_id = strtoul(argv[0] + 2, NULL, 0);
	} else {
		ret = ctdb_ctrl_getdbmap(ctdb, TIMELIMIT(), options.pnn, tmp_ctx, &dbmap);
		if (ret != 0) {
			DEBUG(DEBUG_ERR, ("Unable to get dbids from node %u\n", options.pnn));
			talloc_free(tmp_ctx);
			return ret;
		}
		for(i=0;i<dbmap->num;i++){
			const char *name;

			ctdb_ctrl_getdbname(ctdb, TIMELIMIT(), options.pnn, dbmap->dbs[i].dbid, tmp_ctx, &name);
			if(!strcmp(argv[0], name)){
				talloc_free(discard_const(name));
				break;
			}
			talloc_free(discard_const(name));
		}
		if (i == dbmap->num) {
			DEBUG(DEBUG_ERR,("No database with name '%s' found\n", argv[0]));
			talloc_free(tmp_ctx);
			return -1;
		}
		db_id = dbmap->dbs[i].dbid;
	}

	ret = ctdb_ctrl_set_db_readonly(ctdb, options.pnn, db_id);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,("Unable to set db to support readonly\n"));
		talloc_free(tmp_ctx);
		return -1;
	}

	talloc_free(tmp_ctx);
	return 0;
}

/*
  get db seqnum
 */
static int control_getdbseqnum(struct ctdb_context *ctdb, int argc, const char **argv)
{
	bool ret;
	uint32_t db_id;
	uint64_t seqnum;

	if (argc < 1) {
		usage();
	}

	db_id = strtoul(argv[0], NULL, 0);

	ret = ctdb_getdbseqnum(ctdb_connection, options.pnn, db_id, &seqnum);
	if (!ret) {
		DEBUG(DEBUG_ERR, ("Unable to get seqnum from node."));
		return -1;
	}

	printf("Sequence number:%lld\n", (long long)seqnum);

	return 0;
}

/*
  run an eventscript on a node
 */
static int control_eventscript(struct ctdb_context *ctdb, int argc, const char **argv)
{
	TDB_DATA data;
	int ret;
	int32_t res;
	char *errmsg;
	TALLOC_CTX *tmp_ctx = talloc_new(ctdb);

	if (argc != 1) {
		DEBUG(DEBUG_ERR,("Invalid arguments\n"));
		return -1;
	}

	data.dptr = (unsigned char *)discard_const(argv[0]);
	data.dsize = strlen((char *)data.dptr) + 1;

	DEBUG(DEBUG_ERR, ("Running eventscripts with arguments \"%s\" on node %u\n", data.dptr, options.pnn));

	ret = ctdb_control(ctdb, options.pnn, 0, CTDB_CONTROL_RUN_EVENTSCRIPTS,
			   0, data, tmp_ctx, NULL, &res, NULL, &errmsg);
	if (ret != 0 || res != 0) {
		DEBUG(DEBUG_ERR,("Failed to run eventscripts - %s\n", errmsg));
		talloc_free(tmp_ctx);
		return -1;
	}
	talloc_free(tmp_ctx);
	return 0;
}

#define DB_VERSION 1
#define MAX_DB_NAME 64
struct db_file_header {
	unsigned long version;
	time_t timestamp;
	unsigned long persistent;
	unsigned long size;
	const char name[MAX_DB_NAME];
};

struct backup_data {
	struct ctdb_marshall_buffer *records;
	uint32_t len;
	uint32_t total;
	bool traverse_error;
};

static int backup_traverse(struct tdb_context *tdb, TDB_DATA key, TDB_DATA data, void *private)
{
	struct backup_data *bd = talloc_get_type(private, struct backup_data);
	struct ctdb_rec_data *rec;

	/* add the record */
	rec = ctdb_marshall_record(bd->records, 0, key, NULL, data);
	if (rec == NULL) {
		bd->traverse_error = true;
		DEBUG(DEBUG_ERR,("Failed to marshall record\n"));
		return -1;
	}
	bd->records = talloc_realloc_size(NULL, bd->records, rec->length + bd->len);
	if (bd->records == NULL) {
		DEBUG(DEBUG_ERR,("Failed to expand marshalling buffer\n"));
		bd->traverse_error = true;
		return -1;
	}
	bd->records->count++;
	memcpy(bd->len+(uint8_t *)bd->records, rec, rec->length);
	bd->len += rec->length;
	talloc_free(rec);

	bd->total++;
	return 0;
}

/*
 * backup a database to a file 
 */
static int control_backupdb(struct ctdb_context *ctdb, int argc, const char **argv)
{
	int i, ret;
	struct ctdb_dbid_map *dbmap=NULL;
	TALLOC_CTX *tmp_ctx = talloc_new(ctdb);
	struct db_file_header dbhdr;
	struct ctdb_db_context *ctdb_db;
	struct backup_data *bd;
	int fh = -1;
	int status = -1;
	const char *reason = NULL;

	if (argc != 2) {
		DEBUG(DEBUG_ERR,("Invalid arguments\n"));
		return -1;
	}

	ret = ctdb_ctrl_getdbmap(ctdb, TIMELIMIT(), options.pnn, tmp_ctx, &dbmap);
	if (ret != 0) {
		DEBUG(DEBUG_ERR, ("Unable to get dbids from node %u\n", options.pnn));
		return ret;
	}

	for(i=0;i<dbmap->num;i++){
		const char *name;

		ctdb_ctrl_getdbname(ctdb, TIMELIMIT(), options.pnn, dbmap->dbs[i].dbid, tmp_ctx, &name);
		if(!strcmp(argv[0], name)){
			talloc_free(discard_const(name));
			break;
		}
		talloc_free(discard_const(name));
	}
	if (i == dbmap->num) {
		DEBUG(DEBUG_ERR,("No database with name '%s' found\n", argv[0]));
		talloc_free(tmp_ctx);
		return -1;
	}

	ret = ctdb_ctrl_getdbhealth(ctdb, TIMELIMIT(), options.pnn,
				    dbmap->dbs[i].dbid, tmp_ctx, &reason);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,("Unable to get dbhealth for database '%s'\n",
				 argv[0]));
		talloc_free(tmp_ctx);
		return -1;
	}
	if (reason) {
		uint32_t allow_unhealthy = 0;

		ctdb_ctrl_get_tunable(ctdb, TIMELIMIT(), options.pnn,
				      "AllowUnhealthyDBRead",
				      &allow_unhealthy);

		if (allow_unhealthy != 1) {
			DEBUG(DEBUG_ERR,("database '%s' is unhealthy: %s\n",
					 argv[0], reason));

			DEBUG(DEBUG_ERR,("disallow backup : tunable AllowUnhealthyDBRead = %u\n",
					 allow_unhealthy));
			talloc_free(tmp_ctx);
			return -1;
		}

		DEBUG(DEBUG_WARNING,("WARNING database '%s' is unhealthy - see 'ctdb getdbstatus %s'\n",
				     argv[0], argv[0]));
		DEBUG(DEBUG_WARNING,("WARNING! allow backup of unhealthy database: "
				     "tunnable AllowUnhealthyDBRead = %u\n",
				     allow_unhealthy));
	}

	ctdb_db = ctdb_attach(ctdb, TIMELIMIT(), argv[0], dbmap->dbs[i].flags & CTDB_DB_FLAGS_PERSISTENT, 0);
	if (ctdb_db == NULL) {
		DEBUG(DEBUG_ERR,("Unable to attach to database '%s'\n", argv[0]));
		talloc_free(tmp_ctx);
		return -1;
	}


	ret = tdb_transaction_start(ctdb_db->ltdb->tdb);
	if (ret == -1) {
		DEBUG(DEBUG_ERR,("Failed to start transaction\n"));
		talloc_free(tmp_ctx);
		return -1;
	}


	bd = talloc_zero(tmp_ctx, struct backup_data);
	if (bd == NULL) {
		DEBUG(DEBUG_ERR,("Failed to allocate backup_data\n"));
		talloc_free(tmp_ctx);
		return -1;
	}

	bd->records = talloc_zero(bd, struct ctdb_marshall_buffer);
	if (bd->records == NULL) {
		DEBUG(DEBUG_ERR,("Failed to allocate ctdb_marshall_buffer\n"));
		talloc_free(tmp_ctx);
		return -1;
	}

	bd->len = offsetof(struct ctdb_marshall_buffer, data);
	bd->records->db_id = ctdb_db->db_id;
	/* traverse the database collecting all records */
	if (tdb_traverse_read(ctdb_db->ltdb->tdb, backup_traverse, bd) == -1 ||
	    bd->traverse_error) {
		DEBUG(DEBUG_ERR,("Traverse error\n"));
		talloc_free(tmp_ctx);
		return -1;		
	}

	tdb_transaction_cancel(ctdb_db->ltdb->tdb);


	fh = open(argv[1], O_RDWR|O_CREAT, 0600);
	if (fh == -1) {
		DEBUG(DEBUG_ERR,("Failed to open file '%s'\n", argv[1]));
		talloc_free(tmp_ctx);
		return -1;
	}

	dbhdr.version = DB_VERSION;
	dbhdr.timestamp = time(NULL);
	dbhdr.persistent = dbmap->dbs[i].flags & CTDB_DB_FLAGS_PERSISTENT;
	dbhdr.size = bd->len;
	if (strlen(argv[0]) >= MAX_DB_NAME) {
		DEBUG(DEBUG_ERR,("Too long dbname\n"));
		goto done;
	}
	strncpy(discard_const(dbhdr.name), argv[0], MAX_DB_NAME);
	ret = write(fh, &dbhdr, sizeof(dbhdr));
	if (ret == -1) {
		DEBUG(DEBUG_ERR,("write failed: %s\n", strerror(errno)));
		goto done;
	}
	ret = write(fh, bd->records, bd->len);
	if (ret == -1) {
		DEBUG(DEBUG_ERR,("write failed: %s\n", strerror(errno)));
		goto done;
	}

	status = 0;
done:
	if (fh != -1) {
		ret = close(fh);
		if (ret == -1) {
			DEBUG(DEBUG_ERR,("close failed: %s\n", strerror(errno)));
		}
	}

	DEBUG(DEBUG_ERR,("Database backed up to %s\n", argv[1]));

	talloc_free(tmp_ctx);
	return status;
}

/*
 * restore a database from a file 
 */
static int control_restoredb(struct ctdb_context *ctdb, int argc, const char **argv)
{
	int ret;
	TALLOC_CTX *tmp_ctx = talloc_new(ctdb);
	TDB_DATA outdata;
	TDB_DATA data;
	struct db_file_header dbhdr;
	struct ctdb_db_context *ctdb_db;
	struct ctdb_node_map *nodemap=NULL;
	struct ctdb_vnn_map *vnnmap=NULL;
	int i, fh;
	struct ctdb_control_wipe_database w;
	uint32_t *nodes;
	uint32_t generation;
	struct tm *tm;
	char tbuf[100];
	char *dbname;

	if (argc < 1 || argc > 2) {
		DEBUG(DEBUG_ERR,("Invalid arguments\n"));
		return -1;
	}

	fh = open(argv[0], O_RDONLY);
	if (fh == -1) {
		DEBUG(DEBUG_ERR,("Failed to open file '%s'\n", argv[0]));
		talloc_free(tmp_ctx);
		return -1;
	}

	read(fh, &dbhdr, sizeof(dbhdr));
	if (dbhdr.version != DB_VERSION) {
		DEBUG(DEBUG_ERR,("Invalid version of database dump. File is version %lu but expected version was %u\n", dbhdr.version, DB_VERSION));
		talloc_free(tmp_ctx);
		return -1;
	}

	dbname = discard_const(dbhdr.name);
	if (argc == 2) {
		dbname = discard_const(argv[1]);
	}

	outdata.dsize = dbhdr.size;
	outdata.dptr = talloc_size(tmp_ctx, outdata.dsize);
	if (outdata.dptr == NULL) {
		DEBUG(DEBUG_ERR,("Failed to allocate data of size '%lu'\n", dbhdr.size));
		close(fh);
		talloc_free(tmp_ctx);
		return -1;
	}		
	read(fh, outdata.dptr, outdata.dsize);
	close(fh);

	tm = localtime(&dbhdr.timestamp);
	strftime(tbuf,sizeof(tbuf)-1,"%Y/%m/%d %H:%M:%S", tm);
	printf("Restoring database '%s' from backup @ %s\n",
		dbname, tbuf);


	ctdb_db = ctdb_attach(ctdb, TIMELIMIT(), dbname, dbhdr.persistent, 0);
	if (ctdb_db == NULL) {
		DEBUG(DEBUG_ERR,("Unable to attach to database '%s'\n", dbname));
		talloc_free(tmp_ctx);
		return -1;
	}

	ret = ctdb_ctrl_getnodemap(ctdb, TIMELIMIT(), options.pnn, ctdb, &nodemap);
	if (ret != 0) {
		DEBUG(DEBUG_ERR, ("Unable to get nodemap from node %u\n", options.pnn));
		talloc_free(tmp_ctx);
		return ret;
	}


	ret = ctdb_ctrl_getvnnmap(ctdb, TIMELIMIT(), options.pnn, tmp_ctx, &vnnmap);
	if (ret != 0) {
		DEBUG(DEBUG_ERR, ("Unable to get vnnmap from node %u\n", options.pnn));
		talloc_free(tmp_ctx);
		return ret;
	}

	/* freeze all nodes */
	nodes = list_of_active_nodes(ctdb, nodemap, tmp_ctx, true);
	for (i=1; i<=NUM_DB_PRIORITIES; i++) {
		if (ctdb_client_async_control(ctdb, CTDB_CONTROL_FREEZE,
					nodes, i,
					TIMELIMIT(),
					false, tdb_null,
					NULL, NULL,
					NULL) != 0) {
			DEBUG(DEBUG_ERR, ("Unable to freeze nodes.\n"));
			ctdb_ctrl_setrecmode(ctdb, TIMELIMIT(), options.pnn, CTDB_RECOVERY_ACTIVE);
			talloc_free(tmp_ctx);
			return -1;
		}
	}

	generation = vnnmap->generation;
	data.dptr = (void *)&generation;
	data.dsize = sizeof(generation);

	/* start a cluster wide transaction */
	nodes = list_of_active_nodes(ctdb, nodemap, tmp_ctx, true);
	if (ctdb_client_async_control(ctdb, CTDB_CONTROL_TRANSACTION_START,
					nodes, 0,
					TIMELIMIT(), false, data,
					NULL, NULL,
					NULL) != 0) {
		DEBUG(DEBUG_ERR, ("Unable to start cluster wide transactions.\n"));
		return -1;
	}


	w.db_id = ctdb_db->db_id;
	w.transaction_id = generation;

	data.dptr = (void *)&w;
	data.dsize = sizeof(w);

	/* wipe all the remote databases. */
	nodes = list_of_active_nodes(ctdb, nodemap, tmp_ctx, true);
	if (ctdb_client_async_control(ctdb, CTDB_CONTROL_WIPE_DATABASE,
					nodes, 0,
					TIMELIMIT(), false, data,
					NULL, NULL,
					NULL) != 0) {
		DEBUG(DEBUG_ERR, ("Unable to wipe database.\n"));
		ctdb_ctrl_setrecmode(ctdb, TIMELIMIT(), options.pnn, CTDB_RECOVERY_ACTIVE);
		talloc_free(tmp_ctx);
		return -1;
	}
	
	/* push the database */
	nodes = list_of_active_nodes(ctdb, nodemap, tmp_ctx, true);
	if (ctdb_client_async_control(ctdb, CTDB_CONTROL_PUSH_DB,
					nodes, 0,
					TIMELIMIT(), false, outdata,
					NULL, NULL,
					NULL) != 0) {
		DEBUG(DEBUG_ERR, ("Failed to push database.\n"));
		ctdb_ctrl_setrecmode(ctdb, TIMELIMIT(), options.pnn, CTDB_RECOVERY_ACTIVE);
		talloc_free(tmp_ctx);
		return -1;
	}

	data.dptr = (void *)&ctdb_db->db_id;
	data.dsize = sizeof(ctdb_db->db_id);

	/* mark the database as healthy */
	nodes = list_of_active_nodes(ctdb, nodemap, tmp_ctx, true);
	if (ctdb_client_async_control(ctdb, CTDB_CONTROL_DB_SET_HEALTHY,
					nodes, 0,
					TIMELIMIT(), false, data,
					NULL, NULL,
					NULL) != 0) {
		DEBUG(DEBUG_ERR, ("Failed to mark database as healthy.\n"));
		ctdb_ctrl_setrecmode(ctdb, TIMELIMIT(), options.pnn, CTDB_RECOVERY_ACTIVE);
		talloc_free(tmp_ctx);
		return -1;
	}

	data.dptr = (void *)&generation;
	data.dsize = sizeof(generation);

	/* commit all the changes */
	if (ctdb_client_async_control(ctdb, CTDB_CONTROL_TRANSACTION_COMMIT,
					nodes, 0,
					TIMELIMIT(), false, data,
					NULL, NULL,
					NULL) != 0) {
		DEBUG(DEBUG_ERR, ("Unable to commit databases.\n"));
		ctdb_ctrl_setrecmode(ctdb, TIMELIMIT(), options.pnn, CTDB_RECOVERY_ACTIVE);
		talloc_free(tmp_ctx);
		return -1;
	}


	/* thaw all nodes */
	nodes = list_of_active_nodes(ctdb, nodemap, tmp_ctx, true);
	if (ctdb_client_async_control(ctdb, CTDB_CONTROL_THAW,
					nodes, 0,
					TIMELIMIT(),
					false, tdb_null,
					NULL, NULL,
					NULL) != 0) {
		DEBUG(DEBUG_ERR, ("Unable to thaw nodes.\n"));
		ctdb_ctrl_setrecmode(ctdb, TIMELIMIT(), options.pnn, CTDB_RECOVERY_ACTIVE);
		talloc_free(tmp_ctx);
		return -1;
	}


	talloc_free(tmp_ctx);
	return 0;
}

/*
 * dump a database backup from a file
 */
static int control_dumpdbbackup(struct ctdb_context *ctdb, int argc, const char **argv)
{
	TALLOC_CTX *tmp_ctx = talloc_new(ctdb);
	TDB_DATA outdata;
	struct db_file_header dbhdr;
	int i, fh;
	struct tm *tm;
	char tbuf[100];
	struct ctdb_rec_data *rec = NULL;
	struct ctdb_marshall_buffer *m;
	struct ctdb_dump_db_context c;

	if (argc != 1) {
		DEBUG(DEBUG_ERR,("Invalid arguments\n"));
		return -1;
	}

	fh = open(argv[0], O_RDONLY);
	if (fh == -1) {
		DEBUG(DEBUG_ERR,("Failed to open file '%s'\n", argv[0]));
		talloc_free(tmp_ctx);
		return -1;
	}

	read(fh, &dbhdr, sizeof(dbhdr));
	if (dbhdr.version != DB_VERSION) {
		DEBUG(DEBUG_ERR,("Invalid version of database dump. File is version %lu but expected version was %u\n", dbhdr.version, DB_VERSION));
		talloc_free(tmp_ctx);
		return -1;
	}

	outdata.dsize = dbhdr.size;
	outdata.dptr = talloc_size(tmp_ctx, outdata.dsize);
	if (outdata.dptr == NULL) {
		DEBUG(DEBUG_ERR,("Failed to allocate data of size '%lu'\n", dbhdr.size));
		close(fh);
		talloc_free(tmp_ctx);
		return -1;
	}
	read(fh, outdata.dptr, outdata.dsize);
	close(fh);
	m = (struct ctdb_marshall_buffer *)outdata.dptr;

	tm = localtime(&dbhdr.timestamp);
	strftime(tbuf,sizeof(tbuf)-1,"%Y/%m/%d %H:%M:%S", tm);
	printf("Backup of database name:'%s' dbid:0x%x08x from @ %s\n",
		dbhdr.name, m->db_id, tbuf);

	ZERO_STRUCT(c);
	c.f = stdout;
	c.printemptyrecords = (bool)options.printemptyrecords;
	c.printdatasize = (bool)options.printdatasize;
	c.printlmaster = false;
	c.printhash = (bool)options.printhash;
	c.printrecordflags = (bool)options.printrecordflags;

	for (i=0; i < m->count; i++) {
		uint32_t reqid = 0;
		TDB_DATA key, data;

		/* we do not want the header splitted, so we pass NULL*/
		rec = ctdb_marshall_loop_next(m, rec, &reqid,
					      NULL, &key, &data);

		ctdb_dumpdb_record(ctdb, key, data, &c);
	}

	printf("Dumped %d records\n", i);
	talloc_free(tmp_ctx);
	return 0;
}

/*
 * wipe a database from a file
 */
static int control_wipedb(struct ctdb_context *ctdb, int argc,
			  const char **argv)
{
	int ret;
	TALLOC_CTX *tmp_ctx = talloc_new(ctdb);
	TDB_DATA data;
	struct ctdb_db_context *ctdb_db;
	struct ctdb_node_map *nodemap = NULL;
	struct ctdb_vnn_map *vnnmap = NULL;
	int i;
	struct ctdb_control_wipe_database w;
	uint32_t *nodes;
	uint32_t generation;
	struct ctdb_dbid_map *dbmap = NULL;

	if (argc != 1) {
		DEBUG(DEBUG_ERR,("Invalid arguments\n"));
		return -1;
	}

	ret = ctdb_ctrl_getdbmap(ctdb, TIMELIMIT(), options.pnn, tmp_ctx,
				 &dbmap);
	if (ret != 0) {
		DEBUG(DEBUG_ERR, ("Unable to get dbids from node %u\n",
				  options.pnn));
		return ret;
	}

	for(i=0;i<dbmap->num;i++){
		const char *name;

		ctdb_ctrl_getdbname(ctdb, TIMELIMIT(), options.pnn,
				    dbmap->dbs[i].dbid, tmp_ctx, &name);
		if(!strcmp(argv[0], name)){
			talloc_free(discard_const(name));
			break;
		}
		talloc_free(discard_const(name));
	}
	if (i == dbmap->num) {
		DEBUG(DEBUG_ERR, ("No database with name '%s' found\n",
				  argv[0]));
		talloc_free(tmp_ctx);
		return -1;
	}

	ctdb_db = ctdb_attach(ctdb, TIMELIMIT(), argv[0], dbmap->dbs[i].flags & CTDB_DB_FLAGS_PERSISTENT, 0);
	if (ctdb_db == NULL) {
		DEBUG(DEBUG_ERR, ("Unable to attach to database '%s'\n",
				  argv[0]));
		talloc_free(tmp_ctx);
		return -1;
	}

	ret = ctdb_ctrl_getnodemap(ctdb, TIMELIMIT(), options.pnn, ctdb,
				   &nodemap);
	if (ret != 0) {
		DEBUG(DEBUG_ERR, ("Unable to get nodemap from node %u\n",
				  options.pnn));
		talloc_free(tmp_ctx);
		return ret;
	}

	ret = ctdb_ctrl_getvnnmap(ctdb, TIMELIMIT(), options.pnn, tmp_ctx,
				  &vnnmap);
	if (ret != 0) {
		DEBUG(DEBUG_ERR, ("Unable to get vnnmap from node %u\n",
				  options.pnn));
		talloc_free(tmp_ctx);
		return ret;
	}

	/* freeze all nodes */
	nodes = list_of_active_nodes(ctdb, nodemap, tmp_ctx, true);
	for (i=1; i<=NUM_DB_PRIORITIES; i++) {
		ret = ctdb_client_async_control(ctdb, CTDB_CONTROL_FREEZE,
						nodes, i,
						TIMELIMIT(),
						false, tdb_null,
						NULL, NULL,
						NULL);
		if (ret != 0) {
			DEBUG(DEBUG_ERR, ("Unable to freeze nodes.\n"));
			ctdb_ctrl_setrecmode(ctdb, TIMELIMIT(), options.pnn,
					     CTDB_RECOVERY_ACTIVE);
			talloc_free(tmp_ctx);
			return -1;
		}
	}

	generation = vnnmap->generation;
	data.dptr = (void *)&generation;
	data.dsize = sizeof(generation);

	/* start a cluster wide transaction */
	nodes = list_of_active_nodes(ctdb, nodemap, tmp_ctx, true);
	ret = ctdb_client_async_control(ctdb, CTDB_CONTROL_TRANSACTION_START,
					nodes, 0,
					TIMELIMIT(), false, data,
					NULL, NULL,
					NULL);
	if (ret!= 0) {
		DEBUG(DEBUG_ERR, ("Unable to start cluster wide "
				  "transactions.\n"));
		return -1;
	}

	w.db_id = ctdb_db->db_id;
	w.transaction_id = generation;

	data.dptr = (void *)&w;
	data.dsize = sizeof(w);

	/* wipe all the remote databases. */
	nodes = list_of_active_nodes(ctdb, nodemap, tmp_ctx, true);
	if (ctdb_client_async_control(ctdb, CTDB_CONTROL_WIPE_DATABASE,
					nodes, 0,
					TIMELIMIT(), false, data,
					NULL, NULL,
					NULL) != 0) {
		DEBUG(DEBUG_ERR, ("Unable to wipe database.\n"));
		ctdb_ctrl_setrecmode(ctdb, TIMELIMIT(), options.pnn, CTDB_RECOVERY_ACTIVE);
		talloc_free(tmp_ctx);
		return -1;
	}

	data.dptr = (void *)&ctdb_db->db_id;
	data.dsize = sizeof(ctdb_db->db_id);

	/* mark the database as healthy */
	nodes = list_of_active_nodes(ctdb, nodemap, tmp_ctx, true);
	if (ctdb_client_async_control(ctdb, CTDB_CONTROL_DB_SET_HEALTHY,
					nodes, 0,
					TIMELIMIT(), false, data,
					NULL, NULL,
					NULL) != 0) {
		DEBUG(DEBUG_ERR, ("Failed to mark database as healthy.\n"));
		ctdb_ctrl_setrecmode(ctdb, TIMELIMIT(), options.pnn, CTDB_RECOVERY_ACTIVE);
		talloc_free(tmp_ctx);
		return -1;
	}

	data.dptr = (void *)&generation;
	data.dsize = sizeof(generation);

	/* commit all the changes */
	if (ctdb_client_async_control(ctdb, CTDB_CONTROL_TRANSACTION_COMMIT,
					nodes, 0,
					TIMELIMIT(), false, data,
					NULL, NULL,
					NULL) != 0) {
		DEBUG(DEBUG_ERR, ("Unable to commit databases.\n"));
		ctdb_ctrl_setrecmode(ctdb, TIMELIMIT(), options.pnn, CTDB_RECOVERY_ACTIVE);
		talloc_free(tmp_ctx);
		return -1;
	}

	/* thaw all nodes */
	nodes = list_of_active_nodes(ctdb, nodemap, tmp_ctx, true);
	if (ctdb_client_async_control(ctdb, CTDB_CONTROL_THAW,
					nodes, 0,
					TIMELIMIT(),
					false, tdb_null,
					NULL, NULL,
					NULL) != 0) {
		DEBUG(DEBUG_ERR, ("Unable to thaw nodes.\n"));
		ctdb_ctrl_setrecmode(ctdb, TIMELIMIT(), options.pnn, CTDB_RECOVERY_ACTIVE);
		talloc_free(tmp_ctx);
		return -1;
	}

	DEBUG(DEBUG_ERR, ("Database wiped.\n"));

	talloc_free(tmp_ctx);
	return 0;
}

/*
  dump memory usage
 */
static int control_dumpmemory(struct ctdb_context *ctdb, int argc, const char **argv)
{
	TDB_DATA data;
	int ret;
	int32_t res;
	char *errmsg;
	TALLOC_CTX *tmp_ctx = talloc_new(ctdb);
	ret = ctdb_control(ctdb, options.pnn, 0, CTDB_CONTROL_DUMP_MEMORY,
			   0, tdb_null, tmp_ctx, &data, &res, NULL, &errmsg);
	if (ret != 0 || res != 0) {
		DEBUG(DEBUG_ERR,("Failed to dump memory - %s\n", errmsg));
		talloc_free(tmp_ctx);
		return -1;
	}
	write(1, data.dptr, data.dsize);
	talloc_free(tmp_ctx);
	return 0;
}

/*
  handler for memory dumps
*/
static void mem_dump_handler(struct ctdb_context *ctdb, uint64_t srvid, 
			     TDB_DATA data, void *private_data)
{
	write(1, data.dptr, data.dsize);
	exit(0);
}

/*
  dump memory usage on the recovery daemon
 */
static int control_rddumpmemory(struct ctdb_context *ctdb, int argc, const char **argv)
{
	int ret;
	TDB_DATA data;
	struct rd_memdump_reply rd;

	rd.pnn = ctdb_ctrl_getpnn(ctdb, TIMELIMIT(), CTDB_CURRENT_NODE);
	if (rd.pnn == -1) {
		DEBUG(DEBUG_ERR, ("Failed to get pnn of local node\n"));
		return -1;
	}
	rd.srvid = getpid();

	/* register a message port for receiveing the reply so that we
	   can receive the reply
	*/
	ctdb_client_set_message_handler(ctdb, rd.srvid, mem_dump_handler, NULL);


	data.dptr = (uint8_t *)&rd;
	data.dsize = sizeof(rd);

	ret = ctdb_client_send_message(ctdb, options.pnn, CTDB_SRVID_MEM_DUMP, data);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,("Failed to send memdump request message to %u\n", options.pnn));
		return -1;
	}

	/* this loop will terminate when we have received the reply */
	while (1) {	
		event_loop_once(ctdb->ev);
	}

	return 0;
}

/*
  send a message to a srvid
 */
static int control_msgsend(struct ctdb_context *ctdb, int argc, const char **argv)
{
	unsigned long srvid;
	int ret;
	TDB_DATA data;

	if (argc < 2) {
		usage();
	}

	srvid      = strtoul(argv[0], NULL, 0);

	data.dptr = (uint8_t *)discard_const(argv[1]);
	data.dsize= strlen(argv[1]);

	ret = ctdb_client_send_message(ctdb, CTDB_BROADCAST_CONNECTED, srvid, data);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,("Failed to send memdump request message to %u\n", options.pnn));
		return -1;
	}

	return 0;
}

/*
  handler for msglisten
*/
static void msglisten_handler(struct ctdb_context *ctdb, uint64_t srvid, 
			     TDB_DATA data, void *private_data)
{
	int i;

	printf("Message received: ");
	for (i=0;i<data.dsize;i++) {
		printf("%c", data.dptr[i]);
	}
	printf("\n");
}

/*
  listen for messages on a messageport
 */
static int control_msglisten(struct ctdb_context *ctdb, int argc, const char **argv)
{
	uint64_t srvid;

	srvid = getpid();

	/* register a message port and listen for messages
	*/
	ctdb_client_set_message_handler(ctdb, srvid, msglisten_handler, NULL);
	printf("Listening for messages on srvid:%d\n", (int)srvid);

	while (1) {	
		event_loop_once(ctdb->ev);
	}

	return 0;
}

/*
  list all nodes in the cluster
  we parse the nodes file directly
 */
static int control_listnodes(struct ctdb_context *ctdb, int argc, const char **argv)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct pnn_node *pnn_nodes;
	struct pnn_node *pnn_node;

	pnn_nodes = read_nodes_file(mem_ctx);
	if (pnn_nodes == NULL) {
		DEBUG(DEBUG_ERR,("Failed to read nodes file\n"));
		talloc_free(mem_ctx);
		return -1;
	}

	for(pnn_node=pnn_nodes;pnn_node;pnn_node=pnn_node->next) {
		ctdb_sock_addr addr;
		if (parse_ip(pnn_node->addr, NULL, 63999, &addr) == 0) {
			DEBUG(DEBUG_ERR,("Wrongly formed ip address '%s' in nodes file\n", pnn_node->addr));
			talloc_free(mem_ctx);
			return -1;
		}
		if (options.machinereadable){
			printf(":%d:%s:\n", pnn_node->pnn, pnn_node->addr);
		} else {
			printf("%s\n", pnn_node->addr);
		}
	}
	talloc_free(mem_ctx);

	return 0;
}

/*
  reload the nodes file on the local node
 */
static int control_reload_nodes_file(struct ctdb_context *ctdb, int argc, const char **argv)
{
	int i, ret;
	int mypnn;
	struct ctdb_node_map *nodemap=NULL;

	mypnn = ctdb_ctrl_getpnn(ctdb, TIMELIMIT(), CTDB_CURRENT_NODE);
	if (mypnn == -1) {
		DEBUG(DEBUG_ERR, ("Failed to read pnn of local node\n"));
		return -1;
	}

	ret = ctdb_ctrl_getnodemap(ctdb, TIMELIMIT(), CTDB_CURRENT_NODE, ctdb, &nodemap);
	if (ret != 0) {
		DEBUG(DEBUG_ERR, ("Unable to get nodemap from local node\n"));
		return ret;
	}

	/* reload the nodes file on all remote nodes */
	for (i=0;i<nodemap->num;i++) {
		if (nodemap->nodes[i].pnn == mypnn) {
			continue;
		}
		DEBUG(DEBUG_NOTICE, ("Reloading nodes file on node %u\n", nodemap->nodes[i].pnn));
		ret = ctdb_ctrl_reload_nodes_file(ctdb, TIMELIMIT(),
			nodemap->nodes[i].pnn);
		if (ret != 0) {
			DEBUG(DEBUG_ERR, ("ERROR: Failed to reload nodes file on node %u. You MUST fix that node manually!\n", nodemap->nodes[i].pnn));
		}
	}

	/* reload the nodes file on the local node */
	DEBUG(DEBUG_NOTICE, ("Reloading nodes file on node %u\n", mypnn));
	ret = ctdb_ctrl_reload_nodes_file(ctdb, TIMELIMIT(), mypnn);
	if (ret != 0) {
		DEBUG(DEBUG_ERR, ("ERROR: Failed to reload nodes file on node %u. You MUST fix that node manually!\n", mypnn));
	}

	/* initiate a recovery */
	control_recover(ctdb, argc, argv);

	return 0;
}


static const struct {
	const char *name;
	int (*fn)(struct ctdb_context *, int, const char **);
	bool auto_all;
	bool without_daemon; /* can be run without daemon running ? */
	const char *msg;
	const char *args;
} ctdb_commands[] = {
#ifdef CTDB_VERS
	{ "version",         control_version,           true,	false,  "show version of ctdb" },
#endif
	{ "status",          control_status,            true,	false,  "show node status" },
	{ "uptime",          control_uptime,            true,	false,  "show node uptime" },
	{ "ping",            control_ping,              true,	false,  "ping all nodes" },
	{ "getvar",          control_getvar,            true,	false,  "get a tunable variable",               "<name>"},
	{ "setvar",          control_setvar,            true,	false,  "set a tunable variable",               "<name> <value>"},
	{ "listvars",        control_listvars,          true,	false,  "list tunable variables"},
	{ "statistics",      control_statistics,        false,	false, "show statistics" },
	{ "statisticsreset", control_statistics_reset,  true,	false,  "reset statistics"},
	{ "stats",           control_stats,             false,	false,  "show rolling statistics", "[number of history records]" },
	{ "ip",              control_ip,                false,	false,  "show which public ip's that ctdb manages" },
	{ "ipinfo",          control_ipinfo,            true,	false,  "show details about a public ip that ctdb manages", "<ip>" },
	{ "ifaces",          control_ifaces,            true,	false,  "show which interfaces that ctdb manages" },
	{ "setifacelink",    control_setifacelink,      true,	false,  "set interface link status", "<iface> <status>" },
	{ "process-exists",  control_process_exists,    true,	false,  "check if a process exists on a node",  "<pid>"},
	{ "getdbmap",        control_getdbmap,          true,	false,  "show the database map" },
	{ "getdbstatus",     control_getdbstatus,       true,	false,  "show the status of a database", "<dbname>" },
	{ "catdb",           control_catdb,             true,	false,  "dump a ctdb database" ,                     "<dbname>"},
	{ "cattdb",          control_cattdb,            true,	false,  "dump a local tdb database" ,                     "<dbname>"},
	{ "getmonmode",      control_getmonmode,        true,	false,  "show monitoring mode" },
	{ "getcapabilities", control_getcapabilities,   true,	false,  "show node capabilities" },
	{ "pnn",             control_pnn,               true,	false,  "show the pnn of the currnet node" },
	{ "lvs",             control_lvs,               true,	false,  "show lvs configuration" },
	{ "lvsmaster",       control_lvsmaster,         true,	false,  "show which node is the lvs master" },
	{ "disablemonitor",      control_disable_monmode,true,	false,  "set monitoring mode to DISABLE" },
	{ "enablemonitor",      control_enable_monmode, true,	false,  "set monitoring mode to ACTIVE" },
	{ "setdebug",        control_setdebug,          true,	false,  "set debug level",                      "<EMERG|ALERT|CRIT|ERR|WARNING|NOTICE|INFO|DEBUG>" },
	{ "getdebug",        control_getdebug,          true,	false,  "get debug level" },
	{ "getlog",          control_getlog,            true,	false,  "get the log data from the in memory ringbuffer", "<level>" },
	{ "clearlog",          control_clearlog,        true,	false,  "clear the log data from the in memory ringbuffer" },
	{ "attach",          control_attach,            true,	false,  "attach to a database",                 "<dbname> [persistent]" },
	{ "dumpmemory",      control_dumpmemory,        true,	false,  "dump memory map to stdout" },
	{ "rddumpmemory",    control_rddumpmemory,      true,	false,  "dump memory map from the recovery daemon to stdout" },
	{ "getpid",          control_getpid,            true,	false,  "get ctdbd process ID" },
	{ "disable",         control_disable,           true,	false,  "disable a nodes public IP" },
	{ "enable",          control_enable,            true,	false,  "enable a nodes public IP" },
	{ "stop",            control_stop,              true,	false,  "stop a node" },
	{ "continue",        control_continue,          true,	false,  "re-start a stopped node" },
	{ "ban",             control_ban,               true,	false,  "ban a node from the cluster",          "<bantime|0>"},
	{ "unban",           control_unban,             true,	false,  "unban a node" },
	{ "showban",         control_showban,           true,	false,  "show ban information"},
	{ "shutdown",        control_shutdown,          true,	false,  "shutdown ctdbd" },
	{ "recover",         control_recover,           true,	false,  "force recovery" },
	{ "sync", 	     control_ipreallocate,      true,	false,  "wait until ctdbd has synced all state changes" },
	{ "ipreallocate",    control_ipreallocate,      true,	false,  "force the recovery daemon to perform a ip reallocation procedure" },
	{ "thaw",            control_thaw,              true,	false,  "thaw databases", "[priority:1-3]" },
	{ "isnotrecmaster",  control_isnotrecmaster,    false,	false,  "check if the local node is recmaster or not" },
	{ "killtcp",         kill_tcp,                  false,	false, "kill a tcp connection.", "<srcip:port> <dstip:port>" },
	{ "gratiousarp",     control_gratious_arp,      false,	false, "send a gratious arp", "<ip> <interface>" },
	{ "tickle",          tickle_tcp,                false,	false, "send a tcp tickle ack", "<srcip:port> <dstip:port>" },
	{ "gettickles",      control_get_tickles,       false,	false, "get the list of tickles registered for this ip", "<ip> [<port>]" },
	{ "addtickle",       control_add_tickle,        false,	false, "add a tickle for this ip", "<ip>:<port> <ip>:<port>" },

	{ "deltickle",       control_del_tickle,        false,	false, "delete a tickle from this ip", "<ip>:<port> <ip>:<port>" },

	{ "regsrvid",        regsrvid,			false,	false, "register a server id", "<pnn> <type> <id>" },
	{ "unregsrvid",      unregsrvid,		false,	false, "unregister a server id", "<pnn> <type> <id>" },
	{ "chksrvid",        chksrvid,			false,	false, "check if a server id exists", "<pnn> <type> <id>" },
	{ "getsrvids",       getsrvids,			false,	false, "get a list of all server ids"},
	{ "check_srvids",    check_srvids,		false,	false, "check if a srvid exists", "<id>+" },
	{ "vacuum",          ctdb_vacuum,		false,	true, "vacuum the databases of empty records", "[max_records]"},
	{ "repack",          ctdb_repack,		false,	false, "repack all databases", "[max_freelist]"},
	{ "listnodes",       control_listnodes,		false,	true, "list all nodes in the cluster"},
	{ "reloadnodes",     control_reload_nodes_file,	false,	false, "reload the nodes file and restart the transport on all nodes"},
	{ "moveip",          control_moveip,		false,	false, "move/failover an ip address to another node", "<ip> <node>"},
	{ "rebalanceip",     control_rebalanceip,	false,	false, "release an ip from the node and let recd rebalance it", "<ip>"},
	{ "addip",           control_addip,		true,	false, "add a ip address to a node", "<ip/mask> <iface>"},
	{ "delip",           control_delip,		false,	false, "delete an ip address from a node", "<ip>"},
	{ "eventscript",     control_eventscript,	true,	false, "run the eventscript with the given parameters on a node", "<arguments>"},
	{ "backupdb",        control_backupdb,          false,	false, "backup the database into a file.", "<database> <file>"},
	{ "restoredb",        control_restoredb,        false,	false, "restore the database from a file.", "<file> [dbname]"},
	{ "dumpdbbackup",    control_dumpdbbackup,      false,	true,  "dump database backup from a file.", "<file>"},
	{ "wipedb",           control_wipedb,        false,	false, "wipe the contents of a database.", "<dbname>"},
	{ "recmaster",        control_recmaster,        true,	false, "show the pnn for the recovery master."},
	{ "scriptstatus",     control_scriptstatus,     true,	false, "show the status of the monitoring scripts (or all scripts)", "[all]"},
	{ "enablescript",     control_enablescript,  false,	false, "enable an eventscript", "<script>"},
	{ "disablescript",    control_disablescript,  false,	false, "disable an eventscript", "<script>"},
	{ "natgwlist",        control_natgwlist,        false,	false, "show the nodes belonging to this natgw configuration"},
	{ "xpnn",             control_xpnn,             true,	true,  "find the pnn of the local node without talking to the daemon (unreliable)" },
	{ "getreclock",       control_getreclock,	false,	false, "Show the reclock file of a node"},
	{ "setreclock",       control_setreclock,	false,	false, "Set/clear the reclock file of a node", "[filename]"},
	{ "setnatgwstate",    control_setnatgwstate,	false,	false, "Set NATGW state to on/off", "{on|off}"},
	{ "setlmasterrole",   control_setlmasterrole,	false,	false, "Set LMASTER role to on/off", "{on|off}"},
	{ "setrecmasterrole", control_setrecmasterrole,	false,	false, "Set RECMASTER role to on/off", "{on|off}"},
	{ "setdbprio",        control_setdbprio,	false,	false, "Set DB priority", "<dbid> <prio:1-3>"},
	{ "getdbprio",        control_getdbprio,	false,	false, "Get DB priority", "<dbid>"},
	{ "setdbreadonly",    control_setdbreadonly,	false,	false, "Set DB readonly capable", "<dbid>|<name>"},
	{ "setdbsticky",      control_setdbsticky,	false,	false, "Set DB sticky-records capable", "<dbid>|<name>"},
	{ "msglisten",        control_msglisten,	false,	false, "Listen on a srvid port for messages", "<msg srvid>"},
	{ "msgsend",          control_msgsend,	false,	false, "Send a message to srvid", "<srvid> <message>"},
	{ "sync", 	     control_ipreallocate,      false,	false,  "wait until ctdbd has synced all state changes" },
	{ "pfetch", 	     control_pfetch,      	false,	false,  "fetch a record from a persistent database", "<db> <key> [<file>]" },
	{ "pstore", 	     control_pstore,      	false,	false,  "write a record to a persistent database", "<db> <key> <file containing record>" },
	{ "tfetch", 	     control_tfetch,      	false,	true,  "fetch a record from a [c]tdb-file [-v]", "<tdb-file> <key> [<file>]" },
	{ "tstore", 	     control_tstore,      	false,	true,  "store a record (including ltdb header)", "<tdb-file> <key> <data+header>" },
	{ "readkey", 	     control_readkey,      	true,	false,  "read the content off a database key", "<tdb-file> <key>" },
	{ "writekey", 	     control_writekey,      	true,	false,  "write to a database key", "<tdb-file> <key> <value>" },
	{ "checktcpport",    control_chktcpport,      	false,	true,  "check if a service is bound to a specific tcp port or not", "<port>" },
	{ "rebalancenode",     control_rebalancenode,	false,	false, "release a node by allowing it to takeover ips", "<pnn>"},
	{ "getdbseqnum",     control_getdbseqnum,       false,	false, "get the sequence number off a database", "<dbid>" },
	{ "nodestatus",      control_nodestatus,        true,   false,  "show and return node status" },
	{ "dbstatistics",    control_dbstatistics,      false,	false, "show db statistics", "<db>" },
	{ "reloadips",       control_reloadips,         false,	false, "reload the public addresses file on a node" },
	{ "ipiface",         control_ipiface,           true,	true,  "Find which interface an ip address is hsoted on", "<ip>" },
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
"   -v                 generate verbose output\n"
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


static void ctdb_alarm(int sig)
{
	printf("Maximum runtime exceeded - exiting\n");
	_exit(ERR_TIMEOUT);
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
		{ "verbose",    'v', POPT_ARG_NONE, &options.verbose, 0, "enable verbose output", NULL },
		{ "maxruntime", 'T', POPT_ARG_INT, &options.maxruntime, 0, "die if runtime exceeds this limit (in seconds)", "integer" },
		{ "print-emptyrecords", 0, POPT_ARG_NONE, &options.printemptyrecords, 0, "print the empty records when dumping databases (catdb, cattdb, dumpdbbackup)", NULL },
		{ "print-datasize", 0, POPT_ARG_NONE, &options.printdatasize, 0, "do not print record data when dumping databases, only the data size", NULL },
		{ "print-lmaster", 0, POPT_ARG_NONE, &options.printlmaster, 0, "print the record's lmaster in catdb", NULL },
		{ "print-hash", 0, POPT_ARG_NONE, &options.printhash, 0, "print the record's hash when dumping databases", NULL },
		{ "print-recordflags", 0, POPT_ARG_NONE, &options.printrecordflags, 0, "print the record flags in catdb and dumpdbbackup", NULL },
		POPT_TABLEEND
	};
	int opt;
	const char **extra_argv;
	int extra_argc = 0;
	int ret=-1, i;
	poptContext pc;
	struct event_context *ev;
	const char *control;
	const char *socket_name;

	setlinebuf(stdout);
	
	/* set some defaults */
	options.maxruntime = 0;
	options.timelimit = 3;
	options.pnn = CTDB_CURRENT_NODE;

	pc = poptGetContext(argv[0], argc, argv, popt_options, POPT_CONTEXT_KEEP_FIRST);

	while ((opt = poptGetNextOpt(pc)) != -1) {
		switch (opt) {
		default:
			DEBUG(DEBUG_ERR, ("Invalid option %s: %s\n", 
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

	if (options.maxruntime == 0) {
		const char *ctdb_timeout;
		ctdb_timeout = getenv("CTDB_TIMEOUT");
		if (ctdb_timeout != NULL) {
			options.maxruntime = strtoul(ctdb_timeout, NULL, 0);
		} else {
			/* default timeout is 120 seconds */
			options.maxruntime = 120;
		}
	}

	signal(SIGALRM, ctdb_alarm);
	alarm(options.maxruntime);

	control = extra_argv[0];

	ev = event_context_init(NULL);
	if (!ev) {
		DEBUG(DEBUG_ERR, ("Failed to initialize event system\n"));
		exit(1);
	}

	for (i=0;i<ARRAY_SIZE(ctdb_commands);i++) {
		if (strcmp(control, ctdb_commands[i].name) == 0) {
			break;
		}
	}

	if (i == ARRAY_SIZE(ctdb_commands)) {
		DEBUG(DEBUG_ERR, ("Unknown control '%s'\n", control));
		exit(1);
	}

	if (ctdb_commands[i].without_daemon == true) {
		if (nodestring != NULL) {
			DEBUG(DEBUG_ERR, ("Can't specify node(s) with \"ctdb %s\"\n", control));
			exit(1);
		}
		close(2);
		return ctdb_commands[i].fn(NULL, extra_argc-1, extra_argv+1);
	}

	/* initialise ctdb */
	ctdb = ctdb_cmdline_client(ev, TIMELIMIT());

	if (ctdb == NULL) {
		DEBUG(DEBUG_ERR, ("Failed to init ctdb\n"));
		exit(1);
	}

	/* initialize a libctdb connection as well */
	socket_name = ctdb_get_socketname(ctdb);
	ctdb_connection = ctdb_connect(socket_name,
				       ctdb_log_file, stderr);
	if (ctdb_connection == NULL) {
		DEBUG(DEBUG_ERR, ("Failed to connect to daemon from libctdb\n"));
		exit(1);
	}				

	/* setup the node number(s) to contact */
	if (!parse_nodestring(ctdb, nodestring, CTDB_CURRENT_NODE, false,
			      &options.nodes, &options.pnn)) {
		usage();
	}

	if (options.pnn == CTDB_CURRENT_NODE) {
		options.pnn = options.nodes[0];
	}

	if (ctdb_commands[i].auto_all && 
	    ((options.pnn == CTDB_BROADCAST_ALL) ||
	     (options.pnn == CTDB_MULTICAST))) {
		int j;

		ret = 0;
		for (j = 0; j < talloc_array_length(options.nodes); j++) {
			options.pnn = options.nodes[j];
			ret |= ctdb_commands[i].fn(ctdb, extra_argc-1, extra_argv+1);
		}
	} else {
		ret = ctdb_commands[i].fn(ctdb, extra_argc-1, extra_argv+1);
	}

	ctdb_disconnect(ctdb_connection);
	talloc_free(ctdb);
	(void)poptFreeContext(pc);

	return ret;

}
