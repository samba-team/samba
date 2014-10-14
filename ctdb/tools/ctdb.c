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
#include "../include/ctdb_version.h"
#include "../include/ctdb_client.h"
#include "../include/ctdb_private.h"
#include "../common/rb_tree.h"
#include "lib/tdb_wrap/tdb_wrap.h"
#include "lib/util/dlinklist.h"

#define ERR_TIMEOUT	20	/* timed out trying to reach node */
#define ERR_NONODE	21	/* node does not exist */
#define ERR_DISNODE	22	/* node is disconnected */

static void usage(void);

static struct {
	int timelimit;
	uint32_t pnn;
	uint32_t *nodes;
	int machinereadable;
	const char *machineseparator;
	int verbose;
	int maxruntime;
	int printemptyrecords;
	int printdatasize;
	int printlmaster;
	int printhash;
	int printrecordflags;
} options;

#define LONGTIMEOUT options.timelimit*10

#define TIMELIMIT() timeval_current_ofs(options.timelimit, 0)
#define LONGTIMELIMIT() timeval_current_ofs(LONGTIMEOUT, 0)

static double timeval_delta(struct timeval *tv2, struct timeval *tv)
{
	return (tv2->tv_sec - tv->tv_sec) +
		(tv2->tv_usec - tv->tv_usec)*1.0e-6;
}

static int control_version(struct ctdb_context *ctdb, int argc, const char **argv)
{
	printf("CTDB version: %s\n", CTDB_VERSION_STRING);
	return 0;
}

/* Like printf(3) but substitute for separator in format */
static int printm(const char *format, ...) PRINTF_ATTRIBUTE(1,2);
static int printm(const char *format, ...)
{
	va_list ap;
	int ret;
	size_t len = strlen(format);
	char new_format[len+1];

	strcpy(new_format, format);

	if (options.machineseparator[0] != ':') {
		all_string_sub(new_format,
			       ":", options.machineseparator, len + 1);
	}

	va_start(ap, format);
	ret = vprintf(new_format, ap);
	va_end(ap);

	return ret;
}

#define CTDB_NOMEM_ABORT(p) do { if (!(p)) {				\
		DEBUG(DEBUG_ALERT,("ctdb fatal error: %s\n",		\
				   "Out of memory in " __location__ ));	\
		abort();						\
	}} while (0)

static uint32_t getpnn(struct ctdb_context *ctdb)
{
	if ((options.pnn == CTDB_BROADCAST_ALL) ||
	    (options.pnn == CTDB_MULTICAST)) {
		DEBUG(DEBUG_ERR,
		      ("Cannot get PNN for node %u\n", options.pnn));
		exit(1);
	}

	if (options.pnn == CTDB_CURRENT_NODE) {
		return ctdb_get_pnn(ctdb);
	} else {
		return options.pnn;
	}
}

static void assert_single_node_only(void)
{
	if ((options.pnn == CTDB_BROADCAST_ALL) ||
	    (options.pnn == CTDB_MULTICAST)) {
		DEBUG(DEBUG_ERR,
		      ("This control can not be applied to multiple PNNs\n"));
		exit(1);
	}
}

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
				(void) strncat(flags_str, "|", sizeof(flags_str)-1);
				(void) strncat(flags_str, flag_names[j].name,
					       sizeof(flags_str)-1);
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
			     TALLOC_CTX *mem_ctx,
			     const char * nodestring,
			     uint32_t current_pnn,
			     bool dd_ok,
			     uint32_t **nodes,
			     uint32_t *pnn_mode)
{
	TALLOC_CTX *tmp_ctx = talloc_new(mem_ctx);
	int n;
	uint32_t i;
	struct ctdb_node_map *nodemap;
	int ret;

	*nodes = NULL;

	ret = ctdb_ctrl_getnodemap(ctdb, TIMELIMIT(), CTDB_CURRENT_NODE, tmp_ctx, &nodemap);
	if (ret != 0) {
		DEBUG(DEBUG_ERR, ("Unable to get nodemap from local node\n"));
		talloc_free(tmp_ctx);
		exit(10);
	}

	if (nodestring != NULL) {
		*nodes = talloc_array(mem_ctx, uint32_t, 0);
		if (*nodes == NULL) {
			goto failed;
		}

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
				*nodes = talloc_realloc(mem_ctx, *nodes,
							uint32_t, n+1);
				if (*nodes == NULL) {
					goto failed;
				}
				(*nodes)[n] = i;
				n++;
			}
		} else {
			/* x{,y...} */
			char *ns, *tok;

			ns = talloc_strdup(tmp_ctx, nodestring);
			tok = strtok(ns, ",");
			while (tok != NULL) {
				uint32_t pnn;
				char *endptr;
				i = (uint32_t)strtoul(tok, &endptr, 0);
				if (i == 0 && tok == endptr) {
					DEBUG(DEBUG_ERR,
					      ("Invalid node %s\n", tok));
					talloc_free(tmp_ctx);
					exit(ERR_NONODE);
				}
				if (i >= nodemap->num) {
					DEBUG(DEBUG_ERR, ("Node %u does not exist\n", i));
					talloc_free(tmp_ctx);
					exit(ERR_NONODE);
				}
				if ((nodemap->nodes[i].flags & 
				     (NODE_FLAGS_DISCONNECTED |
				      NODE_FLAGS_DELETED)) && !dd_ok) {
					DEBUG(DEBUG_ERR, ("Node %u has status %s\n", i, pretty_print_flags(nodemap->nodes[i].flags)));
					talloc_free(tmp_ctx);
					exit(ERR_DISNODE);
				}
				if ((pnn = ctdb_ctrl_getpnn(ctdb, TIMELIMIT(), i)) < 0) {
					DEBUG(DEBUG_ERR, ("Can not access node %u. Node is not operational.\n", i));
					talloc_free(tmp_ctx);
					exit(10);
				}

				*nodes = talloc_realloc(mem_ctx, *nodes,
							uint32_t, n+1);
				if (*nodes == NULL) {
					goto failed;
				}

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
		*nodes = talloc_array(mem_ctx, uint32_t, 1);
		if (*nodes == NULL) {
			goto failed;
		}
		*pnn_mode = CTDB_CURRENT_NODE;

		if (((*nodes)[0] = ctdb_ctrl_getpnn(ctdb, TIMELIMIT(), current_pnn)) < 0) {
			goto failed;
		}
	}

	talloc_free(tmp_ctx);
	return true;

failed:
	talloc_free(tmp_ctx);
	return false;
}

/*
 check if a database exists
*/
static bool db_exists(struct ctdb_context *ctdb, const char *dbarg,
		      uint32_t *dbid, const char **dbname, uint8_t *flags)
{
	int i, ret;
	struct ctdb_dbid_map *dbmap=NULL;
	bool dbid_given = false, found = false;
	uint32_t id;
	TALLOC_CTX *tmp_ctx = talloc_new(ctdb);
	const char *name;

	ret = ctdb_ctrl_getdbmap(ctdb, TIMELIMIT(), options.pnn, tmp_ctx, &dbmap);
	if (ret != 0) {
		DEBUG(DEBUG_ERR, ("Unable to get dbids from node %u\n", options.pnn));
		goto fail;
	}

	if (strncmp(dbarg, "0x", 2) == 0) {
		id = strtoul(dbarg, NULL, 0);
		dbid_given = true;
	}

	for(i=0; i<dbmap->num; i++) {
		if (dbid_given) {
			if (id == dbmap->dbs[i].dbid) {
				found = true;
				break;
			}
		} else {
			ret = ctdb_ctrl_getdbname(ctdb, TIMELIMIT(), options.pnn, dbmap->dbs[i].dbid, tmp_ctx, &name);
			if (ret != 0) {
				DEBUG(DEBUG_ERR, ("Unable to get dbname from dbid %u\n", dbmap->dbs[i].dbid));
				goto fail;
			}

			if (strcmp(name, dbarg) == 0) {
				id = dbmap->dbs[i].dbid;
				found = true;
				break;
			}
		}
	}

	if (found && dbid_given && dbname != NULL) {
		ret = ctdb_ctrl_getdbname(ctdb, TIMELIMIT(), options.pnn, dbmap->dbs[i].dbid, tmp_ctx, &name);
		if (ret != 0) {
			DEBUG(DEBUG_ERR, ("Unable to get dbname from dbid %u\n", dbmap->dbs[i].dbid));
			found = false;
			goto fail;
		}
	}

	if (found) {
		if (dbid) *dbid = id;
		if (dbname) *dbname = talloc_strdup(ctdb, name);
		if (flags) *flags = dbmap->dbs[i].flags;
	} else {
		DEBUG(DEBUG_ERR,("No database matching '%s' found\n", dbarg));
	}

fail:
	talloc_free(tmp_ctx);
	return found;
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
			printm("CTDB version:");
			printm("Current time of statistics:");
			printm("Statistics collected since:");
			for (i=0;i<ARRAY_SIZE(fields);i++) {
				printm("%s:", fields[i].name);
			}
			printm("num_reclock_ctdbd_latency:");
			printm("min_reclock_ctdbd_latency:");
			printm("avg_reclock_ctdbd_latency:");
			printm("max_reclock_ctdbd_latency:");

			printm("num_reclock_recd_latency:");
			printm("min_reclock_recd_latency:");
			printm("avg_reclock_recd_latency:");
			printm("max_reclock_recd_latency:");

			printm("num_call_latency:");
			printm("min_call_latency:");
			printm("avg_call_latency:");
			printm("max_call_latency:");

			printm("num_lockwait_latency:");
			printm("min_lockwait_latency:");
			printm("avg_lockwait_latency:");
			printm("max_lockwait_latency:");

			printm("num_childwrite_latency:");
			printm("min_childwrite_latency:");
			printm("avg_childwrite_latency:");
			printm("max_childwrite_latency:");
			printm("\n");
		}
		printm("%d:", CTDB_PROTOCOL);
		printm("%d:", (int)s->statistics_current_time.tv_sec);
		printm("%d:", (int)s->statistics_start_time.tv_sec);
		for (i=0;i<ARRAY_SIZE(fields);i++) {
			printm("%d:", *(uint32_t *)(fields[i].offset+(uint8_t *)s));
		}
		printm("%d:", s->reclock.ctdbd.num);
		printm("%.6f:", s->reclock.ctdbd.min);
		printm("%.6f:", s->reclock.ctdbd.num?s->reclock.ctdbd.total/s->reclock.ctdbd.num:0.0);
		printm("%.6f:", s->reclock.ctdbd.max);

		printm("%d:", s->reclock.recd.num);
		printm("%.6f:", s->reclock.recd.min);
		printm("%.6f:", s->reclock.recd.num?s->reclock.recd.total/s->reclock.recd.num:0.0);
		printm("%.6f:", s->reclock.recd.max);

		printm("%d:", s->call_latency.num);
		printm("%.6f:", s->call_latency.min);
		printm("%.6f:", s->call_latency.num?s->call_latency.total/s->call_latency.num:0.0);
		printm("%.6f:", s->call_latency.max);

		printm("%d:", s->childwrite_latency.num);
		printm("%.6f:", s->childwrite_latency.min);
		printm("%.6f:", s->childwrite_latency.num?s->childwrite_latency.total/s->childwrite_latency.num:0.0);
		printm("%.6f:", s->childwrite_latency.max);
		printm("\n");
	} else {
		printf("CTDB version %u\n", CTDB_PROTOCOL);
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
		printf(" lock_buckets:");
		for (i=0; i<MAX_COUNT_BUCKETS; i++) {
			printf(" %d", s->locks.buckets[i]);
		}
		printf("\n");
		printf(" %-30s     %.6f/%.6f/%.6f sec out of %d\n", "locks_latency      MIN/AVG/MAX", s->locks.latency.min, s->locks.latency.num?s->locks.latency.total/s->locks.latency.num:0.0, s->locks.latency.max, s->locks.latency.num);

		printf(" %-30s     %.6f/%.6f/%.6f sec out of %d\n", "reclock_ctdbd      MIN/AVG/MAX", s->reclock.ctdbd.min, s->reclock.ctdbd.num?s->reclock.ctdbd.total/s->reclock.ctdbd.num:0.0, s->reclock.ctdbd.max, s->reclock.ctdbd.num);

		printf(" %-30s     %.6f/%.6f/%.6f sec out of %d\n", "reclock_recd       MIN/AVG/MAX", s->reclock.recd.min, s->reclock.recd.num?s->reclock.recd.total/s->reclock.recd.num:0.0, s->reclock.recd.max, s->reclock.recd.num);

		printf(" %-30s     %.6f/%.6f/%.6f sec out of %d\n", "call_latency       MIN/AVG/MAX", s->call_latency.min, s->call_latency.num?s->call_latency.total/s->call_latency.num:0.0, s->call_latency.max, s->call_latency.num);
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

	assert_single_node_only();

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
	struct ctdb_db_statistics *dbstat;
	int i;
	uint32_t db_id;
	int num_hot_keys;
	int ret;

	if (argc < 1) {
		usage();
	}

	if (!db_exists(ctdb, argv[0], &db_id, NULL, NULL)) {
		return -1;
	}

	ret = ctdb_ctrl_dbstatistics(ctdb, options.pnn, db_id, tmp_ctx, &dbstat);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,("Failed to read db statistics from node\n"));
		talloc_free(tmp_ctx);
		return -1;
	}

	printf("DB Statistics: %s\n", argv[0]);
	printf(" %*s%-22s%*s%10u\n", 0, "", "ro_delegations", 4, "",
		dbstat->db_ro_delegations);
	printf(" %*s%-22s%*s%10u\n", 0, "", "ro_revokes", 4, "",
		dbstat->db_ro_delegations);
	printf(" %s\n", "locks");
	printf(" %*s%-22s%*s%10u\n", 4, "", "total", 0, "",
		dbstat->locks.num_calls);
	printf(" %*s%-22s%*s%10u\n", 4, "", "failed", 0, "",
		dbstat->locks.num_failed);
	printf(" %*s%-22s%*s%10u\n", 4, "", "current", 0, "",
		dbstat->locks.num_current);
	printf(" %*s%-22s%*s%10u\n", 4, "", "pending", 0, "",
		dbstat->locks.num_pending);
	printf(" %s", "hop_count_buckets:");
	for (i=0; i<MAX_COUNT_BUCKETS; i++) {
		printf(" %d", dbstat->hop_count_bucket[i]);
	}
	printf("\n");
	printf(" %s", "lock_buckets:");
	for (i=0; i<MAX_COUNT_BUCKETS; i++) {
		printf(" %d", dbstat->locks.buckets[i]);
	}
	printf("\n");
	printf(" %-30s     %.6f/%.6f/%.6f sec out of %d\n",
		"locks_latency      MIN/AVG/MAX",
		dbstat->locks.latency.min,
		(dbstat->locks.latency.num ?
		 dbstat->locks.latency.total /dbstat->locks.latency.num :
		 0.0),
		dbstat->locks.latency.max,
		dbstat->locks.latency.num);
	printf(" %-30s     %.6f/%.6f/%.6f sec out of %d\n",
		"vacuum_latency     MIN/AVG/MAX",
		dbstat->vacuum.latency.min,
		(dbstat->vacuum.latency.num ?
		 dbstat->vacuum.latency.total /dbstat->vacuum.latency.num :
		 0.0),
		dbstat->vacuum.latency.max,
		dbstat->vacuum.latency.num);
	num_hot_keys = 0;
	for (i=0; i<dbstat->num_hot_keys; i++) {
		if (dbstat->hot_keys[i].count > 0) {
			num_hot_keys++;
		}
	}
	dbstat->num_hot_keys = num_hot_keys;

	printf(" Num Hot Keys:     %d\n", dbstat->num_hot_keys);
	for (i = 0; i < dbstat->num_hot_keys; i++) {
		int j;
		printf("     Count:%d Key:", dbstat->hot_keys[i].count);
		for (j = 0; j < dbstat->hot_keys[i].key.dsize; j++) {
			printf("%02x", dbstat->hot_keys[i].key.dptr[j]&0xff);
		}
		printf("\n");
	}

	talloc_free(tmp_ctx);
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
		printm(":Current Node Time:Ctdb Start Time:Last Recovery/Failover Time:Last Recovery/IPFailover Duration:\n");
		printm(":%u:%u:%u:%lf\n",
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

	mypnn = getpnn(ctdb);

	printf("PNN:%d\n", mypnn);
	return 0;
}


struct pnn_node {
	struct pnn_node *next, *prev;
	ctdb_sock_addr addr;
	int pnn;
};

static struct pnn_node *read_pnn_node_file(TALLOC_CTX *mem_ctx,
					   const char *file)
{
	int nlines;
	char **lines;
	int i, pnn;
	struct pnn_node *pnn_nodes = NULL;
	struct pnn_node *pnn_node;

	lines = file_lines_load(file, &nlines, 0, mem_ctx);
	if (lines == NULL) {
		return NULL;
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

		if (!parse_ip(node, NULL, 0, &pnn_node->addr)) {
			DEBUG(DEBUG_ERR,
			      ("Invalid IP address '%s' in file %s\n",
			       node, file));
			/* Caller will free mem_ctx */
			return NULL;
		}

		DLIST_ADD_END(pnn_nodes, pnn_node, NULL);
	}

	return pnn_nodes;
}

static struct pnn_node *read_nodes_file(TALLOC_CTX *mem_ctx)
{
	const char *nodes_list;

	/* read the nodes file */
	nodes_list = getenv("CTDB_NODES");
	if (nodes_list == NULL) {
		nodes_list = talloc_asprintf(mem_ctx, "%s/nodes",
					     getenv("CTDB_BASE"));
		if (nodes_list == NULL) {
			DEBUG(DEBUG_ALERT,(__location__ " Out of memory\n"));
			exit(1);
		}
	}

	return read_pnn_node_file(mem_ctx, nodes_list);
}

/*
  show the PNN of the current node
  discover the pnn by loading the nodes file and try to bind to all
  addresses one at a time until the ip address is found.
 */
static int find_node_xpnn(void)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct pnn_node *pnn_nodes;
	struct pnn_node *pnn_node;
	int pnn;

	pnn_nodes = read_nodes_file(mem_ctx);
	if (pnn_nodes == NULL) {
		DEBUG(DEBUG_ERR,("Failed to read nodes file\n"));
		talloc_free(mem_ctx);
		return -1;
	}

	for(pnn_node=pnn_nodes;pnn_node;pnn_node=pnn_node->next) {
		if (ctdb_sys_have_ip(&pnn_node->addr)) {
			pnn = pnn_node->pnn;
			talloc_free(mem_ctx);
			return pnn;
		}
	}

	printf("Failed to detect which PNN this node is\n");
	talloc_free(mem_ctx);
	return -1;
}

static int control_xpnn(struct ctdb_context *ctdb, int argc, const char **argv)
{
	uint32_t pnn;

	assert_single_node_only();

	pnn = find_node_xpnn();
	if (pnn == -1) {
		return -1;
	}

	printf("PNN:%d\n", pnn);
	return 0;
}

/* Helpers for ctdb status
 */
static bool is_partially_online(struct ctdb_context *ctdb, struct ctdb_node_and_flags *node)
{
	TALLOC_CTX *tmp_ctx = talloc_new(NULL);
	int j;
	bool ret = false;

	if (node->flags == 0) {
		struct ctdb_control_get_ifaces *ifaces;

		if (ctdb_ctrl_get_ifaces(ctdb, TIMELIMIT(), node->pnn,
					 tmp_ctx, &ifaces) == 0) {
			for (j=0; j < ifaces->num; j++) {
				if (ifaces->ifaces[j].link_state != 0) {
					continue;
				}
				ret = true;
				break;
			}
		}
	}
	talloc_free(tmp_ctx);

	return ret;
}

static void control_status_header_machine(void)
{
	printm(":Node:IP:Disconnected:Banned:Disabled:Unhealthy:Stopped"
	       ":Inactive:PartiallyOnline:ThisNode:\n");
}

static int control_status_1_machine(struct ctdb_context *ctdb, int mypnn,
				    struct ctdb_node_and_flags *node)
{
	printm(":%d:%s:%d:%d:%d:%d:%d:%d:%d:%c:\n", node->pnn,
	       ctdb_addr_to_str(&node->addr),
	       !!(node->flags&NODE_FLAGS_DISCONNECTED),
	       !!(node->flags&NODE_FLAGS_BANNED),
	       !!(node->flags&NODE_FLAGS_PERMANENTLY_DISABLED),
	       !!(node->flags&NODE_FLAGS_UNHEALTHY),
	       !!(node->flags&NODE_FLAGS_STOPPED),
	       !!(node->flags&NODE_FLAGS_INACTIVE),
	       is_partially_online(ctdb, node) ? 1 : 0,
	       (node->pnn == mypnn)?'Y':'N');

	return node->flags;
}

static int control_status_1_human(struct ctdb_context *ctdb, int mypnn,
				  struct ctdb_node_and_flags *node)
{
       printf("pnn:%d %-16s %s%s\n", node->pnn,
              ctdb_addr_to_str(&node->addr),
              is_partially_online(ctdb, node) ? "PARTIALLYONLINE" : pretty_print_flags(node->flags),
              node->pnn == mypnn?" (THIS NODE)":"");

       return node->flags;
}

/*
  display remote ctdb status
 */
static int control_status(struct ctdb_context *ctdb, int argc, const char **argv)
{
	TALLOC_CTX *tmp_ctx = talloc_new(ctdb);
	int i;
	struct ctdb_vnn_map *vnnmap=NULL;
	struct ctdb_node_map *nodemap=NULL;
	uint32_t recmode, recmaster, mypnn;
	int num_deleted_nodes = 0;
	int ret;

	mypnn = getpnn(ctdb);

	ret = ctdb_ctrl_getnodemap(ctdb, TIMELIMIT(), options.pnn, tmp_ctx, &nodemap);
	if (ret != 0) {
		DEBUG(DEBUG_ERR, ("Unable to get nodemap from node %u\n", options.pnn));
		talloc_free(tmp_ctx);
		return -1;
	}

	if (options.machinereadable) {
		control_status_header_machine();
		for (i=0;i<nodemap->num;i++) {
			if (nodemap->nodes[i].flags & NODE_FLAGS_DELETED) {
				continue;
			}
			(void) control_status_1_machine(ctdb, mypnn,
							&nodemap->nodes[i]);
		}
		talloc_free(tmp_ctx);
		return 0;
	}

	for (i=0; i<nodemap->num; i++) {
		if (nodemap->nodes[i].flags & NODE_FLAGS_DELETED) {
			num_deleted_nodes++;
		}
	}
	if (num_deleted_nodes == 0) {
		printf("Number of nodes:%d\n", nodemap->num);
	} else {
		printf("Number of nodes:%d (including %d deleted nodes)\n",
		       nodemap->num, num_deleted_nodes);
	}
	for(i=0;i<nodemap->num;i++){
		if (nodemap->nodes[i].flags & NODE_FLAGS_DELETED) {
			continue;
		}
		(void) control_status_1_human(ctdb, mypnn, &nodemap->nodes[i]);
	}

	ret = ctdb_ctrl_getvnnmap(ctdb, TIMELIMIT(), options.pnn, tmp_ctx, &vnnmap);
	if (ret != 0) {
		DEBUG(DEBUG_ERR, ("Unable to get vnnmap from node %u\n", options.pnn));
		talloc_free(tmp_ctx);
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

	ret = ctdb_ctrl_getrecmode(ctdb, tmp_ctx, TIMELIMIT(), options.pnn, &recmode);
	if (ret != 0) {
		DEBUG(DEBUG_ERR, ("Unable to get recmode from node %u\n", options.pnn));
		talloc_free(tmp_ctx);
		return -1;
	}
	printf("Recovery mode:%s (%d)\n",recmode==CTDB_RECOVERY_NORMAL?"NORMAL":"RECOVERY",recmode);

	ret = ctdb_ctrl_getrecmaster(ctdb, tmp_ctx, TIMELIMIT(), options.pnn, &recmaster);
	if (ret != 0) {
		DEBUG(DEBUG_ERR, ("Unable to get recmaster from node %u\n", options.pnn));
		talloc_free(tmp_ctx);
		return -1;
	}
	printf("Recovery master:%d\n",recmaster);

	talloc_free(tmp_ctx);
	return 0;
}

static int control_nodestatus(struct ctdb_context *ctdb, int argc, const char **argv)
{
	TALLOC_CTX *tmp_ctx = talloc_new(ctdb);
	int i, ret;
	struct ctdb_node_map *nodemap=NULL;
	uint32_t * nodes;
	uint32_t pnn_mode, mypnn;

	if (argc > 1) {
		usage();
	}

	if (!parse_nodestring(ctdb, tmp_ctx, argc == 1 ? argv[0] : NULL,
			      options.pnn, true, &nodes, &pnn_mode)) {
		return -1;
	}

	if (options.machinereadable) {
		control_status_header_machine();
	} else if (pnn_mode == CTDB_BROADCAST_ALL) {
		printf("Number of nodes:%d\n", (int) talloc_array_length(nodes));
	}

	mypnn = getpnn(ctdb);

	ret = ctdb_ctrl_getnodemap(ctdb, TIMELIMIT(), options.pnn, tmp_ctx, &nodemap);
	if (ret != 0) {
		DEBUG(DEBUG_ERR, ("Unable to get nodemap from node %u\n", options.pnn));
		talloc_free(tmp_ctx);
		return -1;
	}

	ret = 0;

	for (i = 0; i < talloc_array_length(nodes); i++) {
		if (options.machinereadable) {
			ret |= control_status_1_machine(ctdb, mypnn,
							&nodemap->nodes[nodes[i]]);
		} else {
			ret |= control_status_1_human(ctdb, mypnn,
						      &nodemap->nodes[nodes[i]]);
		}
	}

	talloc_free(tmp_ctx);
	return ret;
}

static struct pnn_node *read_natgw_nodes_file(struct ctdb_context *ctdb,
					      TALLOC_CTX *mem_ctx)
{
	const char *natgw_list;
	struct pnn_node *natgw_nodes = NULL;

	natgw_list = getenv("CTDB_NATGW_NODES");
	if (natgw_list == NULL) {
		natgw_list = talloc_asprintf(mem_ctx, "%s/natgw_nodes",
					     getenv("CTDB_BASE"));
		if (natgw_list == NULL) {
			DEBUG(DEBUG_ALERT,(__location__ " Out of memory\n"));
			exit(1);
		}
	}
	/* The PNNs will be junk but they're not used */
	natgw_nodes = read_pnn_node_file(mem_ctx, natgw_list);
	if (natgw_nodes == NULL) {
		DEBUG(DEBUG_ERR,
		      ("Failed to load natgw node list '%s'\n", natgw_list));
	}
	return natgw_nodes;
}


/* talloc off the existing nodemap... */
static struct ctdb_node_map *talloc_nodemap(struct ctdb_node_map *nodemap)
{
	return talloc_zero_size(nodemap,
				offsetof(struct ctdb_node_map, nodes) +
				nodemap->num * sizeof(struct ctdb_node_and_flags));
}

static struct ctdb_node_map *
filter_nodemap_by_addrs(struct ctdb_context *ctdb,
			struct ctdb_node_map *nodemap,
			struct pnn_node *nodes)
{
	int i;
	struct pnn_node *n;
	struct ctdb_node_map *ret;

	ret = talloc_nodemap(nodemap);
	CTDB_NO_MEMORY_NULL(ctdb, ret);

	ret->num = 0;

	for (i = 0; i < nodemap->num; i++) {
		for(n = nodes; n != NULL ; n = n->next) {
			if (ctdb_same_ip(&n->addr,
					 &nodemap->nodes[i].addr)) {
				break;
			}
		}
		if (n == NULL) {
			continue;
		}

		ret->nodes[ret->num] = nodemap->nodes[i];
		ret->num++;
	}

	return ret;
}

static struct ctdb_node_map *
filter_nodemap_by_capabilities(struct ctdb_context *ctdb,
			       struct ctdb_node_map *nodemap,
			       uint32_t required_capabilities,
			       bool first_only)
{
	int i;
	uint32_t capabilities;
	struct ctdb_node_map *ret;

	ret = talloc_nodemap(nodemap);
	CTDB_NO_MEMORY_NULL(ctdb, ret);

	ret->num = 0;

	for (i = 0; i < nodemap->num; i++) {
		int res;

		/* Disconnected nodes have no capabilities! */
		if (nodemap->nodes[i].flags & NODE_FLAGS_DISCONNECTED) {
			continue;
		}

		res = ctdb_ctrl_getcapabilities(ctdb, TIMELIMIT(),
						nodemap->nodes[i].pnn,
						&capabilities);
		if (res != 0) {
			DEBUG(DEBUG_ERR, ("Unable to get capabilities from node %u\n",
					  nodemap->nodes[i].pnn));
			talloc_free(ret);
			return NULL;
		}
		if (!(capabilities & required_capabilities)) {
			continue;
		}

		ret->nodes[ret->num] = nodemap->nodes[i];
		ret->num++;
		if (first_only) {
			break;
		}
	}

	return ret;
}

static struct ctdb_node_map *
filter_nodemap_by_flags(struct ctdb_context *ctdb,
			struct ctdb_node_map *nodemap,
			uint32_t flags_mask)
{
	int i;
	struct ctdb_node_map *ret;

	ret = talloc_nodemap(nodemap);
	CTDB_NO_MEMORY_NULL(ctdb, ret);

	ret->num = 0;

	for (i = 0; i < nodemap->num; i++) {
		if (nodemap->nodes[i].flags & flags_mask) {
			continue;
		}

		ret->nodes[ret->num] = nodemap->nodes[i];
		ret->num++;
	}

	return ret;
}

/*
  display the list of nodes belonging to this natgw configuration
 */
static int control_natgwlist(struct ctdb_context *ctdb, int argc, const char **argv)
{
	TALLOC_CTX *tmp_ctx = talloc_new(ctdb);
	int i, ret;
	struct pnn_node *natgw_nodes = NULL;
	struct ctdb_node_map *orig_nodemap=NULL;
	struct ctdb_node_map *nodemap;
	uint32_t mypnn, pnn;
	const char *ip;

	/* When we have some nodes that could be the NATGW, make a
	 * series of attempts to find the first node that doesn't have
	 * certain status flags set.
	 */
	uint32_t exclude_flags[] = {
		/* Look for a nice healthy node */
		NODE_FLAGS_DISCONNECTED|NODE_FLAGS_STOPPED|NODE_FLAGS_DELETED|NODE_FLAGS_BANNED|NODE_FLAGS_UNHEALTHY,
		/* If not found, an UNHEALTHY/BANNED node will do */
		NODE_FLAGS_DISCONNECTED|NODE_FLAGS_STOPPED|NODE_FLAGS_DELETED,
		/* If not found, a STOPPED node will do */
		NODE_FLAGS_DISCONNECTED|NODE_FLAGS_DELETED,
		0,
	};

	/* read the natgw nodes file into a linked list */
	natgw_nodes = read_natgw_nodes_file(ctdb, tmp_ctx);
	if (natgw_nodes == NULL) {
		ret = -1;
		goto done;
	}

	ret = ctdb_ctrl_getnodemap(ctdb, TIMELIMIT(), CTDB_CURRENT_NODE,
				   tmp_ctx, &orig_nodemap);
	if (ret != 0) {
		DEBUG(DEBUG_ERR, ("Unable to get nodemap from local node.\n"));
		talloc_free(tmp_ctx);
		return -1;
	}

	/* Get a nodemap that includes only the nodes in the NATGW
	 * group */
	nodemap = filter_nodemap_by_addrs(ctdb, orig_nodemap, natgw_nodes);
	if (nodemap == NULL) {
		ret = -1;
		goto done;
	}

	ret = 2; /* matches ENOENT */
	pnn = -1;
	ip = "0.0.0.0";
	/* For each flag mask... */
	for (i = 0; exclude_flags[i] != 0; i++) {
		/* ... get a nodemap that excludes nodes with with
		 * masked flags... */
		struct ctdb_node_map *t =
			filter_nodemap_by_flags(ctdb, nodemap,
						exclude_flags[i]);
		if (t == NULL) {
			/* No memory */
			ret = -1;
			goto done;
		}
		if (t->num > 0) {
			/* ... and find the first node with the NATGW
			 * capability */
			struct ctdb_node_map *n;
			n = filter_nodemap_by_capabilities(ctdb, t,
							   CTDB_CAP_NATGW,
							   true);
			if (n == NULL) {
				/* No memory */
				ret = -1;
				goto done;
			}
			if (n->num > 0) {
				ret = 0;
				pnn = n->nodes[0].pnn;
				ip = ctdb_addr_to_str(&n->nodes[0].addr);
				break;
			}
		}
		talloc_free(t);
	}

	if (options.machinereadable) {
		printm(":Node:IP:\n");
		printm(":%d:%s:\n", pnn, ip);
	} else {
		printf("%d %s\n", pnn, ip);
	}

	/* print the pruned list of nodes belonging to this natgw list */
	mypnn = getpnn(ctdb);
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
			control_status_1_machine(ctdb, mypnn, &(nodemap->nodes[i]));
		} else {
			control_status_1_human(ctdb, mypnn, &(nodemap->nodes[i]));
		}
	}

done:
	talloc_free(tmp_ctx);
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
		int num_run = 0;
		for (i=0; i<script_status->num_scripts; i++) {
			if (script_status->scripts[i].status != -ENOEXEC) {
				num_run++;
			}
		}
		printf("%d scripts were executed last %s cycle\n",
		       num_run,
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
			printm(":%s:%s:%i:%s:%lu.%06lu:%lu.%06lu:%s:\n",
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
		printm(":Type:Name:Code:Status:Start:End:Error Output...:\n");
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
	int ret;

	ret = ctdb_ctrl_getrecmaster(ctdb, ctdb, TIMELIMIT(), options.pnn, &recmaster);
	if (ret != 0) {
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

	assert_single_node_only();

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

	assert_single_node_only();

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

	assert_single_node_only();

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
		printm(":source ip:port:destination ip:port:\n");
		for (i=0;i<list->tickles.num;i++) {
			if (port && port != ntohs(list->tickles.connections[i].dst_addr.ip.sin_port)) {
				continue;
			}
			printm(":%s:%u", ctdb_addr_to_str(&list->tickles.connections[i].src_addr), ntohs(list->tickles.connections[i].src_addr.ip.sin_port));
			printm(":%s:%u:\n", ctdb_addr_to_str(&list->tickles.connections[i].dst_addr), ntohs(list->tickles.connections[i].dst_addr.ip.sin_port));
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

	nodes = list_of_nodes(ctdb, nodemap, tmp_ctx, NODE_FLAGS_INACTIVE, pnn);
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
	int pnn;

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
				pnn = nodemap->nodes[i].pnn;
				talloc_free(tmp_ctx);
				return pnn;
			}
		}
		talloc_free(ips);
	}

	talloc_free(tmp_ctx);
	return -1;
}

/* If pnn is -1 then try to find a node to move IP to... */
static bool try_moveip(struct ctdb_context *ctdb, ctdb_sock_addr *addr, uint32_t pnn)
{
	bool pnn_specified = (pnn == -1 ? false : true);
	int retries = 0;

	while (retries < 5) {
		if (!pnn_specified) {
			pnn = find_other_host_for_public_ip(ctdb, addr);
			if (pnn == -1) {
				return false;
			}
			DEBUG(DEBUG_NOTICE,
			      ("Trying to move public IP to node %u\n", pnn));
		}

		if (move_ip(ctdb, addr, pnn) == 0) {
			return true;
		}

		sleep(3);
		retries++;
	}

	return false;
}


/*
  move/failover an ip address to a specific node
 */
static int control_moveip(struct ctdb_context *ctdb, int argc, const char **argv)
{
	uint32_t pnn;
	ctdb_sock_addr addr;

	assert_single_node_only();

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

	if (!try_moveip(ctdb, &addr, pnn)) {
		DEBUG(DEBUG_ERR,("Failed to move IP to node %d.\n", pnn));
		return -1;
	}

	return 0;
}

static int rebalance_node(struct ctdb_context *ctdb, uint32_t pnn)
{
	TDB_DATA data;

	data.dptr  = (uint8_t *)&pnn;
	data.dsize = sizeof(uint32_t);
	if (ctdb_client_send_message(ctdb, CTDB_BROADCAST_CONNECTED, CTDB_SRVID_REBALANCE_NODE, data) != 0) {
		DEBUG(DEBUG_ERR,
		      ("Failed to send message to force node %u to be a rebalancing target\n",
		       pnn));
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
	TALLOC_CTX *tmp_ctx = talloc_new(ctdb);
	uint32_t *nodes;
	uint32_t pnn_mode;
	int i, ret;

	assert_single_node_only();

	if (argc > 1) {
		usage();
	}

	/* Determine the nodes where IPs need to be reloaded */
	if (!parse_nodestring(ctdb, tmp_ctx, argc == 1 ? argv[0] : NULL,
			      options.pnn, true, &nodes, &pnn_mode)) {
		ret = -1;
		goto done;
	}

	for (i = 0; i < talloc_array_length(nodes); i++) {
		if (!rebalance_node(ctdb, nodes[i])) {
			ret = -1;
		}
	}

done:
	talloc_free(tmp_ctx);
	return ret;
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

	assert_single_node_only();

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


static void ctdb_every_second(struct event_context *ev, struct timed_event *te, struct timeval t, void *p)
{
	struct ctdb_context *ctdb = talloc_get_type(p, struct ctdb_context);

	event_add_timed(ctdb->ev, ctdb, 
				timeval_current_ofs(1, 0),
				ctdb_every_second, ctdb);
}

struct srvid_reply_handler_data {
	bool done;
	bool wait_for_all;
	uint32_t *nodes;
	const char *srvid_str;
};

static void srvid_broadcast_reply_handler(struct ctdb_context *ctdb,
					 uint64_t srvid,
					 TDB_DATA data,
					 void *private_data)
{
	struct srvid_reply_handler_data *d =
		(struct srvid_reply_handler_data *)private_data;
	int i;
	int32_t ret;

	if (data.dsize != sizeof(ret)) {
		DEBUG(DEBUG_ERR, (__location__ " Wrong reply size\n"));
		return;
	}

	/* ret will be a PNN (i.e. >=0) on success, or negative on error */
	ret = *(int32_t *)data.dptr;
	if (ret < 0) {
		DEBUG(DEBUG_ERR,
		      ("%s failed with result %d\n", d->srvid_str, ret));
		return;
	}

	if (!d->wait_for_all) {
		d->done = true;
		return;
	}

	/* Wait for all replies */
	d->done = true;
	for (i = 0; i < talloc_array_length(d->nodes); i++) {
		if (d->nodes[i] == ret) {
			DEBUG(DEBUG_INFO,
			      ("%s reply received from node %u\n",
			       d->srvid_str, ret));
			d->nodes[i] = -1;
		}
		if (d->nodes[i] != -1) {
			/* Found a node that hasn't yet replied */
			d->done = false;
		}
	}
}

/* Broadcast the given SRVID to all connected nodes.  Wait for 1 reply
 * or replies from all connected nodes.  arg is the data argument to
 * pass in the srvid_request structure - pass 0 if this isn't needed.
 */
static int srvid_broadcast(struct ctdb_context *ctdb,
			   uint64_t srvid, uint32_t *arg,
			   const char *srvid_str, bool wait_for_all)
{
	int ret;
	TDB_DATA data;
	uint32_t pnn;
	uint64_t reply_srvid;
	struct srvid_request request;
	struct srvid_request_data request_data;
	struct srvid_reply_handler_data reply_data;
	struct timeval tv;

	ZERO_STRUCT(request);

	/* Time ticks to enable timeouts to be processed */
	event_add_timed(ctdb->ev, ctdb, 
				timeval_current_ofs(1, 0),
				ctdb_every_second, ctdb);

	pnn = ctdb_get_pnn(ctdb);
	reply_srvid = getpid();

	if (arg == NULL) {
		request.pnn = pnn;
		request.srvid = reply_srvid;

		data.dptr = (uint8_t *)&request;
		data.dsize = sizeof(request);
	} else {
		request_data.pnn = pnn;
		request_data.srvid = reply_srvid;
		request_data.data = *arg;

		data.dptr = (uint8_t *)&request_data;
		data.dsize = sizeof(request_data);
	}

	/* Register message port for reply from recovery master */
	ctdb_client_set_message_handler(ctdb, reply_srvid,
					srvid_broadcast_reply_handler,
					&reply_data);

	reply_data.wait_for_all = wait_for_all;
	reply_data.nodes = NULL;
	reply_data.srvid_str = srvid_str;

again:
	reply_data.done = false;

	if (wait_for_all) {
		struct ctdb_node_map *nodemap;

		ret = ctdb_ctrl_getnodemap(ctdb, TIMELIMIT(),
					   CTDB_CURRENT_NODE, ctdb, &nodemap);
		if (ret != 0) {
			DEBUG(DEBUG_ERR,
			      ("Unable to get nodemap from current node, try again\n"));
			sleep(1);
			goto again;
		}

		if (reply_data.nodes != NULL) {
			talloc_free(reply_data.nodes);
		}
		reply_data.nodes = list_of_connected_nodes(ctdb, nodemap,
							   NULL, true);

		talloc_free(nodemap);
	}

	/* Send to all connected nodes. Only recmaster replies */
	ret = ctdb_client_send_message(ctdb, CTDB_BROADCAST_CONNECTED,
				       srvid, data);
	if (ret != 0) {
		/* This can only happen if the socket is closed and
		 * there's no way to recover from that, so don't try
		 * again.
		 */
		DEBUG(DEBUG_ERR,
		      ("Failed to send %s request to connected nodes\n",
		       srvid_str));
		return -1;
	}

	tv = timeval_current();
	/* This loop terminates the reply is received */
	while (timeval_elapsed(&tv) < 5.0 && !reply_data.done) {
		event_loop_once(ctdb->ev);
	}

	if (!reply_data.done) {
		DEBUG(DEBUG_NOTICE,
		      ("Still waiting for confirmation of %s\n", srvid_str));
		sleep(1);
		goto again;
	}

	ctdb_client_remove_message_handler(ctdb, reply_srvid, &reply_data);

	talloc_free(reply_data.nodes);

	return 0;
}

static int ipreallocate(struct ctdb_context *ctdb)
{
	return srvid_broadcast(ctdb, CTDB_SRVID_TAKEOVER_RUN, NULL,
			       "IP reallocation", false);
}


static int control_ipreallocate(struct ctdb_context *ctdb, int argc, const char **argv)
{
	return ipreallocate(ctdb);
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
		ret = ctdb_ctrl_get_public_ips(ctdb, TIMELIMIT(), nodemap->nodes[i].pnn, tmp_ctx, &ips);
		if (ret != 0) {
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
		ret = ctdb_ctrl_get_public_ips(ctdb, TIMELIMIT(), nodemap->nodes[i].pnn, tmp_ctx, &ips);
		if (ret != 0) {
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

	/* This is an optimisation.  If this node is hosting the IP
	 * then try to move it somewhere else without invoking a full
	 * takeover run.  We don't care if this doesn't work!
	 */
	if (ips->ips[i].pnn == options.pnn) {
		(void) try_moveip(ctdb, &addr, -1);
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

static int kill_tcp_from_file(struct ctdb_context *ctdb,
			      int argc, const char **argv)
{
	struct ctdb_control_killtcp *killtcp;
	int max_entries, current, i;
	struct timeval timeout;
	char line[128], src[128], dst[128];
	int linenum;
	TDB_DATA data;
	struct client_async_data *async_data;
	struct ctdb_client_control_state *state;

	if (argc != 0) {
		usage();
	}

	linenum = 1;
	killtcp = NULL;
	max_entries = 0;
	current = 0;
	while (!feof(stdin)) {
		if (fgets(line, sizeof(line), stdin) == NULL) {
			continue;
		}

		/* Silently skip empty lines */
		if (line[0] == '\n') {
			continue;
		}

		if (sscanf(line, "%s %s\n", src, dst) != 2) {
			DEBUG(DEBUG_ERR, ("Bad line [%d]: '%s'\n",
					  linenum, line));
			talloc_free(killtcp);
			return -1;
		}

		if (current >= max_entries) {
			max_entries += 1024;
			killtcp = talloc_realloc(ctdb, killtcp,
						 struct ctdb_control_killtcp,
						 max_entries);
			CTDB_NO_MEMORY(ctdb, killtcp);
		}

		if (!parse_ip_port(src, &killtcp[current].src_addr)) {
			DEBUG(DEBUG_ERR, ("Bad IP:port on line [%d]: '%s'\n",
					  linenum, src));
			talloc_free(killtcp);
			return -1;
		}

		if (!parse_ip_port(dst, &killtcp[current].dst_addr)) {
			DEBUG(DEBUG_ERR, ("Bad IP:port on line [%d]: '%s'\n",
					  linenum, dst));
			talloc_free(killtcp);
			return -1;
		}

		current++;
	}

	async_data = talloc_zero(ctdb, struct client_async_data);
	if (async_data == NULL) {
		talloc_free(killtcp);
		return -1;
	}

	for (i = 0; i < current; i++) {

		data.dsize = sizeof(struct ctdb_control_killtcp);
		data.dptr  = (unsigned char *)&killtcp[i];

		timeout = TIMELIMIT();
		state = ctdb_control_send(ctdb, options.pnn, 0,
					  CTDB_CONTROL_KILL_TCP, 0, data,
					  async_data, &timeout, NULL);

		if (state == NULL) {
			DEBUG(DEBUG_ERR,
			      ("Failed to call async killtcp control to node %u\n",
			       options.pnn));
			talloc_free(killtcp);
			return -1;
		}
		
		ctdb_client_async_add(async_data, state);
	}

	if (ctdb_client_async_wait(ctdb, async_data) != 0) {
		DEBUG(DEBUG_ERR,("killtcp failed\n"));
		talloc_free(killtcp);
		return -1;
	}

	talloc_free(killtcp);
	return 0;
}


/*
  kill a tcp connection
 */
static int kill_tcp(struct ctdb_context *ctdb, int argc, const char **argv)
{
	int ret;
	struct ctdb_control_killtcp killtcp;

	assert_single_node_only();

	if (argc == 0) {
		return kill_tcp_from_file(ctdb, argc, argv);
	}

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

	assert_single_node_only();

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

	if (!ctdb_client_check_message_handlers(ctdb, ids, argc, result)) {
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
		printm(":Public IP:Node:");
		if (options.verbose){
			printm("ActiveInterface:AvailableInterfaces:ConfiguredInterfaces:");
		}
		printm("\n");
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
			printm(":%s:%d:",
				ctdb_addr_to_str(&ips->ips[ips->num-i].addr),
				ips->ips[ips->num-i].pnn);
			if (options.verbose){
				printm("%s:%s:%s:",
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
	TALLOC_CTX *tmp_ctx = talloc_new(ctdb);
	int i;
	struct ctdb_control_get_ifaces *ifaces;
	int ret;

	/* read the public ip list from this node */
	ret = ctdb_ctrl_get_ifaces(ctdb, TIMELIMIT(), options.pnn, tmp_ctx, &ifaces);
	if (ret != 0) {
		DEBUG(DEBUG_ERR, ("Unable to get interfaces from node %u\n",
				  options.pnn));
		talloc_free(tmp_ctx);
		return -1;
	}

	if (options.machinereadable){
		printm(":Name:LinkStatus:References:\n");
	} else {
		printf("Interfaces on node %u\n", options.pnn);
	}

	for (i=0; i<ifaces->num; i++) {
		if (options.machinereadable){
			printm(":%s:%s:%u:\n",
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

	talloc_free(tmp_ctx);
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

typedef bool update_flags_handler_t(struct ctdb_context *ctdb, void *data);

static int update_flags_and_ipreallocate(struct ctdb_context *ctdb,
					      void *data,
					      update_flags_handler_t handler,
					      uint32_t flag,
					      const char *desc,
					      bool set_flag)
{
	struct ctdb_node_map *nodemap = NULL;
	bool flag_is_set;
	int ret;

	/* Check if the node is already in the desired state */
	ret = ctdb_ctrl_getnodemap(ctdb, TIMELIMIT(), CTDB_CURRENT_NODE, ctdb, &nodemap);
	if (ret != 0) {
		DEBUG(DEBUG_ERR, ("Unable to get nodemap from local node\n"));
		exit(10);
	}
	flag_is_set = nodemap->nodes[options.pnn].flags & flag;
	if (set_flag == flag_is_set) {
		DEBUG(DEBUG_NOTICE, ("Node %d is %s %s\n", options.pnn,
				     (set_flag ? "already" : "not"), desc));
		return 0;
	}

	do {
		if (!handler(ctdb, data)) {
			DEBUG(DEBUG_WARNING,
			      ("Failed to send control to set state %s on node %u, try again\n",
			       desc, options.pnn));
		}

		sleep(1);

		/* Read the nodemap and verify the change took effect.
		 * Even if the above control/hanlder timed out then it
		 * could still have worked!
		 */
		ret = ctdb_ctrl_getnodemap(ctdb, TIMELIMIT(), CTDB_CURRENT_NODE,
					 ctdb, &nodemap);
		if (ret != 0) {
			DEBUG(DEBUG_WARNING,
			      ("Unable to get nodemap from local node, try again\n"));
		}
		flag_is_set = nodemap->nodes[options.pnn].flags & flag;
	} while (nodemap == NULL || (set_flag != flag_is_set));

	return ipreallocate(ctdb);
}

/* Administratively disable a node */
static bool update_flags_disabled(struct ctdb_context *ctdb, void *data)
{
	int ret;

	ret = ctdb_ctrl_modflags(ctdb, TIMELIMIT(), options.pnn,
				 NODE_FLAGS_PERMANENTLY_DISABLED, 0);
	return ret == 0;
}

static int control_disable(struct ctdb_context *ctdb, int argc, const char **argv)
{
	return update_flags_and_ipreallocate(ctdb, NULL,
						  update_flags_disabled,
						  NODE_FLAGS_PERMANENTLY_DISABLED,
						  "disabled",
						  true /* set_flag*/);
}

/* Administratively re-enable a node */
static bool update_flags_not_disabled(struct ctdb_context *ctdb, void *data)
{
	int ret;

	ret = ctdb_ctrl_modflags(ctdb, TIMELIMIT(), options.pnn,
				 0, NODE_FLAGS_PERMANENTLY_DISABLED);
	return ret == 0;
}

static int control_enable(struct ctdb_context *ctdb,  int argc, const char **argv)
{
	return update_flags_and_ipreallocate(ctdb, NULL,
						  update_flags_not_disabled,
						  NODE_FLAGS_PERMANENTLY_DISABLED,
						  "disabled",
						  false /* set_flag*/);
}

/* Stop a node */
static bool update_flags_stopped(struct ctdb_context *ctdb, void *data)
{
	int ret;

	ret = ctdb_ctrl_stop_node(ctdb, TIMELIMIT(), options.pnn);

	return ret == 0;
}

static int control_stop(struct ctdb_context *ctdb, int argc, const char **argv)
{
	return update_flags_and_ipreallocate(ctdb, NULL,
						  update_flags_stopped,
						  NODE_FLAGS_STOPPED,
						  "stopped",
						  true /* set_flag*/);
}

/* Continue a stopped node */
static bool update_flags_not_stopped(struct ctdb_context *ctdb, void *data)
{
	int ret;

	ret = ctdb_ctrl_continue_node(ctdb, TIMELIMIT(), options.pnn);

	return ret == 0;
}

static int control_continue(struct ctdb_context *ctdb, int argc, const char **argv)
{
	return update_flags_and_ipreallocate(ctdb, NULL,
						  update_flags_not_stopped,
						  NODE_FLAGS_STOPPED,
						  "stopped",
						  false /* set_flag */);
}

static uint32_t get_generation(struct ctdb_context *ctdb)
{
	TALLOC_CTX *tmp_ctx = talloc_new(ctdb);
	struct ctdb_vnn_map *vnnmap=NULL;
	int ret;
	uint32_t generation;

	/* wait until the recmaster is not in recovery mode */
	while (1) {
		uint32_t recmode, recmaster;
		
		if (vnnmap != NULL) {
			talloc_free(vnnmap);
			vnnmap = NULL;
		}

		/* get the recmaster */
		ret = ctdb_ctrl_getrecmaster(ctdb, tmp_ctx, TIMELIMIT(), CTDB_CURRENT_NODE, &recmaster);
		if (ret != 0) {
			DEBUG(DEBUG_ERR, ("Unable to get recmaster from node %u\n", options.pnn));
			talloc_free(tmp_ctx);
			exit(10);
		}

		/* get recovery mode */
		ret = ctdb_ctrl_getrecmode(ctdb, tmp_ctx, TIMELIMIT(), recmaster, &recmode);
		if (ret != 0) {
			DEBUG(DEBUG_ERR, ("Unable to get recmode from node %u\n", options.pnn));
			talloc_free(tmp_ctx);
			exit(10);
		}

		/* get the current generation number */
		ret = ctdb_ctrl_getvnnmap(ctdb, TIMELIMIT(), recmaster, tmp_ctx, &vnnmap);
		if (ret != 0) {
			DEBUG(DEBUG_ERR, ("Unable to get vnnmap from recmaster (%u)\n", recmaster));
			talloc_free(tmp_ctx);
			exit(10);
		}

		if ((recmode == CTDB_RECOVERY_NORMAL) && (vnnmap->generation != 1)) {
			generation = vnnmap->generation;
			talloc_free(tmp_ctx);
			return generation;
		}
		sleep(1);
	}
}

/* Ban a node */
static bool update_state_banned(struct ctdb_context *ctdb, void *data)
{
	struct ctdb_ban_time *bantime = (struct ctdb_ban_time *)data;
	int ret;

	ret = ctdb_ctrl_set_ban(ctdb, TIMELIMIT(), options.pnn, bantime);

	return ret == 0;
}

static int control_ban(struct ctdb_context *ctdb, int argc, const char **argv)
{
	struct ctdb_ban_time bantime;

	if (argc < 1) {
		usage();
	}
	
	bantime.pnn  = options.pnn;
	bantime.time = strtoul(argv[0], NULL, 0);

	if (bantime.time == 0) {
		DEBUG(DEBUG_ERR, ("Invalid ban time specified - must be >0\n"));
		return -1;
	}

	return update_flags_and_ipreallocate(ctdb, &bantime,
						  update_state_banned,
						  NODE_FLAGS_BANNED,
						  "banned",
						  true /* set_flag*/);
}


/* Unban a node */
static int control_unban(struct ctdb_context *ctdb, int argc, const char **argv)
{
	struct ctdb_ban_time bantime;

	bantime.pnn  = options.pnn;
	bantime.time = 0;

	return update_flags_and_ipreallocate(ctdb, &bantime,
						  update_state_banned,
						  NODE_FLAGS_BANNED,
						  "banned",
						  false /* set_flag*/);
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
		printf("Node %u is banned, %d seconds remaining\n",
		       bantime->pnn, bantime->time);
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
		printm(":mode:\n");
		printm(":%d:\n",monmode);
	}
	return 0;
}


/*
  display capabilities of a remote node
 */
static int control_getcapabilities(struct ctdb_context *ctdb, int argc, const char **argv)
{
	uint32_t capabilities;
	int ret;

	ret = ctdb_ctrl_getcapabilities(ctdb, TIMELIMIT(), options.pnn, &capabilities);
	if (ret != 0) {
		DEBUG(DEBUG_ERR, ("Unable to get capabilities from node %u\n", options.pnn));
		return -1;
	}
	
	if (!options.machinereadable){
		printf("RECMASTER: %s\n", (capabilities&CTDB_CAP_RECMASTER)?"YES":"NO");
		printf("LMASTER: %s\n", (capabilities&CTDB_CAP_LMASTER)?"YES":"NO");
		printf("LVS: %s\n", (capabilities&CTDB_CAP_LVS)?"YES":"NO");
		printf("NATGW: %s\n", (capabilities&CTDB_CAP_NATGW)?"YES":"NO");
	} else {
		printm(":RECMASTER:LMASTER:LVS:NATGW:\n");
		printm(":%d:%d:%d:%d:\n",
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

static uint32_t lvs_exclude_flags[] = {
	/* Look for a nice healthy node */
	NODE_FLAGS_INACTIVE|NODE_FLAGS_DISABLED,
	/* If not found, an UNHEALTHY node will do */
	NODE_FLAGS_INACTIVE|NODE_FLAGS_PERMANENTLY_DISABLED,
	0,
};

static int control_lvs(struct ctdb_context *ctdb, int argc, const char **argv)
{
	TALLOC_CTX *tmp_ctx = talloc_new(ctdb);
	struct ctdb_node_map *orig_nodemap=NULL;
	struct ctdb_node_map *nodemap;
	int i, ret;

	ret = ctdb_ctrl_getnodemap(ctdb, TIMELIMIT(), options.pnn,
				   tmp_ctx, &orig_nodemap);
	if (ret != 0) {
		DEBUG(DEBUG_ERR, ("Unable to get nodemap from node %u\n", options.pnn));
		talloc_free(tmp_ctx);
		return -1;
	}

	nodemap = filter_nodemap_by_capabilities(ctdb, orig_nodemap,
						 CTDB_CAP_LVS, false);
	if (nodemap == NULL) {
		/* No memory */
		ret = -1;
		goto done;
	}

	ret = 0;

	for (i = 0; lvs_exclude_flags[i] != 0; i++) {
		struct ctdb_node_map *t =
			filter_nodemap_by_flags(ctdb, nodemap,
						lvs_exclude_flags[i]);
		if (t == NULL) {
			/* No memory */
			ret = -1;
			goto done;
		}
		if (t->num > 0) {
			/* At least 1 node without excluded flags */
			int j;
			for (j = 0; j < t->num; j++) {
				printf("%d:%s\n", t->nodes[j].pnn, 
				       ctdb_addr_to_str(&t->nodes[j].addr));
			}
			goto done;
		}
		talloc_free(t);
	}
done:
	talloc_free(tmp_ctx);
	return ret;
}

/*
  display who is the lvs master
 */
static int control_lvsmaster(struct ctdb_context *ctdb, int argc, const char **argv)
{
	TALLOC_CTX *tmp_ctx = talloc_new(ctdb);
	struct ctdb_node_map *nodemap=NULL;
	int i, ret;

	ret = ctdb_ctrl_getnodemap(ctdb, TIMELIMIT(), options.pnn,
				   tmp_ctx, &nodemap);
	if (ret != 0) {
		DEBUG(DEBUG_ERR, ("Unable to get nodemap from node %u\n", options.pnn));
		talloc_free(tmp_ctx);
		return -1;
	}

	for (i = 0; lvs_exclude_flags[i] != 0; i++) {
		struct ctdb_node_map *t =
			filter_nodemap_by_flags(ctdb, nodemap,
						lvs_exclude_flags[i]);
		if (t == NULL) {
			/* No memory */
			ret = -1;
			goto done;
		}
		if (t->num > 0) {
			struct ctdb_node_map *n;
			n = filter_nodemap_by_capabilities(ctdb,
							   t,
							   CTDB_CAP_LVS,
							   true);
			if (n == NULL) {
				/* No memory */
				ret = -1;
				goto done;
			}
			if (n->num > 0) {
				ret = 0;
				if (options.machinereadable) {
					printm("%d\n", n->nodes[0].pnn);
				} else {
					printf("Node %d is LVS master\n", n->nodes[0].pnn);
				}
				goto done;
			}
		}
		talloc_free(t);
	}

	printf("There is no LVS master\n");
	ret = 255;
done:
	talloc_free(tmp_ctx);
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
	struct ctdb_dump_db_context c;
	uint8_t flags;

	if (argc < 1) {
		usage();
	}

	if (!db_exists(ctdb, argv[0], NULL, &db_name, &flags)) {
		return -1;
	}

	ctdb_db = ctdb_attach(ctdb, TIMELIMIT(), db_name, flags & CTDB_DB_FLAGS_PERSISTENT, 0);
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
	uint8_t flags;

	if (argc < 1) {
		usage();
	}

	if (!db_exists(ctdb, argv[0], NULL, &db_name, &flags)) {
		return -1;
	}

	ctdb_db = ctdb_attach(ctdb, TIMELIMIT(), db_name, flags & CTDB_DB_FLAGS_PERSISTENT, 0);
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
	uint8_t flags;

	if (argc < 2) {
		usage();
	}

	if (!db_exists(ctdb, argv[0], NULL, &db_name, &flags)) {
		return -1;
	}

	ctdb_db = ctdb_attach(ctdb, TIMELIMIT(), db_name, flags & CTDB_DB_FLAGS_PERSISTENT, 0);
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

	printf("Data: size:%d ptr:[%.*s]\n", (int)data.dsize, (int)data.dsize, data.dptr);

	talloc_free(tmp_ctx);
	talloc_free(ctdb_db);
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
	uint8_t flags;

	if (argc < 3) {
		usage();
	}

	if (!db_exists(ctdb, argv[0], NULL, &db_name, &flags)) {
		return -1;
	}

	ctdb_db = ctdb_attach(ctdb, TIMELIMIT(), db_name, flags & CTDB_DB_FLAGS_PERSISTENT, 0);
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
	talloc_free(tmp_ctx);
	talloc_free(ctdb_db);
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
	uint8_t flags;

	if (argc < 2) {
		talloc_free(tmp_ctx);
		usage();
	}

	if (!db_exists(ctdb, argv[0], NULL, &db_name, &flags)) {
		talloc_free(tmp_ctx);
		return -1;
	}

	persistent = flags & CTDB_DB_FLAGS_PERSISTENT;
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
		sys_write(fd, data.dptr, data.dsize);
		close(fd);
	} else {
		sys_write(1, data.dptr, data.dsize);
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
			sys_write(fd, data.dptr, data.dsize);
		} else {
			sys_write(fd, data.dptr+sizeof(struct ctdb_ltdb_header), data.dsize-sizeof(struct ctdb_ltdb_header));
		}
		close(fd);
	} else {
		if (options.verbose){
			sys_write(1, data.dptr, data.dsize);
		} else {
			sys_write(1, data.dptr+sizeof(struct ctdb_ltdb_header), data.dsize-sizeof(struct ctdb_ltdb_header));
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
	TDB_DATA key, value, data;
	TALLOC_CTX *tmp_ctx = talloc_new(NULL);
	struct ctdb_ltdb_header header;

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
		value = hextodata(tmp_ctx, argv[2] + 2);
		if (value.dsize == 0) {
			printf("Failed to convert \"%s\" into a TDB_DATA\n", argv[2]);
			return -1;
		}
	} else {
		value.dptr  = discard_const(argv[2]);
		value.dsize = strlen(argv[2]);
	}

	ZERO_STRUCT(header);
	if (argc > 3) {
		header.rsn = atoll(argv[3]);
	}
	if (argc > 4) {
		header.dmaster = atoi(argv[4]);
	}
	if (argc > 5) {
		header.flags = atoi(argv[5]);
	}

	data.dsize = sizeof(struct ctdb_ltdb_header) + value.dsize;
	data.dptr = talloc_size(tmp_ctx, data.dsize);
	if (data.dptr == NULL) {
		printf("Failed to allocate header+value\n");
		return -1;
	}

	*(struct ctdb_ltdb_header *)data.dptr = header;
	memcpy(data.dptr + sizeof(struct ctdb_ltdb_header), value.dptr, value.dsize);

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
		ret = sys_read(fd, data.dptr, data.dsize);
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
 * delete a record from a persistent database
 */
static int control_pdelete(struct ctdb_context *ctdb, int argc, const char **argv)
{
	const char *db_name;
	struct ctdb_db_context *ctdb_db;
	TALLOC_CTX *tmp_ctx = talloc_new(ctdb);
	struct ctdb_transaction_handle *h;
	TDB_DATA key;
	int ret;
	bool persistent;
	uint8_t flags;

	if (argc < 2) {
		talloc_free(tmp_ctx);
		usage();
	}

	if (!db_exists(ctdb, argv[0], NULL, &db_name, &flags)) {
		talloc_free(tmp_ctx);
		return -1;
	}

	persistent = flags & CTDB_DB_FLAGS_PERSISTENT;
	if (!persistent) {
		DEBUG(DEBUG_ERR, ("Database '%s' is not persistent\n", db_name));
		talloc_free(tmp_ctx);
		return -1;
	}

	ctdb_db = ctdb_attach(ctdb, TIMELIMIT(), db_name, persistent, 0);
	if (ctdb_db == NULL) {
		DEBUG(DEBUG_ERR, ("Unable to attach to database '%s'\n", db_name));
		talloc_free(tmp_ctx);
		return -1;
	}

	h = ctdb_transaction_start(ctdb_db, tmp_ctx);
	if (h == NULL) {
		DEBUG(DEBUG_ERR, ("Failed to start transaction on database %s\n", db_name));
		talloc_free(tmp_ctx);
		return -1;
	}

	key.dptr = discard_const(argv[1]);
	key.dsize = strlen(argv[1]);
	ret = ctdb_transaction_store(h, key, tdb_null);
	if (ret != 0) {
		DEBUG(DEBUG_ERR, ("Failed to delete record\n"));
		talloc_free(tmp_ctx);
		return -1;
	}

	ret = ctdb_transaction_commit(h);
	if (ret != 0) {
		DEBUG(DEBUG_ERR, ("Failed to commit transaction\n"));
		talloc_free(tmp_ctx);
		return -1;
	}

	talloc_free(tmp_ctx);
	return 0;
}

static const char *ptrans_parse_string(TALLOC_CTX *mem_ctx, const char *s,
				       TDB_DATA *data)
{
	const char *t;
	size_t n;
	const char *ret; /* Next byte after successfully parsed value */

	/* Error, unless someone says otherwise */
	ret = NULL;
	/* Indicates no value to parse */
	*data = tdb_null;

	/* Skip whitespace */
	n = strspn(s, " \t");
	t = s + n;

	if (t[0] == '"') {
		/* Quoted ASCII string - no wide characters! */
		t++;
		n = strcspn(t, "\"");
		if (t[n] == '"') {
			if (n > 0) {
				data->dsize = n;
				data->dptr = talloc_memdup(mem_ctx, t, n);
				CTDB_NOMEM_ABORT(data->dptr);
			}
			ret = t + n + 1;
		} else {
			DEBUG(DEBUG_WARNING,("Unmatched \" in input %s\n", s));
		}
	} else {
		DEBUG(DEBUG_WARNING,("Unsupported input format in %s\n", s));
	}

	return ret;
}

static bool ptrans_get_key_value(TALLOC_CTX *mem_ctx, FILE *file,
				 TDB_DATA *key, TDB_DATA *value)
{
	char line [1024]; /* FIXME: make this more flexible? */
	const char *t;
	char *ptr;

	ptr = fgets(line, sizeof(line), file);

	if (ptr == NULL) {
		return false;
	}

	/* Get key */
	t = ptrans_parse_string(mem_ctx, line, key);
	if (t == NULL || key->dptr == NULL) {
		/* Line Ignored but not EOF */
		return true;
	}

	/* Get value */
	t = ptrans_parse_string(mem_ctx, t, value);
	if (t == NULL) {
		/* Line Ignored but not EOF */
		talloc_free(key->dptr);
		*key = tdb_null;
		return true;
	}

	return true;
}

/*
 * Update a persistent database as per file/stdin
 */
static int control_ptrans(struct ctdb_context *ctdb,
			  int argc, const char **argv)
{
	const char *db_name;
	struct ctdb_db_context *ctdb_db;
	TALLOC_CTX *tmp_ctx = talloc_new(ctdb);
	struct ctdb_transaction_handle *h;
	TDB_DATA key, value;
	FILE *file;
	int ret;

	if (argc < 1) {
		talloc_free(tmp_ctx);
		usage();
	}

	file = stdin;
	if (argc == 2) {
		file = fopen(argv[1], "r");
		if (file == NULL) {
			DEBUG(DEBUG_ERR,("Unable to open file for reading '%s'\n", argv[1]));
			talloc_free(tmp_ctx);
			return -1;
		}
	}

	db_name = argv[0];

	ctdb_db = ctdb_attach(ctdb, TIMELIMIT(), db_name, true, 0);
	if (ctdb_db == NULL) {
		DEBUG(DEBUG_ERR,("Unable to attach to database '%s'\n", db_name));
		goto error;
	}

	h = ctdb_transaction_start(ctdb_db, tmp_ctx);
	if (h == NULL) {
		DEBUG(DEBUG_ERR,("Failed to start transaction on database %s\n", db_name));
		goto error;
	}

	while (ptrans_get_key_value(tmp_ctx, file, &key, &value)) {
		if (key.dsize != 0) {
			ret = ctdb_transaction_store(h, key, value);
			/* Minimise memory use */
			talloc_free(key.dptr);
			if (value.dptr != NULL) {
				talloc_free(value.dptr);
			}
			if (ret != 0) {
				DEBUG(DEBUG_ERR,("Failed to store record\n"));
				ctdb_transaction_cancel(h);
				goto error;
			}
		}
	}

	ret = ctdb_transaction_commit(h);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,("Failed to commit transaction\n"));
		goto error;
	}

	if (file != stdin) {
		fclose(file);
	}
	talloc_free(tmp_ctx);
	return 0;

error:
	if (file != stdin) {
		fclose(file);
	}

	talloc_free(tmp_ctx);
	return -1;
}

/*
  check if a service is bound to a port or not
 */
static int control_chktcpport(struct ctdb_context *ctdb, int argc, const char **argv)
{
	int s, ret;
	int v;
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
	if (v == -1 || fcntl(s, F_SETFL, v | O_NONBLOCK) != 0) {
		printf("Unable to set socket non-blocking: %s\n", strerror(errno));
	}

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


/* Reload public IPs on a specified nodes */
static int control_reloadips(struct ctdb_context *ctdb, int argc, const char **argv)
{
	TALLOC_CTX *tmp_ctx = talloc_new(ctdb);
	uint32_t *nodes;
	uint32_t pnn_mode;
	uint32_t timeout;
	int ret;

	assert_single_node_only();

	if (argc > 1) {
		usage();
	}

	/* Determine the nodes where IPs need to be reloaded */
	if (!parse_nodestring(ctdb, tmp_ctx, argc == 1 ? argv[0] : NULL,
			      options.pnn, true, &nodes, &pnn_mode)) {
		ret = -1;
		goto done;
	}

again:
	/* Disable takeover runs on all connected nodes.  A reply
	 * indicating success is needed from each node so all nodes
	 * will need to be active.  This will retry until maxruntime
	 * is exceeded, hence no error handling.
	 * 
	 * A check could be added to not allow reloading of IPs when
	 * there are disconnected nodes.  However, this should
	 * probably be left up to the administrator.
	 */
	timeout = LONGTIMEOUT;
	srvid_broadcast(ctdb, CTDB_SRVID_DISABLE_TAKEOVER_RUNS, &timeout,
			"Disable takeover runs", true);

	/* Now tell all the desired nodes to reload their public IPs.
	 * Keep trying this until it succeeds.  This assumes all
	 * failures are transient, which might not be true...
	 */
	if (ctdb_client_async_control(ctdb, CTDB_CONTROL_RELOAD_PUBLIC_IPS,
				      nodes, 0, LONGTIMELIMIT(),
				      false, tdb_null,
				      NULL, NULL, NULL) != 0) {
		DEBUG(DEBUG_ERR,
		      ("Unable to reload IPs on some nodes, try again.\n"));
		goto again;
	}

	/* It isn't strictly necessary to wait until takeover runs are
	 * re-enabled but doing so can't hurt.
	 */
	timeout = 0;
	srvid_broadcast(ctdb, CTDB_SRVID_DISABLE_TAKEOVER_RUNS, &timeout,
			"Enable takeover runs", true);

	ipreallocate(ctdb);

	ret = 0;
done:
	talloc_free(tmp_ctx);
	return ret;
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
		printm(":ID:Name:Path:Persistent:Sticky:Unhealthy:ReadOnly:\n");
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
			printm(":0x%08X:%s:%s:%d:%d:%d:%d:\n",
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
	const char *db_name;
	uint32_t db_id;
	uint8_t flags;
	const char *path;
	const char *health;

	if (argc < 1) {
		usage();
	}

	if (!db_exists(ctdb, argv[0], &db_id, &db_name, &flags)) {
		return -1;
	}

	ctdb_ctrl_getdbpath(ctdb, TIMELIMIT(), options.pnn, db_id, ctdb, &path);
	ctdb_ctrl_getdbhealth(ctdb, TIMELIMIT(), options.pnn, db_id, ctdb, &health);
	printf("dbid: 0x%08x\nname: %s\npath: %s\nPERSISTENT: %s\nSTICKY: %s\nREADONLY: %s\nHEALTH: %s\n",
	       db_id, db_name, path,
	       (flags & CTDB_DB_FLAGS_PERSISTENT ? "yes" : "no"),
	       (flags & CTDB_DB_FLAGS_STICKY ? "yes" : "no"),
	       (flags & CTDB_DB_FLAGS_READONLY ? "yes" : "no"),
	       (health ? health : "OK"));

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
	int ret;

	assert_single_node_only();

	mypnn = getpnn(ctdb);

	ret = ctdb_ctrl_getrecmaster(ctdb, ctdb, TIMELIMIT(), options.pnn, &recmaster);
	if (ret != 0) {
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
  get a node's runstate
 */
static int control_runstate(struct ctdb_context *ctdb, int argc, const char **argv)
{
	int ret;
	enum ctdb_runstate runstate;

	ret = ctdb_ctrl_get_runstate(ctdb, TIMELIMIT(), options.pnn, &runstate);
	if (ret == -1) {
		printf("Unable to get runstate response from node %u\n",
		       options.pnn);
		return -1;
	} else {
		bool found = true;
		enum ctdb_runstate t;
		int i;
		for (i=0; i<argc; i++) {
			found = false;
			t = runstate_from_string(argv[i]);
			if (t == CTDB_RUNSTATE_UNKNOWN) {
				printf("Invalid run state (%s)\n", argv[i]);
				return -1;
			}

			if (t == runstate) {
				found = true;
				break;
			}
		}

		if (!found) {
			printf("CTDB not in required run state (got %s)\n", 
			       runstate_to_string((enum ctdb_runstate)runstate));
			return -1;
		}
	}

	printf("%s\n", runstate_to_string(runstate));
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
	if (ret != 0) {
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
			printm(":Name:Level:\n");
			printm(":%s:%d:\n",get_debug_by_level(level),level);
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
				printm("%s", reclock);
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
 * detach from a database
 */
static int control_detach(struct ctdb_context *ctdb, int argc,
			  const char **argv)
{
	uint32_t db_id;
	uint8_t flags;
	int ret, i, status = 0;
	struct ctdb_node_map *nodemap = NULL;
	TALLOC_CTX *tmp_ctx = talloc_new(ctdb);
	uint32_t recmode;

	if (argc < 1) {
		usage();
	}

	assert_single_node_only();

	ret = ctdb_ctrl_getrecmode(ctdb, tmp_ctx, TIMELIMIT(), options.pnn,
				    &recmode);
	if (ret != 0) {
		DEBUG(DEBUG_ERR, ("Database cannot be detached "
				  "when recovery is active\n"));
		talloc_free(tmp_ctx);
		return -1;
	}

	ret = ctdb_ctrl_getnodemap(ctdb, TIMELIMIT(), options.pnn, tmp_ctx,
				   &nodemap);
	if (ret != 0) {
		DEBUG(DEBUG_ERR, ("Unable to get nodemap from node %u\n",
				  options.pnn));
		talloc_free(tmp_ctx);
		return -1;
	}

	for (i=0; i<nodemap->num; i++) {
		uint32_t value;

		if (nodemap->nodes[i].flags & NODE_FLAGS_DISCONNECTED) {
			continue;
		}

		if (nodemap->nodes[i].flags & NODE_FLAGS_DELETED) {
			continue;
		}

		if (nodemap->nodes[i].flags & NODE_FLAGS_INACTIVE) {
			DEBUG(DEBUG_ERR, ("Database cannot be detached on "
					  "inactive (stopped or banned) node "
					  "%u\n", nodemap->nodes[i].pnn));
			talloc_free(tmp_ctx);
			return -1;
		}

		ret = ctdb_ctrl_get_tunable(ctdb, TIMELIMIT(),
					    nodemap->nodes[i].pnn,
					    "AllowClientDBAttach",
					    &value);
		if (ret != 0) {
			DEBUG(DEBUG_ERR, ("Unable to get tunable "
					  "AllowClientDBAttach from node %u\n",
					   nodemap->nodes[i].pnn));
			talloc_free(tmp_ctx);
			return -1;
		}

		if (value == 1) {
			DEBUG(DEBUG_ERR, ("Database access is still active on "
					  "node %u. Set AllowClientDBAttach=0 "
					  "on all nodes.\n",
					  nodemap->nodes[i].pnn));
			talloc_free(tmp_ctx);
			return -1;
		}
	}

	talloc_free(tmp_ctx);

	for (i=0; i<argc; i++) {
		if (!db_exists(ctdb, argv[i], &db_id, NULL, &flags)) {
			continue;
		}

		if (flags & CTDB_DB_FLAGS_PERSISTENT) {
			DEBUG(DEBUG_ERR, ("Persistent database '%s' "
					  "cannot be detached\n", argv[i]));
			status = -1;
			continue;
		}

		ret = ctdb_detach(ctdb, db_id);
		if (ret != 0) {
			DEBUG(DEBUG_ERR, ("Database '%s' detach failed\n",
					  argv[i]));
			status = ret;
		}
	}

	return status;
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

	if (!db_exists(ctdb, argv[0], &db_id, NULL, NULL)) {
		return -1;
	}

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
	int ret;

	if (argc < 1) {
		usage();
	}

	if (!db_exists(ctdb, argv[0], &db_id, NULL, NULL)) {
		return -1;
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
	int ret;

	if (argc < 1) {
		usage();
	}

	if (!db_exists(ctdb, argv[0], &db_id, NULL, NULL)) {
		return -1;
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
	uint32_t db_id;
	uint64_t seqnum;
	int ret;

	if (argc < 1) {
		usage();
	}

	if (!db_exists(ctdb, argv[0], &db_id, NULL, NULL)) {
		return -1;
	}

	ret = ctdb_ctrl_getdbseqnum(ctdb, TIMELIMIT(), options.pnn, db_id, &seqnum);
	if (ret != 0) {
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
	const char *db_name;
	int ret;
	TALLOC_CTX *tmp_ctx = talloc_new(ctdb);
	struct db_file_header dbhdr;
	struct ctdb_db_context *ctdb_db;
	struct backup_data *bd;
	int fh = -1;
	int status = -1;
	const char *reason = NULL;
	uint32_t db_id;
	uint8_t flags;

	assert_single_node_only();

	if (argc != 2) {
		DEBUG(DEBUG_ERR,("Invalid arguments\n"));
		return -1;
	}

	if (!db_exists(ctdb, argv[0], &db_id, &db_name, &flags)) {
		return -1;
	}

	ret = ctdb_ctrl_getdbhealth(ctdb, TIMELIMIT(), options.pnn,
				    db_id, tmp_ctx, &reason);
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

	ctdb_db = ctdb_attach(ctdb, TIMELIMIT(), db_name, flags & CTDB_DB_FLAGS_PERSISTENT, 0);
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

	ZERO_STRUCT(dbhdr);
	dbhdr.version = DB_VERSION;
	dbhdr.timestamp = time(NULL);
	dbhdr.persistent = flags & CTDB_DB_FLAGS_PERSISTENT;
	dbhdr.size = bd->len;
	if (strlen(argv[0]) >= MAX_DB_NAME) {
		DEBUG(DEBUG_ERR,("Too long dbname\n"));
		goto done;
	}
	strncpy(discard_const(dbhdr.name), argv[0], MAX_DB_NAME-1);
	ret = sys_write(fh, &dbhdr, sizeof(dbhdr));
	if (ret == -1) {
		DEBUG(DEBUG_ERR,("write failed: %s\n", strerror(errno)));
		goto done;
	}
	ret = sys_write(fh, bd->records, bd->len);
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

	assert_single_node_only();

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

	sys_read(fh, &dbhdr, sizeof(dbhdr));
	if (dbhdr.version != DB_VERSION) {
		DEBUG(DEBUG_ERR,("Invalid version of database dump. File is version %lu but expected version was %u\n", dbhdr.version, DB_VERSION));
		close(fh);
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
	sys_read(fh, outdata.dptr, outdata.dsize);
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

	assert_single_node_only();

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

	sys_read(fh, &dbhdr, sizeof(dbhdr));
	if (dbhdr.version != DB_VERSION) {
		DEBUG(DEBUG_ERR,("Invalid version of database dump. File is version %lu but expected version was %u\n", dbhdr.version, DB_VERSION));
		close(fh);
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
	sys_read(fh, outdata.dptr, outdata.dsize);
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
	const char *db_name;
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
	uint8_t flags;

	assert_single_node_only();

	if (argc != 1) {
		DEBUG(DEBUG_ERR,("Invalid arguments\n"));
		return -1;
	}

	if (!db_exists(ctdb, argv[0], NULL, &db_name, &flags)) {
		return -1;
	}

	ctdb_db = ctdb_attach(ctdb, TIMELIMIT(), db_name, flags & CTDB_DB_FLAGS_PERSISTENT, 0);
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
	sys_write(1, data.dptr, data.dsize);
	talloc_free(tmp_ctx);
	return 0;
}

/*
  handler for memory dumps
*/
static void mem_dump_handler(struct ctdb_context *ctdb, uint64_t srvid, 
			     TDB_DATA data, void *private_data)
{
	sys_write(1, data.dptr, data.dsize);
	exit(0);
}

/*
  dump memory usage on the recovery daemon
 */
static int control_rddumpmemory(struct ctdb_context *ctdb, int argc, const char **argv)
{
	int ret;
	TDB_DATA data;
	struct srvid_request rd;

	rd.pnn = ctdb_get_pnn(ctdb);
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

	assert_single_node_only();

	pnn_nodes = read_nodes_file(mem_ctx);
	if (pnn_nodes == NULL) {
		DEBUG(DEBUG_ERR,("Failed to read nodes file\n"));
		talloc_free(mem_ctx);
		return -1;
	}

	for(pnn_node=pnn_nodes;pnn_node;pnn_node=pnn_node->next) {
		const char *addr = ctdb_addr_to_str(&pnn_node->addr);
		if (options.machinereadable){
			printm(":%d:%s:\n", pnn_node->pnn, addr);
		} else {
			printf("%s\n", addr);
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

	assert_single_node_only();

	mypnn = ctdb_get_pnn(ctdb);

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
	{ "version",         control_version,           true,	true,   "show version of ctdb" },
	{ "status",          control_status,            true,	false,  "show node status" },
	{ "uptime",          control_uptime,            true,	false,  "show node uptime" },
	{ "ping",            control_ping,              true,	false,  "ping all nodes" },
	{ "runstate",        control_runstate,          true,	false,  "get/check runstate of a node", "[setup|first_recovery|startup|running]" },
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
	{ "getdbstatus",     control_getdbstatus,       true,	false,  "show the status of a database", "<dbname|dbid>" },
	{ "catdb",           control_catdb,             true,	false,  "dump a ctdb database" ,                     "<dbname|dbid>"},
	{ "cattdb",          control_cattdb,            true,	false,  "dump a local tdb database" ,                     "<dbname|dbid>"},
	{ "getmonmode",      control_getmonmode,        true,	false,  "show monitoring mode" },
	{ "getcapabilities", control_getcapabilities,   true,	false,  "show node capabilities" },
	{ "pnn",             control_pnn,               true,	false,  "show the pnn of the currnet node" },
	{ "lvs",             control_lvs,               true,	false,  "show lvs configuration" },
	{ "lvsmaster",       control_lvsmaster,         true,	false,  "show which node is the lvs master" },
	{ "disablemonitor",      control_disable_monmode,true,	false,  "set monitoring mode to DISABLE" },
	{ "enablemonitor",      control_enable_monmode, true,	false,  "set monitoring mode to ACTIVE" },
	{ "setdebug",        control_setdebug,          true,	false,  "set debug level",                      "<EMERG|ALERT|CRIT|ERR|WARNING|NOTICE|INFO|DEBUG>" },
	{ "getdebug",        control_getdebug,          true,	false,  "get debug level" },
	{ "attach",          control_attach,            true,	false,  "attach to a database",                 "<dbname> [persistent]" },
	{ "detach",          control_detach,            false,	false,  "detach from a database",                 "<dbname|dbid> [<dbname|dbid> ...]" },
	{ "dumpmemory",      control_dumpmemory,        true,	false,  "dump memory map to stdout" },
	{ "rddumpmemory",    control_rddumpmemory,      true,	false,  "dump memory map from the recovery daemon to stdout" },
	{ "getpid",          control_getpid,            true,	false,  "get ctdbd process ID" },
	{ "disable",         control_disable,           true,	false,  "disable a nodes public IP" },
	{ "enable",          control_enable,            true,	false,  "enable a nodes public IP" },
	{ "stop",            control_stop,              true,	false,  "stop a node" },
	{ "continue",        control_continue,          true,	false,  "re-start a stopped node" },
	{ "ban",             control_ban,               true,	false,  "ban a node from the cluster",          "<bantime>"},
	{ "unban",           control_unban,             true,	false,  "unban a node" },
	{ "showban",         control_showban,           true,	false,  "show ban information"},
	{ "shutdown",        control_shutdown,          true,	false,  "shutdown ctdbd" },
	{ "recover",         control_recover,           true,	false,  "force recovery" },
	{ "sync", 	     control_ipreallocate,      false,	false,  "wait until ctdbd has synced all state changes" },
	{ "ipreallocate",    control_ipreallocate,      false,	false,  "force the recovery daemon to perform a ip reallocation procedure" },
	{ "thaw",            control_thaw,              true,	false,  "thaw databases", "[priority:1-3]" },
	{ "isnotrecmaster",  control_isnotrecmaster,    false,	false,  "check if the local node is recmaster or not" },
	{ "killtcp",         kill_tcp,                  false,	false, "kill a tcp connection.", "[<srcip:port> <dstip:port>]" },
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
	{ "repack",          ctdb_repack,		false,	false, "repack all databases", "[max_freelist]"},
	{ "listnodes",       control_listnodes,		false,	true, "list all nodes in the cluster"},
	{ "reloadnodes",     control_reload_nodes_file,	false,	false, "reload the nodes file and restart the transport on all nodes"},
	{ "moveip",          control_moveip,		false,	false, "move/failover an ip address to another node", "<ip> <node>"},
	{ "rebalanceip",     control_rebalanceip,	false,	false, "release an ip from the node and let recd rebalance it", "<ip>"},
	{ "addip",           control_addip,		true,	false, "add a ip address to a node", "<ip/mask> <iface>"},
	{ "delip",           control_delip,		false,	false, "delete an ip address from a node", "<ip>"},
	{ "eventscript",     control_eventscript,	true,	false, "run the eventscript with the given parameters on a node", "<arguments>"},
	{ "backupdb",        control_backupdb,          false,	false, "backup the database into a file.", "<dbname|dbid> <file>"},
	{ "restoredb",        control_restoredb,        false,	false, "restore the database from a file.", "<file> [dbname]"},
	{ "dumpdbbackup",    control_dumpdbbackup,      false,	true,  "dump database backup from a file.", "<file>"},
	{ "wipedb",           control_wipedb,        false,	false, "wipe the contents of a database.", "<dbname|dbid>"},
	{ "recmaster",        control_recmaster,        true,	false, "show the pnn for the recovery master."},
	{ "scriptstatus",     control_scriptstatus,     true,	false, "show the status of the monitoring scripts (or all scripts)", "[all]"},
	{ "enablescript",     control_enablescript,  true,	false, "enable an eventscript", "<script>"},
	{ "disablescript",    control_disablescript,  true,	false, "disable an eventscript", "<script>"},
	{ "natgwlist",        control_natgwlist,        true,	false, "show the nodes belonging to this natgw configuration"},
	{ "xpnn",             control_xpnn,             false,	true,  "find the pnn of the local node without talking to the daemon (unreliable)" },
	{ "getreclock",       control_getreclock,	true,	false, "Show the reclock file of a node"},
	{ "setreclock",       control_setreclock,	true,	false, "Set/clear the reclock file of a node", "[filename]"},
	{ "setnatgwstate",    control_setnatgwstate,	false,	false, "Set NATGW state to on/off", "{on|off}"},
	{ "setlmasterrole",   control_setlmasterrole,	false,	false, "Set LMASTER role to on/off", "{on|off}"},
	{ "setrecmasterrole", control_setrecmasterrole,	false,	false, "Set RECMASTER role to on/off", "{on|off}"},
	{ "setdbprio",        control_setdbprio,	false,	false, "Set DB priority", "<dbname|dbid> <prio:1-3>"},
	{ "getdbprio",        control_getdbprio,	false,	false, "Get DB priority", "<dbname|dbid>"},
	{ "setdbreadonly",    control_setdbreadonly,	false,	false, "Set DB readonly capable", "<dbname|dbid>"},
	{ "setdbsticky",      control_setdbsticky,	false,	false, "Set DB sticky-records capable", "<dbname|dbid>"},
	{ "msglisten",        control_msglisten,	false,	false, "Listen on a srvid port for messages", "<msg srvid>"},
	{ "msgsend",          control_msgsend,	false,	false, "Send a message to srvid", "<srvid> <message>"},
	{ "pfetch", 	     control_pfetch,      	false,	false,  "fetch a record from a persistent database", "<dbname|dbid> <key> [<file>]" },
	{ "pstore", 	     control_pstore,      	false,	false,  "write a record to a persistent database", "<dbname|dbid> <key> <file containing record>" },
	{ "pdelete", 	     control_pdelete,      	false,	false,  "delete a record from a persistent database", "<dbname|dbid> <key>" },
	{ "ptrans", 	     control_ptrans,      	false,	false,  "update a persistent database (from stdin)", "<dbname|dbid>" },
	{ "tfetch", 	     control_tfetch,      	false,	true,  "fetch a record from a [c]tdb-file [-v]", "<tdb-file> <key> [<file>]" },
	{ "tstore", 	     control_tstore,      	false,	true,  "store a record (including ltdb header)", "<tdb-file> <key> <data> [<rsn> <dmaster> <flags>]" },
	{ "readkey", 	     control_readkey,      	true,	false,  "read the content off a database key", "<dbname|dbid> <key>" },
	{ "writekey", 	     control_writekey,      	true,	false,  "write to a database key", "<dbname|dbid> <key> <value>" },
	{ "checktcpport",    control_chktcpport,      	false,	true,  "check if a service is bound to a specific tcp port or not", "<port>" },
	{ "rebalancenode",     control_rebalancenode,	false,	false, "mark nodes as forced IP rebalancing targets", "[<pnn-list>]"},
	{ "getdbseqnum",     control_getdbseqnum,       false,	false, "get the sequence number off a database", "<dbname|dbid>" },
	{ "nodestatus",      control_nodestatus,        true,   false,  "show and return node status", "[<pnn-list>]" },
	{ "dbstatistics",    control_dbstatistics,      false,	false, "show db statistics", "<dbname|dbid>" },
	{ "reloadips",       control_reloadips,         false,	false, "reload the public addresses file on specified nodes" , "[<pnn-list>]" },
	{ "ipiface",         control_ipiface,           false,	true,  "Find which interface an ip address is hosted on", "<ip>" },
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
"   -Y                 generate machine readable output\n"
"   -x <char>          specify delimiter for machine readable output\n"
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
	int machineparsable = 0;
	struct poptOption popt_options[] = {
		POPT_AUTOHELP
		POPT_CTDB_CMDLINE
		{ "timelimit", 't', POPT_ARG_INT, &options.timelimit, 0, "timelimit", "integer" },
		{ "node",      'n', POPT_ARG_STRING, &nodestring, 0, "node", "integer|all" },
		{ "machinereadable", 'Y', POPT_ARG_NONE, &options.machinereadable, 0, "enable machine readable output", NULL },
		{ NULL, 'x', POPT_ARG_STRING, &options.machineseparator, 0, "specify separator for machine readable output", "char" },
		{ NULL, 'X', POPT_ARG_NONE, &machineparsable, 0, "enable machine parsable output with separator |", NULL },
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

	setlinebuf(stdout);
	
	/* set some defaults */
	options.maxruntime = 0;
	options.timelimit = 10;
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

	if (machineparsable) {
		options.machineseparator = "|";
	}
	if (options.machineseparator != NULL) {
		if (strlen(options.machineseparator) != 1) {
			printf("Invalid separator \"%s\" - "
			       "must be single character\n",
			       options.machineseparator);
			exit(1);
		}

		/* -x implies -Y */
		options.machinereadable = true;
	} else if (options.machinereadable) {
		options.machineseparator = ":";
	}

	signal(SIGALRM, ctdb_alarm);
	alarm(options.maxruntime);

	control = extra_argv[0];

	/* Default value for CTDB_BASE - don't override */
	setenv("CTDB_BASE", CTDB_ETCDIR, 0);

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
		return ctdb_commands[i].fn(NULL, extra_argc-1, extra_argv+1);
	}

	/* initialise ctdb */
	ctdb = ctdb_cmdline_client(ev, TIMELIMIT());

	if (ctdb == NULL) {
		uint32_t pnn;
		DEBUG(DEBUG_ERR, ("Failed to init ctdb\n"));

		pnn = find_node_xpnn();
		if (pnn == -1) {
			DEBUG(DEBUG_ERR,
			      ("Is this node part of a CTDB cluster?\n"));
		}
		exit(1);
	}

	/* setup the node number(s) to contact */
	if (!parse_nodestring(ctdb, ctdb, nodestring, CTDB_CURRENT_NODE, false,
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

	talloc_free(ctdb);
	talloc_free(ev);
	(void)poptFreeContext(pc);

	return ret;

}
