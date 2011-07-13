/*
 * CTDB PMDA
 *
 * Copyright (c) 1995,2004 Silicon Graphics, Inc.  All Rights Reserved.
 * Copyright (c) 2011 David Disseldorp
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 59 Temple Place, Suite 330, Boston, MA  02111-1307 USA
 */

#include <pcp/pmapi.h>
#include <pcp/impl.h>
#include <pcp/pmda.h>
#include "../../include/includes.h"
#include "../../lib/events/events.h"
#include "../../include/ctdb.h"
#include "../../include/ctdb_private.h"
#include "domain.h"

/*
 * CTDB PMDA
 *
 * This PMDA connects to the locally running ctdbd daemon and pulls
 * statistics for export via PCP.
 */

/*
 * list of instances
 */


/*
 * All metrics supported in this PMDA - one table entry for each.
 * The 4th field specifies the serial number of the instance domain
 * for the metric, and must be either PM_INDOM_NULL (denoting a
 * metric that only ever has a single value), or the serial number
 * of one of the instance domains declared in the instance domain table
 * (i.e. in indomtab, above).
 */

static pmdaMetric metrictab[] = {
	/* num_clients */
	{ NULL, { PMDA_PMID(0,0), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_INSTANT,
		PMDA_PMUNITS(0,0,0,0,0,0) }, },
	/* frozen */
	{ NULL, { PMDA_PMID(1,2), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_INSTANT,
		PMDA_PMUNITS(0,0,0,0,0,0) }, },
	/* recovering */
	{ NULL, { PMDA_PMID(3,3), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_INSTANT,
		PMDA_PMUNITS(0,0,0,0,0,0) }, },
	/* client_packets_sent */
	{ NULL, { PMDA_PMID(4,4), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER,
		PMDA_PMUNITS(0,0,1,0,0,PM_COUNT_ONE) }, },
	/* client_packets_recv */
	{ NULL, { PMDA_PMID(5,5), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER,
		PMDA_PMUNITS(0,0,1,0,0,PM_COUNT_ONE) }, },
	/* node_packets_sent */
	{ NULL, { PMDA_PMID(6,6), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER,
		PMDA_PMUNITS(0,0,1,0,0,PM_COUNT_ONE) }, },
	/* node_packets_recv */
	{ NULL, { PMDA_PMID(7,7), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER,
		PMDA_PMUNITS(0,0,1,0,0,PM_COUNT_ONE) }, },
	/* keepalive_packets_sent */
	{ NULL, { PMDA_PMID(8,8), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER,
		PMDA_PMUNITS(0,0,1,0,0,PM_COUNT_ONE) }, },
	/* keepalive_packets_recv */
	{ NULL, { PMDA_PMID(9,9), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER,
		PMDA_PMUNITS(0,0,1,0,0,PM_COUNT_ONE) }, },
	/* req_call */
	{ NULL, { PMDA_PMID(10,10), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER,
		PMDA_PMUNITS(0,0,1,0,0,PM_COUNT_ONE) }, },
	/* reply_call */
	{ NULL, { PMDA_PMID(10,11), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER,
		PMDA_PMUNITS(0,0,1,0,0,PM_COUNT_ONE) }, },
	/* req_dmaster */
	{ NULL, { PMDA_PMID(10,12), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER,
		PMDA_PMUNITS(0,0,1,0,0,PM_COUNT_ONE) }, },
	/* reply_dmaster */
	{ NULL, { PMDA_PMID(10,13), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER,
		PMDA_PMUNITS(0,0,1,0,0,PM_COUNT_ONE) }, },
	/* reply_error */
	{ NULL, { PMDA_PMID(10,14), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER,
		PMDA_PMUNITS(0,0,1,0,0,PM_COUNT_ONE) }, },
	/* req_message */
	{ NULL, { PMDA_PMID(10,15), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER,
		PMDA_PMUNITS(0,0,1,0,0,PM_COUNT_ONE) }, },
	/* req_control */
	{ NULL, { PMDA_PMID(10,16), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER,
		PMDA_PMUNITS(0,0,1,0,0,PM_COUNT_ONE) }, },
	/* reply_control */
	{ NULL, { PMDA_PMID(10,17), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER,
		PMDA_PMUNITS(0,0,1,0,0,PM_COUNT_ONE) }, },
	/* req_call */
	{ NULL, { PMDA_PMID(11,18), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER,
		PMDA_PMUNITS(0,0,1,0,0,PM_COUNT_ONE) }, },
	/* req_message */
	{ NULL, { PMDA_PMID(11,19), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER,
		PMDA_PMUNITS(0,0,1,0,0,PM_COUNT_ONE) }, },
	/* req_control */
	{ NULL, { PMDA_PMID(11,20), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER,
		PMDA_PMUNITS(0,0,1,0,0,PM_COUNT_ONE) }, },
	/* call */
	{ NULL, { PMDA_PMID(12,21), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER,
		PMDA_PMUNITS(0,0,1,0,0,0) }, },
	/* control */
	{ NULL, { PMDA_PMID(12,22), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER,
		PMDA_PMUNITS(0,0,1,0,0,0) }, },
	/* traverse */
	{ NULL, { PMDA_PMID(12,23), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER,
		PMDA_PMUNITS(0,0,1,0,0,0) }, },
	/* total_calls */
	{ NULL, { PMDA_PMID(13,24), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER,
		PMDA_PMUNITS(0,0,1,0,0,PM_COUNT_ONE) }, },
	/* pending_calls */
	{ NULL, { PMDA_PMID(14,25), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_INSTANT,
		PMDA_PMUNITS(0,0,0,0,0,0) }, },
	/* lockwait_calls */
	{ NULL, { PMDA_PMID(15,27), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER,
		PMDA_PMUNITS(0,0,1,0,0,PM_COUNT_ONE) }, },
	/* pending_lockwait_calls */
	{ NULL, { PMDA_PMID(16,27), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_INSTANT,
		PMDA_PMUNITS(0,0,0,0,0,0) }, },
	/* childwrite_calls */
	{ NULL, { PMDA_PMID(17,28), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER,
		PMDA_PMUNITS(0,0,1,0,0,PM_COUNT_ONE) }, },
	/* pending_childwrite_calls */
	{ NULL, { PMDA_PMID(18,29), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_INSTANT,
		PMDA_PMUNITS(0,0,0,0,0,0) }, },
	/* memory_used */
	{ NULL, { PMDA_PMID(19,30), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_INSTANT,
		PMDA_PMUNITS(1,0,0,PM_SPACE_BYTE,0,0) }, },
	/* max_hop_count */
	{ NULL, { PMDA_PMID(20,31), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_INSTANT,
		PMDA_PMUNITS(0,0,0,0,0,0) }, },
	/* max_reclock_ctdbd */
	{ NULL, { PMDA_PMID(21,32), PM_TYPE_DOUBLE, PM_INDOM_NULL, PM_SEM_INSTANT,
		PMDA_PMUNITS(0,1,0,0,PM_TIME_SEC,0) }, },
	/* max_reclock_recd */
	{ NULL, { PMDA_PMID(22,33), PM_TYPE_DOUBLE, PM_INDOM_NULL, PM_SEM_INSTANT,
		PMDA_PMUNITS(0,1,0,0,PM_TIME_SEC,0) }, },
	/* max_call_latency */
	{ NULL, { PMDA_PMID(23,34), PM_TYPE_DOUBLE, PM_INDOM_NULL, PM_SEM_INSTANT,
		PMDA_PMUNITS(0,1,0,0,PM_TIME_SEC,0) }, },
	/* max_lockwait_latency */
	{ NULL, { PMDA_PMID(24,35), PM_TYPE_DOUBLE, PM_INDOM_NULL, PM_SEM_INSTANT,
		PMDA_PMUNITS(0,1,0,0,PM_TIME_SEC,0) }, },
	/* max_childwrite_latency */
	{ NULL, { PMDA_PMID(25,36), PM_TYPE_DOUBLE, PM_INDOM_NULL, PM_SEM_INSTANT,
		PMDA_PMUNITS(0,1,0,0,PM_TIME_SEC,0) }, },
};

static struct ctdb_context *ctdb;
static struct event_context *ev;

static int
fill_node(unsigned int item, struct ctdb_statistics *stats, pmAtomValue *atom)
{
	switch (item) {
	case 10:
		atom->ul = stats->node.req_call;
		break;
	case 11:
		atom->ul = stats->node.reply_call;
		break;
	case 12:
		atom->ul = stats->node.req_dmaster;
		break;
	case 13:
		atom->ul = stats->node.reply_dmaster;
		break;
	case 14:
		atom->ul = stats->node.reply_error;
		break;
	case 15:
		atom->ul = stats->node.req_message;
		break;
	case 16:
		atom->ul = stats->node.req_control;
		break;
	case 17:
		atom->ul = stats->node.reply_control;
		break;
	default:
		return PM_ERR_PMID;
	}

	return 0;
}

static int
fill_client(unsigned int item, struct ctdb_statistics *stats, pmAtomValue *atom)
{
	switch (item) {
	case 18:
		atom->ul = stats->client.req_call;
		break;
	case 19:
		atom->ul = stats->client.req_message;
		break;
	case 20:
		atom->ul = stats->client.req_control;
		break;
	default:
		return PM_ERR_PMID;
	}

	return 0;
}

static int
fill_timeout(unsigned int item, struct ctdb_statistics *stats, pmAtomValue *atom)
{
	switch (item) {
	case 21:
		atom->ul = stats->timeouts.call;
		break;
	case 22:
		atom->ul = stats->timeouts.control;
		break;
	case 23:
		atom->ul = stats->timeouts.traverse;
		break;
	default:
		return PM_ERR_PMID;
	}

	return 0;
}

/*
 * callback provided to pmdaFetch
 */
static int
pmda_ctdb_fetch_cb(pmdaMetric *mdesc, unsigned int inst, pmAtomValue *atom)
{
	struct ctdb_statistics stats;
	int ret;
	__pmID_int *id = (__pmID_int *)&(mdesc->m_desc.pmid);

	if (inst != PM_IN_NULL)
		return PM_ERR_INST;

	ret = ctdb_ctrl_statistics(ctdb, ctdb->pnn, &stats);
	if (ret) {
		ret = PM_ERR_VALUE;
		goto err_out;
	}

	switch (id->cluster) {
	case 0:
		atom->ul = stats.num_clients;
		break;
	case 1:
		atom->ul = stats.frozen;
		break;
	case 3:
		atom->ul = stats.recovering;
		break;
	case 4:
		atom->ul = stats.client_packets_sent;
		break;
	case 5:
		atom->ul = stats.client_packets_recv;
		break;
	case 6:
		atom->ul = stats.node_packets_sent;
		break;
	case 7:
		atom->ul = stats.node_packets_recv;
		break;
	case 8:
		atom->ul = stats.keepalive_packets_sent;
		break;
	case 9:
		atom->ul = stats.keepalive_packets_recv;
		break;
	case 10:
		ret = fill_node(id->item, &stats, atom);
		if (ret)
			goto err_out;
		break;
	case 11:
		ret = fill_client(id->item, &stats, atom);
		if (ret)
			goto err_out;
		break;
	case 12:
		ret = fill_timeout(id->item, &stats, atom);
		if (ret)
			goto err_out;
		break;
	case 13:
		atom->ul = stats.total_calls;
		break;
	case 14:
		atom->ul = stats.pending_calls;
		break;
	case 15:
		atom->ul = stats.lockwait_calls;
		break;
	case 16:
		atom->ul = stats.pending_lockwait_calls;
		break;
	case 17:
		atom->ul = stats.childwrite_calls;
		break;
	case 18:
		atom->ul = stats.pending_childwrite_calls;
		break;
	case 19:
		atom->ul = stats.memory_used;
		break;
	case 20:
		atom->ul = stats.max_hop_count;
		break;
	case 21:
		atom->d = stats.reclock.ctdbd;
		break;
	case 22:
		atom->d = stats.reclock.recd;
		break;
	case 23:
		atom->d = stats.max_call_latency;
		break;
	case 24:
		atom->d = stats.max_lockwait_latency;
		break;
	case 25:
		atom->d = stats.max_childwrite_latency;
		break;
	default:
		return PM_ERR_PMID;
	}

	ret = 0;
err_out:
	return ret;
}

/*
 * This routine is called once for each pmFetch(3) operation, so is a
 * good place to do once-per-fetch functions, such as value caching or
 * instance domain evaluation.
 */
static int
pmda_ctdb_fetch(int numpmid, pmID pmidlist[], pmResult **resp, pmdaExt *pmda)
{
	return pmdaFetch(numpmid, pmidlist, resp, pmda);
}

static int
pmda_ctdb_daemon_connect(void)
{
	const char *socket_name;
	int ret;

	ev = event_context_init(NULL);
	if (ev == NULL) {
		fprintf(stderr, "Failed to init event ctx\n");
		return -1;
	}

	ctdb = ctdb_init(ev);
	if (ctdb == NULL) {
		fprintf(stderr, "Failed to init ctdb\n");
		return -1;
	}

	socket_name = getenv("CTDB_SOCKET");
	if (socket_name == NULL) {
		socket_name = "/var/lib/ctdb/ctdb.socket";
	}

	ret = ctdb_set_socketname(ctdb, socket_name);
	if (ret == -1) {
		fprintf(stderr, "ctdb_set_socketname failed - %s\n",
				ctdb_errstr(ctdb));
		talloc_free(ctdb);
		return -1;
	}

	ret = ctdb_socket_connect(ctdb);
	if (ret != 0) {
		fprintf(stderr, "Failed to connect to daemon\n");
		talloc_free(ctdb);
		return -1;
	}

	ctdb->pnn = ctdb_ctrl_getpnn(ctdb, timeval_current_ofs(3, 0),
				     CTDB_CURRENT_NODE);
	if (ctdb->pnn == (uint32_t)-1) {
		fprintf(stderr, "Failed to get ctdb pnn\n");
		talloc_free(ctdb);
		return -1;
	}

	return 0;
}

/*
 * Initialise the agent
 */
void
pmda_ctdb_init(pmdaInterface *dp)
{
	int ret;

	if (dp->status != 0)
		return;

	ret = pmda_ctdb_daemon_connect();
	if (ret < 0)
		return;

	dp->version.two.fetch = pmda_ctdb_fetch;
	pmdaSetFetchCallBack(dp, pmda_ctdb_fetch_cb);

	pmdaInit(dp, NULL, 0, metrictab, sizeof(metrictab)/sizeof(metrictab[0]));
}

static char *
helpfile(void)
{
	static char buf[MAXPATHLEN];

	if (!buf[0]) {
		snprintf(buf, sizeof(buf), "%s/ctdb/help",
			 pmGetConfig("PCP_PMDAS_DIR"));
	}
	return buf;
}

static void
usage(void)
{
	fprintf(stderr, "Usage: %s [options]\n\n", pmProgname);
	fputs("Options:\n"
	  "  -d domain	use domain (numeric) for metrics domain of PMDA\n"
	  "  -l logfile   write log into logfile rather than using default log name\n"
	  "\nExactly one of the following options may appear:\n"
	  "  -i port	  expect PMCD to connect on given inet port (number or name)\n"
	  "  -p		   expect PMCD to supply stdin/stdout (pipe)\n"
	  "  -u socket	expect PMCD to connect on given unix domain socket\n",
	  stderr);
	exit(1);
}

/*
 * Set up the agent if running as a daemon.
 */
int
main(int argc, char **argv)
{
	int err = 0;
	char log_file[] = "pmda_ctdb.log";
	pmdaInterface dispatch;

	__pmSetProgname(argv[0]);

	pmdaDaemon(&dispatch, PMDA_INTERFACE_2, pmProgname, CTDB,
		   log_file, helpfile());

	if (pmdaGetOpt(argc, argv, "d:i:l:pu:?", &dispatch, &err) != EOF)
		err++;

	if (err)
		usage();

	pmdaOpenLog(&dispatch);
	pmda_ctdb_init(&dispatch);
	pmdaConnect(&dispatch);
	pmdaMain(&dispatch);

	exit(0);
}

