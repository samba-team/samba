/*
 * CTDB Performance Metrics Domain Agent (PMDA) for Performance Co-Pilot (PCP)
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

#include "replace.h"
#include "system/network.h"

#include <talloc.h>
#include <tevent.h>
#include <tdb.h>

#include "lib/util/time.h"
#include "lib/util/blocking.h"

#include "client/client.h"
#include "client/client_sync.h"

#include <pcp/pmapi.h>
#include <pcp/pmda.h>

#ifdef HAVE___PMID_INT
#include <pcp/impl.h>

#define pmID_cluster(id)	id->cluster
#define pmID_item(id)		id->item
#define pmGetProgname()		pmProgname
#define pmSetProgname(a)	__pmSetProgname(a)
#endif

#include "domain.h"

/*
 * CTDB PMDA
 *
 * This PMDA connects to the locally running ctdbd daemon and pulls
 * statistics for export via PCP. The ctdbd Unix domain socket path can be
 * specified with the CTDB_SOCKET environment variable, otherwise the default
 * path is used.
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
	{ NULL, { PMDA_PMID(0,1), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_INSTANT,
		PMDA_PMUNITS(0,0,0,0,0,0) }, },
	/* recovering */
	{ NULL, { PMDA_PMID(0,2), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_INSTANT,
		PMDA_PMUNITS(0,0,0,0,0,0) }, },
	/* client_packets_sent */
	{ NULL, { PMDA_PMID(0,3), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER,
		PMDA_PMUNITS(0,0,1,0,0,PM_COUNT_ONE) }, },
	/* client_packets_recv */
	{ NULL, { PMDA_PMID(0,4), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER,
		PMDA_PMUNITS(0,0,1,0,0,PM_COUNT_ONE) }, },
	/* node_packets_sent */
	{ NULL, { PMDA_PMID(0,5), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER,
		PMDA_PMUNITS(0,0,1,0,0,PM_COUNT_ONE) }, },
	/* node_packets_recv */
	{ NULL, { PMDA_PMID(0,6), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER,
		PMDA_PMUNITS(0,0,1,0,0,PM_COUNT_ONE) }, },
	/* keepalive_packets_sent */
	{ NULL, { PMDA_PMID(0,7), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER,
		PMDA_PMUNITS(0,0,1,0,0,PM_COUNT_ONE) }, },
	/* keepalive_packets_recv */
	{ NULL, { PMDA_PMID(0,8), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER,
		PMDA_PMUNITS(0,0,1,0,0,PM_COUNT_ONE) }, },
	/* req_call */
	{ NULL, { PMDA_PMID(1,0), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER,
		PMDA_PMUNITS(0,0,1,0,0,PM_COUNT_ONE) }, },
	/* reply_call */
	{ NULL, { PMDA_PMID(1,1), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER,
		PMDA_PMUNITS(0,0,1,0,0,PM_COUNT_ONE) }, },
	/* req_dmaster */
	{ NULL, { PMDA_PMID(1,2), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER,
		PMDA_PMUNITS(0,0,1,0,0,PM_COUNT_ONE) }, },
	/* reply_dmaster */
	{ NULL, { PMDA_PMID(1,3), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER,
		PMDA_PMUNITS(0,0,1,0,0,PM_COUNT_ONE) }, },
	/* reply_error */
	{ NULL, { PMDA_PMID(1,4), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER,
		PMDA_PMUNITS(0,0,1,0,0,PM_COUNT_ONE) }, },
	/* req_message */
	{ NULL, { PMDA_PMID(1,5), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER,
		PMDA_PMUNITS(0,0,1,0,0,PM_COUNT_ONE) }, },
	/* req_control */
	{ NULL, { PMDA_PMID(1,6), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER,
		PMDA_PMUNITS(0,0,1,0,0,PM_COUNT_ONE) }, },
	/* reply_control */
	{ NULL, { PMDA_PMID(1,7), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER,
		PMDA_PMUNITS(0,0,1,0,0,PM_COUNT_ONE) }, },
	/* req_call */
	{ NULL, { PMDA_PMID(2,0), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER,
		PMDA_PMUNITS(0,0,1,0,0,PM_COUNT_ONE) }, },
	/* req_message */
	{ NULL, { PMDA_PMID(2,1), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER,
		PMDA_PMUNITS(0,0,1,0,0,PM_COUNT_ONE) }, },
	/* req_control */
	{ NULL, { PMDA_PMID(2,2), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER,
		PMDA_PMUNITS(0,0,1,0,0,PM_COUNT_ONE) }, },
	/* call */
	{ NULL, { PMDA_PMID(3,0), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER,
		PMDA_PMUNITS(0,0,1,0,0,0) }, },
	/* control */
	{ NULL, { PMDA_PMID(3,1), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER,
		PMDA_PMUNITS(0,0,1,0,0,0) }, },
	/* traverse */
	{ NULL, { PMDA_PMID(3,2), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER,
		PMDA_PMUNITS(0,0,1,0,0,0) }, },
	/* total_calls */
	{ NULL, { PMDA_PMID(0,9), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER,
		PMDA_PMUNITS(0,0,1,0,0,PM_COUNT_ONE) }, },
	/* pending_calls */
	{ NULL, { PMDA_PMID(0,10), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_INSTANT,
		PMDA_PMUNITS(0,0,0,0,0,0) }, },
	/* locks.num_calls */
	{ NULL, { PMDA_PMID(0,11), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER,
		PMDA_PMUNITS(0,0,1,0,0,PM_COUNT_ONE) }, },
	/* locks.num_pending */
	{ NULL, { PMDA_PMID(0,12), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_INSTANT,
		PMDA_PMUNITS(0,0,0,0,0,0) }, },
	/* childwrite_calls */
	{ NULL, { PMDA_PMID(0,13), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER,
		PMDA_PMUNITS(0,0,1,0,0,PM_COUNT_ONE) }, },
	/* pending_childwrite_calls */
	{ NULL, { PMDA_PMID(0,14), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_INSTANT,
		PMDA_PMUNITS(0,0,0,0,0,0) }, },
	/* memory_used */
	{ NULL, { PMDA_PMID(0,15), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_INSTANT,
		PMDA_PMUNITS(1,0,0,PM_SPACE_BYTE,0,0) }, },
	/* max_hop_count */
	{ NULL, { PMDA_PMID(0,16), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_INSTANT,
		PMDA_PMUNITS(0,0,0,0,0,0) }, },
	/* reclock.ctdbd.max */
	{ NULL, { PMDA_PMID(0,17), PM_TYPE_DOUBLE, PM_INDOM_NULL, PM_SEM_INSTANT,
		PMDA_PMUNITS(0,1,0,0,PM_TIME_SEC,0) }, },
	/* reclock.recd.max */
	{ NULL, { PMDA_PMID(0,18), PM_TYPE_DOUBLE, PM_INDOM_NULL, PM_SEM_INSTANT,
		PMDA_PMUNITS(0,1,0,0,PM_TIME_SEC,0) }, },
	/* call_latency.max */
	{ NULL, { PMDA_PMID(0,19), PM_TYPE_DOUBLE, PM_INDOM_NULL, PM_SEM_INSTANT,
		PMDA_PMUNITS(0,1,0,0,PM_TIME_SEC,0) }, },
	/* locks.latency.max */
	{ NULL, { PMDA_PMID(0,20), PM_TYPE_DOUBLE, PM_INDOM_NULL, PM_SEM_INSTANT,
		PMDA_PMUNITS(0,1,0,0,PM_TIME_SEC,0) }, },
	/* childwrite_latency.max */
	{ NULL, { PMDA_PMID(0,21), PM_TYPE_DOUBLE, PM_INDOM_NULL, PM_SEM_INSTANT,
		PMDA_PMUNITS(0,1,0,0,PM_TIME_SEC,0) }, },
	/* num_recoveries */
	{ NULL, { PMDA_PMID(0,22), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_INSTANT,
		PMDA_PMUNITS(0,0,0,0,0,0) }, },
};

static struct tevent_context *ev;
static struct ctdb_client_context *client;
static struct ctdb_statistics *stats;

static void
pmda_ctdb_disconnected(void *args)
{
	fprintf(stderr, "ctdbd unreachable\n");
	TALLOC_FREE(client);
}


static int
pmda_ctdb_daemon_connect(void)
{
	const char *socket_name;
	int ret;

	ev = tevent_context_init(NULL);
	if (ev == NULL) {
		fprintf(stderr, "Failed to init event ctx\n");
		return -1;
	}

	socket_name = getenv("CTDB_SOCKET");
	if (socket_name == NULL) {
		socket_name = CTDB_SOCKET;
	}

	ret = ctdb_client_init(ev, ev, socket_name, &client);
	if (ret != 0) {
		fprintf(stderr, "Failed to connect to ctdb daemon via %s\n",
			socket_name);
		goto err_ev;
	}

	ctdb_client_set_disconnect_callback(client, pmda_ctdb_disconnected,
					    NULL);

	return 0;

err_ev:
	talloc_free(ev);
	client = NULL;
	return -1;
}

static void
pmda_ctdb_daemon_disconnect(void)
{
	TALLOC_FREE(client);
	talloc_free(ev);
}

static int
fill_base(unsigned int item, pmAtomValue *atom)
{
	switch (item) {
	case 0:
		atom->ul = stats->num_clients;
		break;
	case 1:
		atom->ul = stats->frozen;
		break;
	case 2:
		atom->ul = stats->recovering;
		break;
	case 3:
		atom->ul = stats->client_packets_sent;
		break;
	case 4:
		atom->ul = stats->client_packets_recv;
		break;
	case 5:
		atom->ul = stats->node_packets_sent;
		break;
	case 6:
		atom->ul = stats->node_packets_recv;
		break;
	case 7:
		atom->ul = stats->keepalive_packets_sent;
		break;
	case 8:
		atom->ul = stats->keepalive_packets_recv;
		break;
	case 9:
		atom->ul = stats->total_calls;
		break;
	case 10:
		atom->ul = stats->pending_calls;
		break;
	case 11:
		atom->ul = stats->locks.num_calls;
		break;
	case 12:
		atom->ul = stats->locks.num_pending;
		break;
	case 13:
		atom->ul = stats->childwrite_calls;
		break;
	case 14:
		atom->ul = stats->pending_childwrite_calls;
		break;
	case 15:
		atom->ul = stats->memory_used;
		break;
	case 16:
		atom->ul = stats->max_hop_count;
		break;
	case 17:
		atom->d = stats->reclock.ctdbd.max;
		break;
	case 18:
		atom->d = stats->reclock.recd.max;
		break;
	case 19:
		atom->d = stats->call_latency.max;
		break;
	case 20:
		atom->d = stats->locks.latency.max;
		break;
	case 21:
		atom->d = stats->childwrite_latency.max;
		break;
	case 22:
		atom->ul = stats->num_recoveries;
		break;
	default:
		return PM_ERR_PMID;
	}

	return 0;
}

static int
fill_node(unsigned int item, pmAtomValue *atom)
{
	switch (item) {
	case 0:
	       atom->ul = stats->node.req_call;
	       break;
	case 1:
	       atom->ul = stats->node.reply_call;
	       break;
	case 2:
	       atom->ul = stats->node.req_dmaster;
	       break;
	case 3:
	       atom->ul = stats->node.reply_dmaster;
	       break;
	case 4:
	       atom->ul = stats->node.reply_error;
	       break;
	case 5:
	       atom->ul = stats->node.req_message;
	       break;
	case 6:
	       atom->ul = stats->node.req_control;
	       break;
	case 7:
		atom->ul = stats->node.reply_control;
		break;
	default:
		return PM_ERR_PMID;
	}

	return 0;
}


static int
fill_client(unsigned int item, pmAtomValue *atom)
{
	switch (item) {
	case 0:
		atom->ul = stats->client.req_call;
		break;
	case 1:
		atom->ul = stats->client.req_message;
		break;
	case 2:
		atom->ul = stats->client.req_control;
		break;
	default:
		return PM_ERR_PMID;
	}

	return 0;
}

static int
fill_timeout(unsigned int item, pmAtomValue *atom)
{
	switch (item) {
	case 0:
		atom->ul = stats->timeouts.call;
		break;
	case 1:
		atom->ul = stats->timeouts.control;
		break;
	case 2:
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
	int ret;
#ifdef HAVE___PMID_INT
	__pmID_int *id = (__pmID_int *)&(mdesc->m_desc.pmid);
#else
	pmID id = *(pmID *)&(mdesc->m_desc.pmid);
#endif

	if (inst != PM_IN_NULL) {
		return PM_ERR_INST;
	}

	if (stats == NULL) {
		fprintf(stderr, "stats not available\n");
		ret = PM_ERR_VALUE;
		goto err_out;
	}


	switch (pmID_cluster(id)) {
	case 0:
		ret = fill_base(pmID_item(id), atom);
		if (ret) {
			goto err_out;
		}
		break;
	case 1:
		ret = fill_node(pmID_item(id), atom);
		if (ret) {
			goto err_out;
		}
		break;
	case 2:
		ret = fill_client(pmID_item(id), atom);
		if (ret) {
			goto err_out;
		}
		break;
	case 3:
		ret = fill_timeout(pmID_item(id), atom);
		if (ret) {
			goto err_out;
		}
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
	int ret;

	if (client == NULL) {
		fprintf(stderr, "attempting reconnect to ctdbd\n");
		ret = pmda_ctdb_daemon_connect();
		if (ret < 0) {
			fprintf(stderr, "reconnect failed\n");
			return PM_ERR_VALUE;
		}
	}

	ret = ctdb_ctrl_statistics(client, ev, client, CTDB_CURRENT_NODE,
				   tevent_timeval_current_ofs(1,0), &stats);
	if (ret != 0) {
		fprintf(stderr, "ctdb control for statistics failed, reconnecting\n");
		pmda_ctdb_daemon_disconnect();
		ret = PM_ERR_VALUE;
		goto err_out;
	}

	ret = pmdaFetch(numpmid, pmidlist, resp, pmda);

	talloc_free(stats);
err_out:
	return ret;
}

void pmda_ctdb_init(pmdaInterface *dp);

/*
 * Initialise the agent
 */
void
pmda_ctdb_init(pmdaInterface *dp)
{
	if (dp->status != 0) {
		return;
	}

	dp->version.two.fetch = pmda_ctdb_fetch;
	pmdaSetFetchCallBack(dp, pmda_ctdb_fetch_cb);

	pmdaInit(dp, NULL, 0, metrictab,
		 (sizeof(metrictab) / sizeof(metrictab[0])));
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
	fprintf(stderr, "Usage: %s [options]\n\n", pmGetProgname());
	fputs("Options:\n"
	  "  -d domain        use domain (numeric) for metrics domain of PMDA\n"
	  "  -l logfile       write log into logfile rather than using default log name\n"
	  "\nExactly one of the following options may appear:\n"
	  "  -i port          expect PMCD to connect on given inet port (number or name)\n"
	  "  -p               expect PMCD to supply stdin/stdout (pipe)\n"
	  "  -u socket        expect PMCD to connect on given unix domain socket\n",
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

	pmSetProgname(argv[0]);

	pmdaDaemon(&dispatch, PMDA_INTERFACE_2, argv[0], CTDB,
		   log_file, helpfile());

	if (pmdaGetOpt(argc, argv, "d:i:l:pu:?", &dispatch, &err) != EOF) {
		err++;
	}

	if (err) {
		usage();
	}

	pmdaOpenLog(&dispatch);
	pmda_ctdb_init(&dispatch);
	pmdaConnect(&dispatch);
	pmdaMain(&dispatch);

	exit(0);
}

