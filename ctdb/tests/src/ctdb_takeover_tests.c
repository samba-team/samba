/* 
   Tests for ctdb_takeover.c

   Copyright (C) Martin Schwenke 2011

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

#include <assert.h>

#include "ctdbd_test.c"

static void print_ctdb_public_ip_list(struct public_ip_list * ips)
{
	while (ips) {
		printf("%s %d\n", ctdb_addr_to_str(&(ips->addr)), ips->pnn);
		ips = ips->next;
	}
}

static uint32_t *get_tunable_values(TALLOC_CTX *tmp_ctx,
				    int numnodes,
				    const char *tunable);
static enum ctdb_runstate *get_runstate(TALLOC_CTX *tmp_ctx,
					int numnodes);

static void add_ip(TALLOC_CTX *mem_ctx,
		   struct ctdb_public_ip_list *l,
		   ctdb_sock_addr *addr,
		   uint32_t pnn)
{

	l->ip = talloc_realloc(mem_ctx, l->ip,
			       struct ctdb_public_ip, l->num + 1);
	assert(l->ip != NULL);

	l->ip[l->num].addr = *addr;
	l->ip[l->num].pnn  = pnn;
	l->num++;
}

/* Format of each line is "IP CURRENT_PNN [ALLOWED_PNN,...]".
 * If multi is true then ALLOWED_PNNs are not allowed.  */
static void read_ctdb_public_ip_info_node(int numnodes,
					  bool multi,
					  struct ctdb_public_ip_list **k,
					  struct ctdb_public_ip_list *known)
{
	char line[1024];
	ctdb_sock_addr addr;
	char *t, *tok;
	int pnn, n;

	/* Known public IPs */
	*k = talloc_zero(known, struct ctdb_public_ip_list);
	assert(k != NULL);

	while (fgets(line, sizeof(line), stdin) != NULL) {

		/* Get rid of pesky newline */
		if ((t = strchr(line, '\n')) != NULL) {
			*t = '\0';
		}

		/* Exit on an empty line */
		if (line[0] == '\0') {
			break;
		}

		/* Get the IP address */
		tok = strtok(line, " \t");
		if (tok == NULL) {
			DEBUG(DEBUG_ERR, (__location__ " WARNING, bad line ignored :%s\n", line));
			continue;
		}

		if (!parse_ip(tok, NULL, 0, &addr)) {
			DEBUG(DEBUG_ERR, (__location__ " ERROR, bad address :%s\n", tok));
			continue;
		}

		/* Get the PNN */
		pnn = -1;
		tok = strtok(NULL, " \t");
		if (tok != NULL) {
			pnn = (int) strtol(tok, (char **) NULL, 10);
		}

		add_ip(*k, *k, &addr, pnn);

		tok = strtok(NULL, " \t#");
		if (tok == NULL) {
			continue;
		}

		/* Handle allowed nodes for addr */
		assert(multi == false);
		t = strtok(tok, ",");
		while (t != NULL) {
			n = (int) strtol(t, (char **) NULL, 10);
			add_ip(known, &known[n], &addr, pnn);
			t = strtok(NULL, ",");
		}
	}
}

static void read_ctdb_public_ip_info(TALLOC_CTX *ctx,
				     int numnodes,
				     bool multi,
				     struct ctdb_public_ip_list ** known,
				     struct ctdb_public_ip_list ** avail)
{
	int n;
	struct ctdb_public_ip_list * k;
	enum ctdb_runstate *runstate;

	*known = talloc_zero_array(ctx, struct ctdb_public_ip_list,
				   numnodes);
	assert(*known != NULL);
	*avail = talloc_zero_array(ctx, struct ctdb_public_ip_list,
				   numnodes);
	assert(*avail != NULL);

	if (multi) {
		for (n = 0; n < numnodes; n++) {
			read_ctdb_public_ip_info_node(numnodes, multi,
						      &k, *known);

			(*known)[n] = *k;
		}
	} else {
		read_ctdb_public_ip_info_node(numnodes, multi, &k, *known);

		/* Assign it to any nodes that don't have a list assigned */
		for (n = 0; n < numnodes; n++) {
			if ((*known)[n].num == 0) {
				(*known)[n] = *k;
			}
		}
	}

	runstate = get_runstate(ctx, numnodes);
	for (n = 0; n < numnodes; n++) {
		if (runstate[n] == CTDB_RUNSTATE_RUNNING) {
			(*avail)[n] = (*known)[n];
		}
	}
}

static uint32_t *get_tunable_values(TALLOC_CTX *tmp_ctx,
				    int numnodes,
				    const char *tunable)
{
	int i;
	char *tok;
	uint32_t *tvals = talloc_zero_array(tmp_ctx, uint32_t, numnodes);
	char *t = getenv(tunable);

	if (t) {
		if (strcmp(t, "1") == 0) {
			for (i=0; i<numnodes; i++) {
				tvals[i] = 1;
			}
		} else {
			tok = strtok(t, ",");
			i = 0;
			while (tok != NULL) {
				tvals[i] =
					(uint32_t) strtol(tok, NULL, 0);
				i++;
				tok = strtok(NULL, ",");
			}
			if (i != numnodes) {
				fprintf(stderr, "ERROR: Wrong number of values in %s\n", tunable);
				exit(1);
			}
		}
	}

	return tvals;
}

static enum ctdb_runstate *get_runstate(TALLOC_CTX *tmp_ctx,
					int numnodes)
{
	int i;
	uint32_t *tvals;
	enum ctdb_runstate *runstate =
		talloc_zero_array(tmp_ctx, enum ctdb_runstate, numnodes);
	char *t = getenv("CTDB_TEST_RUNSTATE");

	if (t == NULL) {
		for (i=0; i<numnodes; i++) {
			runstate[i] = CTDB_RUNSTATE_RUNNING;
		}
	} else {
		tvals = get_tunable_values(tmp_ctx, numnodes, "CTDB_TEST_RUNSTATE");
		for (i=0; i<numnodes; i++) {
			runstate[i] = (enum ctdb_runstate) tvals[i];
		}
		talloc_free(tvals);
	}

	return runstate;
}

/* Fake up enough CTDB state to be able to run the IP allocation
 * algorithm.  Usually this sets up some standard state, sets the node
 * states from the command-line and reads the current IP layout from
 * stdin.
 *
 * However, if read_ips_for_multiple_nodes is true then each node's
 * idea of the IP layout is read separately from stdin.  In this mode
 * is doesn't make much sense to use read_ctdb_public_ip_info's
 * optional ALLOWED_PNN,... list in the input, since each node is
 * being handled separately anyway.  IPs for each node are separated
 * by a blank line.  This mode is for testing weird behaviours where
 * the IP layouts differs across nodes and we want to improve
 * create_merged_ip_list(), so should only be used in tests of
 * ipalloc().  Yes, it is a hack...  :-)
 */
static void ctdb_test_init(const char nodestates[],
			   struct ctdb_context **ctdb,
			   struct ipalloc_state **ipalloc_state,
			   bool read_ips_for_multiple_nodes)
{
	struct ctdb_public_ip_list *known;
	struct ctdb_public_ip_list *avail;
	int i;
	char *tok, *ns, *t;
	struct ctdb_node_map_old *nodemap;
	uint32_t *tval_noiptakeover;
	uint32_t *tval_noiptakeoverondisabled;
	ctdb_sock_addr sa_zero = { .ip = { 0 } };

	*ctdb = talloc_zero(NULL, struct ctdb_context);

	/* Avoid that const */
	ns = talloc_strdup(*ctdb, nodestates);

	nodemap = talloc_zero(*ctdb, struct ctdb_node_map_old);
	assert(nodemap != NULL);
	nodemap->num = 0;
	tok = strtok(ns, ",");
	while (tok != NULL) {
		uint32_t n = nodemap->num;
		size_t size =
			offsetof(struct ctdb_node_map_old, nodes) +
			(n + 1) * sizeof(struct ctdb_node_and_flags);
		nodemap = talloc_realloc_size(*ctdb, nodemap, size);
		nodemap->nodes[n].pnn = n;
		nodemap->nodes[n].flags = (uint32_t) strtol(tok, NULL, 0);
		nodemap->nodes[n].addr = sa_zero;
		nodemap->num++;
		tok = strtok(NULL, ",");
	}
	
	/* Fake things up... */
	(*ctdb)->num_nodes = nodemap->num;

	/* Default to LCP2 */
	(*ctdb)->tunable.lcp2_public_ip_assignment = 1;
	(*ctdb)->tunable.deterministic_public_ips = 0;
	(*ctdb)->tunable.disable_ip_failover = 0;
	(*ctdb)->tunable.no_ip_failback = 0;

	if ((t = getenv("CTDB_IP_ALGORITHM"))) {
		if (strcmp(t, "lcp2") == 0) {
			(*ctdb)->tunable.lcp2_public_ip_assignment = 1;
		} else if (strcmp(t, "nondet") == 0) {
			(*ctdb)->tunable.lcp2_public_ip_assignment = 0;
		} else if (strcmp(t, "det") == 0) {
			(*ctdb)->tunable.lcp2_public_ip_assignment = 0;
			(*ctdb)->tunable.deterministic_public_ips = 1;
		} else {
			fprintf(stderr, "ERROR: unknown IP algorithm %s\n", t);
			exit(1);
		}
	}

	tval_noiptakeover = get_tunable_values(*ctdb, nodemap->num,
					       "CTDB_SET_NoIPTakeover");
	tval_noiptakeoverondisabled =
		get_tunable_values(*ctdb, nodemap->num,
				   "CTDB_SET_NoIPHostOnAllDisabled");

	(*ctdb)->nodes = talloc_array(*ctdb, struct ctdb_node *, nodemap->num); // FIXME: bogus size, overkill

	*ipalloc_state = ipalloc_state_init(*ctdb, *ctdb);

	read_ctdb_public_ip_info(*ctdb, nodemap->num,
				 read_ips_for_multiple_nodes,
				 &known, &avail);

	for (i=0; i < nodemap->num; i++) {
		(*ctdb)->nodes[i] = talloc(*ctdb, struct ctdb_node);
		(*ctdb)->nodes[i]->pnn = i;
		(*ctdb)->nodes[i]->flags = nodemap->nodes[i].flags;
	}

	(*ipalloc_state)->available_public_ips = avail;
	(*ipalloc_state)->known_public_ips = known;

	set_ipflags_internal(*ipalloc_state, nodemap,
			     tval_noiptakeover,
			     tval_noiptakeoverondisabled);

	(*ipalloc_state)->all_ips = create_merged_ip_list(*ctdb,
							  *ipalloc_state);

	(*ipalloc_state)->force_rebalance_nodes = NULL;
}

/* IP layout is read from stdin.  See comment for ctdb_test_init() for
 * explanation of read_ips_for_multiple_nodes.
 */
static void ctdb_test_ipalloc(const char nodestates[],
			      bool read_ips_for_multiple_nodes)
{
	struct ctdb_context *ctdb;
	struct ipalloc_state *ipalloc_state;

	ctdb_test_init(nodestates, &ctdb, &ipalloc_state,
		       read_ips_for_multiple_nodes);

	ipalloc(ipalloc_state);

	print_ctdb_public_ip_list(ipalloc_state->all_ips);

	talloc_free(ctdb);
}

static void usage(void)
{
	fprintf(stderr, "usage: ctdb_takeover_tests <op>\n");
	exit(1);
}

int main(int argc, const char *argv[])
{
	DEBUGLEVEL = DEBUG_DEBUG;
	if (getenv("CTDB_TEST_LOGLEVEL")) {
		DEBUGLEVEL = atoi(getenv("CTDB_TEST_LOGLEVEL"));
	}

	if (argc < 2) {
		usage();
	}

	if (argc == 3 &&
		   strcmp(argv[1], "ipalloc") == 0) {
		ctdb_test_ipalloc(argv[2], false);
	} else if (argc == 4 &&
		   strcmp(argv[1], "ipalloc") == 0 &&
		   strcmp(argv[3], "multi") == 0) {
		ctdb_test_ipalloc(argv[2], true);
	} else {
		usage();
	}

	return 0;
}
