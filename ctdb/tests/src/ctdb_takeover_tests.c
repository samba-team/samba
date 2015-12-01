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

#include "ctdbd_test.c"

/* This is lazy... but it is test code! */
#define CTDB_TEST_MAX_NODES 256
#define CTDB_TEST_MAX_IPS 1024

/* Format of each line is "IP pnn" - the separator has to be at least
 * 1 space (not a tab or whatever - a space!).
 */
static struct public_ip_list *
read_ctdb_public_ip_list(TALLOC_CTX *ctx)
{
	char line[1024];
	ctdb_sock_addr addr;
	char *t;
	int pnn;
	struct public_ip_list *last = NULL;

	struct public_ip_list *ret = NULL;

	while (fgets(line, sizeof(line), stdin) != NULL) {
		
		if ((t = strchr(line, ' ')) != NULL) {
			/* Make line contain just the address */
			*t = '\0';
			/* Point to PNN or leading whitespace...  */
			t++;
			pnn = (int) strtol(t, (char **) NULL, 10);
		} else {
			/* Assume just an IP address, default to PNN -1 */
			if ((t = strchr(line, '\n')) != NULL) {
				*t = '\0';
			}
			pnn = -1;
		}
	       
		if (parse_ip(line, NULL, 0, &addr)) {
			if (last == NULL) {
				last = talloc(ctx, struct public_ip_list);
			} else {
				last->next = talloc(ctx, struct public_ip_list);
				last = last->next;
			}
			last->next = NULL;
			last->pnn = pnn;
			memcpy(&(last->addr), &addr, sizeof(addr));
			if (ret == NULL) {
				ret = last;
			}
		} else {
			DEBUG(DEBUG_ERR, (__location__ " ERROR, bad address :%s\n", line));
		}
	}
			
	return ret;
}

static void print_ctdb_public_ip_list(struct public_ip_list * ips)
{
	while (ips) {
		printf("%s %d\n", ctdb_addr_to_str(&(ips->addr)), ips->pnn);
		ips = ips->next;
	}
}

/* Read some IPs from stdin, 1 per line, parse them and then print
 * them back out. */
static void ctdb_test_read_ctdb_public_ip_list(void)
{
	struct public_ip_list *l;

	TALLOC_CTX *tmp_ctx = talloc_new(NULL);

	l = read_ctdb_public_ip_list(tmp_ctx);

	print_ctdb_public_ip_list(l);

	talloc_free(tmp_ctx);
}

static uint32_t *get_tunable_values(TALLOC_CTX *tmp_ctx,
				    int numnodes,
				    const char *tunable);
static enum ctdb_runstate *get_runstate(TALLOC_CTX *tmp_ctx,
					int numnodes);

/* Format of each line is "IP CURRENT_PNN ALLOWED_PNN,...".
 */
static bool
read_ctdb_public_ip_info(TALLOC_CTX *ctx  ,
			 int numnodes,
			 struct public_ip_list ** all_ips,
			 struct ctdb_public_ip_list_old *** known,
			 struct ctdb_public_ip_list_old *** avail)
{
	char line[1024];
	ctdb_sock_addr addr;
	char *t, *tok;
	struct public_ip_list * ta;
	int pnn, numips, curr, n, i;
	struct ctdb_public_ip_list_old * a;

	struct public_ip_list *last = NULL;
	enum ctdb_runstate *runstate;

	runstate = get_runstate(ctx, numnodes);

	*known = talloc_array_size(ctx, sizeof(struct ctdb_public_ip_list_old *), CTDB_TEST_MAX_NODES);
	memset(*known, 0,
	       sizeof(struct ctdb_public_ip_list_old *) * CTDB_TEST_MAX_NODES);

	*avail = talloc_array_size(ctx, sizeof(struct ctdb_public_ip_list_old *),
				   CTDB_TEST_MAX_NODES);
	memset(*avail, 0,
	       sizeof(struct ctdb_public_ip_list_old *) * CTDB_TEST_MAX_NODES);

	numips = 0;
	*all_ips = NULL;
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

		numips++;
		if (numips > CTDB_TEST_MAX_IPS) {
			DEBUG(DEBUG_ERR, ("ERROR: Exceeding CTDB_TEST_MAX_IPS: %d\n", CTDB_TEST_MAX_IPS));
			exit(1);
		}

		/* Get the PNN */
		pnn = -1;
		tok = strtok(NULL, " \t");
		if (tok != NULL) {
			pnn = (int) strtol(tok, (char **) NULL, 10);
		}

		/* Add address + pnn to all_ips */
		if (last == NULL) {
			last = talloc(ctx, struct public_ip_list);
		} else {
			last->next = talloc(ctx, struct public_ip_list);
			last = last->next;
		}
		last->next = NULL;
		last->pnn = pnn;
		memcpy(&(last->addr), &addr, sizeof(addr));
		if (*all_ips == NULL) {
			*all_ips = last;
		}

		tok = strtok(NULL, " \t#");
		if (tok == NULL) {
			continue;
		}

		/* Handle allowed nodes for addr */
		t = strtok(tok, ",");
		while (t != NULL) {
			n = (int) strtol(t, (char **) NULL, 10);
			if ((*known)[n] == NULL) {
				/* Array size here has to be
				 * CTDB_TEST_MAX_IPS because total
				 * number of IPs isn't yet known */
				(*known)[n] = talloc_size(ctx,
							  offsetof(struct ctdb_public_ip_list_old, ips) +
							  CTDB_TEST_MAX_IPS * sizeof(struct ctdb_public_ip));
				(*known)[n]->num = 0;
			}
			curr = (*known)[n]->num;
			(*known)[n]->ips[curr].pnn = pnn;
			memcpy(&((*known)[n]->ips[curr].addr),
			       &addr, sizeof(addr));
			(*known)[n]->num++;
			t = strtok(NULL, ",");
		}

	}

	/* Build list of all allowed IPs */
	a = talloc_size(ctx,
			offsetof(struct ctdb_public_ip_list_old, ips) +
			numips * sizeof(struct ctdb_public_ip));
	a->num = numips;
	for (ta = *all_ips, i=0; ta != NULL && i < numips ; ta = ta->next, i++) {
		a->ips[i].pnn = ta->pnn;
		memcpy(&(a->ips[i].addr), &(ta->addr), sizeof(ta->addr));
	}

	/* Assign it to any nodes that don't have a list assigned */
	for (n = 0; n < numnodes; n++) {
		if ((*known)[n] == NULL) {
			(*known)[n] = a;
		}
		if (runstate[n] == CTDB_RUNSTATE_RUNNING) {
			(*avail)[n] = (*known)[n];
		}
	}

	return true;
}

static void print_ctdb_available_ips(int numnodes,
				     struct ctdb_public_ip_list_old **avail)
{
	int n, i;

	for (n = 0; n < numnodes; n++) {
		if ((avail[n] != NULL) && (avail[n]->num > 0)) {
			printf("%d:", n);
			for (i = 0; i < avail[n]->num; i++) {
				printf("%s%s",
				       (i == 0) ? " " : ", ",
				       ctdb_addr_to_str(&(avail[n]->ips[i].addr)));
			}
			printf("\n");
		}
	}
}

static void ctdb_test_read_ctdb_public_ip_info(const char nodestates[])
{
	int numnodes;
	struct public_ip_list *l;
	struct ctdb_public_ip_list_old **known;
	struct ctdb_public_ip_list_old **avail;
	char *tok, *ns;

	TALLOC_CTX *tmp_ctx = talloc_new(NULL);

	/* Avoid that const */
	ns = talloc_strdup(tmp_ctx, nodestates);

	numnodes = 0;
	tok = strtok(ns, ",");
	while (tok != NULL) {
		numnodes++;
		if (numnodes > CTDB_TEST_MAX_NODES) {
			DEBUG(DEBUG_ERR, ("ERROR: Exceeding CTDB_TEST_MAX_NODES: %d\n", CTDB_TEST_MAX_NODES));
			exit(1);
		}
		tok = strtok(NULL, ",");
	}
	
	read_ctdb_public_ip_info(tmp_ctx, numnodes, &l, &known, &avail);

	print_ctdb_public_ip_list(l);
	print_ctdb_available_ips(numnodes, avail);

	talloc_free(tmp_ctx);
}

/* Read 2 IPs from stdin, calculate the IP distance and print it. */
static void ctdb_test_ip_distance(void)
{
	struct public_ip_list *l;
	uint32_t distance;

	TALLOC_CTX *tmp_ctx = talloc_new(NULL);

	l = read_ctdb_public_ip_list(tmp_ctx);

	if (l && l->next) {
		distance = ip_distance(&(l->addr), &(l->next->addr));
		printf ("%lu\n", (unsigned long) distance);
	}

	talloc_free(tmp_ctx);
}

/* Read some IPs from stdin, calculate the sum of the squares of the
 * IP distances between the 1st argument and those read that are on
 * the given node. The given IP must one of the ones in the list.  */
static void ctdb_test_ip_distance_2_sum(const char ip[], int pnn)
{
	struct public_ip_list *l;
	struct public_ip_list *t;
	ctdb_sock_addr addr;
	uint32_t distance;

	TALLOC_CTX *tmp_ctx = talloc_new(NULL);

	
	l = read_ctdb_public_ip_list(tmp_ctx);

	if (l && parse_ip(ip, NULL, 0, &addr)) {
		/* find the entry for the specified IP */
		for (t=l; t!=NULL; t=t->next) {
			if (ctdb_same_ip(&(t->addr), &addr)) {
				break;
			}
		}

		if (t == NULL) {
			fprintf(stderr, "IP NOT PRESENT IN LIST");
			exit(1);
		}

		distance = ip_distance_2_sum(&(t->addr), l, pnn);
		printf ("%lu\n", (unsigned long) distance);
	} else {
		fprintf(stderr, "BAD INPUT");
		exit(1);
	}

	talloc_free(tmp_ctx);
}

/* Read some IPs from stdin, calculate the sum of the squares of the
 * IP distances between the first and the rest, and print it. */
static void ctdb_test_lcp2_imbalance(int pnn)
{
	struct public_ip_list *l;
	uint32_t imbalance;

	TALLOC_CTX *tmp_ctx = talloc_new(NULL);

	l = read_ctdb_public_ip_list(tmp_ctx);

	imbalance = lcp2_imbalance(l, pnn);
	printf ("%lu\n", (unsigned long) imbalance);

	talloc_free(tmp_ctx);
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
	struct ctdb_public_ip_list_old **known;
	struct ctdb_public_ip_list_old **avail;
	int i, numnodes;
	uint32_t nodeflags[CTDB_TEST_MAX_NODES];
	char *tok, *ns, *t;
	struct ctdb_node_map_old *nodemap;
	uint32_t *tval_noiptakeover;
	uint32_t *tval_noiptakeoverondisabled;
	struct public_ip_list *all_ips;

	*ctdb = talloc_zero(NULL, struct ctdb_context);

	/* Avoid that const */
	ns = talloc_strdup(*ctdb, nodestates);

	numnodes = 0;
	tok = strtok(ns, ",");
	while (tok != NULL) {
		nodeflags[numnodes] = (uint32_t) strtol(tok, NULL, 0);
		numnodes++;
		if (numnodes >= CTDB_TEST_MAX_NODES) {
			DEBUG(DEBUG_ERR, ("ERROR: Exceeding CTDB_TEST_MAX_NODES: %d\n", CTDB_TEST_MAX_NODES));
			exit(1);
		}
		tok = strtok(NULL, ",");
	}
	
	/* Fake things up... */
	(*ctdb)->num_nodes = numnodes;

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

	tval_noiptakeover = get_tunable_values(*ctdb, numnodes,
					       "CTDB_SET_NoIPTakeover");
	tval_noiptakeoverondisabled =
		get_tunable_values(*ctdb, numnodes,
				   "CTDB_SET_NoIPHostOnAllDisabled");

	nodemap =  talloc_array(*ctdb, struct ctdb_node_map_old, numnodes);
	nodemap->num = numnodes;

	if (!read_ips_for_multiple_nodes) {
		read_ctdb_public_ip_info(*ctdb, numnodes,
					 &all_ips, &known, &avail);
	}

	(*ctdb)->nodes = talloc_array(*ctdb, struct ctdb_node *, numnodes); // FIXME: bogus size, overkill

	*ipalloc_state = ipalloc_state_init(*ctdb, *ctdb);

	for (i=0; i < numnodes; i++) {
		nodemap->nodes[i].pnn = i;
		nodemap->nodes[i].flags = nodeflags[i];
		/* nodemap->nodes[i].sockaddr is uninitialised */

		if (read_ips_for_multiple_nodes) {
			read_ctdb_public_ip_info(*ctdb, numnodes,
						 &all_ips, &known, &avail);
		}

		(*ctdb)->nodes[i] = talloc(*ctdb, struct ctdb_node);
		(*ctdb)->nodes[i]->pnn = i;
		(*ctdb)->nodes[i]->flags = nodeflags[i];

		(*ipalloc_state)->available_public_ips[i] = avail[i];
		(*ipalloc_state)->known_public_ips[i] = known[i];
	}

	set_ipflags_internal(*ipalloc_state, nodemap,
			     tval_noiptakeover,
			     tval_noiptakeoverondisabled);

	(*ipalloc_state)->all_ips = create_merged_ip_list(*ctdb,
							  *ipalloc_state);

	(*ipalloc_state)->force_rebalance_nodes = NULL;
}

/* IP layout is read from stdin. */
static void ctdb_test_lcp2_allocate_unassigned(const char nodestates[])
{
	struct ctdb_context *ctdb;
	struct ipalloc_state *ipalloc_state;

	uint32_t *lcp2_imbalances;
	bool *newly_healthy;

	ctdb_test_init(nodestates, &ctdb, &ipalloc_state, false);

	lcp2_init(ipalloc_state, &lcp2_imbalances, &newly_healthy);

	lcp2_allocate_unassigned(ipalloc_state, lcp2_imbalances);

	print_ctdb_public_ip_list(ipalloc_state->all_ips);

	talloc_free(ctdb);
}

/* IP layout is read from stdin. */
static void ctdb_test_lcp2_failback(const char nodestates[])
{
	struct ctdb_context *ctdb;
	struct ipalloc_state *ipalloc_state;

	uint32_t *lcp2_imbalances;
	bool *newly_healthy;

	ctdb_test_init(nodestates, &ctdb, &ipalloc_state, false);

	lcp2_init(ipalloc_state, &lcp2_imbalances, &newly_healthy);

	lcp2_failback(ipalloc_state, lcp2_imbalances, newly_healthy);

	print_ctdb_public_ip_list(ipalloc_state->all_ips);

	talloc_free(ctdb);
}

/* IP layout is read from stdin. */
static void ctdb_test_lcp2_failback_loop(const char nodestates[])
{
	struct ctdb_context *ctdb;
	struct ipalloc_state *ipalloc_state;

	uint32_t *lcp2_imbalances;
	bool *newly_healthy;

	ctdb_test_init(nodestates, &ctdb, &ipalloc_state, false);

	lcp2_init(ipalloc_state, &lcp2_imbalances, &newly_healthy);

	lcp2_failback(ipalloc_state, lcp2_imbalances, newly_healthy);

	print_ctdb_public_ip_list(ipalloc_state->all_ips);

	talloc_free(ctdb);
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

	if (strcmp(argv[1], "ip_list") == 0) {
		ctdb_test_read_ctdb_public_ip_list();
	} else if (argc == 3 && strcmp(argv[1], "ip_info") == 0) {
		ctdb_test_read_ctdb_public_ip_info(argv[2]);
	} else if (strcmp(argv[1], "ip_distance") == 0) {
		ctdb_test_ip_distance();
	} else if (argc == 4 && strcmp(argv[1], "ip_distance_2_sum") == 0) {
		ctdb_test_ip_distance_2_sum(argv[2], atoi(argv[3]));
	} else if (argc >= 3 && strcmp(argv[1], "lcp2_imbalance") == 0) {
		ctdb_test_lcp2_imbalance(atoi(argv[2]));
	} else if (argc == 3 && strcmp(argv[1], "lcp2_allocate_unassigned") == 0) {
		ctdb_test_lcp2_allocate_unassigned(argv[2]);
	} else if (argc == 3 && strcmp(argv[1], "lcp2_failback") == 0) {
		ctdb_test_lcp2_failback(argv[2]);
	} else if (argc == 3 && strcmp(argv[1], "lcp2_failback_loop") == 0) {
		ctdb_test_lcp2_failback_loop(argv[2]);
	} else if (argc == 3 &&
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
