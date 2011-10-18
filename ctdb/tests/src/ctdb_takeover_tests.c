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

#include "includes.h"
#include "../include/ctdb_private.h"

/*
 * Need these, since they're defined in ctdbd.c but we can't link
 * that.
 */
int script_log_level;
bool fast_start;
void ctdb_load_nodes_file(struct ctdb_context *ctdb) {}

/* Format of each line is "IP pnn" - the separator has to be at least
 * 1 space (not a tab or whatever - a space!).
 */
static struct ctdb_public_ip_list *
read_ctdb_public_ip_list(TALLOC_CTX *ctx)
{
	char line[1024];
	ctdb_sock_addr addr;
	char *t;
	int pnn;
	struct ctdb_public_ip_list *last = NULL;

	struct ctdb_public_ip_list *ret = NULL;

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
				last = talloc(ctx, struct ctdb_public_ip_list);
			} else {
				last->next = talloc(ctx, struct ctdb_public_ip_list);
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

void print_ctdb_public_ip_list(struct ctdb_public_ip_list * ips)
{
	while (ips) {
		printf("%s %d\n", ctdb_addr_to_str(&(ips->addr)), ips->pnn);
		ips = ips->next;
	}
}

/* Read some IPs from stdin, 1 per line, parse them and then print
 * them back out. */
void ctdb_test_read_ctdb_public_ip_list(void)
{
	struct ctdb_public_ip_list *l;

	TALLOC_CTX *tmp_ctx = talloc_new(NULL);

	l = read_ctdb_public_ip_list(tmp_ctx);

	print_ctdb_public_ip_list(l);

	talloc_free(tmp_ctx);
}

/* Read 2 IPs from stdin, calculate the IP distance and print it. */
void ctdb_test_ip_distance(void)
{
	struct ctdb_public_ip_list *l;
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
void ctdb_test_ip_distance_2_sum(const char ip[], int pnn)
{
	struct ctdb_public_ip_list *l;
	struct ctdb_public_ip_list *t;
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

/* Read some IPs from stdin, calculate the sume of the squares of the
 * IP distances between the first and the rest, and print it. */
void ctdb_test_lcp2_imbalance(int pnn)
{
	struct ctdb_public_ip_list *l;
	uint32_t imbalance;

	TALLOC_CTX *tmp_ctx = talloc_new(NULL);

	l = read_ctdb_public_ip_list(tmp_ctx);

	imbalance = lcp2_imbalance(l, pnn);
	printf ("%lu\n", (unsigned long) imbalance);

	talloc_free(tmp_ctx);
}

void ctdb_test_init(const char nodestates[],
		    struct ctdb_context **ctdb,
		    struct ctdb_public_ip_list **all_ips,
		    struct ctdb_node_map **nodemap)
{
	struct ctdb_public_ip_list *t;
	struct ctdb_all_public_ips *available_public_ips;
	int i, numips, numnodes;
	/* This is test code and this is unreasonably big... :-) */
	uint32_t nodeflags[256];
	char *tok, *ns;

	*ctdb = talloc_zero(NULL, struct ctdb_context);

	/* Avoid that const */
	ns = talloc_strdup(*ctdb, nodestates);

	numnodes = 0;
	tok = strtok(ns, ",");
	while (tok != NULL) {
		nodeflags[numnodes] = (uint32_t) strtol(tok, NULL, 16);
		numnodes++;
		tok = strtok(NULL, ",");
	}
	
	/* Fake things up... */
	(*ctdb)->num_nodes = numnodes;

	(*ctdb)->tunable.deterministic_public_ips = 0;
	(*ctdb)->tunable.disable_ip_failover = 0;
	(*ctdb)->tunable.no_ip_failback = 0;

	if (getenv("CTDB_LCP2")) {
		if (strcmp(getenv("CTDB_LCP2"), "yes") == 0) {
			(*ctdb)->tunable.lcp2_public_ip_assignment = 1;
		} else {
			(*ctdb)->tunable.lcp2_public_ip_assignment = 0;
		}
	}

	*nodemap =  talloc_array(*ctdb, struct ctdb_node_map, numnodes);
	(*nodemap)->num = numnodes;

	*all_ips = read_ctdb_public_ip_list(*ctdb);
	numips = 0;
	for (t = *all_ips; t != NULL; t = t->next) {
		numips++;
	}

	available_public_ips = talloc_array(*ctdb, struct ctdb_all_public_ips, numips); // FIXME: bogus size, overkill
	available_public_ips->num = numips;
	for (t = *all_ips, i=0; t != NULL && i < numips ; t = t->next, i++) {
		available_public_ips->ips[i].pnn = t->pnn;
		memcpy(&(available_public_ips->ips[i].addr), &(t->addr), sizeof(t->addr));
	}

	(*ctdb)->nodes = talloc_array(*ctdb, struct ctdb_node *, numnodes); // FIXME: bogus size, overkill

	/* Setup both nodemap and ctdb->nodes.  Mark all nodes as
	 * healthy - change this later. */
	for (i=0; i < numnodes; i++) {
		(*nodemap)->nodes[i].pnn = i;
		(*nodemap)->nodes[i].flags = nodeflags[i];
		/* nodemap->nodes[i].sockaddr is uninitialised */

		(*ctdb)->nodes[i] = talloc(*ctdb, struct ctdb_node);
		(*ctdb)->nodes[i]->pnn = i;
		(*ctdb)->nodes[i]->flags = nodeflags[i];
		(*ctdb)->nodes[i]->available_public_ips = available_public_ips;
		(*ctdb)->nodes[i]->known_public_ips = available_public_ips;
	}
}

/* IP layout is read from stdin. */
void ctdb_test_lcp2_allocate_unassigned(const char nodestates[])
{
	struct ctdb_context *ctdb;
	struct ctdb_public_ip_list *all_ips;
	struct ctdb_node_map *nodemap;

	uint32_t *lcp2_imbalances;
	bool *newly_healthy;

	ctdb_test_init(nodestates, &ctdb, &all_ips, &nodemap);

	lcp2_init(ctdb, nodemap,
		  NODE_FLAGS_INACTIVE|NODE_FLAGS_DISABLED,
		  all_ips, &lcp2_imbalances, &newly_healthy);

	lcp2_allocate_unassigned(ctdb, nodemap,
				 NODE_FLAGS_INACTIVE|NODE_FLAGS_DISABLED,
				 all_ips, lcp2_imbalances);

	print_ctdb_public_ip_list(all_ips);

	talloc_free(ctdb);
}

/* IP layout is read from stdin. */
void ctdb_test_lcp2_failback(const char nodestates[])
{
	struct ctdb_context *ctdb;
	struct ctdb_public_ip_list *all_ips;
	struct ctdb_node_map *nodemap;

	uint32_t *lcp2_imbalances;
	bool *newly_healthy;

	ctdb_test_init(nodestates, &ctdb, &all_ips, &nodemap);

	lcp2_init(ctdb, nodemap,
		  NODE_FLAGS_INACTIVE|NODE_FLAGS_DISABLED,
		  all_ips, &lcp2_imbalances, &newly_healthy);

	lcp2_failback(ctdb, nodemap,
				 NODE_FLAGS_INACTIVE|NODE_FLAGS_DISABLED,
		      all_ips, lcp2_imbalances, newly_healthy);

	print_ctdb_public_ip_list(all_ips);

	talloc_free(ctdb);
}

/* IP layout is read from stdin. */
void ctdb_test_lcp2_failback_loop(const char nodestates[])
{
	struct ctdb_context *ctdb;
	struct ctdb_public_ip_list *all_ips;
	struct ctdb_node_map *nodemap;

	uint32_t *lcp2_imbalances;
	bool *newly_healthy;

	ctdb_test_init(nodestates, &ctdb, &all_ips, &nodemap);

	lcp2_init(ctdb, nodemap,
		  NODE_FLAGS_INACTIVE|NODE_FLAGS_DISABLED,
		  all_ips, &lcp2_imbalances, &newly_healthy);

try_again:
	if (lcp2_failback(ctdb, nodemap,
			  NODE_FLAGS_INACTIVE|NODE_FLAGS_DISABLED,
			  all_ips, lcp2_imbalances, newly_healthy)) {
		goto try_again;
	}

	print_ctdb_public_ip_list(all_ips);

	talloc_free(ctdb);
}

/* IP layout is read from stdin. */
void ctdb_test_ctdb_takeover_run_core(const char nodestates[])
{
	struct ctdb_context *ctdb;
	struct ctdb_public_ip_list *all_ips;
	struct ctdb_node_map *nodemap;

	ctdb_test_init(nodestates, &ctdb, &all_ips, &nodemap);

	ctdb_takeover_run_core(ctdb, nodemap, &all_ips);

	print_ctdb_public_ip_list(all_ips);

	talloc_free(ctdb);
}

void usage(void)
{
	fprintf(stderr, "usage: ctdb_takeover_tests <op>\n");
	exit(1);
}

int main(int argc, const char *argv[])
{
	LogLevel = DEBUG_DEBUG;
	if (getenv("CTDB_TEST_LOGLEVEL")) {
		LogLevel = atoi(getenv("CTDB_TEST_LOGLEVEL"));
	}

	if (argc < 2) {
		usage();
	}

	if (strcmp(argv[1], "ip_list") == 0) {
		ctdb_test_read_ctdb_public_ip_list();
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
	} else if (argc == 3 && strcmp(argv[1], "ctdb_takeover_run_core") == 0) {
		ctdb_test_ctdb_takeover_run_core(argv[2]);
	} else {
		usage();
	}

	return 0;
}
