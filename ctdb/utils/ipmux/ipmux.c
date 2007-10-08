/* 
   simple ip multiplexer

   Copyright (C) Ronnie Sahlberg 2007

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
#include "ctdb.h"
#include "ctdb_private.h"
#include <linux/netfilter.h>
#include <libipq.h>

#define CONTROL_TIMEOUT() timeval_current_ofs(5, 0)

struct ipmux_node {
	uint32_t pnn;
	struct sockaddr_in sin;
};
struct ipmux_node *ipmux_nodes;


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
	uint32_t mypnn, recmaster;
	TALLOC_CTX *mem_ctx=NULL;
	struct ctdb_node_map *nodemap;
	int i, num_nodes;
	int s;
	struct ipq_handle *ipqh;
#define PKTSIZE 65535
	unsigned char pktbuf[PKTSIZE];
	ipq_packet_msg_t *ipqp;
	struct iphdr *ip;
	int hash;

	pc = poptGetContext(argv[0], argc, argv, popt_options, POPT_CONTEXT_KEEP_FIRST);

	while ((opt = poptGetNextOpt(pc)) != -1) {
		switch (opt) {
		default:
			fprintf(stderr, "Invalid option %s: %s\n", 
				poptBadOption(pc, 0), poptStrerror(opt));
			exit(1);
		}
	}

	/* talloc_enable_leak_report_full(); */

	/* setup the remaining options for the main program to use */
	extra_argv = poptGetArgs(pc);
	if (extra_argv) {
		extra_argv++;
		while (extra_argv[extra_argc]) extra_argc++;
	}

	ev = event_context_init(NULL);

	ctdb = ctdb_cmdline_client(ev);


	mem_ctx = talloc_new(ctdb);

	/* get our pnn */
	mypnn = ctdb_ctrl_getpnn(ctdb, CONTROL_TIMEOUT(), CTDB_CURRENT_NODE);
	if (mypnn == (uint32_t)-1) {
		DEBUG(0,("IPMUX: Failed to get local pnn - exiting\n"));
		talloc_free(mem_ctx);
		exit(10);
	}


	/* get the recmaster */
	ret = ctdb_ctrl_getrecmaster(ctdb, mem_ctx, CONTROL_TIMEOUT(), CTDB_CURRENT_NODE, &recmaster);
	if (ret != 0) {
		DEBUG(0,("IPMUX: Failed to get recmaster - exiting\n"));
		talloc_free(mem_ctx);
		exit(10);
	}


	/* verify we are the recmaster */
	if (recmaster != mypnn) {
		DEBUG(0,("IPMUX: we are not the recmaster - exiting\n"));
		talloc_free(mem_ctx);
		exit(10);
	}


	/* get the list of nodes */
	ret = ctdb_ctrl_getnodemap(ctdb, CONTROL_TIMEOUT(), CTDB_CURRENT_NODE, mem_ctx, &nodemap);
	if (ret != 0) {
		DEBUG(0,("IPMUX: failed to get the nodemap - exiting\n"));
		talloc_free(mem_ctx);
		exit(10);
	}


	/* count how many connected nodes we have */
	num_nodes = 0;
	for (i=0; i<nodemap->num; i++) {
		if (nodemap->nodes[i].flags & NODE_FLAGS_DISCONNECTED) {
			continue;
		}

		num_nodes++;
	}
	if (num_nodes == 0) {
		DEBUG(0,("IPMUX: no connected nodes - exiting\n"));
		talloc_free(mem_ctx);
		exit(10);
	}

	ipmux_nodes = talloc_array(mem_ctx, struct ipmux_node, num_nodes);
	if (ipmux_nodes == NULL) {
		DEBUG(0,("IPMUX: failed to allocate ipmux node array - exiting\n"));
		talloc_free(mem_ctx);
		exit(10);
	}


	/* populate the ipmux node array */
	num_nodes = 0;
	for (i=0; i<nodemap->num; i++) {
		if (nodemap->nodes[i].flags & NODE_FLAGS_DISCONNECTED) {
			continue;
		}
		ipmux_nodes[num_nodes].pnn = i;
		ipmux_nodes[num_nodes].sin = nodemap->nodes[i].sin;
		num_nodes++;
	}

	
	/* open a raw socket to send the packets out through */
	s = ctdb_sys_open_sending_socket();
	if (s == -1) {
		DEBUG(0,("IPMUX: failed to open raw socket - exiting\n"));
		talloc_free(mem_ctx);
		exit(10);
	}


	/* open the ipq handle */
	ipqh = ipq_create_handle(0, PF_INET);
	if (ipqh == NULL) {
		DEBUG(0,("IPMUX: failed to create ipq handle - exiting\n"));
		talloc_free(mem_ctx);
		exit(10);
	}
	
	ret = ipq_set_mode(ipqh, IPQ_COPY_PACKET, PKTSIZE);
	if (ret < 0) {
		DEBUG(0,("IPMUX: failed to set ipq mode. make sure the ip_queue module is loaded - exiting\n"));
		talloc_free(mem_ctx);
		exit(10);
	}

	while (1) {
		/* wait for the next packet */
		ret = ipq_read(ipqh, pktbuf, PKTSIZE, 0);
		if (ret <= 0) {
			continue;
		}

		/* read the packet */
		ipqp = ipq_get_packet(pktbuf);
		if (ipqp == NULL) {
			continue;
		}

		/* calculate a hash based on the clients ip address */
		ip = (struct iphdr *)&ipqp->payload[0];
		/* ntohl here since the client ip addresses are much more
		   likely to differ in the lower bits than the hight bits */
		hash = ntohl(ip->saddr) % num_nodes;
 

		/* if the packet is hashed to the current host, then
		   just accept it and let the kernel pass it onto
		   the local stack
		*/
		if (ipmux_nodes[hash].pnn == mypnn) {
			ipq_set_verdict(ipqh, ipqp->packet_id, NF_ACCEPT, 0, pktbuf);
			continue;
		}

		/* we have hashed it to one of the other nodes, so
		   send the packet off and tell the kernel to not worry
		   about this packet any more
		*/
		ret = sendto(s, &ipqp->payload[0], ipqp->data_len, 0, &ipmux_nodes[hash].sin, sizeof(struct sockaddr_in));
		ipq_set_verdict(ipqh, ipqp->packet_id, NF_STOLEN, 0, pktbuf);

	}

	return 0;
}
