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
#include "../include/ctdb_private.h"


/*
  show usage message
 */
static void usage(void)
{
	printf("Usage: ctdb_control [options] <control>\n");
	printf("\nControls:\n");
	printf("  process-exists <vnn:pid>\n");
	printf("  status <vnn>\n");
	exit(1);
}

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

	ret = ctdb_process_exists(ctdb, vnn, pid);
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
	printf("   reply_redirect        %u\n", s->count.reply_redirect);
	printf("   req_dmaster           %u\n", s->count.req_dmaster);
	printf("   reply_dmaster         %u\n", s->count.reply_dmaster);
	printf("   reply_error           %u\n", s->count.reply_error);
	printf("   reply_redirect        %u\n", s->count.reply_redirect);
	printf("   req_message           %u\n", s->count.req_message);
	printf("   req_finished          %u\n", s->count.req_finished);
	printf(" total_calls             %u\n", s->total_calls);
	printf(" pending_calls           %u\n", s->pending_calls);
	printf(" lockwait_calls          %u\n", s->lockwait_calls);
	printf(" pending_lockwait_calls  %u\n", s->pending_lockwait_calls);
	printf(" max_redirect_count      %u\n", s->max_redirect_count);
	printf(" max_call_latency        %.6f sec\n", s->max_call_latency);
	printf(" max_lockwait_latency    %.6f sec\n", s->max_lockwait_latency);
}

static int control_status(struct ctdb_context *ctdb, int argc, const char **argv)
{
	uint32_t vnn;
	int ret;
	struct ctdb_status status;
	if (argc < 1) {
		usage();
	}

	vnn = strtoul(argv[0], NULL, 0);

	ret = ctdb_status(ctdb, vnn, &status);
	if (ret != 0) {
		printf("Unable to get status from node %u\n", vnn);
		return ret;
	}
	show_status(&status);
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
	} else {
		printf("Unknown control '%s'\n", control);
		exit(1);
	}

	return ret;
}
