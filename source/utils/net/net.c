/* 
   Samba Unix/Linux SMB client library 
   Distributed SMB/CIFS Server Management Utility 
   Copyright (C) 2001 Steve French  (sfrench@us.ibm.com)
   Copyright (C) 2001 Jim McDonough (jmcd@us.ibm.com)
   Copyright (C) 2001 Andrew Tridgell (tridge@samba.org)
   Copyright (C) 2001 Andrew Bartlett (abartlet@samba.org)
   Copyright (C) 2004 Stefan Metzmacher (metze@samba.org)

   Largely rewritten by metze in August 2004

   Originally written by Steve and Jim. Largely rewritten by tridge in
   November 2001.

   Reworked again by abartlet in December 2001

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/
 
/*****************************************************/
/*                                                   */
/*   Distributed SMB/CIFS Server Management Utility  */
/*                                                   */
/*   The intent was to make the syntax similar       */
/*   to the NET utility (first developed in DOS      */
/*   with additional interesting & useful functions  */
/*   added in later SMB server network operating     */
/*   systems).                                       */
/*                                                   */
/*****************************************************/

#include "includes.h"
#include "utils/net/net.h"

/*
  run a function from a function table. If not found then
  call the specified usage function 
*/
int net_run_function(struct net_context *ctx,
			int argc, const char **argv,
			const struct net_functable *functable, 
			int (*help_fn)(struct net_context *ctx, int argc, const char **argv))
{
	int i;
	
	if (argc < 1) {
		d_printf("Usage: \n");
		return help_fn(ctx, argc, argv);
	}
	for (i=0; functable[i].name; i++) {
		if (StrCaseCmp(argv[0], functable[i].name) == 0)
			return functable[i].fn(ctx, argc-1, argv+1);
	}
	d_printf("No command: %s\n", argv[0]);
	return help_fn(ctx, argc, argv);
}

/*
  run a help function from a function table. If not found then fail
*/
int net_run_help(struct net_context *ctx,
			int argc, const char **argv,
			const struct net_functable *functable)
{
	int i;
	
	if (argc < 1) {
		d_printf("net_run_help: TODO (argc < 1)\n");
		return 1;
	}
	for (i=0; functable[i].name; i++) {
		if (StrCaseCmp(argv[0], functable[i].name) == 0)
			if (functable[i].help) {
				return functable[i].help(ctx, argc-1, argv+1);
			}
	}
	d_printf("No help for command: %s\n", argv[0]);
	return 1;
}

static int net_help_msg(struct net_context *ctx, int argc, const char **argv)
{
	d_printf("Help: TODO\n");
	return 0;	
}

static int net_help(struct net_context *ctx, int argc, const char **argv);

/* main function table */
static const struct net_functable net_functable[] = {
/*	{"password", net_password, net_password_help},*/

	{"help", net_help_msg, net_help_msg},
	{NULL, NULL}
};

static int net_help(struct net_context *ctx, int argc, const char **argv)
{
	return net_run_help(ctx, argc, argv, net_functable);
}

/****************************************************************************
  main program
****************************************************************************/
static int binary_net(int argc, const char **argv)
{
	int opt,i;
	int rc;
	int argc_new;
	const char **argv_new;
	struct net_context ctx;
	poptContext pc;

	setup_logging("net", DEBUG_STDOUT);

#ifdef HAVE_SETBUFFER
	setbuffer(stdout, NULL, 0);
#endif

	ctx.mem_ctx = talloc_init("net_context");
	if (!ctx.mem_ctx) {
		d_printf("talloc_init(net_context) failed\n");
		exit(1);
	}

	struct poptOption long_options[] = {
		{"help",	'h', POPT_ARG_NONE,   0, 'h'},
		{NULL, 0, POPT_ARG_INCLUDE_TABLE, popt_common_version},
		{ 0, 0, 0, 0}
	};

	pc = poptGetContext(NULL, argc, (const char **) argv, long_options, 
			    POPT_CONTEXT_KEEP_FIRST);

	while((opt = poptGetNextOpt(pc)) != -1) {
		switch (opt) {
		case 'h':
			net_help(&ctx, argc, argv);
			exit(0);
			break;
		default:
			d_printf("Invalid option %s: %s\n", 
				 poptBadOption(pc, 0), poptStrerror(opt));
			net_help(&ctx, argc, argv);
			exit(1);
		}
	}

	lp_load(dyn_CONFIGFILE,True,False,False);
	load_interfaces();

	argv_new = (const char **)poptGetArgs(pc);

	argc_new = argc;
	for (i=0; i<argc; i++) {
		if (argv_new[i] == NULL) {
			argc_new = i;
			break;
		}
	}

	if (argc_new < 2) {
		d_printf("Usage: TODO\n");
		return 1;
	}

	rc = net_run_function(&ctx, argc_new-1, argv_new+1, net_functable, net_help_msg);

	if (rc != 0) {
		DEBUG(0,("return code = %d\n", rc));
	}
	return rc;
}

 int main(int argc, const char **argv)
{
	return binary_net(argc, argv);
}
