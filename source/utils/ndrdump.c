/* 
   Unix SMB/CIFS implementation.
   SMB torture tester
   Copyright (C) Andrew Tridgell 2003
   
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

#include "includes.h"
#include "lib/cmdline/popt_common.h"
#include "system/iconv.h"

static const struct dcerpc_interface_call *find_function(
	const struct dcerpc_interface_table *p,
	const char *function)
{
	int i;
	if (isdigit(function[0])) {
		i = strtol(function, NULL, 0);
		return &p->calls[i];
	}
	for (i=0;i<p->num_calls;i++) {
		if (strcmp(p->calls[i].name, function) == 0) {
			break;
		}
	}
	if (i == p->num_calls) {
		printf("Function '%s' not found\n", function);
		exit(1);
	}
	return &p->calls[i];
}


static void show_pipes(void)
{
	struct dcerpc_interface_list *p;
	printf("\nYou must specify a pipe\n");
	printf("known pipes are:\n");
	for (p=dcerpc_pipes;p;p=p->next) {
		if(p->table->helpstring) {
			printf("\t%s - %s\n", p->table->name, p->table->helpstring);
		} else {
			printf("\t%s\n", p->table->name);
		}
	}
	exit(1);
}

static void show_functions(const struct dcerpc_interface_table *p)
{
	int i;
	printf("\nYou must specify a function\n");
	printf("known functions on '%s' are:\n", p->name);
	for (i=0;i<p->num_calls;i++) {
		printf("\t0x%02x (%2d) %s\n", i, i, p->calls[i].name);
	}
	exit(1);
}

 int main(int argc, const char *argv[])
{
	const struct dcerpc_interface_table *p;
	const struct dcerpc_interface_call *f;
	const char *pipe_name, *function, *inout, *filename;
	char *data;
	size_t size;
	DATA_BLOB blob;
	struct ndr_pull *ndr;
	TALLOC_CTX *mem_ctx;
	int flags;
	poptContext pc;
	NTSTATUS status;
	void *st;
	const char *ctx_filename = NULL;
	int opt;
	struct ndr_print *pr;
	struct poptOption long_options[] = {
		{"context-file", 'c', POPT_ARG_STRING, &ctx_filename, 0, "In-filename to parse first", "CTX-FILE" },
		POPT_AUTOHELP
		POPT_TABLEEND
	};

	DEBUGLEVEL = 10;

	setup_logging("ndrdump", DEBUG_STDOUT);

	ndrdump_init_subsystems;

	pc = poptGetContext("ndrdump", argc, argv, long_options, 0);
	
	poptSetOtherOptionHelp(pc, "<pipe> <function> <inout> <filename>");

	while ((opt = poptGetNextOpt(pc)) != -1) {
	}

	pipe_name = poptGetArg(pc);

	if (!pipe_name) {
		poptPrintUsage(pc, stderr, 0);
		show_pipes();
		exit(1);
	}

	p = idl_iface_by_name(pipe_name);

	if (!p) {
		printf("Unknown pipe '%s'\n", pipe_name);
		exit(1);
	}

	function = poptGetArg(pc);
	inout = poptGetArg(pc);
	filename = poptGetArg(pc);

	if (!function || !inout || !filename) {
		poptPrintUsage(pc, stderr, 0);
		show_functions(p);
		exit(1);
	}

	if (strcmp(inout, "in") == 0 ||
	    strcmp(inout, "request") == 0) {
		flags = NDR_IN;
	} else if (strcmp(inout, "out") == 0 ||
		   strcmp(inout, "response") == 0) {
		flags = NDR_OUT;
	} else {
		printf("Bad inout value '%s'\n", inout);
		exit(1);
	}

	f = find_function(p, function);

	mem_ctx = talloc_init("ndrdump");

	st = talloc_zero(mem_ctx, f->struct_size);
	if (!st) {
		printf("Unable to allocate %d bytes\n", f->struct_size);
		exit(1);
	}

	if (ctx_filename) {
		if (flags == NDR_IN) {
			printf("Context file can only be used for \"out\" packages\n");
			exit(1);
		}
			
		data = file_load(ctx_filename, &size);
		if (!data) {
			perror(ctx_filename);
			exit(1);
		}

		blob.data = data;
		blob.length = size;

		ndr = ndr_pull_init_blob(&blob, mem_ctx);

		status = f->ndr_pull(ndr, NDR_IN, st);

		if (ndr->offset != ndr->data_size) {
			printf("WARNING! %d unread bytes while parsing context file\n", ndr->data_size - ndr->offset);
		}

		if (!NT_STATUS_IS_OK(status)) {
			printf("pull for context file returned %s\n", nt_errstr(status));
			exit(1);
		}
	} 

	data = file_load(filename, &size);
	if (!data) {
		perror(filename);
		exit(1);
	}

	blob.data = data;
	blob.length = size;

	ndr = ndr_pull_init_blob(&blob, mem_ctx);

	if (flags == NDR_OUT) {
		ndr->flags |= LIBNDR_FLAG_REF_ALLOC;
	}

	status = f->ndr_pull(ndr, flags, st);

	printf("pull returned %s\n", nt_errstr(status));

	if (ndr->offset != ndr->data_size) {
		printf("WARNING! %d unread bytes\n", ndr->data_size - ndr->offset);
		dump_data(0, ndr->data+ndr->offset, ndr->data_size - ndr->offset);
	}

	pr = talloc_p(NULL, struct ndr_print);
	pr->print = ndr_print_debug_helper;
	pr->depth = 1;
	f->ndr_print(pr, function, flags, st);

	if (!NT_STATUS_IS_OK(status) ||
	    ndr->offset != ndr->data_size) {
		printf("dump FAILED\n");
		exit(1);
	}

	printf("dump OK\n");

	talloc_free(pr);
	
	poptFreeContext(pc);
	
	return 0;
}
