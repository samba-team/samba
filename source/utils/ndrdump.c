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

static const struct dcerpc_interface_table *find_pipe(const char *pipe_name)
{
	int i;
	for (i=0;dcerpc_pipes[i];i++) {
		if (strcmp(dcerpc_pipes[i]->name, pipe_name) == 0) {
			break;
		}
	}
	if (!dcerpc_pipes[i]) {
		printf("pipe '%s' not in table\n", pipe_name);
		exit(1);
	}
	return dcerpc_pipes[i];
}

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

static void usage(void)
{
	printf("Usage: ndrdump <pipe> <function> <inout> <filename>\n");
}


static void show_pipes(void)
{
	int i;
	usage();
	printf("\nYou must specify a pipe\n");
	printf("known pipes are:\n");
	for (i=0;dcerpc_pipes[i];i++) {
		if(dcerpc_pipes[i]->helpstring) {
			printf("\t%s - %s\n", dcerpc_pipes[i]->name, dcerpc_pipes[i]->helpstring);
		} else {
			printf("\t%s\n", dcerpc_pipes[i]->name);
		}
	}
	exit(1);
}

static void show_functions(const struct dcerpc_interface_table *p)
{
	int i;
	usage();
	printf("\nYou must specify a function\n");
	printf("known functions on '%s' are:\n", p->name);
	for (i=0;i<p->num_calls;i++) {
		printf("\t0x%02x (%2d) %s\n", i, i, p->calls[i].name);
	}
	exit(1);
}

 int main(int argc, char *argv[])
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
	NTSTATUS status;
	void *st;
	struct ndr_print pr;

	DEBUGLEVEL = 10;

	setup_logging("smbtorture", DEBUG_STDOUT);

	if (argc < 2) {
		show_pipes();
		exit(1);
	}

	pipe_name = argv[1];

	p = find_pipe(pipe_name);

	if (argc < 5) {
		show_functions(p);
		exit(1);
	}

	function = argv[2];
	inout = argv[3];
	filename = argv[4];

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

	data = file_load(filename, &size);
	if (!data) {
		perror(filename);
		exit(1);
	}

	blob.data = data;
	blob.length = size;

	mem_ctx = talloc_init("ndrdump");
	
	ndr = ndr_pull_init_blob(&blob, mem_ctx);

	st = talloc_zero(mem_ctx, f->struct_size);
	if (!st) {
		printf("Unable to allocate %d bytes\n", f->struct_size);
		exit(1);
	}

	if (flags == NDR_OUT) {
		ndr->flags |= LIBNDR_FLAG_REF_ALLOC;
	}

	status = f->ndr_pull(ndr, flags, st);

	printf("pull returned %s\n", nt_errstr(status));

	if (ndr->offset != ndr->data_size) {
		printf("WARNING! %d unread bytes\n", ndr->data_size - ndr->offset);
		dump_data(0, ndr->data+ndr->offset, ndr->data_size - ndr->offset);
	}

	pr.mem_ctx = mem_ctx;
	pr.print = ndr_print_debug_helper;
	pr.depth = 1;
	f->ndr_print(&pr, function, flags, st);

	if (!NT_STATUS_IS_OK(status) ||
	    ndr->offset != ndr->data_size) {
		printf("dump FAILED\n");
		exit(1);
	}

	printf("dump OK\n");
	
	return 0;
}
