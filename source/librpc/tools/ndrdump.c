/* 
   Unix SMB/CIFS implementation.
   SMB torture tester
   Copyright (C) Andrew Tridgell 2003
   Copyright (C) Jelmer Vernooij 2006
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "includes.h"
#if (_SAMBA_BUILD_ >= 4)
#include "lib/cmdline/popt_common.h"
#include "system/filesys.h"
#include "system/locale.h"
#include "librpc/rpc/dcerpc.h"
#include "librpc/rpc/dcerpc_table.h"
#endif

static const struct ndr_interface_call *find_function(
	const struct ndr_interface_table *p,
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

#if (_SAMBA_BUILD_ >= 4)

static void show_pipes(void)
{
	const struct ndr_interface_list *l;
	printf("\nYou must specify a pipe\n");
	printf("known pipes are:\n");
	for (l=librpc_dcerpc_pipes();l;l=l->next) {
		if(l->table->helpstring) {
			printf("\t%s - %s\n", l->table->name, l->table->helpstring);
		} else {
			printf("\t%s\n", l->table->name);
		}
	}
	exit(1);
}

#endif

static void show_functions(const struct ndr_interface_table *p)
{
	int i;
	printf("\nYou must specify a function\n");
	printf("known functions on '%s' are:\n", p->name);
	for (i=0;i<p->num_calls;i++) {
		printf("\t0x%02x (%2d) %s\n", i, i, p->calls[i].name);
	}
	exit(1);
}

static char *stdin_load(TALLOC_CTX *mem_ctx, size_t *size)
{
	int num_read, total_len = 0;
	char buf[255];
	char *result = NULL;

	while((num_read = read(STDIN_FILENO, buf, 255)) > 0) {

		if (result) {
			result = (char *) talloc_realloc(
				mem_ctx, result, char *, total_len + num_read);
		} else {
			result = (char *) talloc_size(mem_ctx, num_read);
		}

		memcpy(result + total_len, buf, num_read);

		total_len += num_read;
	}

	if (size)
		*size = total_len;

	return result;
}

static const struct ndr_interface_table *load_iface_from_plugin(const char *plugin, const char *pipe_name)
{
	const struct ndr_interface_table *p;
	void *handle;
	char *symbol;

	handle = dlopen(plugin, RTLD_NOW);
	if (handle == NULL) {
		printf("%s: Unable to open: %s\n", plugin, dlerror());
		return NULL;
	}

	symbol = talloc_asprintf(NULL, "ndr_table_%s", pipe_name);
	p = (const struct ndr_interface_table *)dlsym(handle, symbol);

	if (!p) {
		printf("%s: Unable to find DCE/RPC interface table for '%s': %s\n", plugin, pipe_name, dlerror());
		talloc_free(symbol);
		return NULL;
	}

	talloc_free(symbol);
	
	return p;
}

 int main(int argc, const char *argv[])
{
	const struct ndr_interface_table *p = NULL;
	const struct ndr_interface_call *f;
	const char *pipe_name, *function, *inout, *filename;
	uint8_t *data;
	size_t size;
	DATA_BLOB blob;
	struct ndr_pull *ndr_pull;
	struct ndr_print *ndr_print;
	TALLOC_CTX *mem_ctx;
	int flags;
	poptContext pc;
	NTSTATUS status;
	enum ndr_err_code ndr_err;
	void *st;
	void *v_st;
	const char *ctx_filename = NULL;
	const char *plugin = NULL;
	bool validate = false;
	bool dumpdata = false;
	int opt;
	enum {OPT_CONTEXT_FILE=1000, OPT_VALIDATE, OPT_DUMP_DATA, OPT_LOAD_DSO};
	struct poptOption long_options[] = {
		POPT_AUTOHELP
		{"context-file", 'c', POPT_ARG_STRING, NULL, OPT_CONTEXT_FILE, "In-filename to parse first", "CTX-FILE" },
		{"validate", 0, POPT_ARG_NONE, NULL, OPT_VALIDATE, "try to validate the data", NULL },	
		{"dump-data", 0, POPT_ARG_NONE, NULL, OPT_DUMP_DATA, "dump the hex data", NULL },	
		{"load-dso", 'l', POPT_ARG_STRING, NULL, OPT_LOAD_DSO, "load from shared object file", NULL },
		POPT_COMMON_SAMBA
		POPT_COMMON_VERSION
		{ NULL }
	};

#if (_SAMBA_BUILD_ >= 4)
	ndr_table_init();
#else
	/* Initialise samba stuff */
	load_case_tables();

	setlinebuf(stdout);

	dbf = x_stderr;

	setup_logging(argv[0],True);
#endif

	pc = poptGetContext("ndrdump", argc, argv, long_options, 0);
	
	poptSetOtherOptionHelp(
		pc, "<pipe|uuid> <function> <inout> [<filename>]");

	while ((opt = poptGetNextOpt(pc)) != -1) {
		switch (opt) {
		case OPT_CONTEXT_FILE:
			ctx_filename = poptGetOptArg(pc);
			break;
		case OPT_VALIDATE:
			validate = true;
			break;
		case OPT_DUMP_DATA:
			dumpdata = true;
			break;
		case OPT_LOAD_DSO:
			plugin = poptGetOptArg(pc);
			break;
		}
	}

	pipe_name = poptGetArg(pc);

	if (!pipe_name) {
		poptPrintUsage(pc, stderr, 0);
#if (_SAMBA_BUILD_ >= 4)
		show_pipes();
#endif
		exit(1);
	}

	if (plugin != NULL) {
		p = load_iface_from_plugin(plugin, pipe_name);
	} 
#if (_SAMBA_BUILD_ <= 3)
	else {
		fprintf(stderr, "Only loading from DSO's supported in Samba 3\n");
		exit(1);
	}
#else
	if (!p) {
		p = idl_iface_by_name(pipe_name);
	}

	if (!p) {
		struct GUID uuid;

		status = GUID_from_string(pipe_name, &uuid);

		if (NT_STATUS_IS_OK(status)) {
			p = idl_iface_by_uuid(&uuid);
		}
	}
#endif

	if (!p) {
		printf("Unknown pipe or UUID '%s'\n", pipe_name);
		exit(1);
	}

	function = poptGetArg(pc);
	inout = poptGetArg(pc);
	filename = poptGetArg(pc);

	if (!function || !inout) {
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

	st = talloc_zero_size(mem_ctx, f->struct_size);
	if (!st) {
		printf("Unable to allocate %d bytes\n", (int)f->struct_size);
		exit(1);
	}

	v_st = talloc_zero_size(mem_ctx, f->struct_size);
	if (!v_st) {
		printf("Unable to allocate %d bytes\n", (int)f->struct_size);
		exit(1);
	}

	if (ctx_filename) {
		if (flags == NDR_IN) {
			printf("Context file can only be used for \"out\" packages\n");
			exit(1);
		}
			
#if (_SAMBA_BUILD_ >= 4)
		data = (uint8_t *)file_load(ctx_filename, &size, mem_ctx);
#else
		data = (uint8_t *)file_load(ctx_filename, &size, 0);
#endif
		if (!data) {
			perror(ctx_filename);
			exit(1);
		}

		blob.data = data;
		blob.length = size;

		ndr_pull = ndr_pull_init_blob(&blob, mem_ctx);
		ndr_pull->flags |= LIBNDR_FLAG_REF_ALLOC;

		ndr_err = f->ndr_pull(ndr_pull, NDR_IN, st);

		if (ndr_pull->offset != ndr_pull->data_size) {
			printf("WARNING! %d unread bytes while parsing context file\n", ndr_pull->data_size - ndr_pull->offset);
		}

		if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
			status = ndr_map_error2ntstatus(ndr_err);
			printf("pull for context file returned %s\n", nt_errstr(status));
			exit(1);
		}
		memcpy(v_st, st, f->struct_size);
	} 

	if (filename)
#if (_SAMBA_BUILD_ >= 4)
		data = (uint8_t *)file_load(filename, &size, mem_ctx);
#else
		data = (uint8_t *)file_load(filename, &size, 0);
#endif
	else
		data = (uint8_t *)stdin_load(mem_ctx, &size);

	if (!data) {
		if (filename)
			perror(filename);
		else
			perror("stdin");
		exit(1);
	}

	blob.data = data;
	blob.length = size;

	ndr_pull = ndr_pull_init_blob(&blob, mem_ctx);
	ndr_pull->flags |= LIBNDR_FLAG_REF_ALLOC;

	ndr_err = f->ndr_pull(ndr_pull, flags, st);
	status = ndr_map_error2ntstatus(ndr_err);

	printf("pull returned %s\n", nt_errstr(status));

	if (ndr_pull->offset != ndr_pull->data_size) {
		printf("WARNING! %d unread bytes\n", ndr_pull->data_size - ndr_pull->offset);
		dump_data(0, ndr_pull->data+ndr_pull->offset, ndr_pull->data_size - ndr_pull->offset);
	}

	if (dumpdata) {
		printf("%d bytes consumed\n", ndr_pull->offset);
		dump_data(0, blob.data, blob.length);
	}

	ndr_print = talloc_zero(mem_ctx, struct ndr_print);
	ndr_print->print = ndr_print_debug_helper;
	ndr_print->depth = 1;
	f->ndr_print(ndr_print, function, flags, st);

	if (!NT_STATUS_IS_OK(status)) {
		printf("dump FAILED\n");
		exit(1);
	}

	if (validate) {
		DATA_BLOB v_blob;
		struct ndr_push *ndr_v_push;
		struct ndr_pull *ndr_v_pull;
		struct ndr_print *ndr_v_print;
		uint32_t i;
		uint8_t byte_a, byte_b;
		bool differ;

		ndr_v_push = ndr_push_init_ctx(mem_ctx);
		
		ndr_err = f->ndr_push(ndr_v_push, flags, st);
		status = ndr_map_error2ntstatus(ndr_err);
		printf("push returned %s\n", nt_errstr(status));
		if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
			printf("validate push FAILED\n");
			exit(1);
		}

		v_blob = ndr_push_blob(ndr_v_push);

		if (dumpdata) {
			printf("%ld bytes generated (validate)\n", (long)v_blob.length);
			dump_data(0, v_blob.data, v_blob.length);
		}

		ndr_v_pull = ndr_pull_init_blob(&v_blob, mem_ctx);
		ndr_v_pull->flags |= LIBNDR_FLAG_REF_ALLOC;

		ndr_err = f->ndr_pull(ndr_v_pull, flags, v_st);
		status = ndr_map_error2ntstatus(ndr_err);
		printf("pull returned %s\n", nt_errstr(status));
		if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
			printf("validate pull FAILED\n");
			exit(1);
		}


		if (ndr_v_pull->offset != ndr_v_pull->data_size) {
			printf("WARNING! %d unread bytes in validation\n", ndr_v_pull->data_size - ndr_v_pull->offset);
			dump_data(0, ndr_v_pull->data+ndr_v_pull->offset, ndr_v_pull->data_size - ndr_v_pull->offset);
		}

		ndr_v_print = talloc_zero(mem_ctx, struct ndr_print);
		ndr_v_print->print = ndr_print_debug_helper;
		ndr_v_print->depth = 1;
		f->ndr_print(ndr_v_print, function, flags, v_st);

		if (blob.length != v_blob.length) {
			printf("WARNING! orig bytes:%u validated pushed "
			       "bytes:%u\n", (unsigned int)blob.length,
			       (unsigned int)v_blob.length);
		}

		if (ndr_pull->offset != ndr_v_pull->offset) {
			printf("WARNING! orig pulled bytes:%u validated pulled bytes:%u\n", ndr_pull->offset, ndr_v_pull->offset);
		}

		differ = false;
		byte_a = 0x00;
		byte_b = 0x00;
		for (i=0; i < blob.length; i++) {
			byte_a = blob.data[i];

			if (i == v_blob.length) {
				byte_b = 0x00;
				differ = true;
				break;
			}

			byte_b = v_blob.data[i];

			if (byte_a != byte_b) {
				differ = true;
				break;
			}
		}
		if (differ) {
			printf("WARNING! orig and validated differ at byte 0x%02X (%u)\n", i, i);
			printf("WARNING! orig byte[0x%02X] = 0x%02X validated byte[0x%02X] = 0x%02X\n",
				i, byte_a, i, byte_b);
		}
	}

	printf("dump OK\n");

	talloc_free(mem_ctx);

	poptFreeContext(pc);
	
	return 0;
}
