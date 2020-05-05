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
#include "system/filesys.h"
#include "system/locale.h"
#include "librpc/ndr/libndr.h"
#include "librpc/ndr/ndr_table.h"
#include "librpc/gen_ndr/ndr_dcerpc.h"
#include "lib/cmdline/popt_common.h"
#include "param/param.h"
#include "lib/util/base64.h"

static const struct ndr_interface_call *find_function(
	const struct ndr_interface_table *p,
	const char *function)
{
	unsigned int i;
	if (isdigit(function[0])) {
		char *eptr = NULL;
		i = strtoul(function, &eptr, 0);
		if (i >= p->num_calls
		    || eptr == NULL
		    || eptr[0] != '\0') {
			printf("Function number '%s' not found\n",
			       function);
			exit(1);
		}
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

/*
 * Find a public structure on the pipe and return it as if it were
 * a function (as the rest of ndrdump is based around functions)
 */
static const struct ndr_interface_call *find_struct(
	const struct ndr_interface_table *p,
	const char *struct_name,
	struct ndr_interface_call *out_buffer)
{
	unsigned int i;
	const struct ndr_interface_public_struct *public_struct = NULL;
	if (isdigit(struct_name[0])) {
		char *eptr = NULL;
		i = strtoul(struct_name, &eptr, 0);
		if (i >= p->num_public_structs
		    || eptr == NULL
		    || eptr[0] != '\0') {
			printf("Public structure number '%s' not found\n",
			       struct_name);
			exit(1);
		}
		public_struct = &p->public_structs[i];
	} else {
		for (i=0;i<p->num_public_structs;i++) {
			if (strcmp(p->public_structs[i].name, struct_name) == 0) {
				break;
			}
		}
		if (i == p->num_public_structs) {
			printf("Public structure '%s' not found\n", struct_name);
			exit(1);
		}
		public_struct = &p->public_structs[i];
	}
	*out_buffer = (struct ndr_interface_call) {
		.name = public_struct->name,
		.struct_size = public_struct->struct_size,
		.ndr_pull = public_struct->ndr_pull,
		.ndr_push = public_struct->ndr_push,
		.ndr_print = public_struct->ndr_print
	};
	return out_buffer;
}

_NORETURN_ static void show_pipes(void)
{
	const struct ndr_interface_list *l;
	printf("\nYou must specify a pipe\n");
	printf("known pipes are:\n");
	for (l=ndr_table_list();l;l=l->next) {
		if(l->table->helpstring) {
			printf("\t%s - %s\n", l->table->name, l->table->helpstring);
		} else {
			printf("\t%s\n", l->table->name);
		}
	}
	exit(1);
}

_NORETURN_ static void show_functions(const struct ndr_interface_table *p)
{
	int i;
	printf("\nYou must specify a function\n");
	printf("known functions on '%s' are:\n", p->name);
	for (i=0;i<p->num_calls;i++) {
		printf("\t0x%02x (%2d) %s\n", i, i, p->calls[i].name);
	}
	printf("known public structures on '%s' are:\n", p->name);
	for (i=0;i<p->num_public_structs;i++) {
		printf("\t%s\n", p->public_structs[i].name);
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
			result = talloc_realloc(
				mem_ctx, result, char, total_len + num_read);
		} else {
			result = talloc_array(mem_ctx, char, num_read);
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
		dlclose(handle);
		return NULL;
	}

	talloc_free(symbol);
	
	return p;
}

static void ndrdump_data(uint8_t *d, uint32_t l, bool force)
{
	dump_data_file(d, l, !force, stdout);
}

static NTSTATUS ndrdump_pull_and_print_pipes(const char *function,
				struct ndr_pull *ndr_pull,
				struct ndr_print *ndr_print,
				const struct ndr_interface_call_pipes *pipes)
{
	enum ndr_err_code ndr_err;
	uint32_t i;

	for (i=0; i < pipes->num_pipes; i++) {
		uint64_t idx = 0;
		while (true) {
			void *saved_mem_ctx;
			uint32_t *count;
			void *c;
			char *n;

			c = talloc_zero_size(ndr_pull, pipes->pipes[i].chunk_struct_size);
			talloc_set_name(c, "struct %s", pipes->pipes[i].name);
			/*
			 * Note: the first struct member is always
			 * 'uint32_t count;'
			 */
			count = (uint32_t *)c;

			n = talloc_asprintf(c, "%s: %s[%llu]",
					function, pipes->pipes[i].name,
					(unsigned long long)idx);

			saved_mem_ctx = ndr_pull->current_mem_ctx;
			ndr_pull->current_mem_ctx = c;
			ndr_err = pipes->pipes[i].ndr_pull(ndr_pull, NDR_SCALARS, c);
			ndr_pull->current_mem_ctx = saved_mem_ctx;

			printf("pull returned %s\n",
			       ndr_map_error2string(ndr_err));
			if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
				talloc_free(c);
				return ndr_map_error2ntstatus(ndr_err);
			}
			pipes->pipes[i].ndr_print(ndr_print, n, c);
			if (*count == 0) {
				talloc_free(c);
				break;
			}
			talloc_free(c);
			idx++;
		}
	}

	return NT_STATUS_OK;
}

static void ndr_print_dummy(struct ndr_print *ndr, const char *format, ...)
{
	/* This is here so that you can turn ndr printing off for the purposes
	   of benchmarking ndr parsing. */
}

 int main(int argc, const char *argv[])
{
	const struct ndr_interface_table *p = NULL;
	const struct ndr_interface_call *f;
	struct ndr_interface_call f_buffer;
	const char *pipe_name = NULL;
	const char *filename = NULL;
	/*
	 * The format type:
	 *   in:     a request
	 *   out:    a response
	 *   struct: a public structure
	 */
	const char *type = NULL;
	/*
	 * Format is either the name of the decoding function or the
	 * name of a public structure
	 */
	const char *format = NULL;
	const char *cmdline_input = NULL;
	const uint8_t *data;
	size_t size;
	DATA_BLOB blob;
	struct ndr_pull *ndr_pull;
	struct ndr_print *ndr_print;
	TALLOC_CTX *mem_ctx;
	int flags = 0;
	poptContext pc;
	NTSTATUS status;
	enum ndr_err_code ndr_err;
	void *st;
	void *v_st;
	const char *ctx_filename = NULL;
	const char *plugin = NULL;
	bool validate = false;
	bool dumpdata = false;
	bool assume_ndr64 = false;
	bool quiet = false;
	bool hex_input = false;
	bool base64_input = false;
	bool print_after_parse_failure = false;
	int opt;
	enum {
		OPT_CONTEXT_FILE=1000,
		OPT_VALIDATE,
		OPT_DUMP_DATA,
		OPT_LOAD_DSO,
		OPT_NDR64,
		OPT_QUIET,
		OPT_BASE64_INPUT,
		OPT_HEX_INPUT,
		OPT_CMDLINE_INPUT,
		OPT_PRINT_AFTER_PARSE_FAILURE,
	};
	struct poptOption long_options[] = {
		POPT_AUTOHELP
		{"context-file", 'c', POPT_ARG_STRING, NULL, OPT_CONTEXT_FILE, "In-filename to parse first", "CTX-FILE" },
		{"validate", 0, POPT_ARG_NONE, NULL, OPT_VALIDATE, "try to validate the data", NULL },	
		{"dump-data", 0, POPT_ARG_NONE, NULL, OPT_DUMP_DATA, "dump the hex data", NULL },	
		{"load-dso", 'l', POPT_ARG_STRING, NULL, OPT_LOAD_DSO, "load from shared object file", NULL },
		{"ndr64", 0, POPT_ARG_NONE, NULL, OPT_NDR64, "Assume NDR64 data", NULL },
		{"quiet", 0, POPT_ARG_NONE, NULL, OPT_QUIET, "Don't actually dump anything", NULL },
		{"base64-input", 0, POPT_ARG_NONE, NULL, OPT_BASE64_INPUT, "Read the input file in as a base64 string", NULL },
		{"hex-input", 0, POPT_ARG_NONE, NULL, OPT_HEX_INPUT, "Read the input file in as a hex dump", NULL },
		{"input", 0, POPT_ARG_STRING, NULL, OPT_CMDLINE_INPUT, "Provide the input on the command line (use with --base64-input)", "INPUT" },
		{"print-after-parse-failure", 0, POPT_ARG_NONE, NULL, OPT_PRINT_AFTER_PARSE_FAILURE,
		 "Try to print structures that fail to parse (used to develop parsers, segfaults are likely).", NULL },
		POPT_COMMON_SAMBA
		POPT_COMMON_VERSION
		{0}
	};
	uint32_t highest_ofs;
	struct dcerpc_sec_verification_trailer *sec_vt = NULL;
	
	ndr_table_init();

	/* Initialise samba stuff */
	smb_init_locale();

	setlinebuf(stdout);

	setup_logging("ndrdump", DEBUG_STDOUT);

	pc = poptGetContext("ndrdump", argc, argv, long_options, 0);
	
	poptSetOtherOptionHelp(
		pc, "<pipe|uuid> <format> <in|out|struct> [<filename>]");

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
		case OPT_NDR64:
			assume_ndr64 = true;
			break;
		case OPT_QUIET:
			quiet = true;
			break;
		case OPT_BASE64_INPUT:
			base64_input = true;
			break;
		case OPT_HEX_INPUT:
			hex_input = true;
			break;
		case OPT_CMDLINE_INPUT:
			cmdline_input = poptGetOptArg(pc);
			break;
		case OPT_PRINT_AFTER_PARSE_FAILURE:
			print_after_parse_failure = true;
			break;
		}
	}

	pipe_name = poptGetArg(pc);

	if (!pipe_name) {
		poptPrintUsage(pc, stderr, 0);
		show_pipes();
		exit(1);
	}

	if (plugin != NULL) {
		p = load_iface_from_plugin(plugin, pipe_name);
	} 
	if (!p) {
		p = ndr_table_by_name(pipe_name);
	}

	if (!p) {
		struct GUID uuid;

		status = GUID_from_string(pipe_name, &uuid);

		if (NT_STATUS_IS_OK(status)) {
			p = ndr_table_by_uuid(&uuid);
		}
	}

	if (!p) {
		printf("Unknown pipe or UUID '%s'\n", pipe_name);
		exit(1);
	}

	format = poptGetArg(pc);
	type = poptGetArg(pc);
	filename = poptGetArg(pc);

	if (!format || !type) {
		poptPrintUsage(pc, stderr, 0);
		show_functions(p);
		exit(1);
	}

	if (strcmp(type, "struct") == 0) {
		flags = NDR_SCALARS|NDR_BUFFERS; /* neither NDR_IN nor NDR_OUT */
		f = find_struct(p, format, &f_buffer);
	} else {
		f = find_function(p, format);
		if (strcmp(type, "in") == 0 ||
		    strcmp(type, "request") == 0) {
			flags |= NDR_IN;
		} else if (strcmp(type, "out") == 0 ||
			   strcmp(type, "response") == 0) {
			flags |= NDR_OUT;
		} else {
			printf("Bad type value '%s'\n", type);
			exit(1);
		}
	}


	mem_ctx = talloc_init("ndrdump");

	st = talloc_zero_size(mem_ctx, f->struct_size);
	if (!st) {
		printf("Unable to allocate %d bytes for %s structure\n",
		       (int)f->struct_size,
		       f->name);
		TALLOC_FREE(mem_ctx);
		exit(1);
	}

	v_st = talloc_zero_size(mem_ctx, f->struct_size);
	if (!v_st) {
		printf("Unable to allocate %d bytes for %s validation "
		       "structure\n",
		       (int)f->struct_size,
		       f->name);
		TALLOC_FREE(mem_ctx);
		exit(1);
	}

	if (ctx_filename) {
		if (flags & NDR_IN) {
			printf("Context file can only be used for \"out\" packages\n");
			TALLOC_FREE(mem_ctx);
			exit(1);
		}
			
		data = (uint8_t *)file_load(ctx_filename, &size, 0, mem_ctx);
		if (!data) {
			perror(ctx_filename);
			TALLOC_FREE(mem_ctx);
			exit(1);
		}

		blob = data_blob_const(data, size);

		ndr_pull = ndr_pull_init_blob(&blob, mem_ctx);
		if (ndr_pull == NULL) {
			perror("ndr_pull_init_blob");
			TALLOC_FREE(mem_ctx);
			exit(1);
		}
		ndr_pull->flags |= LIBNDR_FLAG_REF_ALLOC;
		if (assume_ndr64) {
			ndr_pull->flags |= LIBNDR_FLAG_NDR64;
		}

		ndr_err = f->ndr_pull(ndr_pull, NDR_IN, st);

		if (ndr_pull->offset > ndr_pull->relative_highest_offset) {
			highest_ofs = ndr_pull->offset;
		} else {
			highest_ofs = ndr_pull->relative_highest_offset;
		}

		if (highest_ofs != ndr_pull->data_size) {
			printf("WARNING! %d unread bytes while parsing context file\n", ndr_pull->data_size - highest_ofs);
		}

		if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
			printf("pull for context file returned %s\n",
			       ndr_map_error2string(ndr_err));
			TALLOC_FREE(mem_ctx);
			exit(2);
		}
		memcpy(v_st, st, f->struct_size);
	}

	if (filename && cmdline_input) {
		printf("cannot combine --input with a filename\n");
		TALLOC_FREE(mem_ctx);
		exit(1);
	} else if (cmdline_input) {
		data = (const uint8_t *)cmdline_input;
		size = strlen(cmdline_input);
	} else if (filename) {
		data = (uint8_t *)file_load(filename, &size, 0, mem_ctx);
	} else {
		data = (uint8_t *)stdin_load(mem_ctx, &size);
	}

	if (!data) {
		if (filename)
			perror(filename);
		else
			perror("stdin");
		exit(1);
	}
	
	if (hex_input && base64_input) {
		printf("cannot combine --hex-input with --base64-input\n");
		TALLOC_FREE(mem_ctx);
		exit(1);

	} else if (hex_input) {
		blob = hexdump_to_data_blob(mem_ctx, (const char *)data, size);
	} else if (base64_input) {
		/* Use talloc_strndup() to ensure null termination */
		blob = base64_decode_data_blob(talloc_strndup(mem_ctx,
							      (const char *)data, size));
		/* base64_decode_data_blob() allocates on NULL */
		talloc_steal(mem_ctx, blob.data);
	} else {
		blob = data_blob_const(data, size);
	}

	if (data != NULL && blob.data == NULL) {
		printf("failed to decode input data\n");
		TALLOC_FREE(mem_ctx);
		exit(1);
	}

	ndr_pull = ndr_pull_init_blob(&blob, mem_ctx);
	if (ndr_pull == NULL) {
		perror("ndr_pull_init_blob");
		TALLOC_FREE(mem_ctx);
		exit(1);
	}
	ndr_pull->flags |= LIBNDR_FLAG_REF_ALLOC;
	if (assume_ndr64) {
		ndr_pull->flags |= LIBNDR_FLAG_NDR64;
	}

	ndr_print = talloc_zero(mem_ctx, struct ndr_print);
	if (quiet) {
		ndr_print->print = ndr_print_dummy;
	} else {
		ndr_print->print = ndr_print_printf_helper;
	}
	ndr_print->depth = 1;

	ndr_err = ndr_pop_dcerpc_sec_verification_trailer(ndr_pull, mem_ctx, &sec_vt);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		printf("ndr_pop_dcerpc_sec_verification_trailer returned %s\n",
		       ndr_map_error2string(ndr_err));
	}

	if (sec_vt != NULL && sec_vt->count.count > 0) {
		printf("SEC_VT: consumed %d bytes\n",
		       (int)(blob.length - ndr_pull->data_size));
		if (dumpdata) {
			ndrdump_data(blob.data + ndr_pull->data_size,
				     blob.length - ndr_pull->data_size,
				     dumpdata);
		}
		ndr_print_dcerpc_sec_verification_trailer(ndr_print, "SEC_VT", sec_vt);
	}
	TALLOC_FREE(sec_vt);

	if (flags & NDR_OUT) {
		status = ndrdump_pull_and_print_pipes(format,
						      ndr_pull,
						      ndr_print,
						      &f->out_pipes);
		if (!NT_STATUS_IS_OK(status)) {
			printf("pull and dump of OUT pipes FAILED: %s\n",
			       nt_errstr(status));
			TALLOC_FREE(mem_ctx);
			exit(2);
		}
	}

	ndr_err = f->ndr_pull(ndr_pull, flags, st);
	printf("pull returned %s\n",
	       ndr_map_error2string(ndr_err));

	if (ndr_pull->offset > ndr_pull->relative_highest_offset) {
		highest_ofs = ndr_pull->offset;
	} else {
		highest_ofs = ndr_pull->relative_highest_offset;
	}

	if (dumpdata) {
		printf("%d bytes consumed\n", highest_ofs);
		ndrdump_data(blob.data, blob.length, dumpdata);
	}

	if (!print_after_parse_failure && !NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		TALLOC_FREE(mem_ctx);
		exit(2);
	}

	if (highest_ofs != ndr_pull->data_size) {
		printf("WARNING! %d unread bytes\n", ndr_pull->data_size - highest_ofs);
		ndrdump_data(ndr_pull->data+highest_ofs,
			     ndr_pull->data_size - highest_ofs,
			     dumpdata);
	}

	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		printf("WARNING: pull of %s was incomplete, "
		       "therefore the parse below may SEGFAULT\n",
			f->name);
	}

	f->ndr_print(ndr_print, f->name, flags, st);

	if (flags & NDR_IN) {
		status = ndrdump_pull_and_print_pipes(format,
						      ndr_pull,
						      ndr_print,
						      &f->in_pipes);
		if (!NT_STATUS_IS_OK(status)) {
			printf("pull and dump of IN pipes FAILED: %s\n",
			       nt_errstr(status));
			exit(1);
		}
	}

	/* Do not proceed to validate if we got an error */
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		printf("dump of failed-to-parse %s complete\n",
		       f->name);
		TALLOC_FREE(mem_ctx);
		exit(2);
	}

	if (validate) {
		DATA_BLOB v_blob;
		struct ndr_push *ndr_v_push;
		struct ndr_pull *ndr_v_pull;
		struct ndr_print *ndr_v_print;
		uint32_t highest_v_ofs;
		uint32_t i;
		uint8_t byte_a, byte_b;
		bool differ;

		ndr_v_push = ndr_push_init_ctx(mem_ctx);
		if (ndr_v_push == NULL) {
			printf("No memory\n");
			exit(1);
		}

		if (assume_ndr64) {
			ndr_v_push->flags |= LIBNDR_FLAG_NDR64;
		}

		ndr_err = f->ndr_push(ndr_v_push, flags, st);
		printf("push returned %s\n",
		       ndr_map_error2string(ndr_err));
		if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
			printf("validate push FAILED\n");
			TALLOC_FREE(mem_ctx);
			exit(1);
		}

		v_blob = ndr_push_blob(ndr_v_push);

		if (dumpdata) {
			printf("%ld bytes generated (validate)\n", (long)v_blob.length);
			ndrdump_data(v_blob.data, v_blob.length, dumpdata);
		}

		ndr_v_pull = ndr_pull_init_blob(&v_blob, mem_ctx);
		if (ndr_v_pull == NULL) {
			perror("ndr_pull_init_blob");
			TALLOC_FREE(mem_ctx);
			exit(1);
		}
		ndr_v_pull->flags |= LIBNDR_FLAG_REF_ALLOC;

		ndr_err = f->ndr_pull(ndr_v_pull, flags, v_st);
		printf("pull returned %s\n",
		       ndr_map_error2string(ndr_err));
		if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
			printf("validate pull FAILED\n");
			TALLOC_FREE(mem_ctx);
			exit(1);
		}

		if (ndr_v_pull->offset > ndr_v_pull->relative_highest_offset) {
			highest_v_ofs = ndr_v_pull->offset;
		} else {
			highest_v_ofs = ndr_v_pull->relative_highest_offset;
		}

		if (highest_v_ofs != ndr_v_pull->data_size) {
			printf("WARNING! %d unread bytes in validation\n",
			       ndr_v_pull->data_size - highest_v_ofs);
			ndrdump_data(ndr_v_pull->data + highest_v_ofs,
				     ndr_v_pull->data_size - highest_v_ofs,
				     dumpdata);
		}

		ndr_v_print = talloc_zero(mem_ctx, struct ndr_print);
		ndr_v_print->print = ndr_print_debug_helper;
		ndr_v_print->depth = 1;
		f->ndr_print(ndr_v_print,
			     format,
			     flags, v_st);

		if (blob.length != v_blob.length) {
			printf("WARNING! orig bytes:%llu validated pushed bytes:%llu\n", 
			       (unsigned long long)blob.length, (unsigned long long)v_blob.length);
		}

		if (highest_ofs != highest_v_ofs) {
			printf("WARNING! orig pulled bytes:%llu validated pulled bytes:%llu\n", 
			       (unsigned long long)highest_ofs, (unsigned long long)highest_v_ofs);
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
	TALLOC_FREE(mem_ctx);

	poptFreeContext(pc);
	
	return 0;
}
