/* 
   Unix SMB/CIFS implementation.
   simple registry frontend
   
   Copyright (C) Jelmer Vernooij 2004

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
#include "lib/registry/registry.h"
#include "lib/cmdline/popt_common.h"
#include "lib/events/events.h"
#include "system/time.h"
#include "lib/smbreadline/smbreadline.h"
#include "librpc/gen_ndr/ndr_security.h"

/* 
 * ck/cd - change key
 * ls - list values/keys
 * rmval/rm - remove value
 * rmkey/rmdir - remove key
 * mkkey/mkdir - make key
 * ch - change hive
 * info - show key info
 * save - save hive
 * print - print value
 * help
 * exit
 */

static struct registry_key *cmd_info(TALLOC_CTX *mem_ctx, struct registry_context *ctx,struct registry_key *cur, int argc, char **argv)
{
	struct security_descriptor *sec_desc = NULL;
	time_t last_mod;
	WERROR error;
	
	printf("Name: %s\n", cur->name);
	printf("Full path: %s\n", cur->path);
	printf("Key Class: %s\n", cur->class_name);
	last_mod = nt_time_to_unix(cur->last_mod);
	printf("Time Last Modified: %s\n", ctime(&last_mod));

	error = reg_get_sec_desc(mem_ctx, cur, &sec_desc);
	if (!W_ERROR_IS_OK(error)) {
		printf("Error getting security descriptor\n");
	} else {
		ndr_print_debug((ndr_print_fn_t)ndr_print_security_descriptor, "Security", sec_desc);
	}
	talloc_free(sec_desc);
	return cur;
}

static struct registry_key *cmd_predef(TALLOC_CTX *mem_ctx, struct registry_context *ctx, struct registry_key *cur, int argc, char **argv)
{
	struct registry_key *ret = NULL;
	if (argc < 2) {
		fprintf(stderr, "Usage: predef predefined-key-name\n");
	} else if (!ctx) {
		fprintf(stderr, "No full registry loaded, no predefined keys defined\n");
	} else {
		WERROR error = reg_get_predefined_key_by_name(ctx, argv[1], &ret);

		if (!W_ERROR_IS_OK(error)) {
			fprintf(stderr, "Error opening predefined key %s: %s\n", argv[1], win_errstr(error));
			ret = NULL;
		}
	}
	return ret;
}

static struct registry_key *cmd_pwd(TALLOC_CTX *mem_ctx, struct registry_context *ctx,struct registry_key *cur, int argc, char **argv)
{
	printf("%s\n", cur->path);
	return cur;
}

static struct registry_key *cmd_set(TALLOC_CTX *mem_ctx, struct registry_context *ctx,struct registry_key *cur, int argc, char **argv)
{
	struct registry_value val;
	WERROR error;

	if (argc < 4) {
		fprintf(stderr, "Usage: set value-name type value\n");
		return cur;
	} 

	if (!reg_string_to_val(mem_ctx, argv[2], argv[3], &val.data_type, &val.data)) {
		fprintf(stderr, "Unable to interpret data\n");
		return cur;
	}

	error = reg_val_set(cur, argv[1], val.data_type, val.data);
	if (!W_ERROR_IS_OK(error)) {
		fprintf(stderr, "Error setting value: %s\n", win_errstr(error));
		return NULL;
	}
	return cur;
}

static struct registry_key *cmd_ck(TALLOC_CTX *mem_ctx, struct registry_context *ctx,struct registry_key *cur, int argc, char **argv)
{ 
	struct registry_key *new = NULL;
	WERROR error;
	if(argc < 2) {
		new = cur;
	} else {
		error = reg_open_key(mem_ctx, cur, argv[1], &new);
		if(!W_ERROR_IS_OK(error)) {
			DEBUG(0, ("Error opening specified key: %s\n", win_errstr(error)));
			return NULL;
		}
	} 

	printf("Current path is: %s\n", new->path);
	
	return new;
}

static struct registry_key *cmd_print(TALLOC_CTX *mem_ctx, struct registry_context *ctx,struct registry_key *cur, int argc, char **argv)
{
	struct registry_value *value;
	WERROR error;

	if (argc != 2) {
		fprintf(stderr, "Usage: print <valuename>");
		return NULL;
	}
	
	error = reg_key_get_value_by_name(mem_ctx, cur, argv[1], &value);
	if (!W_ERROR_IS_OK(error)) {
		fprintf(stderr, "No such value '%s'\n", argv[1]);
		return NULL;
	}

	printf("%s\n%s\n", str_regtype(value->data_type), reg_val_data_string(mem_ctx, value->data_type, &value->data));
	return NULL;
}

static struct registry_key *cmd_ls(TALLOC_CTX *mem_ctx, struct registry_context *ctx,struct registry_key *cur, int argc, char **argv)
{
	int i;
	WERROR error;
	struct registry_value *value;
	struct registry_key *sub;
	for(i = 0; W_ERROR_IS_OK(error = reg_key_get_subkey_by_index(mem_ctx, cur, i, &sub)); i++) {
		printf("K %s\n", sub->name);
	}

	if(!W_ERROR_EQUAL(error, WERR_NO_MORE_ITEMS)) {
		DEBUG(0, ("Error occured while browsing thru keys: %s\n", win_errstr(error)));
	}

	for(i = 0; W_ERROR_IS_OK(error = reg_key_get_value_by_index(mem_ctx, cur, i, &value)); i++) {
		printf("V \"%s\" %s %s\n", value->name, str_regtype(value->data_type), reg_val_data_string(mem_ctx, value->data_type, &value->data));
	}
	
	return NULL; 
}
static struct registry_key *cmd_mkkey(TALLOC_CTX *mem_ctx, struct registry_context *ctx,struct registry_key *cur, int argc, char **argv)
{ 
	struct registry_key *tmp;
	if(argc < 2) {
		fprintf(stderr, "Usage: mkkey <keyname>\n");
		return NULL;
	}
	
	if(!W_ERROR_IS_OK(reg_key_add_name(mem_ctx, cur, argv[1], 0, NULL, &tmp))) {
		fprintf(stderr, "Error adding new subkey '%s'\n", argv[1]);
		return NULL;
	}

	return NULL; 
}

static struct registry_key *cmd_rmkey(TALLOC_CTX *mem_ctx, struct registry_context *ctx,struct registry_key *cur, int argc, char **argv)
{ 
	if(argc < 2) {
		fprintf(stderr, "Usage: rmkey <name>\n");
		return NULL;
	}

	if(!W_ERROR_IS_OK(reg_key_del(cur, argv[1]))) {
		fprintf(stderr, "Error deleting '%s'\n", argv[1]);
	} else {
		fprintf(stderr, "Successfully deleted '%s'\n", argv[1]);
	}
	
	return NULL; 
}

static struct registry_key *cmd_rmval(TALLOC_CTX *mem_ctx, struct registry_context *ctx,struct registry_key *cur, int argc, char **argv)
{ 
	if(argc < 2) {
		fprintf(stderr, "Usage: rmval <valuename>\n");
		return NULL;
	}

	if(!W_ERROR_IS_OK(reg_del_value(cur, argv[1]))) {
		fprintf(stderr, "Error deleting value '%s'\n", argv[1]);
	} else {
		fprintf(stderr, "Successfully deleted value '%s'\n", argv[1]);
	}

	return NULL; 
}

static struct registry_key *cmd_exit(TALLOC_CTX *mem_ctx, struct registry_context *ctx,struct registry_key *cur, int argc, char **argv)
{
	exit(0);
	return NULL; 
}

static struct registry_key *cmd_help(TALLOC_CTX *mem_ctx, struct registry_context *ctx,struct registry_key *, int, char **);

static struct {
	const char *name;
	const char *alias;
	const char *help;
	struct registry_key *(*handle)(TALLOC_CTX *mem_ctx, struct registry_context *ctx,struct registry_key *, int argc, char **argv);
} regshell_cmds[] = {
	{"ck", "cd", "Change current key", cmd_ck },
	{"info", "i", "Show detailed information of a key", cmd_info },
	{"list", "ls", "List values/keys in current key", cmd_ls },
	{"print", "p", "Print value", cmd_print },
	{"mkkey", "mkdir", "Make new key", cmd_mkkey },
	{"rmval", "rm", "Remove value", cmd_rmval },
	{"rmkey", "rmdir", "Remove key", cmd_rmkey },
	{"pwd", "pwk", "Printing current key", cmd_pwd },
	{"set", "update", "Update value", cmd_set },
	{"help", "?", "Help", cmd_help },
	{"exit", "quit", "Exit", cmd_exit },
	{"predef", "predefined", "Go to predefined key", cmd_predef },
	{NULL }
};

static struct registry_key *cmd_help(TALLOC_CTX *mem_ctx, struct registry_context *ctx, struct registry_key *cur, int argc, char **argv)
{
	int i;
	printf("Available commands:\n");
	for(i = 0; regshell_cmds[i].name; i++) {
		printf("%s - %s\n", regshell_cmds[i].name, regshell_cmds[i].help);
	}
	return NULL;
} 

static struct registry_key *process_cmd(TALLOC_CTX *mem_ctx, struct registry_context *ctx, struct registry_key *k, char *line)
{
	int argc;
	char **argv = NULL;
	int ret, i;

	if ((ret = poptParseArgvString(line, &argc, (const char ***) &argv)) != 0) {
		fprintf(stderr, "regshell: %s\n", poptStrerror(ret));
		return k;
	}

	for(i = 0; regshell_cmds[i].name; i++) {
		if(!strcmp(regshell_cmds[i].name, argv[0]) || 
		   (regshell_cmds[i].alias && !strcmp(regshell_cmds[i].alias, argv[0]))) {
			return regshell_cmds[i].handle(mem_ctx, ctx, k, argc, argv);
		}
	}

	fprintf(stderr, "No such command '%s'\n", argv[0]);
	
	return k;
}

#define MAX_COMPLETIONS 100

static struct registry_key *current_key = NULL;

static char **reg_complete_command(const char *text, int start, int end)
{
	/* Complete command */
	char **matches;
	int i, len, samelen=0, count=1;

	matches = malloc_array_p(char *, MAX_COMPLETIONS);
	if (!matches) return NULL;
	matches[0] = NULL;

	len = strlen(text);
	for (i=0;regshell_cmds[i].handle && count < MAX_COMPLETIONS-1;i++) {
		if (strncmp(text, regshell_cmds[i].name, len) == 0) {
			matches[count] = strdup(regshell_cmds[i].name);
			if (!matches[count])
				goto cleanup;
			if (count == 1)
				samelen = strlen(matches[count]);
			else
				while (strncmp(matches[count], matches[count-1], samelen) != 0)
					samelen--;
			count++;
		}
	}

	switch (count) {
	case 0:	/* should never happen */
	case 1:
		goto cleanup;
	case 2:
		matches[0] = strdup(matches[1]);
		break;
	default:
		matches[0] = strndup(matches[1], samelen);
	}
	matches[count] = NULL;
	return matches;

cleanup:
	count--;
	while (count >= 0) {
		free(matches[count]);
		count--;
	}
	free(matches);
	return NULL;
}

static char **reg_complete_key(const char *text, int start, int end)
{
	struct registry_key *base;
	struct registry_key *subkey;
	int i, j = 1;
	int samelen = 0;
	int len;
	char **matches;
	const char *base_n = "";
	TALLOC_CTX *mem_ctx;
	WERROR status;

	matches = malloc_array_p(char *, MAX_COMPLETIONS);
	if (!matches) return NULL;
	matches[0] = NULL;
	mem_ctx = talloc_init("completion");

	base = current_key;

	len = strlen(text);
	for(i = 0; j < MAX_COMPLETIONS-1; i++) {
		status = reg_key_get_subkey_by_index(mem_ctx, base, i, &subkey);
		if(W_ERROR_IS_OK(status)) {
			if(!strncmp(text, subkey->name, len)) {
				matches[j] = strdup(subkey->name);
				j++;

				if (j == 1)
					samelen = strlen(matches[j]);
				else
					while (strncmp(matches[j], matches[j-1], samelen) != 0)
						samelen--;
			}
		} else if(W_ERROR_EQUAL(status, WERR_NO_MORE_ITEMS)) {
			break;
		} else {
			printf("Error creating completion list: %s\n", win_errstr(status));
			talloc_free(mem_ctx);
			return NULL;
		}
	}

	if (j == 1) { /* No matches at all */
		SAFE_FREE(matches);
		talloc_free(mem_ctx);
		return NULL;
	}

	if (j == 2) { /* Exact match */
		asprintf(&matches[0], "%s%s", base_n, matches[1]);
	} else {
		asprintf(&matches[0], "%s%s", base_n, talloc_strndup(mem_ctx, matches[1], samelen));
	}		
	talloc_free(mem_ctx);

	matches[j] = NULL;
	return matches;
}

static char **reg_completion(const char *text, int start, int end)
{
	smb_readline_ca_char(' ');

	if (start == 0) {
		return reg_complete_command(text, start, end);
	} else {
		return reg_complete_key(text, start, end);
	}
}

 int main(int argc, char **argv)
{
	int opt;
	const char *backend = NULL;
	struct registry_key *curkey = NULL;
	poptContext pc;
	WERROR error;
	TALLOC_CTX *mem_ctx = talloc_init("cmd");
	const char *remote = NULL;
	struct registry_context *h = NULL;
	struct poptOption long_options[] = {
		POPT_AUTOHELP
		{"backend", 'b', POPT_ARG_STRING, &backend, 0, "backend to use", NULL},
		{"remote", 'R', POPT_ARG_STRING, &remote, 0, "connect to specified remote server", NULL},
		POPT_COMMON_SAMBA
		POPT_COMMON_CREDENTIALS
		POPT_COMMON_VERSION
		{ NULL }
	};

	pc = poptGetContext(argv[0], argc, (const char **) argv, long_options,0);
	
	while((opt = poptGetNextOpt(pc)) != -1) {
	}

	registry_init();

	if (remote) {
		error = reg_open_remote (&h, NULL, cmdline_credentials, remote, NULL); 
	} else if (backend) {
		error = reg_open_hive(NULL, backend, poptGetArg(pc), NULL, cmdline_credentials, &curkey);
	} else {
		error = reg_open_local(NULL, &h, NULL, cmdline_credentials);
	}

	if(!W_ERROR_IS_OK(error)) {
		fprintf(stderr, "Unable to open registry\n");
		return 1;
	}

	if (h) {
		int i;

		for (i = 0; reg_predefined_keys[i].handle; i++) {
			WERROR err;
			err = reg_get_predefined_key(h, reg_predefined_keys[i].handle, &curkey);
			if (W_ERROR_IS_OK(err)) {
				break;
			} else {
				curkey = NULL;
			}
		}
	}

	if (!curkey) {
		fprintf(stderr, "Unable to access any of the predefined keys\n");
		return -1;
	}
	
	poptFreeContext(pc);
	
	while(True) {
		char *line, *prompt;
		
		if(curkey->hive->root->name) {
			asprintf(&prompt, "%s:%s> ", curkey->hive->root->name, curkey->path);
		} else {
			asprintf(&prompt, "%s> ", curkey->path);
		}
		
		current_key = curkey; 		/* No way to pass a void * pointer 
									   via readline :-( */
		line = smb_readline(prompt, NULL, reg_completion);

		if(!line)
			break;

		if(line[0] != '\n') {
			struct registry_key *new = process_cmd(mem_ctx, h, curkey, line);
			if(new)curkey = new;
		}
	}
	talloc_free(mem_ctx);

	return 0;
}
