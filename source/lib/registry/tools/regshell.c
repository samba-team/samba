/* 
   Unix SMB/CIFS implementation.
   simple registry frontend
   
   Copyright (C) Jelmer Vernooij 2004

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
#include "dynconfig.h"
#include "registry.h"
#include "lib/cmdline/popt_common.h"
#include "system/time.h"

/* 
 * ck/cd - change key
 * ls - list values/keys
 * rmval/rm - remove value
 * rmkey/rmdir - remove key
 * mkkey/mkdir - make key
 * ch - change hive
 * info - show key info
 * help
 * exit
 */

static struct registry_key *cmd_info(TALLOC_CTX *mem_ctx, struct registry_key *cur, int argc, char **argv)
{
	time_t last_mod;
	printf("Name: %s\n", cur->name);
	printf("Full path: %s\n", cur->path);
	printf("Key Class: %s\n", cur->class_name);
	last_mod = nt_time_to_unix(cur->last_mod);
	printf("Time Last Modified: %s\n", ctime(&last_mod));
	/* FIXME: Security info */
	return cur;
}

static struct registry_key *cmd_pwd(TALLOC_CTX *mem_ctx, struct registry_key *cur, int argc, char **argv)
{
	printf("%s\n", cur->path);
	return cur;
}

static struct registry_key *cmd_set(TALLOC_CTX *mem_ctx, struct registry_key *cur, int argc, char **argv)
{
	/* FIXME */
	return NULL;
}

static struct registry_key *cmd_ck(TALLOC_CTX *mem_ctx, struct registry_key *cur, int argc, char **argv)
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

static struct registry_key *cmd_ls(TALLOC_CTX *mem_ctx, struct registry_key *cur, int argc, char **argv)
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
		printf("V \"%s\" %s %s\n", value->name, str_regtype(value->data_type), reg_val_data_string(mem_ctx, value));
	}
	
	return NULL; 
}
static struct registry_key *cmd_mkkey(TALLOC_CTX *mem_ctx, struct registry_key *cur, int argc, char **argv)
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

	fprintf(stderr, "Successfully added new subkey '%s' to '%s'\n", argv[1], cur->path);
	
	return NULL; 
}

static struct registry_key *cmd_rmkey(TALLOC_CTX *mem_ctx, struct registry_key *cur, int argc, char **argv)
{ 
	struct registry_key *key;
	if(argc < 2) {
		fprintf(stderr, "Usage: rmkey <name>\n");
		return NULL;
	}

	if(!W_ERROR_IS_OK(reg_open_key(mem_ctx, cur, argv[1], &key))) {
		fprintf(stderr, "No such subkey '%s'\n", argv[1]);
		return NULL;
	}

	if(!W_ERROR_IS_OK(reg_key_del(key))) {
		fprintf(stderr, "Error deleting '%s'\n", argv[1]);
	} else {
		fprintf(stderr, "Successfully deleted '%s'\n", argv[1]);
	}
	
	return NULL; 
}

static struct registry_key *cmd_rmval(TALLOC_CTX *mem_ctx, struct registry_key *cur, int argc, char **argv)
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

static struct registry_key *cmd_exit(TALLOC_CTX *mem_ctx, struct registry_key *cur, int argc, char **argv)
{
	exit(0);
	return NULL; 
}

static struct registry_key *cmd_help(TALLOC_CTX *mem_ctx, struct registry_key *, int, char **);

struct {
	const char *name;
	const char *alias;
	const char *help;
	struct registry_key *(*handle)(TALLOC_CTX *mem_ctx, struct registry_key *, int argc, char **argv);
} regshell_cmds[] = {
	{"ck", "cd", "Change current key", cmd_ck },
	{"info", "i", "Show detailed information of a key", cmd_info },
	{"list", "ls", "List values/keys in current key", cmd_ls },
	{"mkkey", "mkdir", "Make new key", cmd_mkkey },
	{"rmval", "rm", "Remove value", cmd_rmval },
	{"rmkey", "rmdir", "Remove key", cmd_rmkey },
	{"pwd", "pwk", "Printing current key", cmd_pwd },
	{"set", "update", "Update value", cmd_set },
	{"help", "?", "Help", cmd_help },
	{"exit", "quit", "Exit", cmd_exit },
	{NULL }
};

static struct registry_key *cmd_help(TALLOC_CTX *mem_ctx, struct registry_key *cur, int argc, char **argv)
{
	int i;
	printf("Available commands:\n");
	for(i = 0; regshell_cmds[i].name; i++) {
		printf("%s - %s\n", regshell_cmds[i].name, regshell_cmds[i].help);
	}
	return NULL;
} 

static struct registry_key *process_cmd(TALLOC_CTX *mem_ctx, struct registry_key *k, char *line)
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
			return regshell_cmds[i].handle(mem_ctx, k, argc, argv);
		}
	}

	fprintf(stderr, "No such command '%s'\n", argv[0]);
	
	return k;
}

#define MAX_COMPLETIONS 100

static struct registry_key *current_key = NULL;

static char **reg_complete_command(const char *text, int end)
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
	while (i >= 0) {
		free(matches[i]);
		i--;
	}
	free(matches);
	return NULL;
}

static char **reg_complete_key(const char *text, int end)
{
	struct registry_key *subkey;
	int i, j = 1;
	int samelen = 0;
	int len;
	char **matches;
	TALLOC_CTX *mem_ctx;

	matches = malloc_array_p(char *, MAX_COMPLETIONS);
	if (!matches) return NULL;
	matches[0] = NULL;

	len = strlen(text);
	mem_ctx = talloc_init("completion");
	for(i = 0; j < MAX_COMPLETIONS-1; i++) {
		WERROR status = reg_key_get_subkey_by_index(mem_ctx, current_key, i, &subkey);
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
			talloc_destroy(mem_ctx);
			return NULL;
		}
	}
	talloc_destroy(mem_ctx);

	if (j == 1) { /* No matches at all */
		SAFE_FREE(matches);
		return NULL;
	}

	if (j == 2) { /* Exact match */
		matches[0] = strdup(matches[1]);
	} else {
		matches[0] = strndup(matches[1], samelen);
	}		

	matches[j] = NULL;
	return matches;
}

static char **reg_completion(const char *text, int start, int end)
{
	smb_readline_ca_char(' ');

	if (start == 0) {
		return reg_complete_command(text, end);
	} else {
		return reg_complete_key(text, end);
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
		POPT_COMMON_CREDENTIALS
		{"backend", 'b', POPT_ARG_STRING, &backend, 0, "backend to use", NULL},
		{"remote", 'R', POPT_ARG_STRING, &remote, 0, "connect to specified remote server", NULL},
		POPT_TABLEEND
	};

	regshell_init_subsystems;

	if (!lp_load(dyn_CONFIGFILE,True,False,False)) {
		fprintf(stderr, "Can't load %s - run testparm to debug it\n", dyn_CONFIGFILE);
	}

	
	pc = poptGetContext(argv[0], argc, (const char **) argv, long_options,0);
	
	while((opt = poptGetNextOpt(pc)) != -1) {
	}

    setup_logging("regtree", True);

	if (remote) {
		error = reg_open_remote (&h, cmdline_get_username(), cmdline_get_userpassword(), remote); 
	} else if (backend) {
		error = reg_open_hive(NULL, backend, poptGetArg(pc), NULL, &curkey);
	} else {
		error = reg_open_local(&h);
	}

	if(!W_ERROR_IS_OK(error)) {
		fprintf(stderr, "Unable to open registry\n");
		return 1;
	}

	if (h) {
		/*FIXME: What if HKEY_CLASSES_ROOT is not present ? */
		reg_get_predefined_key(h, HKEY_CLASSES_ROOT, &curkey);
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
			struct registry_key *new = process_cmd(mem_ctx, curkey, line);
			if(new)curkey = new;
		}
	}
	talloc_destroy(mem_ctx);

	return 0;
}
