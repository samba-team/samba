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

static REG_KEY *cmd_info(REG_KEY *cur, int argc, char **argv)
{
	time_t last_mod;
	printf("Name: %s\n", reg_key_name(cur));
	printf("Full path: %s\n", reg_key_get_path(cur));
	printf("Key Class: %s\n", reg_key_class(cur));
	last_mod = nt_time_to_unix(reg_key_last_modified(cur));
	printf("Time Last Modified: %s\n", ctime(&last_mod));
	/* FIXME: Security info */
	return cur;
}

static REG_KEY *cmd_pwd(REG_KEY *cur, int argc, char **argv)
{
	printf("%s\n", reg_key_get_path_abs(cur));
	return cur;
}

static REG_KEY *cmd_set(REG_KEY *cur, int argc, char **argv)
{
	/* FIXME */
	return NULL;
}

static REG_KEY *cmd_ck(REG_KEY *cur, int argc, char **argv)
{ 
	REG_KEY *new = NULL;
	WERROR error;
	if(argc < 2) {
		new = cur;
	} else {
		error = reg_open_key(cur, argv[1], &new);
		if(!W_ERROR_IS_OK(error)) {
			DEBUG(0, ("Error opening specified key: %s\n", win_errstr(error)));
			return NULL;
		}
	} 

	printf("Current path is: %s\n", reg_key_get_path_abs(new));
	
	return new;
}

static REG_KEY *cmd_ls(REG_KEY *cur, int argc, char **argv)
{
	int i;
	WERROR error;
	REG_VAL *value;
	REG_KEY *sub;
	for(i = 0; W_ERROR_IS_OK(error = reg_key_get_subkey_by_index(cur, i, &sub)); i++) {
		printf("K %s\n", reg_key_name(sub));
	}

	if(!W_ERROR_EQUAL(error, WERR_NO_MORE_ITEMS)) {
		DEBUG(0, ("Error occured while browsing thru keys: %s\n", win_errstr(error)));
	}

	for(i = 0; W_ERROR_IS_OK(error = reg_key_get_value_by_index(cur, i, &value)); i++) {
		printf("V \"%s\" %s %s\n", reg_val_name(value), str_regtype(reg_val_type(value)), reg_val_data_string(value));
	}
	
	return NULL; 
}
static REG_KEY *cmd_mkkey(REG_KEY *cur, int argc, char **argv)
{ 
	REG_KEY *tmp;
	if(argc < 2) {
		fprintf(stderr, "Usage: mkkey <keyname>\n");
		return NULL;
	}
	
	if(!W_ERROR_IS_OK(reg_key_add_name(cur, argv[1], 0, NULL, &tmp))) {
		fprintf(stderr, "Error adding new subkey '%s'\n", argv[1]);
		return NULL;
	}

	fprintf(stderr, "Successfully added new subkey '%s' to '%s'\n", argv[1], reg_key_get_path_abs(cur));
	
	return NULL; 
}

static REG_KEY *cmd_rmkey(REG_KEY *cur, int argc, char **argv)
{ 
	REG_KEY *key;
	if(argc < 2) {
		fprintf(stderr, "Usage: rmkey <name>\n");
		return NULL;
	}

	if(!W_ERROR_IS_OK(reg_open_key(cur, argv[1], &key))) {
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

static REG_KEY *cmd_rmval(REG_KEY *cur, int argc, char **argv)
{ 
	REG_VAL *val;
	if(argc < 2) {
		fprintf(stderr, "Usage: rmval <valuename>\n");
		return NULL;
	}

	if(!W_ERROR_IS_OK(reg_key_get_value_by_name(cur, argv[1], &val))) {
		fprintf(stderr, "No such value '%s'\n", argv[1]);
		return NULL;
	}

	if(!W_ERROR_IS_OK(reg_val_del(val))) {
		fprintf(stderr, "Error deleting value '%s'\n", argv[1]);
	} else {
		fprintf(stderr, "Successfully deleted value '%s'\n", argv[1]);
	}

	return NULL; 
}

static REG_KEY *cmd_hive(REG_KEY *cur, int argc, char **argv)
{
	int i;
	WERROR error = WERR_OK;
	for(i = 0; W_ERROR_IS_OK(error); i++) {
		REG_KEY *hive;
		error = reg_get_hive(reg_key_handle(cur), i, &hive);
		if(!W_ERROR_IS_OK(error)) break;

		if(argc == 1) {
			printf("%s\n", reg_key_name(hive));
		} else if(!strcmp(reg_key_name(hive), argv[1])) {
			return hive;
		} 
		reg_key_free(hive);
	}
	return NULL;
}

static REG_KEY *cmd_exit(REG_KEY *cur, int argc, char **argv)
{
	exit(0);
	return NULL; 
}

static REG_KEY *cmd_help(REG_KEY *, int, char **);

struct {
	const char *name;
	const char *alias;
	const char *help;
	REG_KEY *(*handle)(REG_KEY *, int argc, char **argv);
} regshell_cmds[] = {
	{"ck", "cd", "Change current key", cmd_ck },
	{"ch", "hive", "Change current hive", cmd_hive },
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

static REG_KEY *cmd_help(REG_KEY *cur, int argc, char **argv)
{
	int i;
	printf("Available commands:\n");
	for(i = 0; regshell_cmds[i].name; i++) {
		printf("%s - %s\n", regshell_cmds[i].name, regshell_cmds[i].help);
	}
	return NULL;
} 

static REG_KEY *process_cmd(REG_KEY *k, char *line)
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
			return regshell_cmds[i].handle(k, argc, argv);
		}
	}

	fprintf(stderr, "No such command '%s'\n", argv[0]);
	
	return k;
}

#define MAX_COMPLETIONS 100

static REG_KEY *current_key = NULL;

static char **reg_complete_command(const char *text, int end)
{
	/* Complete command */
	char **matches;
	int i, len, samelen, count=1;

	matches = (char **)malloc(sizeof(matches[0])*MAX_COMPLETIONS);
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
		matches[0] = malloc(samelen+1);
		if (!matches[0])
			goto cleanup;
		strncpy(matches[0], matches[1], samelen);
		matches[0][samelen] = 0;
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
	REG_KEY *subkey;
	int i, j = 0;
	int len;
	char **matches;
	/* Complete argument */

	matches = (char **)malloc(sizeof(matches[0])*MAX_COMPLETIONS);
	if (!matches) return NULL;
	matches[0] = NULL;

	len = strlen(text);
	for(i = 0; j < MAX_COMPLETIONS-1; i++) {
		WERROR status = reg_key_get_subkey_by_index(current_key, i, &subkey);
		if(W_ERROR_IS_OK(status)) {
			if(!strncmp(text, reg_key_name(subkey), len)) {
				matches[j] = strdup(reg_key_name(subkey));
				j++;
			}
			reg_key_free(subkey);
		} else if(W_ERROR_EQUAL(status, WERR_NO_MORE_ITEMS)) {
			break;
		} else {
			printf("Error creating completion list: %s\n", win_errstr(status));
			return NULL;
		}
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
	const char *backend = "dir";
	const char *credentials = NULL;
	REG_KEY *curkey = NULL;
	poptContext pc;
	WERROR error;
	REG_HANDLE *h;
	struct poptOption long_options[] = {
		POPT_AUTOHELP
		POPT_COMMON_SAMBA
		{"backend", 'b', POPT_ARG_STRING, &backend, 0, "backend to use", NULL},
		{"credentials", 'c', POPT_ARG_STRING, &credentials, 0, "credentials", NULL},
		POPT_TABLEEND
	};
	
	pc = poptGetContext(argv[0], argc, (const char **) argv, long_options,0);
	
	while((opt = poptGetNextOpt(pc)) != -1) {
	}

	error = reg_open(backend, poptPeekArg(pc), credentials, &h);
	if(!W_ERROR_IS_OK(error)) {
		fprintf(stderr, "Unable to open '%s' with backend '%s'\n", poptGetArg(pc), backend);
		return 1;
	}
	poptFreeContext(pc);

    setup_logging("regtree", True);

	error = reg_get_hive(h, 0, &curkey);

	if(!W_ERROR_IS_OK(error)) return 1;

	while(True) {
		char *line, *prompt;
		
		asprintf(&prompt, "%s> ", reg_key_get_path_abs(curkey));
		
		current_key = curkey; 		/* No way to pass a void * pointer 
									   via readline :-( */
		line = smb_readline(prompt, NULL, reg_completion);

		if(!line)
			break;

		if(line[0] != '\n') {
			REG_KEY *new = process_cmd(curkey, line);
			if(new)curkey = new;
		}
	}

	return 0;
}
