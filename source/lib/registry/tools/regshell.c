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
 * help
 * exit
 */

static REG_KEY *cmd_set(REG_KEY *cur, int argc, char **argv)
{
	/* FIXME */
	return NULL;
}

static REG_KEY *cmd_ck(REG_KEY *cur, int argc, char **argv)
{ 
	REG_KEY *new;
	if(argc < 2) {
		new = cur;
	} else {
		new = reg_open_key(cur, argv[1]);
	}
	
	if(!new) new = cur;

	printf("Current path is: %s\n", reg_key_get_path(new));
	
	return new;
}

static REG_KEY *cmd_ls(REG_KEY *cur, int argc, char **argv)
{
	int i, num;
	num = reg_key_num_subkeys(cur);
	for(i = 0; i < num; i++) {
		REG_KEY *sub = reg_key_get_subkey_by_index(cur, i);
		printf("K %s\n", reg_key_name(sub));
	}

	num = reg_key_num_values(cur);
	for(i = 0; i < num; i++) {
		REG_VAL *sub = reg_key_get_value_by_index(cur, i);
		printf("V %s %s %s\n", reg_val_name(sub), str_regtype(reg_val_type(sub)), reg_val_data_string(sub));
	}
	
	return NULL; 
}
static REG_KEY *cmd_mkkey(REG_KEY *cur, int argc, char **argv)
{ 
	if(argc < 2) {
		fprintf(stderr, "Usage: mkkey <keyname>\n");
		return NULL;
	}
	
	if(!reg_key_add_name(cur, argv[1])) {
		fprintf(stderr, "Error adding new subkey '%s'\n", argv[1]);
		return NULL;
	}

	fprintf(stderr, "Successfully added new subkey '%s' to '%s'\n", argv[1], reg_key_get_path(cur));
	
	return NULL; 
}

static REG_KEY *cmd_rmkey(REG_KEY *cur, int argc, char **argv)
{ 
	REG_KEY *key;
	if(argc < 2) {
		fprintf(stderr, "Usage: rmkey <name>\n");
		return NULL;
	}

	key = reg_open_key(cur, argv[1]);
	if(!key) {
		fprintf(stderr, "No such subkey '%s'\n", argv[1]);
		return NULL;
	}

	if(!reg_key_del(key)) {
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

	val = reg_key_get_value_by_name(cur, argv[1]);
	if(!val) {
		fprintf(stderr, "No such value '%s'\n", argv[1]);
		return NULL;
	}

	if(!reg_val_del(val)) {
		fprintf(stderr, "Error deleting value '%s'\n", argv[1]);
	} else {
		fprintf(stderr, "Successfully deleted value '%s'\n", argv[1]);
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
	{"list", "ls", "List values/keys in current key", cmd_ls },
	{"mkkey", "mkdir", "Make new key", cmd_mkkey },
	{"rmval", "rm", "Remove value", cmd_rmval },
	{"rmkey", "rmdir", "Remove key", cmd_rmkey },
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

REG_KEY *process_cmd(REG_KEY *k, char *line)
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

int main (int argc, char **argv)
{
	uint32	setparms, checkparms;
	int opt;
	char *backend = "dir";
	REG_KEY *curkey = NULL;;
	poptContext pc;
	REG_HANDLE *h;
	struct poptOption long_options[] = {
		POPT_AUTOHELP
		{"backend", 'b', POPT_ARG_STRING, &backend, 0, "backend to use", NULL},
		POPT_TABLEEND
	};
	
	pc = poptGetContext(argv[0], argc, (const char **) argv, long_options,0);
	
	while((opt = poptGetNextOpt(pc)) != -1) {
	}

	h = reg_open(backend, poptPeekArg(pc), True);
	if(!h) {
		fprintf(stderr, "Unable to open '%s' with backend '%s'\n", poptGetArg(pc), backend);
		return 1;
	}
	poptFreeContext(pc);

    setup_logging("regtree", True);

	curkey = reg_get_root(h);

	if(!curkey) return 1;

	while(True) {
		char *line, *prompt;
		
		asprintf(&prompt, "%s> ", reg_key_get_path(curkey));
		
		line = smb_readline(prompt, NULL, NULL);

		if(!line)
			break;

		if(line[0] != '\n') {
			REG_KEY *new = process_cmd(curkey, line);
			if(new)curkey = new;
		}
	}

	return 0;
}
