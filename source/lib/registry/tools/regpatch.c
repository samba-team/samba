/* 
   Unix SMB/CIFS implementation.
   simple registry frontend
   
   Copyright (C) 2002, Richard Sharpe, rsharpe@richardsharpe.com
   Copyright (C) 2004, Jelmer Vernooij, jelmer@samba.org

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

/*
 * Routines to parse a REGEDIT4 file
 * 
 * The file consists of:
 * 
 * REGEDIT4
 * \[[-]key-path\]\n
 * <value-spec>*
 *
 * Format:
 * [cmd:]name=type:value
 *
 * cmd = a|d|c|add|delete|change|as|ds|cs
 *
 * There can be more than one key-path and value-spec.
 *
 * Since we want to support more than one type of file format, we
 * construct a command-file structure that keeps info about the command file
 */

#define FMT_UNREC -1
#define FMT_REGEDIT4 0
#define FMT_EDITREG1_1 1

#define FMT_STRING_REGEDIT4 "REGEDIT4"
#define FMT_STRING_EDITREG1_0 "EDITREG1.0"

#define CMD_NONE     0
#define CMD_ADD_KEY  1
#define CMD_DEL_KEY  2

#define CMD_KEY 1
#define CMD_VAL 2

typedef struct val_spec_list {
  struct val_spec_list *next;
  char *name;
  int type;
  char *val;    /* Kept as a char string, really? */
} VAL_SPEC_LIST;

typedef struct command_s {
  int cmd;
  char *key;
  int val_count;
  VAL_SPEC_LIST *val_spec_list, *val_spec_last;
} CMD;

typedef struct cmd_line {
  int len, line_len;
  char *line;
} CMD_LINE;

static void free_val_spec_list(VAL_SPEC_LIST *vl)
{
  if (!vl) return;
  if (vl->name) free(vl->name);
  if (vl->val) free(vl->val);
  free(vl);

}

/* 
 * Some routines to handle lines of info in the command files
 */
static void skip_to_eol(int fd)
{
  int rc;
  char ch = 0;

  while ((rc = read(fd, &ch, 1)) == 1) {
    if (ch == 0x0A) return;
  }
  if (rc < 0) {
    DEBUG(0, ("Could not read file descriptor: %d, %s\n",
	    fd, strerror(errno)));
    exit(1);
  }
}

static void free_cmd(CMD *cmd)
{
  if (!cmd) return;

  while (cmd->val_spec_list) {
    VAL_SPEC_LIST *tmp;

    tmp = cmd->val_spec_list;
    cmd->val_spec_list = tmp->next;
    free(tmp);
  }

  free(cmd);

}

static void free_cmd_line(CMD_LINE *cmd_line)
{
  if (cmd_line) {
    if (cmd_line->line) free(cmd_line->line);
    free(cmd_line);
  }
}

static void print_line(struct cmd_line *cl)
{
  char *pl;

  if (!cl) return;

  pl = smb_xmalloc(cl->line_len + 1);

  strncpy(pl, cl->line, cl->line_len);
  pl[cl->line_len] = 0;

  fprintf(stdout, "%s\n", pl);
  free(pl);
}

#define INIT_ALLOC 10 

/*
 * Read a line from the input file.
 * NULL returned when EOF and no chars read
 * Otherwise we return a cmd_line *
 * Exit if other errors
 */
static struct cmd_line *get_cmd_line(int fd)
{
  CMD_LINE *cl = smb_xmalloc_p(CMD_LINE);
  int i = 0, rc;
  uint8_t ch;

  cl->len = INIT_ALLOC;

  /*
   * Allocate some space for the line. We extend later if needed.
   */

  cl->line = (char *)smb_xmalloc(INIT_ALLOC);

  /*
   * Now read in the chars to EOL. Don't store the EOL in the 
   * line. What about CR?
   */

  while ((rc = read(fd, &ch, 1)) == 1 && ch != '\n') {
    if (ch == '\r') continue; /* skip CR */
    if (i == cl->len-1) {
      /*
       * Allocate some more memory
       */
      if ((cl->line = realloc(cl->line, cl->len + INIT_ALLOC)) == NULL) {
	DEBUG(0, ("Unable to realloc space for line: %s\n",
		strerror(errno)));
	exit(1);
      }
      cl->len += INIT_ALLOC;
    }
    cl->line[i] = ch;
    i++;
  }

  /* read 0 and we were at loc'n 0, return NULL */
  if (rc == 0 && i == 0) {
    free_cmd_line(cl);
    return NULL;
  }

  cl->line[i] = '\0';
  cl->line_len = i;

  return cl;

}

/*
 * parse_value: parse out a value. We pull it apart as:
 *
 * <value> ::= <value-name>=<type>:<value-string>
 *
 * <value-name> ::= char-string-without-spaces | '"' char-string '"'
 *
 * If it parsed OK, return the <value-name> as a string, and the
 * value type and value-string in parameters.
 *
 * The value name can be empty. There can only be one empty name in 
 * a list of values. A value of - removes the value entirely.  
 */

static char *parse_name(char *nstr)
{
  int len = 0, start = 0;
  if (!nstr) return NULL;

  len = strlen(nstr);

  while (len && nstr[len - 1] == ' ') len--;

  nstr[len] = 0; /* Trim any spaces ... if there were none, doesn't matter */

  /*
   * Beginning and end should be '"' or neither should be so
   */
  if ((nstr[0] == '"' && nstr[len - 1] != '"') ||
      (nstr[0] != '"' && nstr[len - 1] == '"'))
    return NULL;

  if (nstr[0] == '"') {
    start = 1;
    len -= 2;
  }

  return strndup(&nstr[start], len);
}

static int parse_value_type(char *tstr)
{
  int len = strlen(tstr);
  
  while (len && tstr[len - 1] == ' ') len--;
  tstr[len] = 0;

  if (strcmp(tstr, "REG_DWORD") == 0)
    return REG_DWORD;
  else if (strcmp(tstr, "dword") == 0)
    return REG_DWORD;
  else if (strcmp(tstr, "REG_EXPAND_SZ") == 0)
    return REG_EXPAND_SZ;
  else if (strcmp(tstr, "REG_BIN") == 0)
    return REG_BINARY;
  else if (strcmp(tstr, "REG_SZ") == 0)
    return REG_SZ;
  else if (strcmp(tstr, "REG_MULTI_SZ") == 0)
    return REG_MULTI_SZ;
  else if (strcmp(tstr, "-") == 0)
    return REG_DELETE;

  return 0;
}

static char *parse_val_str(char *vstr)
{
  
  return strndup(vstr, strlen(vstr));

}

static char *parse_value(struct cmd_line *cl, int *vtype, char **val)
{
  char *p1 = NULL, *p2 = NULL, *nstr = NULL, *tstr = NULL, *vstr = NULL;
  
  if (!cl || !vtype || !val) return NULL;
  if (!cl->line[0]) return NULL;

  p1 = strdup(cl->line);
  /* FIXME: Better return codes etc ... */
  if (!p1) return NULL;
  p2 = strchr(p1, '=');
  if (!p2) return NULL;

  *p2 = 0; p2++; /* Split into two strings at p2 */

  /* Now, parse the name ... */

  nstr = parse_name(p1);
  if (!nstr) goto error;

  /* Now, split the remainder and parse on type and val ... */

  tstr = p2;
  while (*tstr == ' ') tstr++; /* Skip leading white space */
  p2 = strchr(p2, ':');

  if (p2) {
    *p2 = 0; p2++; /* split on the : */
  }

  *vtype = parse_value_type(tstr);

  if (!vtype) goto error;

  if (!p2 || !*p2) return nstr;

  /* Now, parse the value string. It should return a newly malloc'd string */
  
  while (*p2 == ' ') p2++; /* Skip leading space */
  vstr = parse_val_str(p2);

  if (!vstr) goto error;

  *val = vstr;

  return nstr;

 error:
  if (p1) free(p1);
  if (nstr) free(nstr);
  if (vstr) free(vstr);
  return NULL;
}

/*
 * Parse out a key. Look for a correctly formatted key [...] 
 * and whether it is a delete or add? A delete is signalled 
 * by a - in front of the key.
 * Assumes that there are no leading and trailing spaces
 */

static char *parse_key(struct cmd_line *cl, int *cmd)
{
  int start = 1;
  char *tmp;

  if (cl->line[0] != '[' ||
      cl->line[cl->line_len - 1] != ']') return NULL;
  if (cl->line_len == 2) return NULL;
  *cmd = CMD_ADD_KEY;
  if (cl->line[1] == '-') {
    if (cl->line_len == 3) return NULL;
    start = 2;
    *cmd = CMD_DEL_KEY;
  }
  tmp = smb_xmalloc(cl->line_len - 1 - start + 1);
  strncpy(tmp, &cl->line[start], cl->line_len - 1 - start);
  tmp[cl->line_len - 1 - start] = 0;
  return tmp;
}

/*
 * Parse a line to determine if we have a key or a value
 * We only check for key or val ...
 */

static int parse_line(struct cmd_line *cl)
{

  if (!cl || cl->len == 0) return 0;

  if (cl->line[0] == '[')  /* No further checking for now */
    return CMD_KEY;
  else 
    return CMD_VAL;
}

/*
 * We seek to offset 0, read in the required number of bytes, 
 * and compare to the correct value.
 * We then seek back to the original location
 */
static int regedit4_file_type(int fd)
{
  int cur_ofs = 0;
  char desc[9];

  cur_ofs = lseek(fd, 0, SEEK_CUR); /* Get current offset */
  if (cur_ofs < 0) {
    DEBUG(0, ("Unable to get current offset: (%d) %s\n", cur_ofs, strerror(errno)));
    exit(1);  /* FIXME */
  }

  if (cur_ofs) {
    lseek(fd, 0, SEEK_SET);
  }

  if (read(fd, desc, 8) < 8) {
    DEBUG(0, ("Unable to read command file format\n")); 
    exit(2);  /* FIXME */
  }

  desc[8] = 0;

  if (strcmp(desc, FMT_STRING_REGEDIT4) == 0) {
    if (cur_ofs) {
      lseek(fd, cur_ofs, SEEK_SET);
    } else {
      skip_to_eol(fd);
    }
    return FMT_REGEDIT4;
  }

  return FMT_UNREC;
}

/*
 * Run though the data in the line and strip anything after a comment
 * char.
 */
static void strip_comment(struct cmd_line *cl)
{
  int i;

  if (!cl) return;

  for (i = 0; i < cl->line_len; i++) {
    if (cl->line[i] == ';') {
		cl->line[i] = '\0';
      cl->line_len = i;
      return;
    }
  }
}

/* 
 * Get a command ... This consists of possibly multiple lines:
 * [key]
 * values*
 * possibly Empty line
 *
 * value ::= <value-name>=<value-type>':'<value-string>
 * <value-name> is some path, possibly enclosed in quotes ...
 * We alctually look for the next key to terminate a previous key
 * if <value-type> == '-', then it is a delete type.
 */
static CMD *regedit4_get_cmd(int fd)
{
  struct command_s *cmd = NULL;
  struct cmd_line *cl = NULL;
  struct val_spec_list *vl = NULL;

  cmd = smb_xmalloc_p(struct command_s);

  cmd->cmd = CMD_NONE;
  cmd->key = NULL;
  cmd->val_count = 0;
  cmd->val_spec_list = cmd->val_spec_last = NULL;
  while ((cl = get_cmd_line(fd))) {

    /*
     * If it is an empty command line, and we already have a key
     * then exit from here ... FIXME: Clean up the parser
     */

    if (cl->line_len == 0 && cmd->key) {
      free_cmd_line(cl);
      break;
    } 

    strip_comment(cl);     /* remove anything beyond a comment char */
	trim_string(cl->line, " \t", " \t");

    if (!cl->line[0]) {    /* An empty line */
      free_cmd_line(cl);
    }
    else {                 /* Else, non-empty ... */
      /* 
       * Parse out the bits ... 
       */
      switch (parse_line(cl)) {
      case CMD_KEY:
	if ((cmd->key = parse_key(cl, &cmd->cmd)) == NULL) {
	  DEBUG(0, ("Error parsing key from line: "));
	  print_line(cl);
	  DEBUG(0, ("\n"));
	}
	break;

      case CMD_VAL:
	/*
	 * We need to add the value stuff to the list
	 * There could be a \ on the end which we need to 
	 * handle at some time
	 */
	vl = smb_xmalloc_p(struct val_spec_list);
	vl->next = NULL;
	vl->val = NULL;
	vl->name = parse_value(cl, &vl->type, &vl->val);
	if (!vl->name) goto error;
	if (cmd->val_spec_list == NULL) {
	  cmd->val_spec_list = cmd->val_spec_last = vl;
	}
	else {
	  cmd->val_spec_last->next = vl;
	  cmd->val_spec_last = vl;
	}
	cmd->val_count++;
	break;

      default:
	DEBUG(0, ("Unrecognized line in command file: \n"));
	print_line(cl);
	break;
      }
    }

  }
  if (!cmd->cmd) goto error; /* End of file ... */

  return cmd;

 error:
  if (vl) free(vl);
  if (cmd) free_cmd(cmd);
  return NULL;
}

static int regedit4_exec_cmd(CMD *cmd)
{

  return 0;
}

static int editreg_1_0_file_type(int fd)
{
  int cur_ofs = 0;
  char desc[11];

  cur_ofs = lseek(fd, 0, SEEK_CUR); /* Get current offset */
  if (cur_ofs < 0) {
    DEBUG(0, ("Unable to get current offset: %s\n", strerror(errno)));
    exit(1);  /* FIXME */
  }

  if (cur_ofs) {
    lseek(fd, 0, SEEK_SET);
  }

  if (read(fd, desc, 10) < 10) {
    DEBUG(0, ("Unable to read command file format\n")); 
    exit(2);  /* FIXME */
  }

  desc[10] = 0;

  if (strcmp(desc, FMT_STRING_EDITREG1_0) == 0) {
    lseek(fd, cur_ofs, SEEK_SET);
    return FMT_REGEDIT4;
  }

  return FMT_UNREC;
}

static CMD *editreg_1_0_get_cmd(int fd)
{
  return NULL;
}

static int editreg_1_0_exec_cmd(CMD *cmd)
{

  return -1;
}

typedef struct command_ops_s {
  int type;
  int (*file_type)(int fd);
  CMD *(*get_cmd)(int fd);
  int (*exec_cmd)(CMD *cmd);
} CMD_OPS;

CMD_OPS default_cmd_ops[] = {
  {0, regedit4_file_type, regedit4_get_cmd, regedit4_exec_cmd},
  {1, editreg_1_0_file_type, editreg_1_0_get_cmd, editreg_1_0_exec_cmd},
  {-1,  NULL, NULL, NULL}
}; 

typedef struct command_file_s {
  char *name;
  int type, fd;
  CMD_OPS cmd_ops;
} CMD_FILE;

/*
 * Create a new command file structure
 */

static CMD_FILE *cmd_file_create(const char *file)
{
  CMD_FILE *tmp;
  struct stat sbuf;
  int i = 0;

  /*
   * Let's check if the file exists ...
   * No use creating the cmd_file structure if the file does not exist
   */

  if (stat(file, &sbuf) < 0) { /* Not able to access file */
	DEBUG(0,("Stat on %s failed\n", file));
    return NULL;
  }

  tmp = smb_xmalloc_p(CMD_FILE); 

  /*
   * Let's fill in some of the fields;
   */

  tmp->name = strdup(file);

  if ((tmp->fd = open(file, O_RDONLY, 666)) < 0) {
	DEBUG(0,("Error opening %s\n", file));
    free(tmp);
    return NULL;
  }

  /*
   * Now, try to find the format by indexing through the table
   */
  while (default_cmd_ops[i].type != -1) {
    if ((tmp->type = default_cmd_ops[i].file_type(tmp->fd)) >= 0) {
      tmp->cmd_ops = default_cmd_ops[i];
      return tmp;
    }
    i++;
  }

  /* 
   * If we got here, return NULL, as we could not figure out the type
   * of command file.
   *
   * What about errors? 
   */

  free(tmp);
  DEBUG(0,("Unknown type\n"));
  return NULL;
}

/*
 * Extract commands from the command file, and execute them.
 * We pass a table of command callbacks for that 
 */

/* FIXME */

/*
 * Main code from here on ...
 */

/*
 * key print function here ...
 */

/*
 * Sec Desc print functions 
 */

char *str_type(uint8_t type);

static int nt_apply_reg_command_file(struct registry_context *r, const char *cmd_file_name)
{
	CMD *cmd;
	BOOL modified = False;
	CMD_FILE *cmd_file = NULL;
	TALLOC_CTX *mem_ctx = talloc_init("apply_cmd_file");
	struct registry_key *tmp = NULL;
	WERROR error;
	cmd_file = cmd_file_create(cmd_file_name);

	while ((cmd = cmd_file->cmd_ops.get_cmd(cmd_file->fd)) != NULL) {

		/*
		 * Now, apply the requests to the tree ...
		 */
		switch (cmd->cmd) {
		case CMD_ADD_KEY: 
		  error = reg_open_key_abs(mem_ctx, r, cmd->key, &tmp);

		  /* If we found it, apply the other bits, else create such a key */
		  if (W_ERROR_EQUAL(error, WERR_DEST_NOT_FOUND)) {
			  if(!W_ERROR_IS_OK(reg_key_add_abs(mem_ctx, r, cmd->key, 0, NULL, &tmp))) {
					DEBUG(0, ("Error adding new key '%s'\n", cmd->key));
					continue;
			  }
			  modified = True;
		  }

		  while (cmd->val_count) {
			  VAL_SPEC_LIST *val = cmd->val_spec_list;

			  if (val->type == REG_DELETE) {
				  error = reg_del_value(tmp, val->name);
				  if(!W_ERROR_IS_OK(error)) {
					DEBUG(0, ("Error removing value '%s'\n", val->name));
				  }
				  modified = True;
			  }
			  else {
				  if(!W_ERROR_IS_OK(reg_val_set(tmp, val->name, val->type, val->val, strlen(val->val)))) {
					  DEBUG(0, ("Error adding new value '%s'\n", val->name));
					  continue;
				  }
				  modified = True;
			  }

			  cmd->val_spec_list = val->next;
			  free_val_spec_list(val);
			  cmd->val_count--;
		  }

		  break;

		case CMD_DEL_KEY:
		  /* 
		   * Any value does not matter ...
		   * Find the key if it exists, and delete it ...
		   */

		  error = reg_key_del_abs(r, cmd->key); 
		  if(!W_ERROR_IS_OK(error)) {
			  DEBUG(0, ("Unable to delete key '%s'\n", cmd->key));
			  continue;
		  }
		  modified = True;
		  break;
		}
	}
	free_cmd(cmd);

	return modified;
}

 int main(int argc, char **argv)
{
	int opt;
	poptContext pc;
	const char *patch;
	struct registry_context *h;
	const char *remote = NULL;
	WERROR error;
	struct poptOption long_options[] = {
		POPT_AUTOHELP
		POPT_COMMON_CREDENTIALS
		{"remote", 'R', POPT_ARG_STRING, &remote, 0, "connect to specified remote server", NULL},
		POPT_TABLEEND
	};

	regpatch_init_subsystems;

	if (!lp_load(dyn_CONFIGFILE,True,False,False)) {
		fprintf(stderr, "Can't load %s - run testparm to debug it\n", dyn_CONFIGFILE);
	}


	pc = poptGetContext(argv[0], argc, (const char **) argv, long_options,0);

	while((opt = poptGetNextOpt(pc)) != -1) {
	}

	setup_logging(argv[0], True);

	if (remote) {
		error = reg_open_remote (&h, cmdline_get_username(), cmdline_get_userpassword(), remote);
	} else {
		error = reg_open_local (&h);
	}

	if (W_ERROR_IS_OK(error)) {
		fprintf(stderr, "Error: %s\n", win_errstr(error));
		return 1;
	}
		
	patch = poptGetArg(pc);
	if(!patch) patch = "/dev/stdin";
	poptFreeContext(pc);

	nt_apply_reg_command_file(h, patch);

	return 0;
}
